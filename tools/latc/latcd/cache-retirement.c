#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cache-retirement.h"
#include "../aot-v2/runtime/cache-lifecycle.h"
#include "parson/parson.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define MANIFEST_LIMIT 4096
#define RECORD_LIMIT 65536

static bool object_name_valid(const char *source, const char *name)
{
    if (!name || strncmp(source, name, 64)) return false;
    const char *suffix = name + 64;
    if (*suffix == '-') {
        suffix++;
        if (strlen(suffix) < 64 || strspn(suffix, "0123456789abcdef") != 64) return false;
        suffix += 64;
    }
    return !strcmp(suffix, ".so") || !strcmp(suffix, ".native") ||
           !strcmp(suffix, ".tbset");
}

static bool object_stat_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

typedef struct RecoveryObject {
    struct stat identity;
    char *evidence;
} RecoveryObject;

struct LatcdRecoveryCursor {
    char *root_path;
    int root;
    DIR *directory;
    bool tombstones, done, failed, yielded;
    char *pending;
    struct stat pending_identity;
    GHashTable *verified;
    int hash_fd;
    char *hash_name;
    struct stat hash_identity;
    GChecksum *hash;
    uint64_t offset, bytes_left;
    int64_t deadline;
    LatcdRecoveryProgress progress;
};

static char *recovery_capture(int root, const char *source, const char *name,
                              LatcdRecoveryCursor *cursor);

static char *capture_objects(int directory, const char *source,
                             const char *const *names, size_t count)
{
    if (!source || strlen(source) != 64 ||
        strspn(source, "0123456789abcdef") != 64 || !names || !count || count > 6) return NULL;
    GKeyFile *objects = g_key_file_new();
    bool valid = true;
    g_key_file_set_integer(objects, "objects", "count", count);
    for (size_t i = 0; valid && i < count; i++) {
        if (!object_name_valid(source, names[i])) { valid = false; break; }
        int fd = openat(directory, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, path;
        valid = fd >= 0 && !flock(fd, LOCK_SH | LOCK_NB) && !fstat(fd, &before) &&
            S_ISREG(before.st_mode) && before.st_uid == geteuid() &&
            before.st_nlink == 1 && !(before.st_mode & 0222) && before.st_size > 0;
        GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
        unsigned char buffer[65536];
        uint64_t total = 0;
        while (valid) {
            ssize_t bytes = read(fd, buffer, sizeof(buffer));
            if (bytes < 0 && errno == EINTR) continue;
            if (bytes < 0) { valid = false; break; }
            if (!bytes) break;
            total += bytes;
            if (total > (uint64_t)before.st_size) { valid = false; break; }
            g_checksum_update(hash, buffer, bytes);
        }
        valid = valid && total == (uint64_t)before.st_size && !fstat(fd, &after) &&
            !fstatat(directory, names[i], &path, AT_SYMLINK_NOFOLLOW) &&
            object_stat_equal(&before, &after) && object_stat_equal(&before, &path);
        if (valid) {
            char group[32];
            snprintf(group, sizeof(group), "object%zu", i);
            g_key_file_set_string(objects, group, "name", names[i]);
            g_key_file_set_uint64(objects, group, "device", before.st_dev);
            g_key_file_set_uint64(objects, group, "inode", before.st_ino);
            g_key_file_set_uint64(objects, group, "size", before.st_size);
            g_key_file_set_uint64(objects, group, "allocated", (uint64_t)before.st_blocks * 512);
            g_key_file_set_string(objects, group, "sha256", g_checksum_get_string(hash));
        }
        g_checksum_free(hash);
        if (fd >= 0) close(fd);
    }
    char *data = valid ? g_key_file_to_data(objects, NULL, NULL) : NULL;
    g_key_file_unref(objects);
    return data;
}

char *latcd_retirement_capture_objects(const char *root, const char *source,
                                      const char *const *names, size_t count)
{
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return NULL;
    char *data = capture_objects(directory, source, names, count);
    close(directory);
    return data;
}

static int fail(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (error && size) vsnprintf(error, size, format, args);
    va_end(args);
    return -1;
}

static bool source_valid(const char *source)
{
    return source && strlen(source) == 64 &&
        strspn(source, "0123456789abcdef") == 64;
}

static int open_directory(int parent, const char *name, bool create)
{
    if (create && mkdirat(parent, name, 0700) && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) || st.st_uid != geteuid() ||
                    (st.st_mode & 0077))) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    if (fd >= 0 && create && fsync(parent)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_store(int root, bool create)
{
    int gc = open_directory(root, ".gc", create);
    if (gc < 0) return -1;
    int records = open_directory(gc, "transactions", create);
    close(gc);
    return records;
}

int latcd_retirement_roots_lock(const char *root, int operation,
                                char *error, size_t error_size)
{
    if (operation != LOCK_SH && operation != (LOCK_SH | LOCK_NB) &&
        operation != (LOCK_EX | LOCK_NB))
        return fail(error, error_size, "invalid reference roots latch operation");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int fd = gc < 0 ? -1 : openat(gc, "reference-roots.lock",
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    bool created = fd >= 0;
    if (gc >= 0 && fd < 0 && errno == EEXIST)
        fd = openat(gc, "reference-roots.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    struct stat st, path;
    bool valid = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 && !(st.st_mode & 0077) &&
        !st.st_size && (!created || (!fsync(fd) && !fsync(gc))) &&
        !lat_aot_v2_cache_lock_fd(fd, operation, error, error_size) &&
        !fstatat(gc, "reference-roots.lock", &path, AT_SYMLINK_NOFOLLOW) &&
        object_stat_equal(&st, &path);
    int saved = errno;
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    if (valid) return fd;
    if (fd >= 0) close(fd);
    errno = saved;
    return fail(error, error_size, "reference roots latch busy or unsafe");
}

/* ENOENT is separate from a malformed, unsafe or unreadable root. */
static int read_file(int directory, const char *name, size_t limit,
                     char **contents, size_t *size)
{
    *contents = NULL;
    *size = 0;
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    struct stat before, after;
    int result = -1;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0222) || before.st_size <= 0 ||
        (uint64_t)before.st_size > limit) goto out;
    char *data = g_malloc((size_t)before.st_size + 1);
    size_t offset = 0;
    while (offset < (size_t)before.st_size) {
        ssize_t count = read(fd, data + offset, before.st_size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { g_free(data); goto out; }
        offset += count;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        g_free(data);
        goto out;
    }
    data[offset] = 0;
    *contents = data;
    *size = offset;
    result = 0;
out:
    close(fd);
    return result;
}

static bool record_write_fault(const char *point)
{
    const char *fault = getenv("LATCD_TEST_RETIREMENT_IO");
    if (!fault) return false;
    if (g_str_has_prefix(fault, "crash:") && !strcmp(fault + 6, point)) {
        raise(SIGKILL);
        _exit(127);
    }
    if (g_str_has_prefix(fault, "error:") && !strcmp(fault + 6, point)) {
        errno = EIO;
        return true;
    }
    return false;
}

static int write_record(int directory, const char *name, GKeyFile *record)
{
    gsize size;
    char *data = g_key_file_to_data(record, &size, NULL);
    char *temporary = NULL;
    int fd = -1;
    /* A forked writer may share the parent's random state. Never remove an
     * existing writer's evidence on O_EXCL collision. */
    for (int attempt = 0; attempt < 16; attempt++) {
        char *uuid = g_uuid_string_random();
        g_free(temporary);
        temporary = g_strdup_printf(".write-%s", uuid);
        g_free(uuid);
        fd = openat(directory, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    bool created = fd >= 0;
    int result = -1;
    int saved;
    if (fd < 0) goto out;
    if (record_write_fault("created")) goto close_out;
    size_t offset = 0;
    while (offset < size) {
        /* Exercise an interrupted short write without changing normal I/O. */
        size_t chunk = size - offset;
        const char *fault = getenv("LATCD_TEST_RETIREMENT_IO");
        if (!offset && fault && g_str_has_suffix(fault, ":partial-write"))
            chunk = MAX((size_t)1, chunk / 2);
        ssize_t count = write(fd, data + offset, chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto close_out;
        offset += count;
        if (record_write_fault("partial-write")) goto close_out;
    }
    if (record_write_fault("written") || fchmod(fd, 0400) ||
        record_write_fault("chmod") || fsync(fd) ||
        record_write_fault("file-synced")) goto close_out;
    if (close(fd)) { fd = -1; goto out; }
    fd = -1;
    if (record_write_fault("closed") ||
        renameat(directory, temporary, directory, name) ||
        record_write_fault("renamed") || fsync(directory) ||
        record_write_fault("directory-synced")) goto out;
    result = 0;
close_out:
    if (fd >= 0) close(fd);
out:
    saved = errno;
    if (result && created) unlinkat(directory, temporary, 0);
    g_free(temporary);
    g_free(data);
    errno = saved;
    return result;
}

static void set_clock(GKeyFile *record, const char *prefix)
{
    struct timespec now;
    gchar *boot = NULL;
    gsize size;
    char *boot_key = g_strdup_printf("%s_boot", prefix);
    char *time_key = g_strdup_printf("%s_boottime_us", prefix);
    if (!clock_gettime(CLOCK_BOOTTIME, &now) &&
        g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, &size, NULL)) {
        g_strchomp(boot);
        g_key_file_set_string(record, "transaction", boot_key, boot);
        g_key_file_set_uint64(record, "transaction", time_key,
                             (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000);
    }
    g_free(boot);
    g_free(boot_key);
    g_free(time_key);
}

int latcd_retirement_prepare(const char *root, const char *source,
                            const char *next, size_t next_size, const char *objects,
                            char **transaction, char *error, size_t error_size)
{
    *transaction = NULL;
    if (!source_valid(source) || !next || !next_size || next_size > MANIFEST_LIMIT)
        return fail(error, error_size, "invalid retirement transaction input");
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int store = root_fd < 0 ? -1 : open_store(root_fd, true);
    int result = -1;
    char *previous = NULL;
    size_t previous_size = 0;
    char *current = g_strdup_printf("%s.current", source);
    if (store < 0 || read_file(root_fd, current, MANIFEST_LIMIT,
                              &previous, &previous_size) < 0) goto out;
    GKeyFile *record = g_key_file_new();
    char *old64 = g_base64_encode((guchar *)previous, previous_size);
    char *new64 = g_base64_encode((const guchar *)next, next_size);
    g_key_file_set_integer(record, "transaction", "version", 2);
    char *object64 = g_base64_encode((const guchar *)(objects ? objects : ""),
                                    objects ? strlen(objects) : 0);
    g_key_file_set_string(record, "transaction", "objects", object64);
    g_free(object64);
    g_key_file_set_string(record, "transaction", "source", source);
    g_key_file_set_string(record, "transaction", "state", "PREPARED");
    g_key_file_set_string(record, "transaction", "previous", old64);
    g_key_file_set_string(record, "transaction", "next", new64);
    set_clock(record, "prepared");
    char *uuid = g_uuid_string_random();
    char *name = g_strdup_printf("%s.ini", uuid);
    g_free(uuid);
    result = write_record(store, name, record);
    if (!result) *transaction = g_strdup(name);
    g_free(name);
    g_free(old64);
    g_free(new64);
    g_key_file_unref(record);
out:
    if (result) fail(error, error_size, "cannot persist retirement PREPARED: %s", strerror(errno));
    if (store >= 0) close(store);
    if (root_fd >= 0) close(root_fd);
    g_free(current);
    g_free(previous);
    return result;
}

static bool name_valid(const char *name)
{
    if (!name || strlen(name) != 40 || strcmp(name + 36, ".ini")) return false;
    char uuid[37];
    memcpy(uuid, name, 36);
    uuid[36] = 0;
    return g_uuid_string_is_valid(uuid);
}

static bool record_shape_valid(GKeyFile *record)
{
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "transaction");
    g_strfreev(groups);
    char **keys = g_key_file_get_keys(record, "transaction", &count, NULL);
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
    const char *allowed[] = { "version", "source", "state", "previous", "next",
        "prepared_boot", "prepared_boottime_us", "retired_boot", "retired_boottime_us",
        "objects", "objects_status", "binding_status" };
    for (gsize i = 0; valid && i < count; i++) {
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(allowed); j++)
            known |= !strcmp(keys[i], allowed[j]);
        valid = known && g_hash_table_add(seen, keys[i]);
    }
    g_hash_table_unref(seen);
    g_strfreev(keys);
    return valid;
}

static guchar *decode_snapshot(const char *value, gsize *size)
{
    guchar *decoded = g_base64_decode(value, size);
    char *canonical = g_base64_encode(decoded, *size);
    bool valid = *size <= MANIFEST_LIMIT && !strcmp(value, canonical);
    g_free(canonical);
    if (!valid) { g_free(decoded); return NULL; }
    return decoded;
}

static bool exact_keys(GKeyFile *record, const char *group,
                        const char *const *required, size_t required_count)
{
    gsize count;
    char **keys = g_key_file_get_keys(record, group, &count, NULL);
    bool valid = keys && count == required_count;
    for (size_t i = 0; valid && i < required_count; i++) {
        unsigned matches = 0;
        for (gsize j = 0; j < count; j++) matches += !strcmp(keys[j], required[i]);
        valid = matches == 1;
    }
    g_strfreev(keys);
    return valid;
}

static bool digest_valid(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static bool manifest_references(const char *source, const char *raw, size_t size,
                                GHashTable *expected)
{
    if (!raw || !size || size >= MANIFEST_LIMIT || memchr(raw, 0, size)) return false;
    char *text = g_strndup(raw, size);
    JSON_Value *value = json_parse_string(text);
    JSON_Object *manifest = json_value_get_object(value);
    const char *required[] = {"version", "module", "native", "tbset",
        "source_sha256", "codegen_id", "published_sequence"};
    const char *optional[] = {"module_sha256", "native_sha256"};
    bool valid = manifest != NULL;
    for (size_t i = 0; valid && i < json_object_get_count(manifest); i++) {
        const char *key = json_object_get_name(manifest, i);
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(required); j++) known |= !strcmp(key, required[j]);
        for (size_t j = 0; j < G_N_ELEMENTS(optional); j++) known |= !strcmp(key, optional[j]);
        valid = known;
    }
    for (size_t i = 0; valid && i < G_N_ELEMENTS(required); i++)
        valid = json_object_has_value(manifest, required[i]);
    const char *version = lat_json_number_token(json_object_get_value(manifest, "version"));
    const char *sequence = lat_json_number_token(json_object_get_value(manifest, "published_sequence"));
    const char *identity = json_object_get_string(manifest, "source_sha256");
    const char *codegen = json_object_get_string(manifest, "codegen_id");
    char *end = NULL;
    errno = 0;
    if (sequence) (void)g_ascii_strtoull(sequence, &end, 10);
    valid = valid && version && !strcmp(version, "2") && sequence && *sequence &&
        strspn(sequence, "0123456789") == strlen(sequence) && end && !*end && !errno &&
        identity && !strcmp(identity, source) && digest_valid(codegen);
    valid = valid && identity && codegen &&
        json_object_get_string_len(manifest, "source_sha256") == strlen(identity) &&
        json_object_get_string_len(manifest, "codegen_id") == strlen(codegen);
    for (size_t i = 0; valid && i < G_N_ELEMENTS(optional); i++) {
        if (json_object_has_value(manifest, optional[i])) {
            const char *hash = json_object_get_string(manifest, optional[i]);
            valid = digest_valid(hash) && json_object_get_string_len(manifest, optional[i]) == strlen(hash);
        }
    }
    const char *roles[] = {"module", "native", "tbset"};
    const char *suffixes[] = {".so", ".native", ".tbset"};
    for (size_t i = 0; valid && i < G_N_ELEMENTS(roles); i++) {
        const char *name = json_object_get_string(manifest, roles[i]);
        valid = name && json_object_get_string_len(manifest, roles[i]) == strlen(name);
        if (!valid || (i == 2 && !*name)) continue;
        valid = object_name_valid(source, name) && g_str_has_suffix(name, suffixes[i]);
        if (!valid) break;
        const char *hash = i < 2 ? json_object_get_string(manifest, optional[i]) : NULL;
        const char *prior = g_hash_table_lookup(expected, name);
        if (prior && *prior && hash && strcmp(prior, hash)) { valid = false; break; }
        if (!prior || !*prior)
            g_hash_table_replace(expected, g_strdup(name), g_strdup(hash ? hash : ""));
    }
    json_value_free(value);
    g_free(text);
    return valid;
}

/* Caller holds the reference roots EX latch under the owner contract. This bounded final
 * check is defense in depth, not a persistent reference index or domain gate. */
static int object_current_status(int root, const char *name)
{
    int copy = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *directory = copy < 0 ? NULL : fdopendir(copy);
    if (!directory) { if (copy >= 0) close(copy); return -1; }
    struct stat before = {0}, after;
    int result = fstat(root, &before) ? -1 : 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 4096 || g_get_monotonic_time() - started >= 10000) { result = -1; break; }
        if (!g_str_has_suffix(entry->d_name, ".current")) continue;
        char source[65] = {0};
        if (strlen(entry->d_name) == 72) memcpy(source, entry->d_name, 64);
        char *raw = NULL;
        size_t size;
        GHashTable *refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        bool valid = source_valid(source) &&
            !read_file(root, entry->d_name, MANIFEST_LIMIT, &raw, &size) &&
            manifest_references(source, raw, size, refs);
        result = !valid ? -1 : g_hash_table_contains(refs, name) ? 1 : 0;
        g_hash_table_unref(refs);
        g_free(raw);
    }
    if (fstat(root, &after) || !object_stat_equal(&before, &after)) result = -1;
    closedir(directory);
    return result;
}

int latcd_retirement_validate_binding(const char *source,
                                      const char *previous, size_t previous_size,
                                      const char *next, size_t next_size,
                                      const char *raw, size_t size)
{
    if (!source_valid(source) || !raw || !size || size >= 16384 || memchr(raw, 0, size)) return -1;
    GHashTable *expected = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    GHashTable *observed = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    bool valid = (!previous_size || manifest_references(source, previous, previous_size, expected)) &&
        manifest_references(source, next, next_size, expected);
    GKeyFile *objects = g_key_file_new();
    valid = valid && g_key_file_load_from_data(objects, raw, size, 0, NULL);
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    const char *header[] = {"count"};
    const char *object_fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    gsize group_count;
    char **groups = g_key_file_get_groups(objects, &group_count);
    valid = valid && count > 0 && count <= 6 && group_count == (gsize)count + 1 &&
        exact_keys(objects, "objects", header, G_N_ELEMENTS(header));
    g_strfreev(groups);
    for (int i = 0; valid && i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!exact_keys(objects, group, object_fields, G_N_ELEMENTS(object_fields))) { valid = false; break; }
        char *name = g_key_file_get_string(objects, group, "name", NULL);
        char *hash = g_key_file_get_string(objects, group, "sha256", NULL);
        const char *required_hash = name ? g_hash_table_lookup(expected, name) : NULL;
        valid = required_hash && digest_valid(hash) && (!*required_hash || !strcmp(required_hash, hash));
        if (valid) {
            /* Repeated names occur when consecutive manifests share an object.
             * All identity fields must agree, not merely the filename/hash. */
            const char *fields[] = {"device", "inode", "size", "allocated", "sha256"};
            GString *signature = g_string_new(NULL);
            for (size_t j = 0; valid && j < G_N_ELEMENTS(fields); j++) {
                char *field = g_key_file_get_string(objects, group, fields[j], NULL);
                valid = field && !strchr(field, '\n');
                if (valid && j < 4) {
                    char *end;
                    errno = 0;
                    (void)g_ascii_strtoull(field, &end, 10);
                    valid = *field && strspn(field, "0123456789") == strlen(field) && !*end && !errno;
                }
                if (valid) g_string_append_printf(signature, "%s\n", field);
                g_free(field);
            }
            const char *prior = g_hash_table_lookup(observed, name);
            valid = valid && (!prior || !strcmp(prior, signature->str));
            if (valid) g_hash_table_replace(observed, g_strdup(name), g_strdup(signature->str));
            g_string_free(signature, TRUE);
        }
        g_free(name);
        g_free(hash);
    }
    valid = valid && g_hash_table_size(expected) == g_hash_table_size(observed);
    g_hash_table_unref(expected);
    g_hash_table_unref(observed);
    g_key_file_unref(objects);
    return valid ? 0 : -1;
}

static bool hold_id_valid(const char *id)
{
    return id && strlen(id) == 36 && g_uuid_string_is_valid(id);
}

static bool hold_record_valid(GKeyFile *record, const char *id, const char *name,
                               const struct stat *cache, const struct stat *object)
{
    const char *fields[] = {"version", "id", "name", "reason", "state",
        "cache_device", "cache_inode", "object_device", "object_inode"};
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "hold") &&
        exact_keys(record, "hold", fields, G_N_ELEMENTS(fields));
    g_strfreev(groups);
    const char *keys[] = {"version", "id", "name"};
    const char *expected[] = {"1", id, name};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(keys); i++) {
        char *value = g_key_file_get_string(record, "hold", keys[i], NULL);
        valid = !g_strcmp0(value, expected[i]);
        g_free(value);
    }
    char *reason = g_key_file_get_string(record, "hold", "reason", NULL);
    char *state = g_key_file_get_string(record, "hold", "state", NULL);
    valid &= (!g_strcmp0(reason, "ROLLBACK") || !g_strcmp0(reason, "MIGRATION") ||
              !g_strcmp0(reason, "EXTERNAL")) &&
             (!g_strcmp0(state, "ACTIVE") || !g_strcmp0(state, "RELEASED"));
    g_free(reason); g_free(state);
    uint64_t numbers[] = {cache->st_dev, cache->st_ino, object->st_dev, object->st_ino};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(numbers); i++) {
        char *value = g_key_file_get_string(record, "hold", fields[5 + i], NULL);
        errno = 0;
        char *end = NULL;
        uint64_t number = value ? g_ascii_strtoull(value, &end, 10) : 0;
        valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
            !errno && end && !*end && number == numbers[i];
        g_free(value);
    }
    return valid;
}

static bool record_string_is(GKeyFile *record, const char *group,
                             const char *key, const char *expected);
static bool record_uint64(GKeyFile *record, const char *group,
                          const char *key, uint64_t *value);

typedef struct MountLeaseRecord {
    char *scope;
    char *source;
    char *name;
    char *state;
    uint64_t object_device;
    uint64_t object_inode;
} MountLeaseRecord;

static void mount_lease_clear(MountLeaseRecord *lease)
{
    g_free(lease->scope);
    g_free(lease->source);
    g_free(lease->name);
    g_free(lease->state);
    memset(lease, 0, sizeof(*lease));
}

static bool mount_lease_parse(GKeyFile *record, const char *id,
                              const struct stat *cache, MountLeaseRecord *lease)
{
    const char *fields[] = {"version", "id", "scope", "state", "cache_device",
        "cache_inode", "source", "name", "object_device", "object_inode"};
    gsize groups = 0;
    char **names = g_key_file_get_groups(record, &groups);
    bool valid = groups == 1 && !strcmp(names[0], "mount") &&
        exact_keys(record, "mount", fields, G_N_ELEMENTS(fields));
    g_strfreev(names);
    valid = valid && record_string_is(record, "mount", "version", "1") &&
        record_string_is(record, "mount", "id", id);
    uint64_t cache_device, cache_inode;
    valid = valid &&
        record_uint64(record, "mount", "cache_device", &cache_device) &&
        cache_device == (uint64_t)cache->st_dev &&
        record_uint64(record, "mount", "cache_inode", &cache_inode) &&
        cache_inode == (uint64_t)cache->st_ino;
    lease->scope = g_key_file_get_string(record, "mount", "scope", NULL);
    lease->source = g_key_file_get_string(record, "mount", "source", NULL);
    lease->name = g_key_file_get_string(record, "mount", "name", NULL);
    lease->state = g_key_file_get_string(record, "mount", "state", NULL);
    valid = valid && lease->scope && lease->source && lease->name && lease->state &&
        (!strcmp(lease->state, "ACTIVE") || !strcmp(lease->state, "RELEASED")) &&
        record_uint64(record, "mount", "object_device", &lease->object_device) &&
        record_uint64(record, "mount", "object_inode", &lease->object_inode);
    if (!valid) {
        mount_lease_clear(lease);
        return false;
    }
    if (!strcmp(lease->scope, "CACHE")) {
        valid = valid && !*lease->source && !*lease->name &&
            !lease->object_device && !lease->object_inode;
    } else if (!strcmp(lease->scope, "SOURCE")) {
        valid = valid && source_valid(lease->source) && !*lease->name &&
            !lease->object_device && !lease->object_inode;
    } else if (!strcmp(lease->scope, "OBJECT")) {
        valid = valid && source_valid(lease->source) &&
            object_name_valid(lease->source, lease->name) &&
            lease->object_device && lease->object_inode;
    } else valid = false;
    if (!valid) mount_lease_clear(lease);
    return valid;
}

/* Called with retirement roots EX (or while a participant still holds SH).
 * One malformed or excessive record freezes the object. */
static int mount_lease_status(int root, int gc, const char *source,
                              const char *name, const struct stat *object)
{
    int store = open_directory(gc, "mount-leases", false);
    int saved = errno;
    if (store < 0) return saved == ENOENT ? 0 : -1;
    struct stat cache;
    if (fstat(root, &cache)) { close(store); return -1; }
    DIR *directory = fdopendir(store);
    if (!directory) { close(store); return -1; }
    int result = 0;
    unsigned visited = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 128 || strlen(entry->d_name) != 40 ||
            strcmp(entry->d_name + 36, ".ini")) { result = -1; break; }
        char id[37];
        memcpy(id, entry->d_name, 36);
        id[36] = 0;
        char *raw = NULL;
        size_t size;
        GKeyFile *record = g_key_file_new();
        MountLeaseRecord lease = {0};
        bool valid = hold_id_valid(id) &&
            !read_file(dirfd(directory), entry->d_name, MANIFEST_LIMIT, &raw, &size) &&
            !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            mount_lease_parse(record, id, &cache, &lease);
        if (!valid) result = -1;
        else if (!strcmp(lease.state, "ACTIVE")) {
            if (!strcmp(lease.scope, "CACHE")) result = 1;
            else if (!strcmp(lease.scope, "SOURCE") && !strcmp(lease.source, source))
                result = 1;
            else if (!strcmp(lease.scope, "OBJECT") && !strcmp(lease.source, source) &&
                     !strcmp(lease.name, name)) {
                if (lease.object_device != (uint64_t)object->st_dev ||
                    lease.object_inode != (uint64_t)object->st_ino) result = -1;
                else result = 1;
            }
        }
        mount_lease_clear(&lease);
        g_free(raw);
        g_key_file_unref(record);
        if (result) break;
    }
    closedir(directory);
    return result;
}

/* Called under source EX. Any unreadable or partial hold freezes the object.
 * Bounded work: overflow retains rather than doing a long scan under S. */
static int object_hold_status(int root, const char *name, const struct stat *object)
{
    int gc = open_directory(root, ".gc", false);
    if (gc < 0) return errno == ENOENT ? 0 : -1;
    int holds = open_directory(gc, "holds", false);
    int saved = errno;
    close(gc);
    if (holds < 0) return saved == ENOENT ? 0 : -1;
    int fd = open_directory(holds, name, false);
    saved = errno;
    close(holds);
    if (fd < 0) return saved == ENOENT ? 0 : -1;
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    struct stat cache;
    int result = fstat(root, &cache) ? -1 : 0;
    unsigned visited = 0;
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        if (++visited > 128 || !name_valid(entry->d_name) ||
            read_file(fd, entry->d_name, MANIFEST_LIMIT, &raw, &size)) { result = -1; break; }
        char id[37];
        memcpy(id, entry->d_name, 36); id[36] = 0;
        GKeyFile *record = g_key_file_new();
        bool valid = !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            hold_record_valid(record, id, name, &cache, object);
        char *state = g_key_file_get_string(record, "hold", "state", NULL);
        result = !valid ? -1 : !g_strcmp0(state, "ACTIVE") ? 1 : 0;
        g_free(state); g_free(raw); g_key_file_unref(record);
    }
    closedir(directory);
    return result;
}

static bool record_string_is(GKeyFile *record, const char *group,
                              const char *key, const char *expected)
{
    char *value = g_key_file_get_string(record, group, key, NULL);
    bool equal = !g_strcmp0(value, expected);
    g_free(value);
    return equal;
}

static bool record_uint64(GKeyFile *record, const char *group, const char *key,
                           uint64_t *number)
{
    char *value = g_key_file_get_string(record, group, key, NULL), *end = NULL;
    errno = 0;
    *number = value ? g_ascii_strtoull(value, &end, 10) : 0;
    bool valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
        !errno && end && !*end;
    g_free(value);
    return valid;
}

static bool domain_record_parse(GKeyFile *record, const struct stat *cache,
                                const struct stat *lock, char id[37])
{
    const char *fields[] = {"version", "id", "cache_device", "cache_inode",
        "lock_device", "lock_inode", "created_boot", "created_boottime_us"};
    gsize groups = 0;
    char **names = g_key_file_get_groups(record, &groups);
    bool valid = groups == 1 && !strcmp(names[0], "domain") &&
        exact_keys(record, "domain", fields, G_N_ELEMENTS(fields));
    g_strfreev(names);
    char *stored_id = g_key_file_get_string(record, "domain", "id", NULL);
    char *created_boot = g_key_file_get_string(record, "domain", "created_boot", NULL);
    uint64_t cache_device, cache_inode, lock_device, lock_inode, created;
    valid = valid && hold_id_valid(stored_id) &&
        record_uint64(record, "domain", "cache_device", &cache_device) &&
        cache_device == (uint64_t)cache->st_dev &&
        record_uint64(record, "domain", "cache_inode", &cache_inode) &&
        cache_inode == (uint64_t)cache->st_ino &&
        record_uint64(record, "domain", "lock_device", &lock_device) &&
        lock_device == (uint64_t)lock->st_dev &&
        record_uint64(record, "domain", "lock_inode", &lock_inode) &&
        lock_inode == (uint64_t)lock->st_ino && hold_id_valid(created_boot) &&
        record_uint64(record, "domain", "created_boottime_us", &created);
    if (valid && id) memcpy(id, stored_id, 37);
    g_free(stored_id);
    g_free(created_boot);
    return valid;
}

static int domain_validate_open(int gc, const struct stat *cache,
                                char id[37], char *error, size_t error_size)
{
    char *raw = NULL;
    size_t size = 0;
    int status = read_file(gc, "domain.ini", MANIFEST_LIMIT, &raw, &size);
    int lock = openat(gc, "domain.lock",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int lock_error = errno;
    if (status == 1 && lock < 0 && lock_error == ENOENT) {
        g_free(raw);
        return 0;
    }
    struct stat lock_status;
    bool valid = status == 0 && lock >= 0 && !memchr(raw, 0, size) &&
        !fstat(lock, &lock_status) && S_ISREG(lock_status.st_mode) &&
        lock_status.st_uid == geteuid() && lock_status.st_nlink == 1 &&
        !(lock_status.st_mode & 0077) && !lock_status.st_size;
    GKeyFile *record = g_key_file_new();
    valid = valid && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
        domain_record_parse(record, cache, &lock_status, id);
    g_key_file_unref(record);
    if (lock >= 0) close(lock);
    g_free(raw);
    if (!valid) return fail(error, error_size,
        "cache domain metadata is incomplete, malformed or rebound");
    return 1;
}

int latcd_cache_domain_validate(const char *root, char id[37],
                                char *error, size_t error_size)
{
    if (!root || !*root) return fail(error, error_size, "invalid cache domain root");
    if (id) id[0] = 0;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return fail(error, error_size, "cannot open cache domain root");
    struct stat cache;
    int gc = -1, result = -1;
    if (fstat(directory, &cache) || !S_ISDIR(cache.st_mode) ||
        cache.st_uid != geteuid() || (cache.st_mode & 0077)) goto out;
    gc = open_directory(directory, ".gc", false);
    if (gc < 0) {
        if (errno == ENOENT) result = 0;
        goto out;
    }
    result = domain_validate_open(gc, &cache, id, error, error_size);
out:
    if (gc >= 0) close(gc);
    close(directory);
    return result;
}

int latcd_cache_domain_init(const char *root, char id[37],
                            char *error, size_t error_size)
{
    if (!root || !*root || !id) return fail(error, error_size, "invalid cache domain root");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return fail(error, error_size, "cannot open cache domain root");
    struct stat cache, lock_status;
    int gc = -1, lock = -1, result = -1;
    if (fstat(directory, &cache) || !S_ISDIR(cache.st_mode) ||
        cache.st_uid != geteuid() || (cache.st_mode & 0077)) goto out;
    gc = open_directory(directory, ".gc", true);
    if (gc < 0) goto out;
    lock = openat(gc, "domain.lock",
                  O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool created = lock >= 0;
    if (lock < 0 && errno == EEXIST)
        lock = openat(gc, "domain.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (lock < 0 || (created && fchmod(lock, 0600)) ||
        flock(lock, LOCK_EX | LOCK_NB) ||
        fstat(lock, &lock_status) || !S_ISREG(lock_status.st_mode) ||
        lock_status.st_uid != geteuid() || lock_status.st_nlink != 1 ||
        (lock_status.st_mode & 0077) || lock_status.st_size) goto out;
    char *raw = NULL;
    size_t size = 0;
    int status = read_file(gc, "domain.ini", MANIFEST_LIMIT, &raw, &size);
    if (status < 0) { g_free(raw); goto out; }
    if (!status) {
        GKeyFile *record = g_key_file_new();
        bool valid = !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            domain_record_parse(record, &cache, &lock_status, id);
        g_key_file_unref(record);
        g_free(raw);
        if (!valid) goto out;
        result = 0;
        goto out;
    }
    g_free(raw);
    char *new_id = g_uuid_string_random();
    char *boot = NULL;
    struct timespec now;
    uint64_t now_us;
    if (!new_id || clock_gettime(CLOCK_BOOTTIME, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > UINT64_MAX / 1000000 ||
        !g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL)) {
        g_free(new_id);
        g_free(boot);
        goto out;
    }
    g_strchomp(boot);
    now_us = (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
    GKeyFile *record = g_key_file_new();
    g_key_file_set_integer(record, "domain", "version", 1);
    g_key_file_set_string(record, "domain", "id", new_id);
    g_key_file_set_uint64(record, "domain", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "domain", "cache_inode", cache.st_ino);
    g_key_file_set_uint64(record, "domain", "lock_device", lock_status.st_dev);
    g_key_file_set_uint64(record, "domain", "lock_inode", lock_status.st_ino);
    g_key_file_set_string(record, "domain", "created_boot", boot);
    g_key_file_set_uint64(record, "domain", "created_boottime_us", now_us);
    if (!hold_id_valid(boot) || write_record(gc, "domain.ini", record)) {
        g_key_file_unref(record);
        g_free(new_id);
        g_free(boot);
        goto out;
    }
    g_key_file_unref(record);
    memcpy(id, new_id, 37);
    g_free(new_id);
    g_free(boot);
    result = 0;
out:
    if (lock >= 0) close(lock);
    if (gc >= 0) close(gc);
    close(directory);
    if (result) return fail(error, error_size,
        "cache domain initialization rejected or incomplete");
    return 0;
}

static bool task_identity_valid(GKeyFile *record, const char *group)
{
    const char *numbers[] = {"device", "inode", "size", "mode", "uid", "mtime_nsec"};
    uint64_t value;
    for (unsigned i = 0; i < G_N_ELEMENTS(numbers); i++) {
        if (!record_uint64(record, group, numbers[i], &value) ||
            (i == 5 && value >= 1000000000)) return false;
    }
    char *seconds = g_key_file_get_string(record, group, "mtime_sec", NULL), *end = NULL;
    const char *digits = seconds && *seconds == '-' ? seconds + 1 : seconds;
    errno = 0;
    if (seconds) (void)g_ascii_strtoll(seconds, &end, 10);
    bool valid = digits && *digits && strspn(digits, "0123456789") == strlen(digits) &&
        !errno && end && !*end;
    g_free(seconds);
    return valid;
}

/* A release receipt is effective only with an exact task inode and no holder.
 * Missing receipt is a hold, not evidence of task completion. */
static int task_inputs_released(int gc, const char *name, bool copying,
                                 int task, const struct stat *identity)
{
    int releases = open_directory(gc, copying ? "copy-releases" : "compiler-releases", false);
    if (releases < 0) return errno == ENOENT ? 0 : -1;
    char *raw = NULL;
    size_t size;
    int status = read_file(releases, name, MANIFEST_LIMIT, &raw, &size);
    close(releases);
    if (status) return status == 1 ? 0 : -1;
    GKeyFile *record = g_key_file_new();
    const char *keys[] = {"version", "task_id", "state", "task_device", "task_inode"};
    gsize count;
    char id[37];
    memcpy(id, name, 36); id[36] = 0;
    bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL);
    char **groups = g_key_file_get_groups(record, &count);
    uint64_t device, inode;
    valid = valid && count == 1 && !strcmp(groups[0], "handoff") &&
        exact_keys(record, "handoff", keys, G_N_ELEMENTS(keys)) &&
        record_string_is(record, "handoff", "version", "1") &&
        record_string_is(record, "handoff", "task_id", id) &&
        record_string_is(record, "handoff", "state", copying ? "RELEASED" : "INPUTS_RELEASED") &&
        record_uint64(record, "handoff", "task_device", &device) && device == (uint64_t)identity->st_dev &&
        record_uint64(record, "handoff", "task_inode", &inode) && inode == (uint64_t)identity->st_ino;
    g_strfreev(groups); g_free(raw); g_key_file_unref(record);
    if (!valid) return -1;
    if (flock(task, LOCK_EX | LOCK_NB)) return errno == EWOULDBLOCK ? 0 : -1;
    return 1;
}

/* Defense in depth, not the full reference graph. The management owner must
 * serialize local publisher transitions. No unbounded task walk under S. */
static int object_task_status(int root, const char *name, const struct stat *object)
{
    int gc = open_directory(root, ".gc", false);
    if (gc < 0) return errno == ENOENT ? 0 : -1;
    int tasks = open_directory(gc, "tasks", false);
    if (tasks < 0) { int result = errno == ENOENT ? 0 : -1; close(gc); return result; }
    DIR *directory = fdopendir(tasks);
    if (!directory) { close(tasks); close(gc); return -1; }
    struct stat cache;
    int result = fstat(root, &cache) ? -1 : 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 128 || g_get_monotonic_time() - started >= 10000 ||
            !name_valid(entry->d_name)) { result = -1; break; }
        int task = openat(tasks, entry->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, path;
        char *raw = NULL;
        size_t size;
        GKeyFile *record = g_key_file_new();
        bool valid = task >= 0 && !fstat(task, &before) &&
            !read_file(tasks, entry->d_name, RECORD_LIMIT, &raw, &size) &&
            !fstat(task, &after) && object_stat_equal(&before, &after) &&
            !fstatat(tasks, entry->d_name, &path, AT_SYMLINK_NOFOLLOW) && object_stat_equal(&before, &path) &&
            !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL);
        char id[37];
        memcpy(id, entry->d_name, 36); id[36] = 0;
        bool copying = record_string_is(record, "task", "version", "2");
        const char *task_keys[] = {"version", "id", "state", "source", "build_id",
                                  copying ? "kind" : "environment_sha256"};
        valid = valid && (copying || record_string_is(record, "task", "version", "1")) &&
            exact_keys(record, "task", task_keys, G_N_ELEMENTS(task_keys)) &&
            record_string_is(record, "task", "id", id) && record_string_is(record, "task", "state", "BOUND");
        if (copying) valid &= record_string_is(record, "task", "kind", "COPY");
        const char *digests[] = {"source", "build_id", "environment_sha256"};
        for (unsigned i = 0; valid && i < (copying ? 2u : 3u); i++) {
            char *value = g_key_file_get_string(record, "task", digests[i], NULL);
            valid = digest_valid(value); g_free(value);
        }
        uint64_t device, inode;
        valid = valid && record_uint64(record, "cache", "device", &device) && device == (uint64_t)cache.st_dev &&
            record_uint64(record, "cache", "inode", &inode) && inode == (uint64_t)cache.st_ino;
        bool referenced = false;
        const char *roles[] = {"source", "tbset", "base_native", "base_module", "input"};
        gsize count;
        char **groups = g_key_file_get_groups(record, &count);
        for (gsize i = 0; valid && i < count; i++) {
            const char *group = groups[i];
            bool input = false;
            for (unsigned j = 0; j < G_N_ELEMENTS(roles); j++) input |= !strcmp(group, roles[j]);
            if (!input) {
                if (!strcmp(group, "task")) continue;
                bool location = !strcmp(group, "cache") || !strcmp(group, "temporary") || !strcmp(group, "collected");
                bool output = !strcmp(group, copying ? "output" : "output_native") ||
                    (!copying && !strcmp(group, "output_module"));
                const char *identity_fields[] = {"device", "inode", "size", "mode", "uid", "mtime_sec", "mtime_nsec"};
                const char *output_fields[] = {"name"};
                valid = location ? exact_keys(record, group, identity_fields, G_N_ELEMENTS(identity_fields)) &&
                    task_identity_valid(record, group) : output && exact_keys(record, group, output_fields, 1);
                if (valid && output) {
                    char *value = g_key_file_get_string(record, group, "name", NULL);
                    valid = value && *value && !strchr(value, '/') && strcmp(value, ".") && strcmp(value, "..");
                    g_free(value);
                }
                continue;
            }
            const char *fields[] = {"name", "directory", "device", "inode", "size", "mode", "uid", "mtime_sec", "mtime_nsec"};
            char *input_name = g_key_file_get_string(record, group, "name", NULL);
            char *location = g_key_file_get_string(record, group, "directory", NULL);
            valid = exact_keys(record, group, fields, G_N_ELEMENTS(fields)) && input_name && *input_name &&
                !strchr(input_name, '/') && strcmp(input_name, ".") && strcmp(input_name, "..") &&
                (!g_strcmp0(location, "cache") || !g_strcmp0(location, "temporary") || !g_strcmp0(location, "collected")) &&
                task_identity_valid(record, group) &&
                record_uint64(record, group, "device", &device) && record_uint64(record, group, "inode", &inode);
            valid &= copying ? !strcmp(group, "input") : strcmp(group, "input") != 0;
            if (valid) referenced |= (!strcmp(location, "cache") && !strcmp(input_name, name)) ||
                (device == (uint64_t)object->st_dev && inode == (uint64_t)object->st_ino);
            g_free(input_name); g_free(location);
        }
        valid = valid && g_key_file_has_group(record, copying ? "input" : "source") &&
            g_key_file_has_group(record, "temporary") &&
            g_key_file_has_group(record, copying ? "output" : "output_native") &&
            (copying || g_key_file_has_group(record, "output_module"));
        g_strfreev(groups);
        if (!valid) result = -1;
        else if (referenced) {
            int released = task_inputs_released(gc, entry->d_name, copying, task, &before);
            if (released > 0 && copying) {
                char *output = g_key_file_get_string(record, "output", "name", NULL);
                int temporary = open_directory(root, ".tmp", false);
                struct stat st;
                if (!output || !*output || strchr(output, '/') || !strcmp(output, ".") || !strcmp(output, "..") ||
                    temporary < 0 || !fstatat(temporary, output, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)
                    released = 0;
                if (temporary >= 0) close(temporary);
                g_free(output);
            }
            result = released < 0 ? -1 : released ? 0 : 1;
        }
        if (task >= 0) close(task);
        g_free(raw); g_key_file_unref(record);
    }
    closedir(directory); close(gc);
    return result;
}

static int object_transaction_status(int root, const char *name, const struct stat *object,
                                      const uint64_t *grace_us)
{
    int store = open_store(root, false);
    if (store < 0)
        return errno == ENOENT && (!grace_us || !*grace_us) ? 0 : -1;
    DIR *directory = fdopendir(store);
    if (!directory) { close(store); return -1; }
    int result = 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    char *boot = NULL;
    struct timespec now;
    uint64_t now_us = 0, latest_deadline = 0;
    bool retirement_observed = false;
    if (grace_us) {
        if (clock_gettime(CLOCK_BOOTTIME, &now) || now.tv_sec < 0 ||
            (uint64_t)now.tv_sec > UINT64_MAX / 1000000 ||
            !g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL)) result = -1;
        if (!result) {
            g_strchomp(boot);
            if (!hold_id_valid(boot)) result = -1;
            now_us = (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
        }
    }
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        if (++visited > 128 || g_get_monotonic_time() - started >= 10000 ||
            !name_valid(entry->d_name) || read_file(store, entry->d_name, RECORD_LIMIT, &raw, &size)) {
            result = -1; break;
        }
        GKeyFile *record = g_key_file_new();
        bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            record_shape_valid(record);
        char *source = g_key_file_get_string(record, "transaction", "source", NULL);
        char *previous64 = g_key_file_get_string(record, "transaction", "previous", NULL);
        char *next64 = g_key_file_get_string(record, "transaction", "next", NULL);
        char *objects64 = g_key_file_get_string(record, "transaction", "objects", NULL);
        char *state = g_key_file_get_string(record, "transaction", "state", NULL);
        gsize previous_size = 0, next_size = 0, object_size = 0;
        guchar *previous = previous64 ? decode_snapshot(previous64, &previous_size) : NULL;
        guchar *next = next64 ? decode_snapshot(next64, &next_size) : NULL;
        guchar *objects = objects64 ? g_base64_decode(objects64, &object_size) : NULL;
        char *canonical = objects ? g_base64_encode(objects, object_size) : NULL;
        valid = valid && source_valid(source) && previous && next && next_size &&
            (record_string_is(record, "transaction", "version", "1") ||
             record_string_is(record, "transaction", "version", "2")) && state &&
            (!strcmp(state, "PREPARED") || !strcmp(state, "RETIRED") ||
             !strcmp(state, "ABORTED") || !strcmp(state, "UNKNOWN"));
        GHashTable *refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        valid = valid && (!previous_size || manifest_references(source, (char *)previous, previous_size, refs)) &&
            manifest_references(source, (char *)next, next_size, refs);
        bool referenced = valid && g_hash_table_contains(refs, name);
        bool retired = record_string_is(record, "transaction", "state", "RETIRED");
        bool bound = valid && objects && canonical && !strcmp(canonical, objects64) &&
            !latcd_retirement_validate_binding(source, (char *)previous, previous_size,
                (char *)next, next_size, (char *)objects, object_size);
        /* Legacy/unproven records cannot erase a root. A fully bound RETIRED
         * snapshot is history, not an indefinite hold on its former next set. */
        if (referenced && retired) {
            valid = bound && record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
                record_string_is(record, "transaction", "objects_status", "RECORDED");
        }
        if (bound) {
            GKeyFile *evidence = g_key_file_new();
            valid &= g_key_file_load_from_data(evidence, (char *)objects, object_size, 0, NULL);
            int count = g_key_file_get_integer(evidence, "objects", "count", NULL);
            for (int i = 0; valid && i < count; i++) {
                char group[32];
                snprintf(group, sizeof(group), "object%d", i);
                char *candidate = g_key_file_get_string(evidence, group, "name", NULL);
                uint64_t device, inode, bytes, allocated;
                valid = record_uint64(evidence, group, "device", &device) &&
                    record_uint64(evidence, group, "inode", &inode) &&
                    record_uint64(evidence, group, "size", &bytes) &&
                    record_uint64(evidence, group, "allocated", &allocated);
                bool same_inode = valid && device == (uint64_t)object->st_dev && inode == (uint64_t)object->st_ino;
                if (!g_strcmp0(candidate, name) || same_inode) {
                    referenced = true;
                    valid = valid && same_inode && bytes == (uint64_t)object->st_size &&
                        allocated == (uint64_t)object->st_blocks * 512;
                }
                g_free(candidate);
            }
            g_key_file_unref(evidence);
        }
        if (valid && referenced && retired && grace_us) {
            GHashTable *old_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            GHashTable *next_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            valid = bound && record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
                record_string_is(record, "transaction", "objects_status", "RECORDED") &&
                (!previous_size || manifest_references(source, (char *)previous, previous_size, old_refs)) &&
                manifest_references(source, (char *)next, next_size, next_refs);
            if (valid && g_hash_table_contains(old_refs, name) && !g_hash_table_contains(next_refs, name)) {
                uint64_t stamp;
                valid = record_string_is(record, "transaction", "retired_boot", boot) &&
                    record_uint64(record, "transaction", "retired_boottime_us", &stamp) &&
                    stamp <= now_us && *grace_us <= UINT64_MAX - stamp;
                if (valid) {
                    retirement_observed = true;
                    latest_deadline = MAX(latest_deadline, stamp + *grace_us);
                }
            }
            g_hash_table_unref(old_refs); g_hash_table_unref(next_refs);
        }
        result = !valid ? -1 : referenced && !retired ? 1 : 0;
        g_hash_table_unref(refs); g_free(canonical); g_free(objects); g_free(next); g_free(previous);
        g_free(state); g_free(objects64); g_free(next64); g_free(previous64); g_free(source);
        g_key_file_unref(record); g_free(raw);
    }
    if (!result && grace_us && (!retirement_observed || latest_deadline > now_us)) result = 1;
    g_free(boot);
    closedir(directory);
    return result;
}

int latcd_retirement_hold(const char *root, const char *source, const char *name,
                           const char *id, const char *reason, bool release,
                           char *error, size_t error_size)
{
    if (!source_valid(source) || !object_name_valid(source, name) || !hold_id_valid(id) ||
        (!reason || (strcmp(reason, "ROLLBACK") && strcmp(reason, "MIGRATION") && strcmp(reason, "EXTERNAL"))))
        return fail(error, error_size, "invalid explicit hold");
    int latch = lat_aot_v2_cache_source_lock(root, source, LOCK_EX | LOCK_NB, false, error, error_size);
    if (latch < 0) return -1;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int holds = gc < 0 ? -1 : open_directory(gc, "holds", true);
    int store = holds < 0 ? -1 : open_directory(holds, name, !release);
    struct stat cache, object;
    int fd = directory < 0 ? -1 : openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int result = -1;
    char *filename = g_strdup_printf("%s.ini", id), *raw = NULL;
    size_t size;
    GKeyFile *record = g_key_file_new();
    if (store < 0 || fd < 0 || fstat(directory, &cache) || fstat(fd, &object) ||
        !S_ISREG(object.st_mode) || object.st_uid != geteuid() || object.st_nlink != 1 ||
        (object.st_mode & 0222) || object.st_size <= 0 || flock(fd, LOCK_SH | LOCK_NB)) goto out;
    if (!release) {
        int tombstones = open_directory(gc, "tombstones", false);
        struct stat marker;
        bool blocked = tombstones < 0 ? errno != ENOENT :
            !fstatat(tombstones, name, &marker, AT_SYMLINK_NOFOLLOW) || errno != ENOENT;
        if (tombstones >= 0) close(tombstones);
        if (blocked) goto out;
    }
    int status = read_file(store, filename, MANIFEST_LIMIT, &raw, &size);
    if (status < 0 || (release && status)) goto out;
    if (!status) {
        if (memchr(raw, 0, size) || !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
            !hold_record_valid(record, id, name, &cache, &object)) goto out;
        char *existing_reason = g_key_file_get_string(record, "hold", "reason", NULL);
        char *state = g_key_file_get_string(record, "hold", "state", NULL);
        bool matched = !g_strcmp0(existing_reason, reason) && (release || !g_strcmp0(state, "ACTIVE"));
        g_free(existing_reason); g_free(state);
        if (!matched) goto out;
    } else {
        g_key_file_set_integer(record, "hold", "version", 1);
        g_key_file_set_string(record, "hold", "id", id);
        g_key_file_set_string(record, "hold", "name", name);
        g_key_file_set_string(record, "hold", "reason", reason);
        g_key_file_set_uint64(record, "hold", "cache_device", cache.st_dev);
        g_key_file_set_uint64(record, "hold", "cache_inode", cache.st_ino);
        g_key_file_set_uint64(record, "hold", "object_device", object.st_dev);
        g_key_file_set_uint64(record, "hold", "object_inode", object.st_ino);
    }
    struct stat after;
    if (fstatat(directory, name, &after, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&object, &after)) goto out;
    g_key_file_set_string(record, "hold", "state", release ? "RELEASED" : "ACTIVE");
    result = write_record(store, filename, record);
out:
    g_free(raw); g_free(filename); g_key_file_unref(record);
    if (fd >= 0) close(fd);
    if (store >= 0) close(store);
    if (holds >= 0) close(holds);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(latch);
    return result ? fail(error, error_size, "explicit object hold rejected or incomplete") : 0;
}

static bool mount_lease_fd_valid(const char *root, int gc, int lease_fd)
{
    int lock = openat(gc, "reference-roots.lock",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat held, path, cache;
    bool valid = lease_fd >= 0 && lock >= 0 && !fstat(lease_fd, &held) &&
        !fstat(lock, &path) && object_stat_equal(&held, &path) &&
        S_ISREG(held.st_mode) && held.st_uid == geteuid() && held.st_nlink == 1 &&
        !(held.st_mode & 0077) && !held.st_size && !fstatat(gc, "reference-roots.lock",
        &path, AT_SYMLINK_NOFOLLOW) && object_stat_equal(&held, &path) &&
        !flock(lease_fd, LOCK_SH | LOCK_NB);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    valid = valid && directory >= 0 && !fstat(directory, &cache);
    if (directory >= 0) close(directory);
    if (lock >= 0) close(lock);
    return valid;
}

int latcd_retirement_mount_lease(const char *root, const char *id, const char *scope,
                                 const char *source, const char *name,
                                 char *error, size_t error_size)
{
    bool cache_scope = !g_strcmp0(scope, "CACHE");
    bool source_scope = !g_strcmp0(scope, "SOURCE");
    bool object_scope = !g_strcmp0(scope, "OBJECT");
    if (!root || !hold_id_valid(id) || (!cache_scope && !source_scope && !object_scope) ||
        ((source_scope || object_scope) && !source_valid(source)) ||
        (object_scope && !object_name_valid(source, name)) ||
        ((cache_scope || source_scope) && name && *name))
        return fail(error, error_size, "invalid mount lease");
    int roots = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, error_size);
    if (roots < 0) return -1;
    int directory = -1, gc = -1, store = -1, object_fd = -1, result = -1;
    struct stat cache, object = {0};
    GKeyFile *record = g_key_file_new();
    char *filename = g_strdup_printf("%s.ini", id);
    char *raw = NULL;
    size_t size = 0;
    directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    store = gc < 0 ? -1 : open_directory(gc, "mount-leases", true);
    if (store < 0 || fstat(directory, &cache)) goto out;
    const char *record_source = cache_scope ? "" : source;
    const char *record_name = object_scope ? name : "";
    if (object_scope) {
        object_fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object_fd < 0 || fstat(object_fd, &object) || !S_ISREG(object.st_mode) ||
            object.st_uid != geteuid() || object.st_nlink != 1 ||
            (object.st_mode & 0222) || object.st_size <= 0 ||
            flock(object_fd, LOCK_SH | LOCK_NB)) goto out;
    }
    int status = read_file(store, filename, MANIFEST_LIMIT, &raw, &size);
    if (status < 0) goto out;
    if (!status) {
        MountLeaseRecord lease = {0};
        bool valid = !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            mount_lease_parse(record, id, &cache, &lease) &&
            !strcmp(lease.state, "ACTIVE") && !strcmp(lease.scope, scope) &&
            !strcmp(lease.source, record_source) && !strcmp(lease.name, record_name) &&
            (!object_scope || (lease.object_device == (uint64_t)object.st_dev &&
                               lease.object_inode == (uint64_t)object.st_ino));
        mount_lease_clear(&lease);
        if (!valid) goto out;
    } else {
        g_key_file_set_integer(record, "mount", "version", 1);
        g_key_file_set_string(record, "mount", "id", id);
        g_key_file_set_string(record, "mount", "scope", scope);
        g_key_file_set_string(record, "mount", "state", "ACTIVE");
        g_key_file_set_uint64(record, "mount", "cache_device", cache.st_dev);
        g_key_file_set_uint64(record, "mount", "cache_inode", cache.st_ino);
        g_key_file_set_string(record, "mount", "source", record_source);
        g_key_file_set_string(record, "mount", "name", record_name);
        g_key_file_set_uint64(record, "mount", "object_device", object.st_dev);
        g_key_file_set_uint64(record, "mount", "object_inode", object.st_ino);
        if (write_record(store, filename, record)) goto out;
    }
    result = roots;
    roots = -1;
out:
    if (roots >= 0) close(roots);
    if (object_fd >= 0) close(object_fd);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    g_free(raw);
    g_free(filename);
    g_key_file_unref(record);
    return result >= 0 ? result : fail(error, error_size,
        "mount lease rejected or incomplete");
}

int latcd_retirement_mount_release(const char *root, const char *id, int lease_fd,
                                   char *error, size_t error_size)
{
    if (!root || !hold_id_valid(id) || lease_fd < 0)
        return fail(error, error_size, "invalid mount lease release");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "mount-leases", false);
    struct stat cache, object = {0};
    int object_fd = -1, result = -1;
    char *filename = g_strdup_printf("%s.ini", id), *raw = NULL;
    size_t size = 0;
    GKeyFile *record = g_key_file_new();
    MountLeaseRecord lease = {0};
    if (store < 0 || fstat(directory, &cache) || !mount_lease_fd_valid(root, gc, lease_fd) ||
        read_file(store, filename, MANIFEST_LIMIT, &raw, &size) ||
        memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !mount_lease_parse(record, id, &cache, &lease)) goto out;
    if (!strcmp(lease.scope, "OBJECT")) {
        object_fd = openat(directory, lease.name,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object_fd < 0 || fstat(object_fd, &object) ||
            lease.object_device != (uint64_t)object.st_dev ||
            lease.object_inode != (uint64_t)object.st_ino) goto out;
    }
    if (!strcmp(lease.state, "ACTIVE")) {
        g_key_file_set_string(record, "mount", "state", "RELEASED");
        if (write_record(store, filename, record)) goto out;
    }
    result = 0;
out:
    mount_lease_clear(&lease);
    if (object_fd >= 0) close(object_fd);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    g_free(raw);
    g_free(filename);
    g_key_file_unref(record);
    return result ? fail(error, error_size,
        "mount lease release rejected or incomplete") : 0;
}

int latcd_retirement_tombstone(const char *root, const char *source,
                               const char *name, int object_fd, const char *evidence,
                               char *error, size_t error_size)
{
    if (!source_valid(source) || !object_name_valid(source, name) || object_fd < 0 ||
        !evidence || strlen(evidence) >= 16384)
        return fail(error, error_size, "invalid tombstone object");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", true);
    int roots = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, error_size);
    int result = -1;
    GKeyFile *record = g_key_file_new();
    GKeyFile *captured = g_key_file_new();
    char *captured_name = NULL, *hash = NULL;
    struct stat before, after, path;
    char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
    size_t size = 0;
    if (store < 0 || roots < 0 || flock(object_fd, LOCK_EX | LOCK_NB) ||
        fstat(object_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0222) || before.st_size <= 0 ||
        fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&before, &path)) goto out;
    const char *header[] = {"count"};
    const char *fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    gsize groups;
    char **group_names;
    if (!g_key_file_load_from_data(captured, evidence, -1, 0, NULL)) goto out;
    group_names = g_key_file_get_groups(captured, &groups);
    g_strfreev(group_names);
    if (groups != 2 || g_key_file_get_integer(captured, "objects", "count", NULL) != 1 ||
        !exact_keys(captured, "objects", header, G_N_ELEMENTS(header)) ||
        !exact_keys(captured, "object0", fields, G_N_ELEMENTS(fields))) goto out;
    captured_name = g_key_file_get_string(captured, "object0", "name", NULL);
    hash = g_key_file_get_string(captured, "object0", "sha256", NULL);
    if (g_strcmp0(captured_name, name) || !digest_valid(hash)) goto out;
    uint64_t expected[] = {before.st_dev, before.st_ino, before.st_size,
                          (uint64_t)before.st_blocks * 512};
    for (size_t i = 0; i < G_N_ELEMENTS(expected); i++) {
        char *value = g_key_file_get_string(captured, "object0", fields[i + 1], NULL);
        errno = 0;
        char *end = NULL;
        uint64_t number = value ? g_ascii_strtoull(value, &end, 10) : 0;
        bool valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
            !errno && end && !*end && number == expected[i];
        g_free(value);
        if (!valid) goto out;
    }
    int status = read_file(directory, current, MANIFEST_LIMIT, &manifest, &size);
    if (status < 0) goto out;
    if (!status) {
        GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        bool safe = manifest_references(source, manifest, size, references) &&
            !g_hash_table_contains(references, name);
        g_hash_table_unref(references);
        if (!safe) goto out;
    }
    if (object_current_status(directory, name) ||
        object_hold_status(directory, name, &before) || object_task_status(directory, name, &before) ||
        object_transaction_status(directory, name, &before, NULL) ||
        mount_lease_status(directory, gc, source, name, &before) ||
        fstat(object_fd, &after) || !object_stat_equal(&before, &after) ||
        fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&before, &path)) goto out;
    /* Never replace earlier intent: its identity is crash-recovery evidence. */
    if (!fstatat(store, name, &path, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto out;
    g_key_file_set_integer(record, "tombstone", "version", 1);
    g_key_file_set_string(record, "tombstone", "source", source);
    g_key_file_set_string(record, "tombstone", "name", name);
    g_key_file_set_string(record, "tombstone", "state", "DELETING");
    g_key_file_set_uint64(record, "tombstone", "device", before.st_dev);
    g_key_file_set_uint64(record, "tombstone", "inode", before.st_ino);
    g_key_file_set_uint64(record, "tombstone", "size", before.st_size);
    g_key_file_set_uint64(record, "tombstone", "allocated", (uint64_t)before.st_blocks * 512);
    g_key_file_set_string(record, "tombstone", "sha256", hash);
    result = write_record(store, name, record);
out:
    g_free(manifest);
    g_free(current);
    g_key_file_unref(record);
    g_key_file_unref(captured);
    g_free(captured_name);
    g_free(hash);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    if (roots >= 0) close(roots);
    return result ? fail(error, error_size, "cannot persist object deletion intent") : 0;
}

/* No pathname here is trusted until its source-bound basename is checked.
 * Content hashing is reserved for startup, outside daemon metadata locks. */
static bool tombstone_shape(GKeyFile *record, const char *name,
                             char **source, uint64_t values[4], char **hash);

static int completed_removal(int root, const char *root_path, const char *source,
                             const char *name, const uint64_t expected[4],
                             const char *digest)
{
    int gc = open_directory(root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    char *raw = NULL, *stored_source = NULL, *hash = NULL;
    size_t size = 0;
    uint64_t values[4] = {0};
    GKeyFile *record = g_key_file_new();
    bool valid = store >= 0 && !read_file(store, name, RECORD_LIMIT, &raw, &size) &&
        !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
        tombstone_shape(record, name, &stored_source, values, &hash) &&
        !g_strcmp0(source, stored_source) && !g_strcmp0(digest, hash) &&
        !memcmp(values, expected, sizeof(values));
    char *deletion = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
    char *observation = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    bool complete = !g_strcmp0(deletion, "UNLINKED") && !g_strcmp0(observation, "MISSING");
    bool pending = !deletion && (!observation || !strcmp(observation, "MATCHED") ||
                                !strcmp(observation, "MISSING"));
    valid = valid && (complete || (root_path && pending));
    int latch = -1, result = 0;
    if (valid && !complete) {
        latch = lat_aot_v2_cache_source_lock(root_path, source, LOCK_EX | LOCK_NB,
                                             false, NULL, 0);
        if (latch < 0) { result = -1; valid = false; }
    }
    /* A receipt cannot erase a current reference, even if the file is absent. */
    char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
    size_t manifest_size = 0;
    GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (valid) valid = !read_file(root, current, MANIFEST_LIMIT, &manifest, &manifest_size) &&
        manifest_references(source, manifest, manifest_size, references) &&
        !g_hash_table_contains(references, name);
    struct stat st;
    if (valid) valid = fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
    if (valid && !complete) {
        /* Observation only: make the already-absent name durable. Never unlink
         * here, and never infer physical block release from this receipt. */
        if (fsync(root) || record_write_fault("missing-synced")) result = -1;
        else {
            g_key_file_set_string(record, "tombstone", "deletion_status", "UNLINKED");
            g_key_file_set_string(record, "tombstone", "recovery_status", "MISSING");
            result = write_record(store, name, record) ? -1 : 1;
        }
    } else if (valid) result = 1;
    if (latch >= 0) close(latch);
    g_hash_table_unref(references);
    g_free(manifest); g_free(current); g_free(deletion); g_free(observation);
    g_free(raw); g_free(stored_source); g_free(hash); g_key_file_unref(record);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    return result;
}

static int verify_objects(int root, const char *root_path, const char *source, const char *encoded,
                           bool content, bool allow_removed, LatcdRecoveryCursor *cursor)
{
    if (!encoded) return -1;
    if (!*encoded) return 2;
    gsize size;
    guchar *raw = g_base64_decode(encoded, &size);
    char *canonical = g_base64_encode(raw, size);
    bool valid = size && size < 16384 && !strcmp(canonical, encoded) && !memchr(raw, 0, size);
    GKeyFile *objects = g_key_file_new();
    valid = valid && g_key_file_load_from_data(objects, (char *)raw, size, 0, NULL);
    g_free(canonical);
    g_free(raw);
    int result = -1;
    if (!valid) goto out;
    const char *header[] = {"count"};
    const char *fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    gsize group_count;
    char **groups = g_key_file_get_groups(objects, &group_count);
    valid = count > 0 && count <= 6 && group_count == (gsize)count + 1 &&
        exact_keys(objects, "objects", header, G_N_ELEMENTS(header));
    g_strfreev(groups);
    if (!valid) goto out;
    result = 0;
    for (int i = 0; i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!exact_keys(objects, group, fields, G_N_ELEMENTS(fields))) { result = -1; break; }
        char *name = g_key_file_get_string(objects, group, "name", NULL);
        char *hash = g_key_file_get_string(objects, group, "sha256", NULL);
        valid = object_name_valid(source, name) && hash && strlen(hash) == 64 &&
            strspn(hash, "0123456789abcdef") == 64;
        uint64_t values[4] = {0};
        for (size_t j = 0; valid && j < G_N_ELEMENTS(values); j++) {
            char *value = g_key_file_get_string(objects, group, fields[j + 1], NULL);
            char *end = NULL;
            errno = 0;
            values[j] = value ? g_ascii_strtoull(value, &end, 10) : 0;
            valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
                end && !*end && !errno;
            g_free(value);
        }
        if (!valid) result = -1;
        else {
            struct stat st;
            int status = fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW);
            int removed = status && errno == ENOENT && allow_removed ?
                completed_removal(root, root_path, source, name, values, hash) : 0;
            if (removed < 0) result = -1;
            else if (removed) {
                /* Durable exact-object receipt replaces only missing content. */
            } else if (status || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
                st.st_nlink != 1 || (st.st_mode & 0222) ||
                (uint64_t)st.st_dev != values[0] || (uint64_t)st.st_ino != values[1] ||
                (uint64_t)st.st_size != values[2] || (uint64_t)st.st_blocks * 512 != values[3]) {
                result = 1;
            } else if (content) {
                /* Reuse the same fd/lease/hash checks as publication capture. */
                const char *names[] = {name};
                char *actual = cursor ? recovery_capture(root, source, name, cursor) :
                    capture_objects(root, source, names, 1);
                if (cursor && cursor->yielded) {
                    g_free(hash); g_free(name);
                    result = 3;
                    break;
                }
                GKeyFile *observed = g_key_file_new();
                char *actual_hash = NULL;
                if (actual && g_key_file_load_from_data(observed, actual, -1, 0, NULL))
                    actual_hash = g_key_file_get_string(observed, "object0", "sha256", NULL);
                if (g_strcmp0(hash, actual_hash)) result = 1;
                for (size_t j = 0; actual_hash && j < G_N_ELEMENTS(values); j++) {
                    if (g_key_file_get_uint64(observed, "object0", fields[j + 1], NULL) != values[j])
                        result = 1;
                }
                g_free(actual_hash);
                g_free(actual);
                g_key_file_unref(observed);
            }
        }
        g_free(hash);
        g_free(name);
        if (result) break;
    }
out:
    g_key_file_unref(objects);
    return result;
}

static int recover_record(int root, int store, const char *name, bool content,
                           LatcdRecoveryCursor *cursor)
{
    char *raw = NULL;
    size_t size;
    if (!name_valid(name) || read_file(store, name, RECORD_LIMIT, &raw, &size)) return -1;
    GKeyFile *record = g_key_file_new();
    int result = -1;
    if (memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, G_KEY_FILE_NONE, NULL) ||
        !record_shape_valid(record)) goto out;
    char *source = g_key_file_get_string(record, "transaction", "source", NULL);
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    char *old64 = g_key_file_get_string(record, "transaction", "previous", NULL);
    char *new64 = g_key_file_get_string(record, "transaction", "next", NULL);
    int version = g_key_file_get_integer(record, "transaction", "version", NULL);
    if ((version != 1 && version != 2) ||
        !source_valid(source) || !state || !old64 || !new64) goto fields_out;
    gsize old_size, new_size;
    guchar *old = decode_snapshot(old64, &old_size);
    guchar *next = decode_snapshot(new64, &new_size);
    if (!old || !next || !new_size) {
        g_free(old);
        g_free(next);
        goto fields_out;
    }
    if (version == 2) {
        char *encoded = g_key_file_get_string(record, "transaction", "objects", NULL);
        gsize object_size = 0;
        guchar *object_data = encoded ? g_base64_decode(encoded, &object_size) : NULL;
        bool bound = object_size && !latcd_retirement_validate_binding(source,
            (char *)old, old_size, (char *)next, new_size, (char *)object_data, object_size);
        int object_result = verify_objects(root, cursor ? cursor->root_path : NULL,
            source, encoded, content, bound && !strcmp(state, "RETIRED"), cursor);
        g_free(object_data);
        g_free(encoded);
        if (object_result == 3) { result = 1; goto snapshots_out; }
        if (object_result < 0) goto snapshots_out;
        g_key_file_set_string(record, "transaction", "binding_status",
                              bound ? "COMPLETE" : "UNPROVEN");
        g_key_file_set_string(record, "transaction", "objects_status",
            object_result == 2 ? "UNPROVEN" : object_result ? "MISMATCH" : "RECORDED");
        if (object_result == 1 || (object_size && !bound)) {
            g_key_file_set_string(record, "transaction", "state", "UNKNOWN");
            result = write_record(store, name, record);
            goto snapshots_out;
        }
    }
    if (strcmp(state, "PREPARED")) {
        result = (!strcmp(state, "RETIRED") || !strcmp(state, "ABORTED") ||
                  !strcmp(state, "UNKNOWN")) ? 0 : -1;
        if (!strcmp(state, "RETIRED")) {
            char *old_boot = g_key_file_get_string(record, "transaction", "retired_boot", NULL);
            char *boot = NULL;
            if (g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL)) {
                g_strchomp(boot);
                if (g_strcmp0(boot, old_boot)) {
                    set_clock(record, "retired");
                    result = write_record(store, name, record);
                }
            } else result = -1;
            g_free(boot);
            g_free(old_boot);
        }
        goto snapshots_out;
    }
    char *current = g_strdup_printf("%s.current", source);
    char *contents = NULL;
    size_t current_size;
    int status = read_file(root, current, MANIFEST_LIMIT, &contents, &current_size);
    const char *outcome = "UNKNOWN";
    if (!status && new_size && new_size <= MANIFEST_LIMIT &&
        current_size == new_size && !memcmp(contents, next, new_size)) {
        /* Restamp on recovery: never infer elapsed grace from wall time. */
        outcome = "RETIRED";
        set_clock(record, "retired");
    } else if ((status == 1 && !old_size) ||
               (!status && old_size && old_size <= MANIFEST_LIMIT &&
                current_size == old_size && !memcmp(contents, old, old_size))) {
        outcome = "ABORTED";
    }
    g_key_file_set_string(record, "transaction", "state", outcome);
    result = write_record(store, name, record);
    g_free(contents);
    g_free(current);
snapshots_out:
    g_free(old);
    g_free(next);
fields_out:
    g_free(source);
    g_free(state);
    g_free(old64);
    g_free(new64);
out:
    g_key_file_unref(record);
    g_free(raw);
    return result;
}

int latcd_retirement_finish(const char *root, const char *transaction,
                           char *error, size_t error_size)
{
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int store = root_fd < 0 ? -1 : open_store(root_fd, false);
    int result = store < 0 || fsync(root_fd) ? -1 :
                 recover_record(root_fd, store, transaction, false, NULL);
    if (store >= 0) close(store);
    if (root_fd >= 0) close(root_fd);
    return result ? fail(error, error_size, "cannot complete retirement transaction") : 0;
}

int latcd_retirement_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, error_size);
    if (!cursor) return -1;
    LatcdRecoveryProgress progress;
    int result;
    do { result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                      &progress, error, error_size); } while (result > 0);
    *recovered = progress.recovered;
    latcd_recovery_close(cursor);
    return result;
}

static bool tombstone_shape(GKeyFile *record, const char *name,
                             char **source, uint64_t values[4], char **hash)
{
    const char *required[] = {"version", "source", "name", "state", "device",
        "inode", "size", "allocated", "sha256"};
    const char *optional[] = {"recovery_status", "deletion_status"};
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "tombstone");
    g_strfreev(groups);
    char **keys = g_key_file_get_keys(record, "tombstone", &count, NULL);
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
    for (gsize i = 0; valid && i < count; i++) {
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(required); j++) known |= !strcmp(keys[i], required[j]);
        for (size_t j = 0; j < G_N_ELEMENTS(optional); j++) known |= !strcmp(keys[i], optional[j]);
        valid = known && g_hash_table_add(seen, keys[i]);
    }
    for (size_t i = 0; valid && i < G_N_ELEMENTS(required); i++)
        valid = g_hash_table_contains(seen, required[i]);
    g_hash_table_unref(seen);
    g_strfreev(keys);
    char *version = g_key_file_get_string(record, "tombstone", "version", NULL);
    char *stored_name = g_key_file_get_string(record, "tombstone", "name", NULL);
    char *state = g_key_file_get_string(record, "tombstone", "state", NULL);
    char *observation = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    char *deletion = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
    *source = g_key_file_get_string(record, "tombstone", "source", NULL);
    *hash = g_key_file_get_string(record, "tombstone", "sha256", NULL);
    valid = valid && !g_strcmp0(version, "1") && source_valid(*source) &&
        object_name_valid(*source, name) && !g_strcmp0(name, stored_name) &&
        !g_strcmp0(state, "DELETING") && digest_valid(*hash) &&
        (!observation || !strcmp(observation, "MATCHED") || !strcmp(observation, "MISSING") ||
         !strcmp(observation, "UNKNOWN") || !strcmp(observation, "BUSY")) &&
        (!deletion || !strcmp(deletion, "UNLINKED"));
    const char *fields[] = {"device", "inode", "size", "allocated"};
    for (size_t i = 0; valid && i < G_N_ELEMENTS(fields); i++) {
        char *text = g_key_file_get_string(record, "tombstone", fields[i], NULL);
        char *end = NULL;
        errno = 0;
        values[i] = text ? g_ascii_strtoull(text, &end, 10) : 0;
        valid = text && *text && strspn(text, "0123456789") == strlen(text) &&
            end && !*end && !errno && (i != 2 || values[i]);
        g_free(text);
    }
    g_free(version); g_free(stored_name); g_free(state); g_free(observation); g_free(deletion);
    return valid;
}

static int recover_tombstone(const char *root_path, int root, int store,
                              const char *name, bool remove_object, LatcdRecoveryCursor *cursor,
                              const uint64_t *grace_us, LatcdRetirementDeletionReport *report)
{
    char *raw = NULL, *source = NULL, *hash = NULL;
    size_t size;
    uint64_t values[4] = {0};
    GKeyFile *record = g_key_file_new();
    int result = -1, object = -1, latch = -1, roots = -1, gc = -1;
    if (read_file(store, name, RECORD_LIMIT, &raw, &size) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !tombstone_shape(record, name, &source, values, &hash)) goto out;
    char *prior = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    bool unknown = !g_strcmp0(prior, "UNKNOWN");
    bool was_missing = !g_strcmp0(prior, "MISSING");
    bool was_unlinked = g_key_file_has_key(record, "tombstone", "deletion_status", NULL);
    const char *observation = unknown ? "UNKNOWN" : "MATCHED";
    bool missing = false;
    struct stat before = {0}, after, path;
    /* Hash outside S. Release this pin before S acquisition; final metadata
     * equality under S+G detects replacement/mutation during the handoff. */
    if (!unknown) {
        object = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object < 0) {
            missing = errno == ENOENT;
            observation = missing ? "MISSING" : "UNKNOWN";
        } else if (was_missing || was_unlinked) {
            observation = "UNKNOWN";
        } else if (flock(object, LOCK_SH | LOCK_NB)) {
            observation = errno == EWOULDBLOCK ? "BUSY" : "UNKNOWN";
        } else {
            const char *names[] = {name};
            char *actual = !fstat(object, &before) ?
                (cursor ? recovery_capture(root, source, name, cursor) :
                 capture_objects(root, source, names, 1)) : NULL;
            if (cursor && cursor->yielded) {
                g_free(prior); result = 1; goto out;
            }
            GKeyFile *captured = g_key_file_new();
            char *actual_hash = NULL;
            if (actual && g_key_file_load_from_data(captured, actual, -1, 0, NULL))
                actual_hash = g_key_file_get_string(captured, "object0", "sha256", NULL);
            if (g_strcmp0(actual_hash, hash) ||
                (uint64_t)before.st_dev != values[0] || (uint64_t)before.st_ino != values[1] ||
                (uint64_t)before.st_size != values[2] || (uint64_t)before.st_blocks * 512 != values[3] ||
                fstat(object, &after) || !object_stat_equal(&before, &after) ||
                fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || !object_stat_equal(&before, &path))
                observation = "UNKNOWN";
            g_free(actual_hash); g_free(actual); g_key_file_unref(captured);
        }
        if (object >= 0) { close(object); object = -1; }
    }
    latch = lat_aot_v2_cache_source_lock(root_path, source, LOCK_EX | LOCK_NB,
                                         false, NULL, 0);
    if (latch < 0 || (remove_object && (roots = latcd_retirement_roots_lock(
            root_path, LOCK_EX | LOCK_NB, NULL, 0)) < 0)) {
        observation = !strcmp(observation, "UNKNOWN") || errno != EWOULDBLOCK ? "UNKNOWN" : "BUSY";
    } else {
        gc = open_directory(root, ".gc", false);
        int mounted = gc < 0 ? -1 : mount_lease_status(
            root, gc, source, name, &before);
        if (mounted > 0) observation = "BUSY";
        else if (mounted < 0) observation = "UNKNOWN";
        char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
        size_t manifest_size = 0;
        int status = read_file(root, current, MANIFEST_LIMIT, &manifest, &manifest_size);
        if (status < 0) observation = "UNKNOWN";
        if (!status) {
            GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            if (!manifest_references(source, manifest, manifest_size, references) ||
                g_hash_table_contains(references, name)) observation = "UNKNOWN";
            g_hash_table_unref(references);
        }
        g_free(current); g_free(manifest);
        if (!strcmp(observation, "MATCHED")) {
            object = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (object < 0) observation = "UNKNOWN";
            else if (flock(object, LOCK_EX | LOCK_NB))
                observation = errno == EWOULDBLOCK ? "BUSY" : "UNKNOWN";
            else if (fstat(object, &after) || !object_stat_equal(&before, &after) ||
                fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || !object_stat_equal(&before, &path))
                observation = "UNKNOWN";
        } else if (!strcmp(observation, "MISSING")) {
            if (!fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || errno != ENOENT || fsync(root))
                observation = "UNKNOWN";
        }
    }
    if (remove_object && !strcmp(observation, "MATCHED")) {
        int held = object_current_status(root, name);
        if (!held) held = object_hold_status(root, name, &after);
        if (!held) held = object_task_status(root, name, &after);
        if (!held) held = object_transaction_status(root, name, &after, grace_us);
        if (held) observation = held < 0 ? "UNKNOWN" : "BUSY";
    }
    if (remove_object && (!strcmp(observation, "MATCHED") || !strcmp(observation, "MISSING"))) {
        /* Persist/confirm intent before dropping S. Readers refuse this name;
         * G remains exclusive through unlink, fsync and progress publication. */
        if (fsync(store)) { g_free(prior); goto out; }
        close(latch);
        latch = -1;
        if (!strcmp(observation, "MATCHED")) {
            if (report) {
                report->logical_bytes = before.st_size;
                report->allocated_bytes_before = (uint64_t)before.st_blocks * 512;
            }
            if (record_write_fault("before-unlink") ||
                unlinkat(root, name, 0)) {
                g_free(prior); goto out;
            }
            if (report) {
                report->object_unlinked = true;
                report->unlinked_allocated_bytes = report->allocated_bytes_before;
            }
            if (record_write_fault("unlinked")) { g_free(prior); goto out; }
        }
        if (fsync(root)) {
            g_free(prior); goto out;
        }
        if (report) report->namespace_durable = true;
        if (record_write_fault("unlink-synced")) { g_free(prior); goto out; }
        g_key_file_set_string(record, "tombstone", "deletion_status", "UNLINKED");
        observation = "MISSING";
    }
    g_key_file_set_string(record, "tombstone", "recovery_status", observation);
    result = !remove_object && !g_strcmp0(prior, observation) ? 0 : write_record(store, name, record);
    if (remove_object && strcmp(observation, "MISSING")) result = -1;
    if (report && !result && remove_object) report->receipt_durable = true;
    g_free(prior);
out:
    if (gc >= 0) close(gc);
    if (object >= 0) close(object);
    if (latch >= 0) close(latch);
    if (roots >= 0) close(roots);
    g_free(raw); g_free(source); g_free(hash);
    g_key_file_unref(record);
    return result;
}

int latcd_tombstone_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, true, error, error_size);
    if (!cursor) return -1;
    LatcdRecoveryProgress progress;
    int result;
    do { result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                      &progress, error, error_size); } while (result > 0);
    *recovered = progress.recovered;
    latcd_recovery_close(cursor);
    return result;
}

static bool filesystem_available(int fd, uint64_t *bytes)
{
    struct statvfs status;
    if (fstatvfs(fd, &status) || !status.f_frsize ||
        status.f_bavail > UINT64_MAX / status.f_frsize) return false;
    *bytes = (uint64_t)status.f_bavail * status.f_frsize;
    return true;
}

static int tombstone_delete(const char *root, const char *name, const uint64_t *grace_us,
                             LatcdRetirementDeletionReport *report,
                             char *error, size_t error_size)
{
    if (report) memset(report, 0, sizeof(*report));
    if (!name || strlen(name) < 64 || strchr(name, '/'))
        return fail(error, error_size, "invalid deletion object name");
    char source[65];
    memcpy(source, name, 64); source[64] = 0;
    if (!source_valid(source) || !object_name_valid(source, name))
        return fail(error, error_size, "invalid deletion object name");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    if (report && directory >= 0)
        report->filesystem_before_valid = filesystem_available(directory, &report->filesystem_available_before);
    int result = store < 0 ? -1 : recover_tombstone(root, directory, store, name, true, NULL, grace_us, report);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (report && directory >= 0)
        report->filesystem_after_valid = filesystem_available(directory, &report->filesystem_available_after);
    if (directory >= 0) close(directory);
    return result ? fail(error, error_size, "object deletion deferred or rejected") : 0;
}

int latcd_tombstone_delete(const char *root, const char *name, char *error, size_t error_size)
{
    return tombstone_delete(root, name, NULL, NULL, error, error_size);
}

int latcd_tombstone_delete_due(const char *root, const char *name, uint64_t grace_us,
                               char *error, size_t error_size)
{
    return tombstone_delete(root, name, &grace_us, NULL, error, error_size);
}

int latcd_tombstone_delete_report(const char *root, const char *name,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    return tombstone_delete(root, name, NULL, report, error, error_size);
}

int latcd_tombstone_delete_due_report(const char *root, const char *name, uint64_t grace_us,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    return tombstone_delete(root, name, &grace_us, report, error, error_size);
}

typedef struct RetirementCandidate {
    uint64_t deadline, enqueued, epoch;
    uint64_t last_attempt, retry_at;
    unsigned busy_count;
} RetirementCandidate;

struct LatcdRetirementQueue {
    char *root;
    uint64_t grace, epoch;
    unsigned visited;
    DIR *cursor;
    GHashTable *candidates;
    bool complete;
    char last_source[65];
    LatcdRetirementAttempt active;
    uint64_t sequence;
};

LatcdRetirementQueue *latcd_retirement_queue_new(const char *root, uint64_t grace_us)
{
    LatcdRetirementQueue *queue = g_new0(LatcdRetirementQueue, 1);
    queue->root = g_strdup(root);
    queue->grace = grace_us;
    queue->candidates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    return queue;
}

void latcd_retirement_queue_free(LatcdRetirementQueue *queue)
{
    if (!queue) return;
    if (queue->cursor) closedir(queue->cursor);
    g_hash_table_unref(queue->candidates);
    g_free(queue->root); g_free(queue);
}

/* Completed namespace removal only, never physical-space or domain admission.
 * Bind the receipt to this transaction's object, not merely its basename. */
static int queue_object_removed(const char *root_path, const char *source,
                                 const char *name, GKeyFile *objects)
{
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_directory(root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    int result = -1;
    char *raw = NULL, *stored_source = NULL, *hash = NULL;
    size_t size;
    GKeyFile *receipt = g_key_file_new();
    if (root < 0 || gc < 0) goto out;
    if (store < 0) { if (errno == ENOENT) result = 0; goto out; }
    int status = read_file(store, name, RECORD_LIMIT, &raw, &size);
    if (status) { if (status == 1) result = 0; goto out; }
    uint64_t values[4];
    if (memchr(raw, 0, size) || !g_key_file_load_from_data(receipt, raw, size, 0, NULL) ||
        !tombstone_shape(receipt, name, &stored_source, values, &hash) ||
        g_strcmp0(source, stored_source)) goto out;
    if (!record_string_is(receipt, "tombstone", "deletion_status", "UNLINKED") ||
        !record_string_is(receipt, "tombstone", "recovery_status", "MISSING")) {
        result = 0;
        goto out;
    }
    struct stat st;
    if (!fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto out;
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    const char *fields[] = {"device", "inode", "size", "allocated"};
    for (int i = 0; i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!record_string_is(objects, group, "name", name)) continue;
        bool matches = record_string_is(objects, group, "sha256", hash);
        for (unsigned j = 0; matches && j < G_N_ELEMENTS(fields); j++) {
            uint64_t value;
            matches = record_uint64(objects, group, fields[j], &value) && value == values[j];
        }
        if (matches) result = 1;
        break;
    }
out:
    g_free(raw); g_free(stored_source); g_free(hash); g_key_file_unref(receipt);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result;
}

static bool queue_record(LatcdRetirementQueue *queue, const char *raw, size_t size,
                          const char *boot, uint64_t now)
{
    GKeyFile *record = g_key_file_new();
    bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
        record_shape_valid(record);
    char *source = g_key_file_get_string(record, "transaction", "source", NULL);
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    valid = valid && source_valid(source) && state &&
        (!strcmp(state, "PREPARED") || !strcmp(state, "RETIRED") ||
         !strcmp(state, "ABORTED") || !strcmp(state, "UNKNOWN"));
    if (!valid || strcmp(state, "RETIRED")) goto out;
    char *old64 = g_key_file_get_string(record, "transaction", "previous", NULL);
    char *next64 = g_key_file_get_string(record, "transaction", "next", NULL);
    char *objects64 = g_key_file_get_string(record, "transaction", "objects", NULL);
    gsize old_size = 0, next_size = 0, object_size = 0;
    guchar *old = old64 ? decode_snapshot(old64, &old_size) : NULL;
    guchar *next = next64 ? decode_snapshot(next64, &next_size) : NULL;
    guchar *objects = objects64 ? g_base64_decode(objects64, &object_size) : NULL;
    char *canonical = objects ? g_base64_encode(objects, object_size) : NULL;
    uint64_t stamp;
    valid = record_string_is(record, "transaction", "version", "2") && old && next && objects &&
        canonical && !g_strcmp0(canonical, objects64) &&
        record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
        record_string_is(record, "transaction", "objects_status", "RECORDED") &&
        !latcd_retirement_validate_binding(source, (char *)old, old_size, (char *)next, next_size,
                                          (char *)objects, object_size) &&
        record_string_is(record, "transaction", "retired_boot", boot) &&
        record_uint64(record, "transaction", "retired_boottime_us", &stamp) && stamp <= now &&
        queue->grace <= UINT64_MAX - stamp;
    GHashTable *old_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    GHashTable *next_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    valid = valid && (!old_size || manifest_references(source, (char *)old, old_size, old_refs)) &&
        manifest_references(source, (char *)next, next_size, next_refs);
    GHashTableIter iterator;
    gpointer key;
    g_hash_table_iter_init(&iterator, old_refs);
    GKeyFile *object_record = g_key_file_new();
    valid = valid && g_key_file_load_from_data(object_record, (char *)objects, object_size, 0, NULL);
    while (valid && g_hash_table_iter_next(&iterator, &key, NULL)) {
        if (g_hash_table_contains(next_refs, key)) continue;
        int removed = queue_object_removed(queue->root, source, key, object_record);
        if (removed < 0) { valid = false; break; }
        if (removed) continue;
        RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, key);
        if (!candidate) {
            if (g_hash_table_size(queue->candidates) >= 128) { valid = false; break; }
            candidate = g_new0(RetirementCandidate, 1);
            candidate->enqueued = now;
            g_hash_table_insert(queue->candidates, g_strdup(key), candidate);
        }
        uint64_t deadline = stamp + queue->grace;
        candidate->deadline = candidate->epoch == queue->epoch ? MAX(candidate->deadline, deadline) : deadline;
        candidate->epoch = queue->epoch;
    }
    g_key_file_unref(object_record);
    g_hash_table_unref(old_refs); g_hash_table_unref(next_refs);
    g_free(canonical); g_free(objects); g_free(next); g_free(old);
    g_free(objects64); g_free(next64); g_free(old64);
out:
    g_free(source); g_free(state); g_key_file_unref(record);
    return valid;
}

int latcd_retirement_queue_step(LatcdRetirementQueue *queue, unsigned entries,
                                 uint64_t time_us, LatcdRetirementQueueStats *stats,
                                 char *error, size_t error_size)
{
    if (!queue || !entries || !time_us || time_us > INT64_MAX / 2 || !stats)
        return fail(error, error_size, "invalid retirement queue budget");
    memset(stats, 0, sizeof(*stats));
    int result = -1;
    char *boot = NULL;
    struct timespec clock;
    uint64_t now = 0;
    if (clock_gettime(CLOCK_BOOTTIME, &clock) || clock.tv_sec < 0 ||
        (uint64_t)clock.tv_sec > UINT64_MAX / 1000000 ||
        !g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL)) goto out;
    g_strchomp(boot);
    if (!hold_id_valid(boot)) goto out;
    now = (uint64_t)clock.tv_sec * 1000000 + clock.tv_nsec / 1000;
    if (!queue->cursor) {
        queue->complete = false;
        queue->visited = 0;
        queue->epoch++;
        int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (root < 0) goto out;
        int store = open_store(root, false), saved = errno;
        close(root);
        if (store < 0) {
            if (saved == ENOENT) { result = 0; goto sweep_complete; }
            goto out;
        }
        queue->cursor = fdopendir(store);
        if (!queue->cursor) { close(store); goto out; }
    }
    int64_t started = g_get_monotonic_time();
    result = 1;
    while (stats->visited < entries && (uint64_t)(g_get_monotonic_time() - started) < time_us) {
        errno = 0;
        struct dirent *entry = readdir(queue->cursor);
        if (!entry) { result = errno ? -1 : 0; break; }
        stats->visited++;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        bool valid = ++queue->visited <= 100000 && name_valid(entry->d_name) &&
            !read_file(dirfd(queue->cursor), entry->d_name, RECORD_LIMIT, &raw, &size) &&
            queue_record(queue, raw, size, boot, now);
        g_free(raw);
        if (!valid) { result = -1; break; }
    }
sweep_complete:
    if (!result) {
        GHashTableIter iterator;
        gpointer value;
        g_hash_table_iter_init(&iterator, queue->candidates);
        while (g_hash_table_iter_next(&iterator, NULL, &value))
            if (((RetirementCandidate *)value)->epoch != queue->epoch) {
                const char *active = queue->active.name;
                if (!*active || g_hash_table_lookup(queue->candidates, active) != value)
                    g_hash_table_iter_remove(&iterator);
            }
        queue->complete = true;
    }
out:
    if (result <= 0 && queue->cursor) { closedir(queue->cursor); queue->cursor = NULL; }
    if (result < 0) queue->complete = false;
    stats->complete = queue->complete;
    stats->candidates = g_hash_table_size(queue->candidates);
    GHashTableIter iterator;
    gpointer value;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        RetirementCandidate *candidate = value;
        if (candidate->deadline <= now) {
            stats->due++;
            uint64_t ready = MAX(candidate->deadline, candidate->enqueued);
            if (ready <= now) stats->oldest_due_wait_us = MAX(stats->oldest_due_wait_us, now - ready);
        } else if (!stats->next_deadline_us || candidate->deadline < stats->next_deadline_us)
            stats->next_deadline_us = candidate->deadline;
    }
    g_free(boot);
    return result < 0 ? fail(error, error_size, "retirement queue discovery incomplete or unsafe") : result;
}

int latcd_retirement_queue_take(LatcdRetirementQueue *queue, uint64_t now_us,
                                LatcdRetirementAttempt *attempt)
{
    if (!queue || !attempt || queue->active.sequence || queue->sequence == UINT64_MAX) return -1;
    memset(attempt, 0, sizeof(*attempt));
    if (!queue->complete) return 0;
    const char *after = NULL, *first = NULL;
    GHashTableIter iterator;
    gpointer key, value;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        RetirementCandidate *candidate = value;
        if (candidate->deadline > now_us || candidate->retry_at > now_us) continue;
        if (!first || strncmp(key, first, 64) < 0) first = key;
        if (strncmp(key, queue->last_source, 64) > 0 && (!after || strncmp(key, after, 64) < 0)) after = key;
    }
    const char *source = after ? after : first, *selected = NULL;
    RetirementCandidate *oldest = NULL;
    if (!source) return 0;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        RetirementCandidate *candidate = value;
        if (strncmp(key, source, 64) || candidate->deadline > now_us || candidate->retry_at > now_us) continue;
        if (!oldest || candidate->last_attempt < oldest->last_attempt ||
            (candidate->last_attempt == oldest->last_attempt &&
             (candidate->enqueued < oldest->enqueued ||
              (candidate->enqueued == oldest->enqueued && strcmp(key, selected) < 0)))) {
            selected = key; oldest = candidate;
        }
    }
    memcpy(queue->last_source, source, 64);
    queue->last_source[64] = 0;
    g_strlcpy(attempt->name, selected, sizeof(attempt->name));
    attempt->sequence = ++queue->sequence;
    oldest->last_attempt = attempt->sequence;
    queue->active = *attempt;
    return 1;
}

int latcd_retirement_queue_defer(LatcdRetirementQueue *queue,
                                 const LatcdRetirementAttempt *attempt,
                                 uint64_t now_us, bool busy)
{
    if (!queue || !attempt || !attempt->sequence ||
        attempt->sequence != queue->active.sequence ||
        memcmp(attempt->name, queue->active.name, sizeof(attempt->name))) return -1;
    RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, attempt->name);
    if (!candidate) return -1;
    candidate->busy_count = busy ? MIN(candidate->busy_count + 1, 7u) : 0;
    uint64_t delay = busy ? MIN(UINT64_C(100000) << (candidate->busy_count - 1), UINT64_C(5000000)) : 100000;
    candidate->retry_at = delay > UINT64_MAX - now_us ? UINT64_MAX : now_us + delay;
    memset(&queue->active, 0, sizeof(queue->active));
    return 0;
}

static int queue_clock(char **boot, uint64_t *now)
{
    struct timespec clock;
    if (clock_gettime(CLOCK_BOOTTIME, &clock) || clock.tv_sec < 0 ||
        (uint64_t)clock.tv_sec > UINT64_MAX / 1000000 ||
        !g_file_get_contents("/proc/sys/kernel/random/boot_id", boot, NULL, NULL)) return -1;
    g_strchomp(*boot);
    if (!hold_id_valid(*boot)) return -1;
    *now = (uint64_t)clock.tv_sec * 1000000 + clock.tv_nsec / 1000;
    return 0;
}

int latcd_retirement_queue_checkpoint(LatcdRetirementQueue *queue,
                                      char *error, size_t error_size)
{
    if (!queue || !queue->complete || queue->cursor)
        return fail(error, error_size, "cannot checkpoint incomplete retirement discovery");
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_directory(root, ".gc", true);
    GKeyFile *record = g_key_file_new();
    struct stat cache;
    char *boot = NULL;
    uint64_t now;
    int result = -1;
    if (gc < 0 || fstat(root, &cache) || queue_clock(&boot, &now)) goto out;
    g_key_file_set_integer(record, "queue", "version", 1);
    g_key_file_set_string(record, "queue", "boot", boot);
    g_key_file_set_uint64(record, "queue", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "queue", "cache_inode", cache.st_ino);
    g_key_file_set_uint64(record, "queue", "grace_us", queue->grace);
    g_key_file_set_uint64(record, "queue", "sequence", queue->sequence);
    g_key_file_set_string(record, "queue", "last_source", queue->last_source);
    GList *names = g_hash_table_get_keys(queue->candidates);
    names = g_list_sort(names, (GCompareFunc)strcmp);
    for (GList *item = names; item; item = item->next) {
        const char *name = item->data;
        RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, name);
        g_key_file_set_uint64(record, name, "enqueued", candidate->enqueued);
        g_key_file_set_uint64(record, name, "last_attempt", candidate->last_attempt);
        g_key_file_set_uint64(record, name, "retry_at", candidate->retry_at);
        g_key_file_set_uint64(record, name, "busy_count", candidate->busy_count);
    }
    g_list_free(names);
    char *previous = NULL;
    size_t previous_size;
    int status = read_file(gc, "retirement-scheduler.ini", RECORD_LIMIT, &previous, &previous_size);
    gsize current_size;
    char *current = g_key_file_to_data(record, &current_size, NULL);
    result = status < 0 || current_size > RECORD_LIMIT ? -1 : !status && previous_size == current_size &&
        !memcmp(previous, current, current_size) ? 0 : write_record(gc, "retirement-scheduler.ini", record);
    g_free(previous); g_free(current);
out:
    g_free(boot); g_key_file_unref(record);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result ? fail(error, error_size, "cannot persist retirement scheduler") : 0;
}

int latcd_retirement_queue_restore(LatcdRetirementQueue *queue,
                                   char *error, size_t error_size)
{
    if (!queue || queue->epoch || queue->cursor || g_hash_table_size(queue->candidates))
        return fail(error, error_size, "retirement scheduler restore requires a new queue");
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_directory(root, ".gc", false);
    int result = -1;
    char *raw = NULL, *boot = NULL;
    size_t size;
    uint64_t now;
    struct stat cache;
    GKeyFile *record = g_key_file_new();
    GHashTable *restored = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (root < 0) goto out;
    if (gc < 0) { if (errno == ENOENT) result = 0; goto out; }
    int status = read_file(gc, "retirement-scheduler.ini", RECORD_LIMIT, &raw, &size);
    if (status) { if (status == 1) result = 0; goto out; }
    if (fstat(root, &cache) || queue_clock(&boot, &now) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL)) goto out;
    const char *keys[] = {"version", "boot", "cache_device", "cache_inode", "grace_us", "sequence", "last_source"};
    uint64_t device, inode, grace, sequence;
    char *saved_boot = g_key_file_get_string(record, "queue", "boot", NULL);
    char *last_source = g_key_file_get_string(record, "queue", "last_source", NULL);
    bool valid = exact_keys(record, "queue", keys, G_N_ELEMENTS(keys)) &&
        record_string_is(record, "queue", "version", "1") && hold_id_valid(saved_boot) &&
        last_source && (!*last_source || source_valid(last_source)) &&
        record_uint64(record, "queue", "cache_device", &device) && device == (uint64_t)cache.st_dev &&
        record_uint64(record, "queue", "cache_inode", &inode) && inode == (uint64_t)cache.st_ino &&
        record_uint64(record, "queue", "grace_us", &grace) &&
        record_uint64(record, "queue", "sequence", &sequence) && sequence < UINT64_MAX;
    bool compatible = valid && !strcmp(boot, saved_boot) && grace == queue->grace;
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    valid &= count <= 129;
    const char *fields[] = {"enqueued", "last_attempt", "retry_at", "busy_count"};
    for (gsize i = 0; valid && i < count; i++) {
        const char *name = groups[i];
        if (!strcmp(name, "queue")) continue;
        char source[65] = {0};
        if (strlen(name) >= 64) memcpy(source, name, 64);
        uint64_t enqueued, attempted, retry, busy;
        valid = source_valid(source) && object_name_valid(source, name) &&
            exact_keys(record, name, fields, G_N_ELEMENTS(fields)) &&
            record_uint64(record, name, "enqueued", &enqueued) &&
            record_uint64(record, name, "last_attempt", &attempted) && attempted <= sequence &&
            record_uint64(record, name, "retry_at", &retry) &&
            record_uint64(record, name, "busy_count", &busy) && busy <= 7;
        if (compatible) valid = valid && enqueued <= now &&
            (retry <= now || retry - now <= UINT64_C(5000000));
        if (valid && compatible) {
            RetirementCandidate *candidate = g_new0(RetirementCandidate, 1);
            candidate->enqueued = enqueued;
            candidate->last_attempt = attempted;
            candidate->retry_at = retry;
            candidate->busy_count = busy;
            g_hash_table_insert(restored, g_strdup(name), candidate);
        }
    }
    g_strfreev(groups);
    if (valid) {
        if (compatible) {
            g_hash_table_unref(queue->candidates);
            queue->candidates = restored;
            restored = NULL;
            queue->sequence = sequence;
            g_strlcpy(queue->last_source, last_source, sizeof(queue->last_source));
        }
        result = 0;
    }
    g_free(last_source); g_free(saved_boot);
out:
    if (restored) g_hash_table_unref(restored);
    g_free(boot); g_free(raw); g_key_file_unref(record);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result ? fail(error, error_size, "retirement scheduler state unsafe or incompatible") : 0;
}

static void recovery_object_free(gpointer pointer)
{
    RecoveryObject *object = pointer;
    g_free(object->evidence);
    g_free(object);
}

static void recovery_hash_clear(LatcdRecoveryCursor *cursor)
{
    if (cursor->hash_fd >= 0) close(cursor->hash_fd);
    cursor->hash_fd = -1;
    g_clear_pointer(&cursor->hash_name, g_free);
    g_clear_pointer(&cursor->hash, g_checksum_free);
    cursor->offset = 0;
}

static char *recovery_capture(int root, const char *source, const char *name,
                              LatcdRecoveryCursor *cursor)
{
    if (!source_valid(source) || !object_name_valid(source, name)) return NULL;
    struct stat path, after;
    RecoveryObject *cached = g_hash_table_lookup(cursor->verified, name);
    if (cached) {
        return !fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) &&
            object_stat_equal(&path, &cached->identity) ? g_strdup(cached->evidence) : NULL;
    }
    if (cursor->hash_fd >= 0 && g_strcmp0(cursor->hash_name, name)) {
        recovery_hash_clear(cursor);
        return NULL;
    }
    if (cursor->hash_fd < 0) {
        cursor->hash_fd = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (cursor->hash_fd < 0 || flock(cursor->hash_fd, LOCK_SH | LOCK_NB) ||
            fstat(cursor->hash_fd, &cursor->hash_identity) ||
            !S_ISREG(cursor->hash_identity.st_mode) || cursor->hash_identity.st_uid != geteuid() ||
            cursor->hash_identity.st_nlink != 1 || cursor->hash_identity.st_mode & 0222 ||
            cursor->hash_identity.st_size <= 0) goto invalid;
        cursor->hash_name = g_strdup(name);
        cursor->hash = g_checksum_new(G_CHECKSUM_SHA256);
    }
    if (fstat(cursor->hash_fd, &after) || !object_stat_equal(&after, &cursor->hash_identity) ||
        fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&path, &cursor->hash_identity)) goto invalid;
    while (cursor->offset < (uint64_t)cursor->hash_identity.st_size) {
        if (!cursor->bytes_left || g_get_monotonic_time() >= cursor->deadline) {
            cursor->yielded = true;
            return NULL;
        }
        unsigned char buffer[65536];
        size_t length = MIN((uint64_t)sizeof(buffer), cursor->bytes_left);
        length = MIN(length, (uint64_t)cursor->hash_identity.st_size - cursor->offset);
        ssize_t count = read(cursor->hash_fd, buffer, length);
        if (count < 0 && errno == EINTR) {
            cursor->yielded = true;
            return NULL;
        }
        if (count <= 0) goto invalid;
        cursor->offset += count;
        cursor->bytes_left -= count;
        cursor->progress.hashed_bytes += count;
        g_checksum_update(cursor->hash, buffer, count);
    }
    if (fstat(cursor->hash_fd, &after) || !object_stat_equal(&after, &cursor->hash_identity) ||
        fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&path, &cursor->hash_identity)) goto invalid;
    GKeyFile *record = g_key_file_new();
    g_key_file_set_integer(record, "objects", "count", 1);
    g_key_file_set_string(record, "object0", "name", name);
    g_key_file_set_uint64(record, "object0", "device", after.st_dev);
    g_key_file_set_uint64(record, "object0", "inode", after.st_ino);
    g_key_file_set_uint64(record, "object0", "size", after.st_size);
    g_key_file_set_uint64(record, "object0", "allocated", (uint64_t)after.st_blocks * 512);
    g_key_file_set_string(record, "object0", "sha256", g_checksum_get_string(cursor->hash));
    RecoveryObject *object = g_new0(RecoveryObject, 1);
    object->identity = after;
    object->evidence = g_key_file_to_data(record, NULL, NULL);
    g_key_file_unref(record);
    g_hash_table_insert(cursor->verified, g_strdup(name), object);
    recovery_hash_clear(cursor);
    return g_strdup(object->evidence);
invalid:
    recovery_hash_clear(cursor);
    return NULL;
}

void latcd_recovery_close(LatcdRecoveryCursor *cursor)
{
    if (!cursor) return;
    recovery_hash_clear(cursor);
    if (cursor->directory) closedir(cursor->directory);
    if (cursor->root >= 0) close(cursor->root);
    g_hash_table_unref(cursor->verified);
    g_free(cursor->root_path); g_free(cursor->pending); g_free(cursor);
}

LatcdRecoveryCursor *latcd_recovery_open(const char *root, bool tombstones,
                                        char *error, size_t error_size)
{
    LatcdRecoveryCursor *cursor = g_new0(LatcdRecoveryCursor, 1);
    cursor->root = -1;
    cursor->hash_fd = -1;
    cursor->tombstones = tombstones;
    cursor->root_path = g_strdup(root);
    cursor->verified = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, recovery_object_free);
    cursor->root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cursor->root < 0) goto invalid;
    int gc = open_directory(cursor->root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, tombstones ? "tombstones" : "transactions", false);
    int saved = errno;
    if (gc >= 0) close(gc);
    if (store < 0) {
        if (saved != ENOENT) goto invalid;
        cursor->done = true;
    } else {
        cursor->directory = fdopendir(store);
        if (!cursor->directory) { close(store); goto invalid; }
    }
    return cursor;
invalid:
    latcd_recovery_close(cursor);
    fail(error, error_size, "unsafe recovery store");
    return NULL;
}

int latcd_recovery_step(LatcdRecoveryCursor *cursor, unsigned entries,
                        uint64_t hash_bytes, uint64_t time_us,
                        LatcdRecoveryProgress *progress, char *error, size_t error_size)
{
    if (!cursor || !progress || !entries || !hash_bytes || !time_us ||
        time_us > INT64_MAX - (uint64_t)g_get_monotonic_time())
        return fail(error, error_size, "invalid recovery budget");
    *progress = cursor->progress;
    if (cursor->failed) return fail(error, error_size, "recovery cursor previously failed");
    if (cursor->done) return 0;
    cursor->bytes_left = hash_bytes;
    cursor->deadline = g_get_monotonic_time() + time_us;
    cursor->yielded = false;
    unsigned visited = 0;
    while (visited < entries && g_get_monotonic_time() < cursor->deadline) {
        if (!cursor->pending) {
            errno = 0;
            struct dirent *entry = readdir(cursor->directory);
            if (!entry) {
                if (errno) goto invalid;
                cursor->done = true;
                break;
            }
            visited++;
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (++cursor->progress.visited > 100000) goto invalid;
            if (g_str_has_prefix(entry->d_name, ".write-")) continue;
            cursor->pending = g_strdup(entry->d_name);
            if (fstatat(dirfd(cursor->directory), cursor->pending, &cursor->pending_identity,
                         AT_SYMLINK_NOFOLLOW)) goto invalid;
        } else visited++;
        struct stat record;
        if (fstatat(dirfd(cursor->directory), cursor->pending, &record, AT_SYMLINK_NOFOLLOW) ||
            !object_stat_equal(&record, &cursor->pending_identity)) goto invalid;
        int result = cursor->tombstones ? recover_tombstone(cursor->root_path, cursor->root,
            dirfd(cursor->directory), cursor->pending, false, cursor, NULL, NULL) :
            recover_record(cursor->root, dirfd(cursor->directory), cursor->pending, true, cursor);
        if (result < 0) goto invalid;
        if (result > 0) break;
        cursor->progress.recovered++;
        g_clear_pointer(&cursor->pending, g_free);
        g_hash_table_remove_all(cursor->verified);
        recovery_hash_clear(cursor);
    }
    *progress = cursor->progress;
    return cursor->done ? 0 : 1;
invalid:
    cursor->failed = true;
    recovery_hash_clear(cursor);
    *progress = cursor->progress;
    return fail(error, error_size, "recovery rejected unknown or changed record");
}
