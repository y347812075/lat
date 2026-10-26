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
    int result = -1;
    GKeyFile *record = g_key_file_new();
    GKeyFile *captured = g_key_file_new();
    char *captured_name = NULL, *hash = NULL;
    struct stat before, after, path;
    char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
    size_t size = 0;
    if (store < 0 || flock(object_fd, LOCK_EX | LOCK_NB) ||
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
    if (fstat(object_fd, &after) || !object_stat_equal(&before, &after) ||
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
    return result ? fail(error, error_size, "cannot persist object deletion intent") : 0;
}

/* No pathname here is trusted until its source-bound basename is checked.
 * Content hashing is reserved for startup, outside daemon metadata locks. */
static int verify_objects(int root, const char *source, const char *encoded,
                           bool content)
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
            if (fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
                st.st_nlink != 1 || (st.st_mode & 0222) ||
                (uint64_t)st.st_dev != values[0] || (uint64_t)st.st_ino != values[1] ||
                (uint64_t)st.st_size != values[2] || (uint64_t)st.st_blocks * 512 != values[3]) {
                result = 1;
            } else if (content) {
                /* Reuse the same fd/lease/hash checks as publication capture. */
                const char *names[] = {name};
                char *actual = capture_objects(root, source, names, 1);
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

static int recover_record(int root, int store, const char *name, bool content)
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
        int object_result = verify_objects(root, source, encoded, content);
        gsize object_size = 0;
        guchar *object_data = encoded ? g_base64_decode(encoded, &object_size) : NULL;
        bool bound = object_size && !latcd_retirement_validate_binding(source,
            (char *)old, old_size, (char *)next, new_size, (char *)object_data, object_size);
        g_free(object_data);
        g_free(encoded);
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
                 recover_record(root_fd, store, transaction, false);
    if (store >= 0) close(store);
    if (root_fd >= 0) close(root_fd);
    return result ? fail(error, error_size, "cannot complete retirement transaction") : 0;
}

int latcd_retirement_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int store = root_fd < 0 ? -1 : open_store(root_fd, false);
    if (store < 0) {
        int saved = errno;
        if (root_fd >= 0) close(root_fd);
        return saved == ENOENT ? 0 : fail(error, error_size, "unsafe retirement store");
    }
    DIR *directory = fdopendir(store);
    int result = directory ? 0 : -1;
    if (!directory) close(store);
    struct dirent *entry;
    while (!result) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        /* Interrupted record writes are evidence, not deletion candidates. */
        if (g_str_has_prefix(entry->d_name, ".write-")) continue;
        if (*recovered >= 100000 || recover_record(root_fd, store, entry->d_name, true)) {
            result = -1;
            break;
        }
        (*recovered)++;
    }
    if (directory) closedir(directory);
    close(root_fd);
    return result ? fail(error, error_size, "retirement recovery rejected unknown record") : 0;
}

static bool tombstone_shape(GKeyFile *record, const char *name,
                             char **source, uint64_t values[4], char **hash)
{
    const char *required[] = {"version", "source", "name", "state", "device",
        "inode", "size", "allocated", "sha256"};
    const char *optional[] = {"recovery_status"};
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
    *source = g_key_file_get_string(record, "tombstone", "source", NULL);
    *hash = g_key_file_get_string(record, "tombstone", "sha256", NULL);
    valid = valid && !g_strcmp0(version, "1") && source_valid(*source) &&
        object_name_valid(*source, name) && !g_strcmp0(name, stored_name) &&
        !g_strcmp0(state, "DELETING") && digest_valid(*hash) &&
        (!observation || !strcmp(observation, "MATCHED") || !strcmp(observation, "MISSING") ||
         !strcmp(observation, "UNKNOWN") || !strcmp(observation, "BUSY"));
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
    g_free(version); g_free(stored_name); g_free(state); g_free(observation);
    return valid;
}

static int recover_tombstone(const char *root_path, int root, int store,
                              const char *name)
{
    char *raw = NULL, *source = NULL, *hash = NULL;
    size_t size;
    uint64_t values[4] = {0};
    GKeyFile *record = g_key_file_new();
    int result = -1, object = -1, latch = -1;
    if (read_file(store, name, RECORD_LIMIT, &raw, &size) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !tombstone_shape(record, name, &source, values, &hash)) goto out;
    char *prior = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    bool unknown = !g_strcmp0(prior, "UNKNOWN");
    bool was_missing = !g_strcmp0(prior, "MISSING");
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
        } else if (was_missing) {
            observation = "UNKNOWN";
        } else if (flock(object, LOCK_SH | LOCK_NB)) {
            observation = errno == EWOULDBLOCK ? "BUSY" : "UNKNOWN";
        } else {
            const char *names[] = {name};
            char *actual = !fstat(object, &before) ? capture_objects(root, source, names, 1) : NULL;
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
    if (latch < 0) {
        observation = !strcmp(observation, "UNKNOWN") || errno != EWOULDBLOCK ? "UNKNOWN" : "BUSY";
    } else {
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
    g_key_file_set_string(record, "tombstone", "recovery_status", observation);
    result = !g_strcmp0(prior, observation) ? 0 : write_record(store, name, record);
    g_free(prior);
out:
    if (object >= 0) close(object);
    if (latch >= 0) close(latch);
    g_free(raw); g_free(source); g_free(hash);
    g_key_file_unref(record);
    return result;
}

int latcd_tombstone_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = root_fd < 0 ? -1 : open_directory(root_fd, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    int saved = errno;
    if (gc >= 0) close(gc);
    if (store < 0) {
        if (root_fd >= 0) close(root_fd);
        return saved == ENOENT ? 0 : fail(error, error_size, "unsafe tombstone store");
    }
    DIR *directory = fdopendir(store);
    int result = directory ? 0 : -1;
    if (!directory) close(store);
    unsigned visited = 0;
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 100000) { result = -1; break; }
        if (g_str_has_prefix(entry->d_name, ".write-")) continue;
        if (recover_tombstone(root, root_fd, store, entry->d_name)) { result = -1; break; }
        (*recovered)++;
    }
    if (directory) closedir(directory);
    close(root_fd);
    return result ? fail(error, error_size, "tombstone recovery rejected unknown record") : 0;
}
