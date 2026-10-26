#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cache-retirement.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MANIFEST_LIMIT 4096
#define RECORD_LIMIT 32768

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

static int write_record(int directory, const char *name, GKeyFile *record)
{
    gsize size;
    char *data = g_key_file_to_data(record, &size, NULL);
    char *uuid = g_uuid_string_random();
    char *temporary = g_strdup_printf(".write-%s", uuid);
    g_free(uuid);
    int fd = openat(directory, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    int result = -1;
    if (fd < 0) goto out;
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = write(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto close_out;
        offset += count;
    }
    if (fchmod(fd, 0400) || fsync(fd)) goto close_out;
    if (close(fd)) { fd = -1; goto out; }
    fd = -1;
    if (renameat(directory, temporary, directory, name) || fsync(directory)) goto out;
    result = 0;
close_out:
    if (fd >= 0) close(fd);
out:
    if (result) unlinkat(directory, temporary, 0);
    g_free(temporary);
    g_free(data);
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
                            const char *next, size_t next_size,
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
    g_key_file_set_integer(record, "transaction", "version", 1);
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
        "prepared_boot", "prepared_boottime_us", "retired_boot", "retired_boottime_us" };
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

static int recover_record(int root, int store, const char *name)
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
    if (g_key_file_get_integer(record, "transaction", "version", NULL) != 1 ||
        !source_valid(source) || !state || !old64 || !new64) goto fields_out;
    gsize old_size, new_size;
    guchar *old = decode_snapshot(old64, &old_size);
    guchar *next = decode_snapshot(new64, &new_size);
    if (!old || !next || !new_size) {
        g_free(old);
        g_free(next);
        goto fields_out;
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
                 recover_record(root_fd, store, transaction);
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
        if (*recovered >= 100000 || recover_record(root_fd, store, entry->d_name)) {
            result = -1;
            break;
        }
        (*recovered)++;
    }
    if (directory) closedir(directory);
    close(root_fd);
    return result ? fail(error, error_size, "retirement recovery rejected unknown record") : 0;
}
