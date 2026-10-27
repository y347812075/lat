#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cache-domain.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DOMAIN_RECORD_LIMIT 4096

static int fail(char *error, size_t error_size, const char *format, ...)
{
    int saved = errno;
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    errno = saved;
    return -1;
}

static bool exact_keys(GKeyFile *record, const char *group,
                       const char *const *required, size_t required_count)
{
    gsize count = 0;
    char **keys = g_key_file_get_keys(record, group, &count, NULL);
    bool valid = keys && count == required_count;
    for (size_t i = 0; valid && i < required_count; i++) {
        unsigned matches = 0;
        for (gsize j = 0; j < count; j++) {
            matches += !strcmp(keys[j], required[i]);
        }
        valid = matches == 1;
    }
    g_strfreev(keys);
    return valid;
}

/* ENOENT is separate from malformed, mutable or unreadable metadata. */
static int read_domain_record(int directory, const char *name,
                              char **contents, size_t *size)
{
    *contents = NULL;
    *size = 0;
    int fd = openat(directory, name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 1 : -1;

    struct stat before, after;
    int result = -1;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0222) || before.st_size <= 0 ||
        (uint64_t)before.st_size > DOMAIN_RECORD_LIMIT) {
        goto out;
    }

    char *data = g_malloc((size_t)before.st_size + 1);
    size_t offset = 0;
    while (offset < (size_t)before.st_size) {
        ssize_t count = read(fd, data + offset, before.st_size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            g_free(data);
            goto out;
        }
        offset += (size_t)count;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_nlink != after.st_nlink ||
        before.st_size != after.st_size ||
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

static bool record_uint64(GKeyFile *record, const char *key, uint64_t *number)
{
    char *value = g_key_file_get_string(record, "domain", key, NULL);
    char *end = NULL;
    errno = 0;
    *number = value ? g_ascii_strtoull(value, &end, 10) : 0;
    bool valid = value && *value &&
        strspn(value, "0123456789") == strlen(value) &&
        !errno && end && !*end;
    g_free(value);
    return valid;
}

static bool domain_record_parse(GKeyFile *record, const struct stat *cache,
                                const struct stat *lock, char id[37])
{
    const char *fields[] = {
        "version", "id", "cache_device", "cache_inode",
        "lock_device", "lock_inode", "created_boot", "created_boottime_us",
    };
    gsize group_count = 0;
    char **groups = g_key_file_get_groups(record, &group_count);
    bool valid = group_count == 1 && groups &&
        !strcmp(groups[0], "domain") &&
        exact_keys(record, "domain", fields, G_N_ELEMENTS(fields));
    g_strfreev(groups);

    char *version = g_key_file_get_string(record, "domain", "version", NULL);
    char *stored_id = g_key_file_get_string(record, "domain", "id", NULL);
    char *created_boot =
        g_key_file_get_string(record, "domain", "created_boot", NULL);
    uint64_t cache_device, cache_inode, lock_device, lock_inode, created;
    valid = valid && !g_strcmp0(version, "1") &&
        stored_id && strlen(stored_id) == 36 &&
        g_uuid_string_is_valid(stored_id) &&
        record_uint64(record, "cache_device", &cache_device) &&
        cache_device == (uint64_t)cache->st_dev &&
        record_uint64(record, "cache_inode", &cache_inode) &&
        cache_inode == (uint64_t)cache->st_ino &&
        record_uint64(record, "lock_device", &lock_device) &&
        lock_device == (uint64_t)lock->st_dev &&
        record_uint64(record, "lock_inode", &lock_inode) &&
        lock_inode == (uint64_t)lock->st_ino &&
        created_boot && strlen(created_boot) == 36 &&
        g_uuid_string_is_valid(created_boot) &&
        record_uint64(record, "created_boottime_us", &created);
    if (valid && id) memcpy(id, stored_id, 37);
    g_free(version);
    g_free(stored_id);
    g_free(created_boot);
    return valid;
}

static int validate_open_domain(int gc, const struct stat *cache,
                                char id[37], char *error,
                                size_t error_size)
{
    char *raw = NULL;
    size_t size = 0;
    int marker_status = read_domain_record(gc, "domain.ini", &raw, &size);

    int lock = openat(gc, "domain.lock",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int lock_error = errno;
    if (marker_status == 1 && lock < 0 && lock_error == ENOENT) {
        g_free(raw);
        return 0;
    }

    struct stat lock_status;
    bool valid = marker_status == 0 && lock >= 0 && raw &&
        !memchr(raw, 0, size) && !fstat(lock, &lock_status) &&
        S_ISREG(lock_status.st_mode) && lock_status.st_uid == geteuid() &&
        lock_status.st_nlink == 1 && !(lock_status.st_mode & 0077) &&
        !lock_status.st_size;
    if (valid) {
        GKeyFile *record = g_key_file_new();
        valid = g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            domain_record_parse(record, cache, &lock_status, id);
        g_key_file_unref(record);
    }
    if (lock >= 0) close(lock);
    g_free(raw);
    if (!valid) {
        errno = ENOEXEC;
        return fail(error, error_size,
                    "cache domain metadata is incomplete, malformed or rebound");
    }
    return 1;
}

int lat_aot_v2_cache_domain_validate(const char *root, char id[37],
                                     char *error, size_t error_size)
{
    if (!root || !*root) {
        errno = EINVAL;
        return fail(error, error_size, "invalid cache domain root");
    }
    if (id) id[0] = 0;
    int directory = open(root,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        return fail(error, error_size, "cannot open cache domain root");
    }

    struct stat cache;
    int gc = -1;
    int result = -1;
    if (fstat(directory, &cache) || !S_ISDIR(cache.st_mode) ||
        cache.st_uid != geteuid() || (cache.st_mode & 0022)) {
        errno = EACCES;
        fail(error, error_size,
             "cache domain root is not a user-owned non-shared-write directory");
        goto out;
    }
    gc = openat(directory, ".gc",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (gc < 0) {
        if (errno == ENOENT) {
            result = 0;
        } else {
            fail(error, error_size, "cannot open cache domain metadata");
        }
        goto out;
    }
    struct stat gc_status;
    if (fstat(gc, &gc_status) || gc_status.st_uid != geteuid() ||
        (gc_status.st_mode & 0022)) {
        errno = EACCES;
        fail(error, error_size,
             "cache domain metadata is not a user-owned non-shared-write directory");
        goto out;
    }
    result = validate_open_domain(gc, &cache, id, error, error_size);
    if (result > 0 && ((cache.st_mode | gc_status.st_mode) & 0077)) {
        if (id) id[0] = 0;
        errno = EACCES;
        result = fail(error, error_size,
                      "managed cache domain requires private user directories");
    }

out:
    if (gc >= 0) close(gc);
    close(directory);
    return result;
}
