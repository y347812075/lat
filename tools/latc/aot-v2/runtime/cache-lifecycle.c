#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cache-lifecycle.h"

#include "internal-fd-registry.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

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

static bool lock_operation_valid(int operation)
{
    int kind = operation & (LOCK_SH | LOCK_EX);
    return (kind == LOCK_SH || kind == LOCK_EX) &&
           !(operation & ~(LOCK_SH | LOCK_EX | LOCK_NB));
}

static int verify_private_directory(int fd, const char *label,
                                    char *error, size_t error_size);

int lat_aot_v2_cache_lock_fd(int fd, int operation,
                             char *error, size_t error_size)
{
    if (fd < 0 || !lock_operation_valid(operation)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid cache lock operation");
    }
    int result;
    do {
        result = flock(fd, operation);
    } while (result && errno == EINTR);
    if (result) {
        return fail(error, error_size, "cannot lock cache file: %s",
                    strerror(errno));
    }
    return 0;
}

int lat_aot_v2_cache_object_available(const char *path,
                                      char *error, size_t error_size)
{
    if (!path || !*path) {
        errno = EINVAL;
        return fail(error, error_size, "invalid cache object path");
    }
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) {
        errno = EINVAL;
        return fail(error, error_size, "invalid cache object basename");
    }
    size_t length = slash ? (size_t)(slash - path) : 1;
    char *parent = malloc((length ? length : 1) + 1);
    if (!parent) return fail(error, error_size, "cannot allocate cache object path");
    if (!slash) memcpy(parent, ".", 2);
    else if (!length) { parent[0] = '/'; parent[1] = 0; }
    else { memcpy(parent, path, length); parent[length] = 0; }
    int root = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    free(parent);
    if (root < 0) return fail(error, error_size, "cannot open cache object parent");
    int gc = openat(root, ".gc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(root);
    if (gc < 0) {
        errno = saved;
        return saved == ENOENT ? 0 : fail(error, error_size, "unsafe cache lifecycle directory");
    }
    if (verify_private_directory(gc, "cache lifecycle", error, error_size)) {
        close(gc);
        return -1;
    }
    int tombstones = openat(gc, "tombstones", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    saved = errno;
    close(gc);
    if (tombstones < 0) {
        errno = saved;
        return saved == ENOENT ? 0 : fail(error, error_size, "unsafe cache tombstone directory");
    }
    if (verify_private_directory(tombstones, "cache tombstones", error, error_size)) {
        close(tombstones);
        return -1;
    }
    struct stat status;
    int result = fstatat(tombstones, name, &status, AT_SYMLINK_NOFOLLOW);
    saved = errno;
    close(tombstones);
    if (!result) {
        errno = ESTALE;
        return fail(error, error_size, "cache object is tombstoned: %s", name);
    }
    errno = saved;
    return saved == ENOENT ? 0 : fail(error, error_size, "cannot inspect cache object tombstone");
}

static bool source_hex_valid(const char *source_hex)
{
    if (!source_hex || strlen(source_hex) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((source_hex[i] >= '0' && source_hex[i] <= '9') ||
              (source_hex[i] >= 'a' && source_hex[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static int verify_private_directory(int fd, const char *label,
                                    char *error, size_t error_size)
{
    struct stat status;
    if (fstat(fd, &status)) {
        return fail(error, error_size, "cannot inspect %s: %s",
                    label, strerror(errno));
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0022)) {
        errno = EACCES;
        return fail(error, error_size,
                    "%s is not a user-owned non-shared-write directory",
                    label);
    }
    return 0;
}

static int open_private_subdirectory(int parent, const char *name,
                                     const char *parent_label,
                                     bool create,
                                     char *error, size_t error_size)
{
    if (create && mkdirat(parent, name, 0700) && errno != EEXIST) {
        return fail(error, error_size, "cannot create %s/%s: %s",
                    parent_label, name, strerror(errno));
    }
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY |
                    O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return fail(error, error_size, "cannot open %s/%s: %s",
                    parent_label, name, strerror(errno));
    }
    if (verify_private_directory(fd, name, error, error_size)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_source_lock_file(int directory, const char *source_hex,
                                 bool create,
                                 char *error, size_t error_size)
{
    char name[80];
    snprintf(name, sizeof(name), "%s.lock", source_hex);
    int fd = create ? openat(directory, name, O_RDWR | O_CREAT | O_EXCL |
                    O_CLOEXEC | O_NOFOLLOW, 0600) :
                    openat(directory, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    bool created = fd >= 0;
    if (create && fd < 0 && errno == EEXIST) {
        fd = openat(directory, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
    created = create && created;
    if (fd < 0) {
        return fail(error, error_size, "cannot open source latch %s: %s",
                    name, strerror(errno));
    }
    struct stat status;
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        status.st_mode & 0077 || (created && fchmod(fd, 0600))) {
        int saved = errno ? errno : EACCES;
        close(fd);
        errno = saved;
        return fail(error, error_size,
                    "source latch is not a private user regular file: %s",
                    name);
    }
    return fd;
}

static bool directory_still_bound(int parent, const char *name, int fd)
{
    struct stat opened, named;
    return !fstat(fd, &opened) &&
        !fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) &&
        S_ISDIR(opened.st_mode) && S_ISDIR(named.st_mode) &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino &&
        opened.st_uid == geteuid() && !(opened.st_mode & 0022);
}

static bool source_lock_still_bound(const char *path, int root, int gc,
                                    int locks, const char *source, int fd)
{
    char name[80];
    struct stat opened, named;
    snprintf(name, sizeof(name), "%s.lock", source);
    return directory_still_bound(AT_FDCWD, path, root) &&
        directory_still_bound(root, ".gc", gc) &&
        directory_still_bound(gc, "source-locks", locks) &&
        !fstat(fd, &opened) &&
        !fstatat(locks, name, &named, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(opened.st_mode) && S_ISREG(named.st_mode) &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino &&
        opened.st_uid == geteuid() && opened.st_nlink == 1 &&
        !(opened.st_mode & 0077);
}

static int cache_source_lock(const char *cache_dir,
                                 const char *source_hex, int operation,
                                 bool protect_from_guest, bool create, int expected_root,
                                 char *error, size_t error_size)
{
    if (!cache_dir || !*cache_dir || !source_hex_valid(source_hex) ||
        !lock_operation_valid(operation)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid source latch arguments");
    }
    if (protect_from_guest) lat_aot_v2_internal_fd_allocation_lock();
    int gc = -1, locks = -1;
    int root = open(cache_dir, O_RDONLY | O_DIRECTORY |
                    O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) {
        fail(error, error_size, "cannot open cache domain %s: %s",
             cache_dir, strerror(errno));
        goto error;
    }
    if (verify_private_directory(root, "cache domain", error, error_size)) {
        goto error;
    }
    if (expected_root >= 0) {
        struct stat actual, expected;
        if (fstat(root, &actual) || fstat(expected_root, &expected) ||
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) {
            errno = ESTALE;
            fail(error, error_size, "offline cache root changed before source latch creation");
            goto error;
        }
    }
    gc = open_private_subdirectory(root, ".gc", "cache", create,
                                       error, error_size);
    if (gc < 0) goto error;
    locks = open_private_subdirectory(gc, "source-locks", ".gc", create,
                                          error, error_size);
    if (locks < 0) goto error;
    int fd = open_source_lock_file(locks, source_hex, create, error, error_size);
    if (fd < 0) goto error;
    if (lat_aot_v2_cache_lock_fd(fd, operation, error, error_size)) {
        int saved = errno;
        close(fd);
        errno = saved;
        goto error;
    }
    if (!source_lock_still_bound(cache_dir, root, gc, locks, source_hex, fd)) {
        close(fd);
        errno = ESTALE;
        fail(error, error_size, "source latch binding changed while acquiring lock");
        goto error;
    }
    if (protect_from_guest && lat_aot_v2_internal_fd_register_locked(fd)) {
        int saved = errno;
        close(fd);
        errno = saved;
        fail(error, error_size, "cannot protect source latch fd: %s",
             strerror(errno));
        goto error;
    }
    int saved = errno;
    close(locks);
    close(gc);
    close(root);
    if (protect_from_guest) lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return fd;

error:
    {
        int saved = errno;
        if (locks >= 0) close(locks);
        if (gc >= 0) close(gc);
        if (root >= 0) close(root);
        if (protect_from_guest) lat_aot_v2_internal_fd_unlock();
        errno = saved;
    }
    return -1;
}

int lat_aot_v2_cache_source_lock(const char *cache_dir,
                                 const char *source_hex, int operation,
                                 bool protect_from_guest,
                                 char *error, size_t error_size)
{
    return cache_source_lock(cache_dir, source_hex, operation,
                             protect_from_guest, true, -1, error, error_size);
}

int lat_aot_v2_cache_source_lock_existing(const char *cache_dir,
                                          const char *source_hex, int operation,
                                          bool protect_from_guest,
                                          char *error, size_t error_size)
{
    return cache_source_lock(cache_dir, source_hex, operation,
                             protect_from_guest, false, -1, error, error_size);
}

int lat_aot_v2_cache_source_lock_offline(const char *cache_dir,
                                         const char *source_hex, int operation,
                                         bool protect_from_guest,
                                         char *error, size_t error_size)
{
    if (!cache_dir || !*cache_dir || !source_hex_valid(source_hex) ||
        !lock_operation_valid(operation)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid offline source latch arguments");
    }
    if (protect_from_guest) lat_aot_v2_internal_fd_allocation_lock();
    int root = open(cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool root_valid = root >= 0 &&
        !verify_private_directory(root, "cache domain", error, error_size);
    int owner = root_valid ? openat(root, ".latcd.lock", O_RDWR | O_CREAT |
                                    O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    struct stat held, named;
    bool valid = root_valid && owner >= 0 && !fstat(owner, &held);
    if (valid && (!S_ISREG(held.st_mode) || held.st_uid != geteuid() ||
                  held.st_nlink != 1 || (held.st_mode & 0077))) {
        errno = EACCES;
        valid = false;
    }
    if (valid && flock(owner, LOCK_EX | LOCK_NB)) valid = false;
    if (valid && (!directory_still_bound(AT_FDCWD, cache_dir, root) ||
        fstatat(root, ".latcd.lock", &named, AT_SYMLINK_NOFOLLOW) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino)) {
        errno = ESTALE;
        valid = false;
    }
    bool root_registered = false, owner_registered = false;
    if (valid && protect_from_guest) {
        root_registered = !lat_aot_v2_internal_fd_register_locked(root);
        owner_registered = root_registered && !lat_aot_v2_internal_fd_register_locked(owner);
        valid = owner_registered;
    }
    int saved = valid ? 0 : (errno ? errno : ESTALE);
    if (!valid) {
        if (owner_registered) lat_aot_v2_internal_fd_unregister_close_locked(owner);
        else if (owner >= 0) close(owner);
        if (root_registered) lat_aot_v2_internal_fd_unregister_close_locked(root);
        else if (root >= 0) close(root);
    }
    if (protect_from_guest) lat_aot_v2_internal_fd_unlock();
    if (!valid) { errno = saved; return fail(error, error_size, "cannot acquire offline cache owner"); }
    int fd = cache_source_lock(cache_dir, source_hex, operation | LOCK_NB, protect_from_guest,
                               true, root, error, error_size);
    saved = errno;
    valid = directory_still_bound(AT_FDCWD, cache_dir, root) &&
        !fstat(owner, &held) && !fstatat(root, ".latcd.lock", &named, AT_SYMLINK_NOFOLLOW) &&
        held.st_dev == named.st_dev && held.st_ino == named.st_ino &&
        S_ISREG(held.st_mode) && held.st_uid == geteuid() && held.st_nlink == 1 &&
        !(held.st_mode & 0077);
    if (!valid && fd >= 0) { lat_aot_v2_cache_close_fd(fd, protect_from_guest, NULL, 0); fd = -1; saved = ESTALE; }
    lat_aot_v2_cache_close_fd(root, protect_from_guest, NULL, 0);
    lat_aot_v2_cache_close_fd(owner, protect_from_guest, NULL, 0);
    errno = saved;
    return fd;
}

int lat_aot_v2_cache_close_fd(int fd, bool protected_from_guest,
                              char *error, size_t error_size)
{
    if (fd < 0) {
        errno = EBADF;
        return fail(error, error_size, "invalid protected cache fd");
    }
    if (!protected_from_guest) {
        if (close(fd)) {
            return fail(error, error_size, "cannot close cache fd: %s",
                        strerror(errno));
        }
        return 0;
    }
    lat_aot_v2_internal_fd_lock();
    int result = lat_aot_v2_internal_fd_unregister_close_locked(fd);
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    if (result) {
        return fail(error, error_size, "cannot close protected cache fd: %s",
                    strerror(errno));
    }
    return 0;
}
