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
                                     char *error, size_t error_size)
{
    if (mkdirat(parent, name, 0700) && errno != EEXIST) {
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
                                 char *error, size_t error_size)
{
    char name[80];
    snprintf(name, sizeof(name), "%s.lock", source_hex);
    int fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL |
                    O_CLOEXEC | O_NOFOLLOW, 0600);
    bool created = fd >= 0;
    if (fd < 0 && errno == EEXIST) {
        fd = openat(directory, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
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

int lat_aot_v2_cache_source_lock(const char *cache_dir,
                                 const char *source_hex, int operation,
                                 bool protect_from_guest,
                                 char *error, size_t error_size)
{
    if (!cache_dir || !*cache_dir || !source_hex_valid(source_hex) ||
        !lock_operation_valid(operation)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid source latch arguments");
    }
    if (protect_from_guest) lat_aot_v2_internal_fd_lock();
    int root = open(cache_dir, O_RDONLY | O_DIRECTORY |
                    O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) {
        fail(error, error_size, "cannot open cache domain %s: %s",
             cache_dir, strerror(errno));
        goto error;
    }
    if (verify_private_directory(root, "cache domain", error, error_size)) {
        close(root);
        goto error;
    }
    int gc = open_private_subdirectory(root, ".gc", "cache",
                                       error, error_size);
    close(root);
    if (gc < 0) goto error;
    int locks = open_private_subdirectory(gc, "source-locks", ".gc",
                                          error, error_size);
    close(gc);
    if (locks < 0) goto error;
    int fd = open_source_lock_file(locks, source_hex, error, error_size);
    close(locks);
    if (fd < 0) goto error;
    if (lat_aot_v2_cache_lock_fd(fd, operation, error, error_size)) {
        int saved = errno;
        close(fd);
        errno = saved;
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
    if (protect_from_guest) lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return fd;

error:
    {
        int saved = errno;
        if (protect_from_guest) lat_aot_v2_internal_fd_unlock();
        errno = saved;
    }
    return -1;
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
