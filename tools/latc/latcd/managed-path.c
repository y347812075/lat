#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "managed-path.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static int check_directory(int fd, uid_t uid, mode_t mode, int leaf)
{
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != uid ||
        (leaf ? (st.st_mode & 07777) != mode : (st.st_mode & 0022))) {
        errno = EACCES;
        return -1;
    }
    /* Reject ACLs rather than interpreting permissions incompletely. */
    const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (fgetxattr(fd, names[i], NULL, 0) >= 0 || errno != ENODATA) {
            errno = EACCES;
            return -1;
        }
    }
    return 0;
}

int latcd_managed_directory(const char *path, uid_t leaf_uid, mode_t leaf_mode)
{
    if (!path || path[0] != '/' || !path[1] || path[strlen(path) - 1] == '/' ||
        strstr(path, "//")) { errno = EINVAL; return -1; }
    char *copy = strdup(path + 1);
    if (!copy) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { free(copy); return -1; }
    bool private_ancestor = false;
    if (check_directory(fd, 0, 0, 0)) goto fail;
    char *component = copy;
    for (;;) {
        char *next = strchr(component, '/');
        if (next) *next++ = '\0';
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..")) {
            errno = EINVAL; goto fail;
        }
        int child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0) goto fail;
        close(fd);
        fd = child;
        if (next) {
            struct stat st;
            if (fstat(fd, &st) || !S_ISDIR(st.st_mode)) {
                errno = EACCES;
                goto fail;
            }
            bool private = st.st_uid == leaf_uid && !(st.st_mode & 0077);
            if (!((st.st_uid == 0 && !(st.st_mode & 0022)) ||
                  private || private_ancestor)) {
                errno = EACCES;
                goto fail;
            }
            if (private) private_ancestor = true;
            const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
            for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (fgetxattr(fd, names[i], NULL, 0) >= 0 || errno != ENODATA) {
                    errno = EACCES;
                    goto fail;
                }
        } else if (check_directory(fd, leaf_uid, leaf_mode, 1)) {
            goto fail;
        }
        if (!next) break;
        component = next;
    }
    free(copy);
    return fd;
fail:
    { int saved = errno; close(fd); free(copy); errno = saved; return -1; }
}

int latcd_managed_directory_matches(int held, const char *path,
                                    uid_t leaf_uid, mode_t leaf_mode)
{
    struct stat old, current;
    if (held < 0 || fstat(held, &old) || !S_ISDIR(old.st_mode)) {
        errno = EINVAL; return -1;
    }
    int fd = latcd_managed_directory(path, leaf_uid, leaf_mode);
    if (fd < 0) return -1;
    int result = fstat(fd, &current);
    int saved = errno;
    close(fd);
    if (result) { errno = saved; return -1; }
    if (old.st_dev != current.st_dev || old.st_ino != current.st_ino) {
        errno = ESTALE; return -1;
    }
    return 0;
}

int latcd_managed_file(const char *path, int executable)
{
    if (!path || path[0] != '/') { errno = EINVAL; return -1; }
    char *copy = strdup(path);
    if (!copy) return -1;
    char *name = strrchr(copy, '/');
    if (!name || name == copy || !name[1] || !strcmp(name + 1, ".") ||
        !strcmp(name + 1, "..")) { free(copy); errno = EINVAL; return -1; }
    *name++ = '\0';
    int directory = latcd_managed_directory(copy, 0, 0755);
    if (directory < 0) { free(copy); return -1; }
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int saved = errno;
    close(directory);
    free(copy);
    if (fd < 0) { errno = saved; return -1; }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022) || (executable && !(st.st_mode & 0111)) ||
        fgetxattr(fd, "system.posix_acl_access", NULL, 0) >= 0 || errno != ENODATA) {
        close(fd); errno = EACCES; return -1;
    }
    return fd;
}

int latcd_managed_config_read(const char *path, char *buffer, size_t capacity,
                              size_t *length)
{
    if (!path || !buffer || !capacity || !length || path[0] != '/') {
        errno = EINVAL; return -1;
    }
    *length = 0;
    char *copy = strdup(path);
    if (!copy) return -1;
    char *name = strrchr(copy, '/');
    if (!name || name == copy || !name[1] || !strcmp(name + 1, ".") ||
        !strcmp(name + 1, "..")) { free(copy); errno = EINVAL; return -1; }
    *name++ = '\0';
    /* Configuration ancestors and parent are root-owned, not writable by others. */
    int directory = latcd_managed_directory(copy, 0, 0755);
    if (directory < 0) { free(copy); return -1; }
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int saved = errno;
    close(directory);
    free(copy);
    if (fd < 0) { errno = saved; return -1; }
    struct stat before, after;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 ||
        before.st_nlink != 1 || (before.st_mode & 0022) || before.st_size < 0 ||
        (unsigned long long)before.st_size >= capacity ||
        fgetxattr(fd, "system.posix_acl_access", NULL, 0) >= 0 || errno != ENODATA) {
        errno = EACCES; goto fail;
    }
    size_t used = 0;
    while (used < (size_t)before.st_size) {
        ssize_t n = read(fd, buffer + used, (size_t)before.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { errno = EIO; goto fail; }
        used += n;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) { errno = ESTALE; goto fail; }
    buffer[used] = '\0';
    *length = used;
    close(fd);
    return 0;
fail:
    saved = errno; close(fd); errno = saved; return -1;
}
