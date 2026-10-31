#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "worker-domain.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <string.h>
#include <sys/statfs.h>
#include <unistd.h>

static bool valid_name(const char *name)
{
    if (!name || !*name || strlen(name) > 127 || name[0] == '.') return false;
    return strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == strlen(name);
}

static int cgroup_dir(int fd)
{
    struct stat st;
    struct statfs fs;
    if (fstat(fd, &st) || fstatfs(fd, &fs)) return -1;
    if (!S_ISDIR(st.st_mode) || fs.f_type != CGROUP2_SUPER_MAGIC) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int latcd_worker_domain_create(int parent, const char *name, struct stat *identity)
{
    if (!identity || !valid_name(name)) { errno = EINVAL; return -1; }
    if (cgroup_dir(parent) || mkdirat(parent, name, 0700)) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (cgroup_dir(fd) || fstat(fd, identity)) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}

int latcd_worker_domain_populated(int parent, const char *name,
                                  const struct stat *identity, int *populated)
{
    if (!identity || !populated || !valid_name(name)) { errno = EINVAL; return -1; }
    if (cgroup_dir(parent)) return -1;
    int dir = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st;
    if (cgroup_dir(dir) || fstat(dir, &st)) {
        int saved = errno; close(dir); errno = saved; return -1;
    }
    if (st.st_dev != identity->st_dev || st.st_ino != identity->st_ino) {
        close(dir); errno = ESTALE; return -1;
    }
    int fd = openat(dir, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { int saved = errno; close(dir); errno = saved; return -1; }
    char data[256];
    ssize_t n;
    do { n = read(fd, data, sizeof(data) - 1); } while (n < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (n < 0) { close(dir); errno = saved; return -1; }
    if (!n || n == (ssize_t)sizeof(data) - 1) { close(dir); errno = EINVAL; return -1; }
    struct stat current;
    if (fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW)) {
        saved = errno; close(dir); errno = saved; return -1;
    }
    close(dir);
    if (!S_ISDIR(current.st_mode) || current.st_dev != identity->st_dev ||
        current.st_ino != identity->st_ino) { errno = ESTALE; return -1; }
    data[n] = 0;
    int value = -1;
    char *save = NULL;
    for (char *line = strtok_r(data, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (!strncmp(line, "populated ", 10)) {
            if (value != -1 || (strcmp(line + 10, "0") && strcmp(line + 10, "1"))) {
                errno = EINVAL; return -1;
            }
            value = line[10] - '0';
        }
    }
    if (value < 0) { errno = EINVAL; return -1; }
    *populated = value;
    return 0;
}

int latcd_worker_domain_kill(int parent, const char *name,
                             const struct stat *identity)
{
    if (!identity || !valid_name(name)) { errno = EINVAL; return -1; }
    if (cgroup_dir(parent)) return -1;
    int dir = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st;
    if (cgroup_dir(dir) || fstat(dir, &st)) {
        int saved = errno; close(dir); errno = saved; return -1;
    }
    if (st.st_dev != identity->st_dev || st.st_ino != identity->st_ino) {
        close(dir); errno = ESTALE; return -1;
    }
    int fd = openat(dir, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { int saved = errno; close(dir); errno = saved; return -1; }
    ssize_t n;
    do { n = write(fd, "1", 1); } while (n < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (n != 1) { close(dir); errno = n < 0 ? saved : EIO; return -1; }
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW)) {
        saved = errno; close(dir); errno = saved; return -1;
    }
    close(dir);
    if (!S_ISDIR(st.st_mode) || st.st_dev != identity->st_dev ||
        st.st_ino != identity->st_ino) { errno = ESTALE; return -1; }
    return 0;
}
