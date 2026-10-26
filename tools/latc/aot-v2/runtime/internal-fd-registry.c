#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "internal-fd-registry.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static int *protected_fds;
static size_t protected_count;
static size_t protected_capacity;
static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;

static void registry_atfork_prepare(void)
{
    pthread_mutex_lock(&registry_lock);
}

static void registry_atfork_release(void)
{
    pthread_mutex_unlock(&registry_lock);
}

static void register_atfork_handlers(void)
{
    (void)pthread_atfork(registry_atfork_prepare, registry_atfork_release,
                         registry_atfork_release);
}

__attribute__((constructor))
static void initialize_internal_fd_registry(void)
{
    (void)pthread_once(&atfork_once, register_atfork_handlers);
}

void lat_aot_v2_internal_fd_lock(void)
{
    pthread_mutex_lock(&registry_lock);
}

void lat_aot_v2_internal_fd_unlock(void)
{
    pthread_mutex_unlock(&registry_lock);
}

static size_t fd_lower_bound(int fd)
{
    size_t low = 0;
    size_t high = protected_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (protected_fds[middle] < fd) low = middle + 1;
        else high = middle;
    }
    return low;
}

int lat_aot_v2_internal_fd_register_locked(int fd)
{
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }
    size_t index = fd_lower_bound(fd);
    if (index < protected_count && protected_fds[index] == fd) return 0;
    if (protected_count == protected_capacity) {
        size_t capacity = protected_capacity ? protected_capacity * 2 : 32;
        if (capacity < protected_capacity ||
            capacity > SIZE_MAX / sizeof(*protected_fds)) {
            errno = ENOMEM;
            return -1;
        }
        int *grown = realloc(protected_fds,
                             capacity * sizeof(*protected_fds));
        if (!grown) {
            errno = ENOMEM;
            return -1;
        }
        protected_fds = grown;
        protected_capacity = capacity;
    }
    for (size_t i = protected_count; i > index; i--) {
        protected_fds[i] = protected_fds[i - 1];
    }
    protected_fds[index] = fd;
    protected_count++;
    return 0;
}

int lat_aot_v2_internal_fd_unregister_close_locked(int fd)
{
    size_t index = fd_lower_bound(fd);
    if (index == protected_count || protected_fds[index] != fd) {
        errno = EBADF;
        return -1;
    }
    for (size_t i = index + 1; i < protected_count; i++) {
        protected_fds[i - 1] = protected_fds[i];
    }
    protected_count--;
    return close(fd);
}

static bool fd_is_protected_locked(int fd)
{
    if (fd < 0) return false;
    size_t index = fd_lower_bound(fd);
    return index < protected_count && protected_fds[index] == fd;
}

bool lat_aot_v2_internal_fd_is_protected(int fd)
{
    lat_aot_v2_internal_fd_lock();
    bool protected = fd_is_protected_locked(fd);
    lat_aot_v2_internal_fd_unlock();
    return protected;
}

int lat_aot_v2_internal_fd_dup_replace(int oldfd, int newfd, int flags, bool use_dup3)
{
    lat_aot_v2_internal_fd_lock();
    int result;
    if (fd_is_protected_locked(oldfd) || fd_is_protected_locked(newfd)) {
        errno = EACCES;
        result = -1;
    } else {
        result = use_dup3 ? dup3(oldfd, newfd, flags) : dup2(oldfd, newfd);
    }
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return result;
}

int lat_aot_v2_internal_fd_snapshot_guest(int fd)
{
    lat_aot_v2_internal_fd_lock();
    int snapshot = -1;
    if (fd_is_protected_locked(fd)) errno = EACCES;
    else {
        snapshot = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (snapshot >= 0 && lat_aot_v2_internal_fd_register_locked(snapshot)) {
            int saved = errno;
            close(snapshot);
            snapshot = -1;
            errno = saved;
        }
    }
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return snapshot;
}

int lat_aot_v2_internal_fd_try_flock(int fd, int operation)
{
    lat_aot_v2_internal_fd_lock();
    int result;
    if (fd_is_protected_locked(fd)) { errno = EACCES; result = -1; }
    else result = flock(fd, operation | LOCK_NB);
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return result;
}

int lat_aot_v2_internal_fd_fcntl(int fd, int command, int argument)
{
    if (command != F_GETFD && command != F_SETFD && command != F_DUPFD &&
        command != F_DUPFD_CLOEXEC) {
        errno = EINVAL;
        return -1;
    }
    lat_aot_v2_internal_fd_lock();
    int result;
    if (fd_is_protected_locked(fd)) { errno = EACCES; result = -1; }
    else result = fcntl(fd, command, argument);
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return result;
}
