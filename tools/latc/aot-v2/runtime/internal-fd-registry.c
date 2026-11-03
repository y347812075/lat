#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "internal-fd-registry.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t closes_idle = PTHREAD_COND_INITIALIZER;
static size_t guest_closes;
static size_t guest_operations;
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

static void registry_atfork_child(void)
{
    /* Other threads' pending closes cannot target the child's fd table. */
    guest_closes = 0;
    guest_operations = 0;
    pthread_mutex_unlock(&registry_lock);
}

static void register_atfork_handlers(void)
{
    (void)pthread_atfork(registry_atfork_prepare, registry_atfork_release,
                         registry_atfork_child);
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

void lat_aot_v2_internal_fd_allocation_lock(void)
{
    pthread_mutex_lock(&registry_lock);
    while (guest_closes || guest_operations)
        pthread_cond_wait(&closes_idle, &registry_lock);
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

int lat_aot_v2_internal_fd_relocate(int fd)
{
    int replacement = -1;
    int saved_errno;

    lat_aot_v2_internal_fd_allocation_lock();
    if (!fd_is_protected_locked(fd)) {
        errno = EINVAL;
        goto out;
    }
    int original_flags = fcntl(fd, F_GETFD);
    if (original_flags < 0) goto out;

    replacement = fcntl(fd, F_DUPFD, 3);
    if (replacement < 0) goto out;
    if ((original_flags & FD_CLOEXEC) &&
        fcntl(replacement, F_SETFD, FD_CLOEXEC)) {
        saved_errno = errno;
        close(replacement);
        replacement = -1;
        errno = saved_errno;
        goto out;
    }
    if (lat_aot_v2_internal_fd_register_locked(replacement)) {
        saved_errno = errno;
        close(replacement);
        replacement = -1;
        errno = saved_errno;
        goto out;
    }
    if (lat_aot_v2_internal_fd_unregister_close_locked(fd)) {
        saved_errno = errno;
        lat_aot_v2_internal_fd_unregister_close_locked(replacement);
        replacement = -1;
        errno = saved_errno;
        goto out;
    }
out:
    saved_errno = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved_errno;
    return replacement;
}

int lat_aot_v2_internal_fd_close_guest(int fd)
{
    lat_aot_v2_internal_fd_lock();
    if (fd_is_protected_locked(fd)) {
        lat_aot_v2_internal_fd_unlock();
        errno = EACCES;
        return -1;
    }
    guest_closes++;
    lat_aot_v2_internal_fd_unlock();
    /* close may wait for a socket peer; only internal allocation must wait. */
    int result = close(fd);
    int saved = errno;
    lat_aot_v2_internal_fd_lock();
    if (!--guest_closes) pthread_cond_broadcast(&closes_idle);
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return result;
}

int lat_aot_v2_internal_fd_guest_begin(int fd)
{
    lat_aot_v2_internal_fd_lock();
    int result = -1;
    if (fd_is_protected_locked(fd)) errno = EACCES;
    else if (guest_operations == SIZE_MAX) errno = EOVERFLOW;
    else {
        guest_operations++;
        result = 0;
    }
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
    return result;
}

void lat_aot_v2_internal_fd_guest_end(void)
{
    int saved = errno;
    lat_aot_v2_internal_fd_lock();
    if (!guest_operations) abort();
    if (!--guest_operations) pthread_cond_broadcast(&closes_idle);
    lat_aot_v2_internal_fd_unlock();
    errno = saved;
}

static int add_range_fd(int **fds, size_t *count, size_t *capacity, int fd)
{
    if (*count == *capacity) {
        size_t grown = *capacity ? *capacity * 2 : 16;
        if (grown < *capacity || grown > SIZE_MAX / sizeof(**fds)) {
            errno = ENOMEM;
            return -1;
        }
        int *new_fds = realloc(*fds, grown * sizeof(**fds));
        if (!new_fds) return -1;
        *fds = new_fds;
        *capacity = grown;
    }
    (*fds)[(*count)++] = fd;
    return 0;
}

int lat_aot_v2_internal_fd_close_range(unsigned first, unsigned last, bool cloexec,
                                        LatAotV2InternalFdRangeProtected extra_protected,
                                        LatAotV2InternalFdRangePrepare prepare,
                                        void *opaque)
{
    if (first > last) {
        errno = EINVAL;
        return -1;
    }
    int *targets = NULL;
    size_t count = 0, capacity = 0;
    DIR *directory = NULL;
    lat_aot_v2_internal_fd_lock();
    directory = opendir("/proc/self/fd");
    if (!directory) goto failed_locked;
    int scan_fd = dirfd(directory);
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            if (errno) goto failed_locked;
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *end = NULL;
        errno = 0;
        unsigned long parsed = strtoul(entry->d_name, &end, 10);
        if (errno || !*entry->d_name || !end || *end || parsed > UINT_MAX ||
            parsed < first || parsed > last || parsed == (unsigned long)scan_fd) continue;
        int fd = (int)parsed;
        if (fd_is_protected_locked(fd) ||
            (extra_protected && extra_protected(fd, opaque))) continue;
        if (add_range_fd(&targets, &count, &capacity, fd)) goto failed_locked;
    }
    closedir(directory);
    directory = NULL;
    lat_aot_v2_internal_fd_unlock();
    int result = 0;
    for (size_t i = 0; prepare && i < count; i++) {
        if (prepare(targets[i], opaque)) {
            result = -1;
            break;
        }
    }
    if (result) {
        int saved = errno;
        free(targets);
        errno = saved;
        return -1;
    }
    lat_aot_v2_internal_fd_lock();
    size_t kept = 0, original_count = count;
    for (size_t i = 0; i < original_count; i++) {
        int fd = targets[i];
        if (fd_is_protected_locked(fd) ||
            (extra_protected && extra_protected(fd, opaque))) continue;
        if (fcntl(fd, F_GETFD) < 0) {
            if (errno == EBADF) continue;
            goto failed_locked;
        }
        targets[kept++] = fd;
    }
    count = kept;
    if (count > SIZE_MAX - guest_closes) {
        errno = EOVERFLOW;
        goto failed_locked;
    }
    guest_closes += count;
    lat_aot_v2_internal_fd_unlock();
    for (size_t i = 0; i < count; i++) {
        if (cloexec) {
            if (!fcntl(targets[i], F_SETFD, FD_CLOEXEC) || errno == EBADF) continue;
        } else if (!close(targets[i]) || errno == EBADF) continue;
        result = -1;
        break;
    }
    int saved = errno;
    lat_aot_v2_internal_fd_lock();
    guest_closes -= count;
    if (!guest_closes) pthread_cond_broadcast(&closes_idle);
    lat_aot_v2_internal_fd_unlock();
    free(targets);
    errno = saved;
    return result;
failed_locked:
    if (directory) closedir(directory);
    lat_aot_v2_internal_fd_unlock();
    free(targets);
    return -1;
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
    lat_aot_v2_internal_fd_allocation_lock();
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
