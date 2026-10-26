#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cache-lifecycle.h"

#include <errno.h>
#include <pthread.h>
#include "internal-fd-registry.h"
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char source_hex[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static int child_exclusive_attempt(const char *root)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        char error[256] = {0};
        int fd = lat_aot_v2_cache_source_lock(
            root, source_hex, LOCK_EX | LOCK_NB, false, error, sizeof(error));
        if (fd >= 0) {
            close(fd);
            _exit(1);
        }
        _exit(errno == EWOULDBLOCK ? 0 : 2);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int wait_byte(int fd)
{
    char byte;
    ssize_t count;
    do {
        count = read(fd, &byte, 1);
    } while (count < 0 && errno == EINTR);
    return count == 1 ? 0 : -1;
}

static int signal_byte(int fd)
{
    char byte = 'x';
    ssize_t count;
    do {
        count = write(fd, &byte, 1);
    } while (count < 0 && errno == EINTR);
    return count == 1 ? 0 : -1;
}

static atomic_int paused_close_fd = -1;
static int close_entered, close_release;
static _Thread_local int allocation_wait_ready = -1;

int __real_pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex);
int __wrap_pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex)
{
    if (allocation_wait_ready >= 0) {
        if (signal_byte(allocation_wait_ready)) return EIO;
        allocation_wait_ready = -1;
    }
    return __real_pthread_cond_wait(condition, mutex);
}

int __real_close(int fd);
int __wrap_close(int fd)
{
    if (fd == atomic_load(&paused_close_fd)) {
        if (signal_byte(close_entered) || wait_byte(close_release)) {
            errno = EIO;
            return -1;
        }
    }
    return __real_close(fd);
}

static void *close_guest_fd(void *opaque)
{
    int fd = *(int *)opaque;
    return lat_aot_v2_internal_fd_close_guest(fd) ? (void *)1 : NULL;
}

typedef struct AllocationAttempt {
    int ready;
    int acquired;
    int fd;
} AllocationAttempt;

static void *allocate_internal_fd(void *opaque)
{
    AllocationAttempt *attempt = opaque;
    allocation_wait_ready = attempt->ready;
    lat_aot_v2_internal_fd_allocation_lock();
    attempt->fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int result = attempt->fd < 0 ||
        lat_aot_v2_internal_fd_register_locked(attempt->fd);
    lat_aot_v2_internal_fd_unlock();
    if (signal_byte(attempt->acquired)) result = -1;
    return result ? (void *)1 : NULL;
}

static int test_guest_close(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || lat_aot_v2_internal_fd_close_guest(fd) ||
        lat_aot_v2_internal_fd_close_guest(fd) != -1 || errno != EBADF) return -1;
    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    lat_aot_v2_internal_fd_allocation_lock();
    int registered = lat_aot_v2_internal_fd_register_locked(fd);
    lat_aot_v2_internal_fd_unlock();
    if (fd < 0 || registered || lat_aot_v2_internal_fd_close_guest(fd) != -1 ||
        errno != EACCES || fcntl(fd, F_GETFD) < 0) return -1;
    lat_aot_v2_internal_fd_lock();
    int result = lat_aot_v2_internal_fd_unregister_close_locked(fd);
    lat_aot_v2_internal_fd_unlock();
    if (result) return -1;

    int entered[2], release[2], ready[2], acquired[2];
    if (pipe(entered) || pipe(release) || pipe(ready) || pipe(acquired)) return -1;
    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int other = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || other < 0) return -1;
    close_entered = entered[1]; close_release = release[0];
    atomic_store(&paused_close_fd, fd);
    pthread_t closer, allocator;
    if (pthread_create(&closer, NULL, close_guest_fd, &fd) || wait_byte(entered[0]))
        return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        alarm(5);
        atomic_store(&paused_close_fd, -1);
        lat_aot_v2_internal_fd_allocation_lock();
        int copy = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int result = copy < 0 || lat_aot_v2_internal_fd_register_locked(copy);
        lat_aot_v2_internal_fd_unlock();
        _exit(result ? 1 : 0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status)) return -1;
    AllocationAttempt attempt = {.ready = ready[1], .acquired = acquired[1], .fd = -1};
    if (pthread_create(&allocator, NULL, allocate_internal_fd, &attempt) ||
        wait_byte(ready[0])) return -1;
    if (lat_aot_v2_internal_fd_fcntl(other, F_GETFD, 0) != FD_CLOEXEC ||
        lat_aot_v2_internal_fd_close_guest(other)) return -1;
    if (signal_byte(release[1])) return -1;
    void *closed, *allocated;
    if (pthread_join(closer, &closed) || pthread_join(allocator, &allocated) ||
        closed || allocated || wait_byte(acquired[0]) ||
        !lat_aot_v2_internal_fd_is_protected(attempt.fd)) return -1;
    atomic_store(&paused_close_fd, -1);
    lat_aot_v2_internal_fd_lock();
    result = lat_aot_v2_internal_fd_unregister_close_locked(attempt.fd);
    lat_aot_v2_internal_fd_unlock();
    for (int i = 0; i < 2; i++) {
        close(entered[i]); close(release[i]); close(ready[i]); close(acquired[i]);
    }
    return result;
}

static int test_source_latch(const char *root)
{
    char error[256] = {0};
    int shared = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_SH, false, error, sizeof(error));
    if (shared < 0) {
        fprintf(stderr, "cannot acquire source share lock: %s\n", error);
        return -1;
    }
    int child_result = child_exclusive_attempt(root);
    if (child_result) {
        fprintf(stderr, "exclusive source child did not block: %d\n",
                child_result);
        close(shared);
        return -1;
    }
    close(shared);
    int exclusive = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_EX | LOCK_NB, false, error, sizeof(error));
    if (exclusive < 0) {
        fprintf(stderr, "released source latch stayed locked: %s\n", error);
        return -1;
    }
    close(exclusive);
    return 0;
}

static int test_guest_fd_registry(const char *root)
{
    char error[256] = {0};
    int fd = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_SH, true, error, sizeof(error));
    if (fd < 0 || !lat_aot_v2_internal_fd_is_protected(fd)) {
        fprintf(stderr, "source latch was not registered as internal: %s\n",
                error);
        if (fd >= 0) close(fd);
        return -1;
    }
    if (lat_aot_v2_cache_close_fd(fd, true, error, sizeof(error)) ||
        lat_aot_v2_internal_fd_is_protected(fd)) {
        fprintf(stderr, "protected source latch was not unregistered: %s\n",
                error);
        return -1;
    }
    return 0;
}

static int test_fork_inheritance(const char *root)
{
    char error[256] = {0};
    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return -1;
    int shared = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_SH, false, error, sizeof(error));
    if (shared < 0) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        close(ready[0]);
        close(release[1]);
        if (signal_byte(ready[1]) || wait_byte(release[0])) _exit(2);
        close(shared);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    close(shared);
    if (wait_byte(ready[0])) return -1;
    int blocked = child_exclusive_attempt(root);
    if (blocked) {
        fprintf(stderr, "forked child did not retain source lock: %d\n", blocked);
        kill(child, SIGKILL);
        return -1;
    }
    if (signal_byte(release[1])) return -1;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status)) return -1;
    int exclusive = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_EX | LOCK_NB, false, error, sizeof(error));
    if (exclusive < 0) {
        fprintf(stderr, "source lock survived forked-child exit: %s\n", error);
        return -1;
    }
    close(exclusive);
    return 0;
}

typedef struct DupAttempt {
    int source;
    int target;
    int ready;
    bool dup3;
    bool snapshot;
    bool close_guest;
    int command;
    int result;
    int error;
} DupAttempt;

static void *attempt_dup(void *opaque)
{
    DupAttempt *attempt = opaque;
    if (signal_byte(attempt->ready)) return (void *)1;
    if (attempt->close_guest)
        attempt->result = lat_aot_v2_internal_fd_close_guest(attempt->source);
    else if (attempt->command >= 0)
        attempt->result = lat_aot_v2_internal_fd_fcntl(attempt->source, attempt->command, 0);
    else if (attempt->snapshot)
        attempt->result = lat_aot_v2_internal_fd_snapshot_guest(attempt->source);
    else
        attempt->result = lat_aot_v2_internal_fd_dup_replace(
            attempt->source, attempt->target, O_CLOEXEC, attempt->dup3);
    attempt->error = errno;
    return NULL;
}

static int test_dup_registration(bool dup3, bool protect_source, bool snapshot, int command,
                                 bool close_guest)
{
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int target = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    int ready[2];
    if (source < 0 || target < 0 || pipe(ready)) return -1;
    struct stat before, after;
    if (fstat(target, &before)) return -1;
    DupAttempt attempt = { .source = source, .target = target,
                           .ready = ready[1], .dup3 = dup3, .snapshot = snapshot,
                           .command = command, .close_guest = close_guest };
    pthread_t worker;
    /* Simulate an internal allocator completing registration while a guest
     * replacement has started but cannot yet enter the shared lock. */
    lat_aot_v2_internal_fd_lock();
    if (pthread_create(&worker, NULL, attempt_dup, &attempt) || wait_byte(ready[0]) ||
        lat_aot_v2_internal_fd_register_locked(protect_source ? source : target)) {
        lat_aot_v2_internal_fd_unlock();
        return -1;
    }
    lat_aot_v2_internal_fd_unlock();
    void *thread_result;
    if (pthread_join(worker, &thread_result) || thread_result || attempt.result != -1 ||
        attempt.error != EACCES || fstat(target, &after) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino) return -1;
    lat_aot_v2_internal_fd_lock();
    int closed = lat_aot_v2_internal_fd_unregister_close_locked(protect_source ? source : target);
    lat_aot_v2_internal_fd_unlock();
    if (closed) return -1;
    close(protect_source ? target : source);
    close(ready[0]); close(ready[1]);

    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    target = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (source < 0 || target < 0 ||
        lat_aot_v2_internal_fd_dup_replace(source, target, O_CLOEXEC, dup3) != target ||
        fstat(source, &before) || fstat(target, &after) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        !!(fcntl(target, F_GETFD) & FD_CLOEXEC) != dup3) return -1;
    if (lat_aot_v2_internal_fd_dup_replace(source, source, 0, dup3) != (dup3 ? -1 : source) ||
        (dup3 && errno != EINVAL)) return -1;
    if (lat_aot_v2_internal_fd_dup_replace(-1, target, 0, dup3) != -1 || errno != EBADF)
        return -1;
    close(source); close(target);
    return 0;
}

static int test_guest_snapshot(const char *root)
{
    char path[4096], error[256];
    snprintf(path, sizeof(path), "%s/flock-snapshot", root);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int contender = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || contender < 0) return -1;
    int snapshot = lat_aot_v2_internal_fd_snapshot_guest(fd);
    if (snapshot < 0 || !lat_aot_v2_internal_fd_is_protected(snapshot) ||
        !(fcntl(snapshot, F_GETFD) & FD_CLOEXEC) ||
        lat_aot_v2_internal_fd_try_flock(fd, LOCK_SH)) return -1;
    if (lat_aot_v2_internal_fd_try_flock(snapshot, LOCK_UN) != -1 || errno != EACCES)
        return -1;
    if (lat_aot_v2_internal_fd_try_flock(contender, LOCK_EX) != -1 || errno != EWOULDBLOCK)
        return -1;
    if (!flock(contender, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) return -1;
    /* Reuse the original number: the snapshot must still address the old OFD. */
    if (close(fd) || dup2(contender, fd) != fd || flock(snapshot, LOCK_UN) ||
        flock(contender, LOCK_EX | LOCK_NB)) return -1;
    if (lat_aot_v2_internal_fd_snapshot_guest(snapshot) != -1 || errno != EACCES ||
        lat_aot_v2_internal_fd_dup_replace(fd, snapshot, 0, false) != -1 || errno != EACCES)
        return -1;
    if (lat_aot_v2_cache_close_fd(snapshot, true, error, sizeof(error)) ||
        lat_aot_v2_internal_fd_is_protected(snapshot)) return -1;
    if (lat_aot_v2_internal_fd_snapshot_guest(-1) != -1 || errno != EBADF) return -1;
    close(fd); close(contender);
    return unlink(path);
}

static int test_guest_fcntl(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || lat_aot_v2_internal_fd_fcntl(fd, F_GETFD, 0) != FD_CLOEXEC ||
        lat_aot_v2_internal_fd_fcntl(fd, F_SETFD, 0) ||
        lat_aot_v2_internal_fd_fcntl(fd, F_GETFD, 0)) return -1;
    const int commands[] = {F_DUPFD, F_DUPFD_CLOEXEC};
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        int copy = lat_aot_v2_internal_fd_fcntl(fd, commands[i], 32);
        if (copy < 32 || lat_aot_v2_internal_fd_is_protected(copy) ||
            !!(fcntl(copy, F_GETFD) & FD_CLOEXEC) != (commands[i] == F_DUPFD_CLOEXEC))
            return -1;
        close(copy);
        if (lat_aot_v2_internal_fd_fcntl(fd, commands[i], -1) != -1 || errno != EINVAL)
            return -1;
    }
    if (lat_aot_v2_internal_fd_fcntl(-1, F_GETFD, 0) != -1 || errno != EBADF ||
        lat_aot_v2_internal_fd_fcntl(fd, F_SETFL, 0) != -1 || errno != EINVAL) return -1;
    close(fd);
    return 0;
}

static void *hold_registry_lock(void *opaque)
{
    (void)opaque;
    lat_aot_v2_internal_fd_lock();
    struct timespec delay = { .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&delay, NULL);
    lat_aot_v2_internal_fd_unlock();
    return NULL;
}

static int test_atfork_registry(void)
{
    pthread_t holder;
    if (pthread_create(&holder, NULL, hold_registry_lock, NULL)) return -1;
    struct timespec delay = { .tv_nsec = 10 * 1000 * 1000 };
    nanosleep(&delay, NULL);
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        alarm(5);
        _exit(lat_aot_v2_internal_fd_is_protected(999) ? 1 : 0);
    }
    int status;
    int result = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 ? 0 : -1;
    pthread_join(holder, NULL);
    if (result) fprintf(stderr, "registry mutex deadlocked after fork\n");
    return result;
}

static int test_exec_closes_latch(const char *root)
{
    char error[256] = {0};
    int shared = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_SH, false, error, sizeof(error));
    if (shared < 0) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        execl("/bin/true", "true", (char *)NULL);
        _exit(127);
    }
    close(shared);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status)) {
        fprintf(stderr, "CLOEXEC source-latch child failed\n");
        return -1;
    }
    int exclusive = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_EX | LOCK_NB, false, error, sizeof(error));
    if (exclusive < 0) {
        fprintf(stderr, "CLOEXEC source latch stayed locked: %s\n", error);
        return -1;
    }
    close(exclusive);
    return 0;
}

static int test_artifact_latch(const char *root)
{
    char error[256] = {0};
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/artifact", root) >= (int)sizeof(path))
        return -1;
    int artifact = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (artifact < 0 || write(artifact, "x", 1) != 1) return -1;
    if (lat_aot_v2_cache_lock_fd(artifact, LOCK_SH,
                                 error, sizeof(error))) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        int contender = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (contender < 0) _exit(2);
        int result = lat_aot_v2_cache_lock_fd(
            contender, LOCK_EX | LOCK_NB, error, sizeof(error));
        close(contender);
        _exit(result < 0 && errno == EWOULDBLOCK ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status)) {
        fprintf(stderr, "artifact shared lease did not exclude GC\n");
        close(artifact);
        return -1;
    }
    close(artifact);
    int exclusive = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (exclusive < 0 || lat_aot_v2_cache_lock_fd(
            exclusive, LOCK_EX | LOCK_NB, error, sizeof(error))) {
        fprintf(stderr, "artifact lease stayed locked: %s\n", error);
        if (exclusive >= 0) close(exclusive);
        return -1;
    }
    close(exclusive);
    return 0;
}

static int test_unsafe_layout(const char *root)
{
    char error[256] = {0};
    char outside[4096], link[4096];
    if (snprintf(outside, sizeof(outside), "%s/outside", root) >=
            (int)sizeof(outside) ||
        snprintf(link, sizeof(link), "%s/.gc", root) >= (int)sizeof(link)) {
        return -1;
    }
    if (mkdir(outside, 0700) || symlink(outside, link)) return -1;
    int fd = lat_aot_v2_cache_source_lock(
        root, source_hex, LOCK_SH, false, error, sizeof(error));
    int result = fd < 0 ? 0 : -1;
    if (fd >= 0) close(fd);
    unlink(link);
    rmdir(outside);
    if (result) fprintf(stderr, "source latch followed .gc symlink\n");
    return result;
}

static int cleanup(const char *root)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/artifact", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/.gc/source-locks/%s.lock",
             root, source_hex);
    unlink(path);
    snprintf(path, sizeof(path), "%s/.gc/source-locks", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/.gc", root);
    rmdir(path);
    return rmdir(root);
}

static int test_tombstones(const char *root)
{
    char path[4096], directory[4096], marker[4096], error[256];
    snprintf(path, sizeof(path), "%s/artifact", root);
    snprintf(directory, sizeof(directory), "%s/.gc/tombstones", root);
    snprintf(marker, sizeof(marker), "%s/.gc/tombstones/artifact", root);
    if (lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    if (mkdir(directory, 0700)) return -1;
    if (lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    /* Garbage metadata, directories and dangling symlinks all fail closed. */
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0400);
    if (fd < 0 || write(fd, "invalid", 7) != 7) return -1;
    close(fd);
    if (!lat_aot_v2_cache_object_available(path, error, sizeof(error)) || errno != ESTALE)
        return -1;
    if (unlink(marker) || mkdir(marker, 0700)) return -1;
    if (!lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    if (rmdir(marker) || symlink("missing", marker)) return -1;
    if (!lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    if (unlink(marker) || rmdir(directory) || symlink("missing", directory)) return -1;
    if (!lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    if (unlink(directory)) return -1;
    if (lat_aot_v2_cache_object_available(path, error, sizeof(error))) return -1;
    if (!lat_aot_v2_cache_object_available(NULL, error, sizeof(error))) return -1;
    return 0;
}

int main(void)
{
    const char *tmpdir = getenv("TMPDIR");
    char fallback[2048];
    if (!tmpdir || !*tmpdir) {
        const char *home = getenv("HOME");
        if (!home || !*home ||
            snprintf(fallback, sizeof(fallback), "%s/tmp", home) >=
                (int)sizeof(fallback)) {
            fprintf(stderr, "cannot choose temporary directory\n");
            return 1;
        }
        tmpdir = fallback;
    }
    char root[2048];
    if (snprintf(root, sizeof(root), "%s/cache-lifecycle-XXXXXX", tmpdir) >=
        (int)sizeof(root) || !mkdtemp(root)) {
        perror("mkdtemp");
        return 1;
    }
    chmod(root, 0700);
    for (int dup3 = 0; dup3 < 2; dup3++)
        for (int source = 0; source < 2; source++)
            if (test_dup_registration(dup3, source, false, -1, false)) {
                fprintf(stderr, "atomic dup registration failed dup3=%d source=%d\n", dup3, source);
                return 1;
            }
    if (test_dup_registration(false, true, true, -1, false) ||
        test_dup_registration(false, true, false, -1, true)) return 1;
    const int commands[] = {F_GETFD, F_SETFD, F_DUPFD, F_DUPFD_CLOEXEC};
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        if (test_dup_registration(false, true, false, commands[i], false)) return 1;
    int result = test_unsafe_layout(root) || test_source_latch(root) ||
        test_guest_fd_registry(root) || test_atfork_registry() ||
        test_fork_inheritance(root) || test_exec_closes_latch(root) ||
        test_artifact_latch(root) || test_tombstones(root) || test_guest_snapshot(root) ||
        test_guest_fcntl() || test_guest_close();
    if (cleanup(root)) {
        fprintf(stderr, "cannot clean lifecycle test directory %s: %s\n",
                root, strerror(errno));
        return 1;
    }
    if (result) return 1;
    puts("test-cache-lifecycle: PASS");
    return 0;
}
