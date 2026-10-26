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
    int result = test_unsafe_layout(root) || test_source_latch(root) ||
        test_guest_fd_registry(root) || test_atfork_registry() ||
        test_fork_inheritance(root) || test_exec_closes_latch(root) ||
        test_artifact_latch(root);
    if (cleanup(root)) {
        fprintf(stderr, "cannot clean lifecycle test directory %s: %s\n",
                root, strerror(errno));
        return 1;
    }
    if (result) return 1;
    puts("test-cache-lifecycle: PASS");
    return 0;
}
