#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "guest-fd-table.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t close_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t close_gate_condition = PTHREAD_COND_INITIALIZER;
static bool close_gate_enabled;
static bool close_gate_entered;
static bool close_gate_release;
static int close_gate_fd = -1;

int __real_close(int fd);
int __real_fcntl(int fd, int command, ...);
int __real_pthread_mutex_lock(pthread_mutex_t *mutex);
void *__real_g_try_malloc(size_t size);

static pthread_mutex_t copy_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t copy_gate_condition = PTHREAD_COND_INITIALIZER;
static bool copy_gate_enabled;
static bool copy_gate_entered;
static bool copy_gate_release;
static bool copy_close_blocked;
static _Thread_local bool probe_copy_close;
static _Thread_local int copy_alloc_fail_after = -1;

void *__wrap_g_try_malloc(size_t size)
{
    pthread_mutex_lock(&copy_gate_mutex);
    if (copy_gate_enabled) {
        copy_gate_entered = true;
        pthread_cond_broadcast(&copy_gate_condition);
        while (!copy_gate_release) {
            pthread_cond_wait(&copy_gate_condition, &copy_gate_mutex);
        }
    }
    pthread_mutex_unlock(&copy_gate_mutex);
    if (copy_alloc_fail_after >= 0 && !copy_alloc_fail_after--) {
        return NULL;
    }
    return __real_g_try_malloc(size);
}

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex)
{
    if (probe_copy_close && mutex != &copy_gate_mutex) {
        probe_copy_close = false;
        int result = pthread_mutex_trylock(mutex);
        assert(result == EBUSY);
        assert(!__real_pthread_mutex_lock(&copy_gate_mutex));
        copy_close_blocked = true;
        pthread_cond_broadcast(&copy_gate_condition);
        pthread_mutex_unlock(&copy_gate_mutex);
    }
    return __real_pthread_mutex_lock(mutex);
}

static int copy_fail_after = -1;
static int copy_backends[8];
static size_t copy_backend_count;
static bool copy_track_backends;

int __wrap_fcntl(int fd, int command, ...)
{
    if (command == F_GETFD) {
        return __real_fcntl(fd, command);
    }
    assert(command == F_SETFD || command == F_DUPFD_CLOEXEC);
    va_list arguments;
    va_start(arguments, command);
    int argument = va_arg(arguments, int);
    va_end(arguments);
    if (command == F_DUPFD_CLOEXEC && copy_fail_after >= 0) {
        if (!copy_fail_after--) {
            errno = EMFILE;
            return -1;
        }
    }
    int result = __real_fcntl(fd, command, argument);
    if (command == F_DUPFD_CLOEXEC && copy_track_backends && result >= 0) {
        assert(copy_backend_count < sizeof(copy_backends) /
                                    sizeof(copy_backends[0]));
        copy_backends[copy_backend_count++] = result;
    }
    return result;
}

static void test_copy(void)
{
    GuestFdTable *source = guest_fd_table_new();
    GuestFdTable *shared;
    GuestFdTable *copy;
    char path[4096];
    const char *home = getenv("HOME");
    int writer, duplicate, lowest;
    bool cloexec;

    assert(source);
    assert(home);
    assert(snprintf(path, sizeof(path), "%s/tmp/guest-fd-copy-XXXXXX",
                    home) < (int)sizeof(path));
    writer = mkstemp(path);
    assert(writer >= 0);
    assert(!unlink(path));
    assert(write(writer, "abc", 3) == 3);
    assert(lseek(writer, 0, SEEK_SET) == 0);
    assert(!guest_fd_table_import(source, 7, writer, false));
    copy_track_backends = true;
    copy_backend_count = 0;
    assert(!guest_fd_table_dup_min(source, 7, 23, true, &duplicate));
    copy_track_backends = false;
    assert(copy_backend_count == 1);
    int duplicated_backend = copy_backends[0];
    assert(duplicate == 23);

    /* A shared-table reference must see mutations; a copied table must not. */
    shared = guest_fd_table_ref(source);
    copy_track_backends = true;
    copy_backend_count = 0;
    copy = guest_fd_table_copy(source);
    copy_track_backends = false;
    assert(copy && copy != source && copy_backend_count == 0);
    assert(fcntl(writer, F_GETFD) & FD_CLOEXEC);
    assert(fcntl(duplicated_backend, F_GETFD) & FD_CLOEXEC);
    assert(!guest_fd_table_get_cloexec(copy, 7, &cloexec) && !cloexec);
    assert(!guest_fd_table_get_cloexec(copy, 23, &cloexec) && cloexec);
    assert(!guest_fd_table_set_cloexec(shared, 7, true));
    assert(!guest_fd_table_get_cloexec(source, 7, &cloexec) && cloexec);
    assert(!guest_fd_table_get_cloexec(copy, 7, &cloexec) && !cloexec);
    char byte;
    assert(read(duplicated_backend, &byte, 1) == 1 && byte == 'a');
    assert(lseek(writer, 0, SEEK_CUR) == 1);
    assert(!guest_fd_table_close(shared, 23));
    errno = 0;
    assert(guest_fd_table_get_cloexec(source, 23, &cloexec) == -1 &&
           errno == EBADF);
    assert(!guest_fd_table_get_cloexec(copy, 23, &cloexec) && cloexec);
    assert(!guest_fd_table_close(copy, 7));
    assert(fcntl(writer, F_GETFD) >= 0);
    assert(!guest_fd_table_dup_min(copy, 23, 0, false, &lowest) && lowest == 0);
    guest_fd_table_unref(copy);
    errno = 0;
    assert(fcntl(duplicated_backend, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(writer, F_GETFD) >= 0);

    assert(!guest_fd_table_dup_min(source, 7, 23, true, &duplicate));
    copy_fail_after = 0;
    errno = 0;
    assert(guest_fd_table_dup_min(source, 7, 30, false, &duplicate) == -1 &&
           errno == EMFILE);
    copy_fail_after = 0;
    errno = 0;
    assert(guest_fd_table_dup_to(source, 7, 23, false) == -1 && errno == EMFILE);
    copy_fail_after = -1;
    assert(!guest_fd_table_get_cloexec(source, 23, &cloexec) && cloexec);
    for (int failure = 0; failure < 2; failure++) {
        copy_track_backends = true;
        copy_backend_count = 0;
        copy_alloc_fail_after = failure;
        errno = 0;
        assert(!guest_fd_table_copy(source) && errno == ENOMEM);
        copy_alloc_fail_after = -1;
        copy_track_backends = false;
        assert(copy_backend_count == 0);
        for (size_t i = 0; i < copy_backend_count; i++) {
            errno = 0;
            assert(fcntl(copy_backends[i], F_GETFD) == -1 && errno == EBADF);
        }
        assert(fcntl(writer, F_GETFD) >= 0);
        assert(!guest_fd_table_get_cloexec(source, 7, &cloexec) && cloexec);
        assert(!guest_fd_table_get_cloexec(source, 23, &cloexec) && cloexec);
    }
    guest_fd_table_unref(shared);
    guest_fd_table_unref(source);
    source = guest_fd_table_new();
    assert(source);
    copy = guest_fd_table_copy(source);
    assert(copy && copy != source);
    guest_fd_table_unref(copy);
    guest_fd_table_unref(source);
    errno = 0;
    assert(!guest_fd_table_copy(NULL) && errno == EINVAL);
}

static bool record_lock_is_held(int fd)
{
    pid_t child = fork();
    int status;

    assert(child >= 0);
    if (!child) {
        struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
        if (__real_fcntl(fd, F_SETLK, &lock) == -1 &&
            (errno == EACCES || errno == EAGAIN)) {
            _exit(0);
        }
        _exit(1);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
    return WEXITSTATUS(status) == 0;
}

static void test_copy_preserves_record_locks(void)
{
    GuestFdTable *source = guest_fd_table_new();
    GuestFdTable *copy;
    char path[4096];
    const char *home = getenv("HOME");
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    int fd;

    assert(source && home);
    assert(snprintf(path, sizeof(path), "%s/tmp/guest-fd-lock-XXXXXX",
                    home) < (int)sizeof(path));
    fd = mkstemp(path);
    assert(fd >= 0 && !unlink(path));
    assert(!guest_fd_table_import(source, 7, fd, false));
    assert(!__real_fcntl(fd, F_SETLK, &lock));
    assert(record_lock_is_held(fd));
    GuestFdHandle *handle = guest_fd_table_acquire(source, 7);
    assert(handle && guest_fd_handle_host_fd(handle) == fd);
    guest_fd_handle_release(handle);
    assert(record_lock_is_held(fd));
    copy_alloc_fail_after = 0;
    assert(!guest_fd_table_acquire(source, 7) && errno == ENOMEM);
    copy_alloc_fail_after = -1;
    assert(record_lock_is_held(fd));
    copy = guest_fd_table_copy(source);
    assert(copy && record_lock_is_held(fd));
    guest_fd_table_unref(copy);
    assert(record_lock_is_held(fd));
    int duplicate;
    assert(!guest_fd_table_dup_min(source, 7, 23, false, &duplicate));
    for (int failure = 0; failure < 2; failure++) {
        copy_alloc_fail_after = failure;
        errno = 0;
        assert(!guest_fd_table_copy(source) && errno == ENOMEM);
        copy_alloc_fail_after = -1;
        assert(record_lock_is_held(fd));
    }
    guest_fd_table_unref(source);
}

int __wrap_close(int fd)
{
    pthread_mutex_lock(&close_gate_mutex);
    if (close_gate_enabled && fd == close_gate_fd) {
        close_gate_entered = true;
        pthread_cond_broadcast(&close_gate_condition);
        while (!close_gate_release) {
            pthread_cond_wait(&close_gate_condition, &close_gate_mutex);
        }
    }
    pthread_mutex_unlock(&close_gate_mutex);
    return __real_close(fd);
}

typedef struct CloseJob {
    GuestFdTable *table;
    int guest_fd;
    int result;
} CloseJob;

typedef struct ForkJob {
    GuestFdTable *table;
    atomic_bool done;
    int result;
} ForkJob;

typedef struct CopyJob {
    GuestFdTable *table;
    GuestFdTable *copy;
} CopyJob;

static void *run_copy(void *opaque)
{
    CopyJob *job = opaque;

    job->copy = guest_fd_table_copy(job->table);
    return NULL;
}

static void *run_copy_close(void *opaque)
{
    CloseJob *job = opaque;

    probe_copy_close = true;
    job->result = guest_fd_table_close(job->table, job->guest_fd);
    return NULL;
}

static void test_copy_close_serialization(void)
{
    GuestFdTable *source = guest_fd_table_new();
    CopyJob copy = { .table = source };
    CloseJob closer = { .table = source, .guest_fd = 17 };
    pthread_t copy_thread, close_thread;
    int pipefd[2];
    bool cloexec;
    char byte;

    assert(source && !pipe2(pipefd, O_CLOEXEC));
    assert(!guest_fd_table_import(source, 17, pipefd[1], false));
    pthread_mutex_lock(&copy_gate_mutex);
    copy_gate_enabled = true;
    copy_gate_entered = copy_gate_release = copy_close_blocked = false;
    pthread_mutex_unlock(&copy_gate_mutex);
    assert(!pthread_create(&copy_thread, NULL, run_copy, &copy));
    pthread_mutex_lock(&copy_gate_mutex);
    while (!copy_gate_entered) {
        pthread_cond_wait(&copy_gate_condition, &copy_gate_mutex);
    }
    pthread_mutex_unlock(&copy_gate_mutex);
    assert(!pthread_create(&close_thread, NULL, run_copy_close, &closer));
    pthread_mutex_lock(&copy_gate_mutex);
    while (!copy_close_blocked) {
        pthread_cond_wait(&copy_gate_condition, &copy_gate_mutex);
    }
    copy_gate_release = true;
    pthread_cond_broadcast(&copy_gate_condition);
    pthread_mutex_unlock(&copy_gate_mutex);
    assert(!pthread_join(copy_thread, NULL));
    assert(!pthread_join(close_thread, NULL));
    assert(copy.copy && !closer.result);
    pthread_mutex_lock(&copy_gate_mutex);
    copy_gate_enabled = false;
    pthread_mutex_unlock(&copy_gate_mutex);
    errno = 0;
    assert(guest_fd_table_get_cloexec(source, 17, &cloexec) == -1 &&
           errno == EBADF);
    assert(!guest_fd_table_get_cloexec(copy.copy, 17, &cloexec) && !cloexec);
    /* Source close cannot release the copied pipe writer. */
    struct pollfd reader = { .fd = pipefd[0], .events = POLLIN };
    assert(poll(&reader, 1, 0) == 0);
    assert(!guest_fd_table_close(copy.copy, 17));
    assert(poll(&reader, 1, 0) == 1 && (reader.revents & POLLHUP));
    assert(read(pipefd[0], &byte, 1) == 0);
    assert(!close(pipefd[0]));
    guest_fd_table_unref(copy.copy);
    guest_fd_table_unref(source);
}

static void *run_close(void *opaque)
{
    CloseJob *job = opaque;

    job->result = guest_fd_table_close(job->table, job->guest_fd);
    return NULL;
}

static void test_handles(void)
{
    GuestFdTable *table = guest_fd_table_new();
    int original[2], replacement[2];
    assert(table && !pipe2(original, O_CLOEXEC) && !pipe2(replacement, O_CLOEXEC));
    assert(!guest_fd_table_import(table, 700, original[1], false));
    assert(!guest_fd_table_import(table, 701, replacement[1], true));
    errno = 0;
    assert(!guest_fd_table_acquire(NULL, 700) && errno == EINVAL);
    assert(!guest_fd_table_acquire(table, -1) && errno == EBADF);
    assert(!guest_fd_table_acquire(table, original[0]) && errno == EBADF);
    assert(guest_fd_handle_host_fd(NULL) == -1 && errno == EBADF);
    copy_alloc_fail_after = 0;
    assert(!guest_fd_table_acquire(table, 700) && errno == ENOMEM);
    copy_alloc_fail_after = -1;
    copy_fail_after = 0;
    GuestFdHandle *old = guest_fd_table_acquire(table, 700);
    assert(old && guest_fd_handle_host_fd(old) == original[1]);
    copy_fail_after = -1;
    assert(guest_fd_table_dup_to(table, 701, 700, false) == 700);
    GuestFdHandle *fresh = guest_fd_table_acquire(table, 700);
    assert(fresh && guest_fd_handle_host_fd(fresh) != guest_fd_handle_host_fd(old));
    CloseJob closer = { .table = table, .guest_fd = 700 };
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, run_close, &closer));
    assert(!pthread_join(thread, NULL) && !closer.result);
    guest_fd_table_unref(table);
    assert(write(guest_fd_handle_host_fd(old), "a", 1) == 1);
    assert(write(guest_fd_handle_host_fd(fresh), "b", 1) == 1);
    char byte;
    assert(read(original[0], &byte, 1) == 1 && byte == 'a');
    assert(read(replacement[0], &byte, 1) == 1 && byte == 'b');
    errno = E2BIG;
    guest_fd_handle_release(old);
    assert(errno == E2BIG && read(original[0], &byte, 1) == 0);
    guest_fd_handle_release(fresh);
    assert(errno == E2BIG && read(replacement[0], &byte, 1) == 0);
    guest_fd_handle_release(NULL);
    assert(errno == E2BIG);
    assert(!close(original[0]) && !close(replacement[0]));
}

static void *run_fork_start(void *opaque)
{
    ForkJob *job = opaque;

    job->result = guest_fd_table_fork_start(job->table);
    if (!job->result) {
        guest_fd_table_fork_end(job->table);
    }
    atomic_store_explicit(&job->done, true, memory_order_release);
    return NULL;
}

int main(void)
{
    test_copy();
    test_copy_preserves_record_locks();
    test_copy_close_serialization();
    test_handles();
    GuestFdTable *table = guest_fd_table_new();
    GuestFdTable *thread_ref;
    int pipefd[2];
    int guest_read;
    int guest_write;
    int duplicate;
    bool cloexec;
    char byte;
    pid_t child;
    int status;

    assert(table);
    thread_ref = guest_fd_table_ref(table);
    assert(thread_ref == table);
    guest_fd_table_unref(thread_ref);

    assert(!pipe2(pipefd, O_CLOEXEC));
    assert(!guest_fd_table_adopt(table, pipefd[0], false, &guest_read));
    assert(!guest_fd_table_adopt(table, pipefd[1], false, &guest_write));
    assert(guest_read == 0);
    assert(guest_write == 1);

    assert(!guest_fd_table_get_cloexec(table, guest_read, &cloexec));
    assert(!cloexec);
    assert(!guest_fd_table_set_cloexec(table, guest_read, true));
    assert(!guest_fd_table_get_cloexec(table, guest_read, &cloexec));
    assert(cloexec);
    assert(!guest_fd_table_set_cloexec(table, guest_read, false));

    assert(write(pipefd[1], "x", 1) == 1);
    assert(read(pipefd[0], &byte, 1) == 1 && byte == 'x');

    assert(!guest_fd_table_dup_min(table, guest_write, 5, true,
                                   &duplicate));
    assert(duplicate == 5);
    assert(!guest_fd_table_get_cloexec(table, duplicate, &cloexec));
    assert(cloexec);
    assert(guest_fd_table_dup_to(table, guest_write, duplicate, false) ==
           duplicate);

    assert(guest_fd_table_close(table, guest_write) == 0);
    errno = 0;
    assert(fcntl(pipefd[1], F_GETFD) == -1 && errno == EBADF);

    assert(!guest_fd_table_fork_start(table));
    child = fork();
    assert(child >= 0);
    if (!child) {
        guest_fd_table_fork_end(table);
        if (guest_fd_table_close(table, duplicate)) {
            _exit(1);
        }
        _exit(0);
    }
    guest_fd_table_fork_end(table);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    assert(guest_fd_table_close(table, duplicate) == 0);
    assert(read(pipefd[0], &byte, 1) == 0);
    assert(guest_fd_table_close(table, guest_read) == 0);
    errno = 0;
    assert(fcntl(pipefd[0], F_GETFD) == -1 && errno == EBADF);
    errno = 0;
    assert(guest_fd_table_close(table, guest_read) == -1 && errno == EBADF);
    guest_fd_table_unref(table);

    {
        GuestFdTable *gate_table = guest_fd_table_new();
        CloseJob close_job = { .table = gate_table };
        ForkJob fork_job;
        pthread_t close_thread;
        pthread_t fork_thread;
        struct timespec delay = { .tv_nsec = 50000000 };
        int gate_pipe[2];

        assert(gate_table);
        assert(!pipe2(gate_pipe, O_CLOEXEC));
        assert(!guest_fd_table_adopt(gate_table, gate_pipe[0], false,
                                     &guest_read));
        assert(!guest_fd_table_adopt(gate_table, gate_pipe[1], false,
                                     &close_job.guest_fd));

        pthread_mutex_lock(&close_gate_mutex);
        close_gate_fd = gate_pipe[1];
        close_gate_enabled = true;
        close_gate_entered = false;
        close_gate_release = false;
        pthread_mutex_unlock(&close_gate_mutex);

        assert(!pthread_create(&close_thread, NULL, run_close, &close_job));
        pthread_mutex_lock(&close_gate_mutex);
        while (!close_gate_entered) {
            pthread_cond_wait(&close_gate_condition, &close_gate_mutex);
        }
        pthread_mutex_unlock(&close_gate_mutex);

        memset(&fork_job, 0, sizeof(fork_job));
        fork_job.table = gate_table;
        atomic_init(&fork_job.done, false);
        assert(!pthread_create(&fork_thread, NULL, run_fork_start, &fork_job));
        nanosleep(&delay, NULL);
        assert(!atomic_load_explicit(&fork_job.done, memory_order_acquire));

        pthread_mutex_lock(&close_gate_mutex);
        close_gate_release = true;
        pthread_cond_broadcast(&close_gate_condition);
        pthread_mutex_unlock(&close_gate_mutex);

        assert(!pthread_join(close_thread, NULL));
        assert(!close_job.result);
        assert(!pthread_join(fork_thread, NULL));
        assert(!fork_job.result);
        pthread_mutex_lock(&close_gate_mutex);
        close_gate_enabled = false;
        close_gate_fd = -1;
        pthread_mutex_unlock(&close_gate_mutex);

        assert(guest_fd_table_close(gate_table, guest_read) == 0);
        guest_fd_table_unref(gate_table);
    }

    puts("test-guest-fd-table: PASS");
    return 0;
}
