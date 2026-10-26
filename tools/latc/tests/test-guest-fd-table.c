#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "guest-fd-table.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
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

static void *run_close(void *opaque)
{
    CloseJob *job = opaque;

    job->result = guest_fd_table_close(job->table, job->guest_fd);
    return NULL;
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
