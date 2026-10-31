#define _GNU_SOURCE
#include "../latcd/worker-seccomp.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void *thread_main(void *arg) { return arg; }

int main(int argc, char **argv)
{
    int fd = latcd_worker_seccomp_fd();
    assert(fd >= 0);
    if (argc > 2 && !strcmp(argv[1], "--bwrap")) {
        char number[32];
        assert(snprintf(number, sizeof(number), "%d", fd) > 0);
        assert(!fcntl(fd, F_SETFD, 0));
        char **args = calloc(argc + 2, sizeof(*args));
        assert(args);
        args[0] = argv[2]; args[1] = "--seccomp"; args[2] = number;
        for (int i = 3; i < argc; i++) args[i] = argv[i];
        execvp(args[0], args);
        return 127;
    }
    assert((fcntl(fd, F_GET_SEALS) & (F_SEAL_WRITE | F_SEAL_SEAL)) ==
           (F_SEAL_WRITE | F_SEAL_SEAL));
    struct stat st;
    assert(!fstat(fd, &st) && st.st_size > 0 &&
           st.st_size % sizeof(struct sock_filter) == 0);
    struct sock_filter *filter = malloc(st.st_size);
    assert(filter && read(fd, filter, st.st_size) == st.st_size);
    struct sock_fprog program = { .len = st.st_size / sizeof(*filter), .filter = filter };
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program));
        errno = 0; assert(syscall(SYS_clone3, NULL, 0) == -1 && errno == ENOSYS);
        errno = 0; assert(socket(AF_UNIX, SOCK_STREAM, 0) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_unshare, CLONE_NEWUSER) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_mount, NULL, NULL, NULL, 0, NULL) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_io_uring_setup, 0, NULL) == -1 && errno == ENOSYS);
        errno = 0; assert(syscall(SYS_open_by_handle_at, -1, NULL, 0) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_pidfd_getfd, -1, -1, 0) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_open_tree, -1, NULL, 0) == -1 && errno == EPERM);
        errno = 0; assert(syscall(SYS_ptrace, 0, 0, NULL, NULL) == -1 && errno == EPERM);
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, thread_main, (void *)1));
        void *result = NULL;
        assert(!pthread_join(thread, &result) && result == (void *)1);
        pid_t nested = fork();
        assert(nested >= 0);
        if (!nested) _exit(0);
        int status;
        assert(waitpid(nested, &status, 0) == nested && WIFEXITED(status) && !WEXITSTATUS(status));
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    free(filter);
    close(fd);
    return 0;
}
