/* Exercise the complete proc-file fstat transaction, including its fallback. */
#define _GNU_SOURCE
#ifndef HOST_HOOK
#define _FILE_OFFSET_BITS 64
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct Control {
    atomic_int loaded;
    atomic_int armed;
    atomic_int stage;
    atomic_int fd;
    atomic_int replaced;
    atomic_int finish;
    atomic_int source_rebind;
    atomic_int input;
} Control;

static Control *control;

#ifdef HOST_HOOK
#include <dlfcn.h>

static int (*next_fstat64)(int, struct stat64 *);
static ssize_t (*next_readlink)(const char *, char *, size_t);

static void __attribute__((constructor)) setup(void)
{
    const char *name = getenv("LATX_FSTAT_PROVIDER_CONTROL");
    int fd;

    next_fstat64 = dlsym(RTLD_NEXT, "fstat64");
    next_readlink = dlsym(RTLD_NEXT, "readlink");
    if (!name) {
        return;
    }
    fd = open(name, O_RDWR);
    if (fd < 0) {
        return;
    }
    control = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (control == MAP_FAILED) {
        control = NULL;
        return;
    }
    atomic_store(&control->loaded, next_fstat64 && next_readlink ? 1 : -1);
}

static void wait_for_writer(int fd)
{
    atomic_store(&control->fd, fd);
    atomic_store(&control->stage, 1);
    /* A correct implementation blocks the writer until this hook returns. */
    for (int i = 0; !atomic_load(&control->replaced) && i < 750; i++) {
        usleep(1000);
    }
}

int fstat64(int fd, struct stat64 *st)
{
    if (control && !atomic_load(&control->source_rebind) &&
        atomic_load(&control->armed)) {
        char path[64], name[512];
        ssize_t len;

        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        len = next_readlink(path, name, sizeof(name) - 1);
        if (len > 5) {
            name[len] = 0;
            if (!strncmp(name, "/proc/", 6) &&
                !strcmp(name + len - 5, "/task") &&
                atomic_exchange(&control->armed, 0)) {
                wait_for_writer(fd);
            }
        }
    }
    return next_fstat64(fd, st);
}

ssize_t readlink(const char *path, char *buf, size_t size)
{
    ssize_t ret = next_readlink(path, buf, size);
    int saved_errno = errno;

    if (control && atomic_load(&control->source_rebind) &&
        atomic_load(&control->armed)) {
        char expected[64];

        snprintf(expected, sizeof(expected), "/proc/self/fd/%d",
                 atomic_load(&control->input));
        if (ret > 0 && !strcmp(path, expected) &&
            atomic_exchange(&control->armed, 0)) {
            wait_for_writer(atomic_load(&control->input));
        }
    }
    errno = saved_errno;
    return ret;
}
#else
static int source;
static int writer_result;

static void *writer(void *unused)
{
    (void)unused;
    while (!atomic_load(&control->stage)) {
        sched_yield();
    }
    writer_result = dup2(source, atomic_load(&control->fd));
    atomic_store(&control->replaced, 1);
    /* Keep two guest threads alive while checking the task directory. */
    while (!atomic_load(&control->finish)) {
        sched_yield();
    }
    return NULL;
}

int main(int argc, char **argv)
{
    char provider[] = "/tmp/latxopen-task.XXXXXX";
    char ordinary[] = "/tmp/lat-fstat-provider-source.XXXXXX";
    struct stat st = { 0 };
    struct stat initial, task;
    pthread_t thread;
    int fd, input, ret, saved_errno, live, bad, source_rebind, own_task;

    if (argc != 3 || (strcmp(argv[2], "temporary") &&
                      strcmp(argv[2], "source-rebind"))) {
        return 2;
    }
    source_rebind = !strcmp(argv[2], "source-rebind");
    fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        return 3;
    }
    control = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (control == MAP_FAILED) {
        return 4;
    }
    if (atomic_load(&control->loaded) != 1) {
        puts("SKIP: native preload hook is unavailable");
        return 77;
    }
    input = mkstemp(provider);
    source = mkstemp(ordinary);
    if (input < 0 || source < 0 || stat("/proc/self/task", &task)) {
        return 5;
    }
    if (source_rebind) {
        int swap = input;

        input = source;
        source = swap;
    }
    if (fstat(input, &initial)) {
        return 6;
    }
    atomic_store(&control->source_rebind, source_rebind);
    atomic_store(&control->input, input);
    if (pthread_create(&thread, NULL, writer, NULL)) {
        return 7;
    }
    atomic_store(&control->armed, 1);
#ifdef SYS_fstat64
    ret = syscall(SYS_fstat64, input, &st);
#else
    ret = syscall(SYS_fstat, input, &st);
#endif
    saved_errno = errno;
    if (!atomic_load(&control->stage)) {
        fputs("FAIL: provider seam was not reached\n", stderr);
        _exit(8);
    }
    while (!atomic_load(&control->replaced)) {
        sched_yield();
    }
    live = fcntl(atomic_load(&control->fd), F_GETFD);
    own_task = !ret && S_ISDIR(st.st_mode) && st.st_dev == task.st_dev &&
               st.st_ino == task.st_ino && st.st_nlink == 4;
    bad = ret || writer_result < 0 || live < 0;
    if (source_rebind) {
        /* Either source state is valid; the proxy's physical inode is not. */
        bad |= !own_task && (st.st_dev != initial.st_dev ||
                             st.st_ino != initial.st_ino);
    } else {
        bad |= !own_task;
    }
    printf("provider %s: ret=%d errno=%d mode=%o nlink=%lu "
           "writer=%d writer_fd_live=%d bad=%d\n", argv[2], ret,
           ret ? saved_errno : 0, st.st_mode, (unsigned long)st.st_nlink,
           writer_result, live, bad);
    atomic_store(&control->finish, 1);
    pthread_join(thread, NULL);
    if (live >= 0 && atomic_load(&control->fd) != input) {
        close(atomic_load(&control->fd));
    }
    close(input);
    close(source);
    unlink(provider);
    unlink(ordinary);
    return bad;
}
#endif
