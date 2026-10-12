/* Verify stat-family pathname snapshots against a concurrent guest writer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef SYS_newfstatat
#define FSTATAT_NR SYS_newfstatat
typedef struct stat PathStat;
#else
#define FSTATAT_NR SYS_fstatat64
typedef struct stat64 PathStat;
#endif

static atomic_int stop_writer;
static _Atomic unsigned char *terminator;

static void *change_terminator(void *unused)
{
    (void)unused;
    while (!atomic_load_explicit(&stop_writer, memory_order_relaxed)) {
        atomic_store_explicit(terminator, 'x', memory_order_relaxed);
        atomic_store_explicit(terminator, 0, memory_order_relaxed);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    struct rlimit no_core = { 0, 0 };
    size_t guard_size = 16 * getauxval(AT_PAGESZ);
    pthread_t writer;
    void *mapping;
    uintptr_t guard;
    char *path;
    unsigned int ok = 0, fault = 0, unexpected = 0;
    bool use_statx = argc == 2 && !strcmp(argv[1], "statx");
    int failed = 0;

    if (!guard_size || setrlimit(RLIMIT_CORE, &no_core)) {
        return 1;
    }
    /* Align the boundary for both 4 KiB guests and larger host pages. */
    mapping = mmap(NULL, 3 * guard_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return 1;
    }
    guard = ((uintptr_t)mapping + guard_size - 1) & ~(guard_size - 1);
    guard += guard_size;
    if (mprotect((void *)guard, guard_size, PROT_NONE)) {
        return 1;
    }
    path = (char *)guard - 2;
    path[0] = '.';
    terminator = (_Atomic unsigned char *)(path + 1);
    atomic_init(terminator, 0);
    if (pthread_create(&writer, NULL, change_terminator, NULL)) {
        return 1;
    }
    printf("pathname snapshot: %s started\n", use_statx ? "statx" : "fstatat");
    fflush(stdout);
    for (unsigned int i = 0; i < 300000; i++) {
        PathStat st;
        struct statx stx;
        long ret;

        ret = use_statx ? syscall(SYS_statx, AT_FDCWD, path, 0,
                                  STATX_BASIC_STATS, &stx) :
                         syscall(FSTATAT_NR, AT_FDCWD, path, &st, 0);
        if (ret == 0) {
            ok++;
        } else if (errno == EFAULT) {
            fault++;
        } else {
            if (!unexpected++) {
                fprintf(stderr, "unexpected syscall result: %ld errno=%d\n",
                        ret, errno);
            }
            failed = 1;
        }
    }
    atomic_store_explicit(&stop_writer, 1, memory_order_relaxed);
    pthread_join(writer, NULL);
    munmap(mapping, 3 * guard_size);
    printf("pathname snapshot: success=%u EFAULT=%u unexpected=%u\n",
           ok, fault, unexpected);
    return failed || !ok || !fault;
}
