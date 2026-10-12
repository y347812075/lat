/*
 * Both names are valid and the entire buffer stays mapped.  A snapshot
 * must not invent EFAULT when a writer moves the terminator between them.
 * The proc-fd chroot forces the pathname-dependent identity fallback.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static atomic_int stop;
static char mapped_path[4096];
static _Atomic char *terminator;
static void *writer(void *unused)
{
    (void)unused;
    while (!atomic_load(&stop)) {
        atomic_store(terminator, '\0');
        atomic_store(terminator, '/');
    }
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    struct stat st;
    struct statx stx;
    struct rlimit no_core = { 0, 0 };
    char name[64];
    char *pathname = mapped_path;
    void *mapping = MAP_FAILED;
    size_t guard_size = 16 * getauxval(AT_PAGESZ);
    unsigned ok = 0, faults = 0, unexpected = 0;
    int extended = argc > 1 && !strcmp(argv[1], "statx");
    int guarded = argc > 2 && !strcmp(argv[2], "guard");
    int root = open("/proc", O_PATH | O_DIRECTORY);
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    int pin = open("/proc/self/task", O_PATH | O_DIRECTORY);
    int length;

    if (root < 0 || dir < 0 || pin < 0 || !guard_size ||
        setrlimit(RLIMIT_CORE, &no_core) ||
        chroot("/proc/self/fd") || chdir("/")) {
        return 2;
    }
    length = snprintf(name, sizeof(name), "%d/self/task", root);
    if (guarded) {
        uintptr_t guard;

        mapping = mmap(NULL, 3 * guard_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            return 2;
        }
        guard = ((uintptr_t)mapping + guard_size - 1) & ~(guard_size - 1);
        guard += guard_size;
        if (mprotect((void *)guard, guard_size, PROT_NONE)) {
            return 2;
        }
        pathname = (char *)guard - length - 1;
    }
    memcpy(pathname, name, length);
    pathname[length] = '/';
    if (!guarded) {
        pathname[length + 1] = '.';
        pathname[length + 2] = '\0';
    }
    terminator = (_Atomic char *)&pathname[length];
    if (pthread_create(&thread, NULL, writer, NULL)) {
        return 3;
    }
    for (int i = 0; i < 300000; i++) {
        int ret;
        if (extended) {
            ret = syscall(SYS_statx, dir, pathname, 0, STATX_BASIC_STATS, &stx);
        } else {
#ifdef SYS_newfstatat
            ret = syscall(SYS_newfstatat, dir, pathname, &st, 0);
#elif defined(SYS_fstatat64)
            ret = syscall(SYS_fstatat64, dir, pathname, &st, 0);
#else
            ret = fstatat(dir, pathname, &st, 0);
#endif
        }
        if (!ret) {
            ok++;
        } else if (errno == EFAULT) {
            faults++;
        } else {
            unexpected++;
        }
    }
    atomic_store(&stop, 1);
    pthread_join(thread, NULL);
    if (mapping != MAP_FAILED) {
        munmap(mapping, 3 * guard_size);
    }
    printf("%s pathname %s success=%u EFAULT=%u unexpected=%u\n",
           guarded ? "guarded" : "mapped", extended ? "statx" : "fstatat",
           ok, faults, unexpected);
    return !ok || unexpected || (guarded ? !faults : faults != 0);
}
