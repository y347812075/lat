#define _GNU_SOURCE

#include "x86-linux-user.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

enum {
    ENV_RAX = 344,
    ENV_RDX = 360,
    ENV_RSI = 392,
    ENV_RDI = 400,
    ENV_R10 = 424,
};

typedef struct TargetSigactionX86_64 {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
} TargetSigactionX86_64;

typedef struct TargetSysinfoX86_64 {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t align_pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    uint32_t tail_pad;
} TargetSysinfoX86_64;

static uint64_t *reg(unsigned char *env, size_t offset)
{
    return (void *)(env + offset);
}

static uint64_t run_syscall(unsigned char *env, uint64_t number,
                            uint64_t arg1, uint64_t arg2, uint64_t arg3,
                            uint64_t arg4)
{
    memset(env, 0, 1024);
    *reg(env, ENV_RAX) = number;
    *reg(env, ENV_RDI) = arg1;
    *reg(env, ENV_RSI) = arg2;
    *reg(env, ENV_RDX) = arg3;
    *reg(env, ENV_R10) = arg4;
    lat_x86_linux_user_syscall(env);
    return *reg(env, ENV_RAX);
}

int main(void)
{
    unsigned char env[1024] = {0};
    long page_size = sysconf(_SC_PAGESIZE);
    void *mapping = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    *reg(env, ENV_RAX) = 11;
    *reg(env, ENV_RDI) = (uintptr_t)mapping;
    *reg(env, ENV_RSI) = (uint64_t)page_size;
    lat_x86_linux_user_syscall(env);
    if (*reg(env, ENV_RAX) != 0) {
        fprintf(stderr, "x86 munmap returned %lld\n",
                (long long)*reg(env, ENV_RAX));
        return 1;
    }
    errno = 0;
    if (mprotect(mapping, (size_t)page_size, PROT_READ) == 0 ||
        errno != ENOMEM) {
        fprintf(stderr, "x86 munmap left the mapping present\n");
        return 1;
    }

    FILE *file = tmpfile();
    if (!file || fputs("abcd", file) == EOF || fflush(file)) {
        perror("tmpfile");
        return 1;
    }
    if (run_syscall(env, 8, (uint64_t)fileno(file), 2, SEEK_SET, 0) != 2) {
        fprintf(stderr, "x86 lseek failed\n");
        return 1;
    }
    fclose(file);

    TargetSigactionX86_64 action = {
        .handler = 0x12345678,
        .flags = 0x04000000,
        .restorer = 0x87654321,
        .mask = 0x55,
    };
    TargetSigactionX86_64 old_action = {0};
    if (run_syscall(env, 13, SIGUSR1, (uintptr_t)&action, 0, 8) != 0 ||
        run_syscall(env, 13, SIGUSR1, 0, (uintptr_t)&old_action, 8) != 0 ||
        memcmp(&action, &old_action, sizeof(action))) {
        fprintf(stderr, "x86 rt_sigaction failed\n");
        return 1;
    }

    TargetSysinfoX86_64 info = {0};
    if (run_syscall(env, 99, (uintptr_t)&info, 0, 0, 0) != 0 ||
        info.mem_unit == 0 || info.procs == 0) {
        fprintf(stderr, "x86 sysinfo failed\n");
        return 1;
    }
    struct rusage usage = {0};
    if (run_syscall(env, 98, RUSAGE_SELF, (uintptr_t)&usage, 0, 0) != 0 ||
        usage.ru_utime.tv_sec < 0 || usage.ru_stime.tv_sec < 0) {
        fprintf(stderr, "x86 getrusage failed\n");
        return 1;
    }
    struct tms target_tms = {0};
    if ((int64_t)run_syscall(env, 100, (uintptr_t)&target_tms, 0, 0, 0) < 0) {
        fprintf(stderr, "x86 times failed\n");
        return 1;
    }
    if (run_syscall(env, 102, 0, 0, 0, 0) != getuid() ||
        run_syscall(env, 104, 0, 0, 0, 0) != getgid() ||
        run_syscall(env, 107, 0, 0, 0, 0) != geteuid() ||
        run_syscall(env, 108, 0, 0, 0, 0) != getegid() ||
        run_syscall(env, 39, 0, 0, 0, 0) != (uint64_t)getpid() ||
        run_syscall(env, 110, 0, 0, 0, 0) != (uint64_t)getppid()) {
        fprintf(stderr, "x86 identity syscall failed\n");
        return 1;
    }

    int64_t target_time = 0;
    time_t before = time(NULL);
    uint64_t returned_time = run_syscall(
        env, 201, (uintptr_t)&target_time, 0, 0, 0);
    time_t after = time(NULL);
    if (returned_time < (uint64_t)before || returned_time > (uint64_t)after ||
        target_time != (int64_t)returned_time) {
        fprintf(stderr, "x86 time failed\n");
        return 1;
    }
    uint32_t futex_word = 0;
    if (run_syscall(env, 202, (uintptr_t)&futex_word, 1, 1, 0) != 0) {
        fprintf(stderr, "x86 futex wake failed\n");
        return 1;
    }

    char path[] = "/tmp/latc-unlink-test.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    if (run_syscall(env, 87, (uintptr_t)path, 0, 0, 0) != 0 ||
        access(path, F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "x86 unlink failed\n");
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd)) {
        perror("pipe");
        return 1;
    }
    uint64_t ioctl_result = run_syscall(
        env, 16, (uint64_t)pipefd[0], 0x5401, 0, 0);
    close(pipefd[0]);
    close(pipefd[1]);
    if (ioctl_result != (uint64_t)(int64_t)-ENOTTY) {
        fprintf(stderr, "x86 ioctl errno conversion failed\n");
        return 1;
    }

    file = tmpfile();
    if (!file || run_syscall(env, 72, (uint64_t)fileno(file), F_SETFD,
                             FD_CLOEXEC, 0) != 0 ||
        fcntl(fileno(file), F_GETFD) != FD_CLOEXEC) {
        fprintf(stderr, "x86 fcntl failed\n");
        return 1;
    }
    fclose(file);

    struct timespec target_timespec = {0};
    if (run_syscall(env, 228, CLOCK_PROCESS_CPUTIME_ID,
                    (uintptr_t)&target_timespec, 0, 0) != 0 ||
        target_timespec.tv_nsec < 0 || target_timespec.tv_nsec >= 1000000000) {
        fprintf(stderr, "x86 clock_gettime failed\n");
        return 1;
    }

    char old_path[] = "/tmp/latc-rename-old.XXXXXX";
    char new_path[] = "/tmp/latc-rename-new.XXXXXX";
    fd = mkstemp(old_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    int new_fd = mkstemp(new_path);
    if (new_fd < 0) {
        unlink(old_path);
        perror("mkstemp");
        return 1;
    }
    close(new_fd);
    unlink(new_path);
    if (run_syscall(env, 82, (uintptr_t)old_path,
                    (uintptr_t)new_path, 0, 0) != 0 ||
        access(old_path, F_OK) == 0 || access(new_path, F_OK) != 0) {
        fprintf(stderr, "x86 rename failed\n");
        unlink(old_path);
        unlink(new_path);
        return 1;
    }
    unlink(new_path);
    puts("test-x86-linux-user: PASS");
    return 0;
}
