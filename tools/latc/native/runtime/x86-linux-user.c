#define _GNU_SOURCE

#include "x86-linux-user.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Kept structurally aligned with linux-user/syscall.c's x86-64 cases. */
enum {
    ENV_RAX = 344,
    ENV_RCX = 352,
    ENV_RDX = 360,
    ENV_RSI = 392,
    ENV_RDI = 400,
    ENV_R8 = 408,
    ENV_R9 = 416,
    ENV_R10 = 424,
    ENV_FS_BASE = 632,
    ENV_GS_BASE = 656,
};

typedef struct TargetRlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
} TargetRlimit64;

typedef struct HostRlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
} HostRlimit64;

typedef struct TargetStatX86_64 {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t pad0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    uint64_t st_atime_sec;
    uint64_t st_atime_nsec;
    uint64_t st_mtime_sec;
    uint64_t st_mtime_nsec;
    uint64_t st_ctime_sec;
    uint64_t st_ctime_nsec;
    int64_t unused[3];
} TargetStatX86_64;

static unsigned char *guest_brk_base;
static unsigned char *guest_brk_current;
static size_t guest_brk_capacity;
static uint64_t guest_clear_tid;

static uint64_t *reg(unsigned char *env, size_t offset)
{
    return (void *)(env + offset);
}

static uint64_t target_errno(long result)
{
    return result < 0 ? (uint64_t)-(int64_t)errno : (uint64_t)result;
}

static int target_to_host_resource(int code)
{
    switch (code) {
    case 0: return RLIMIT_CPU;
    case 1: return RLIMIT_FSIZE;
    case 2: return RLIMIT_DATA;
    case 3: return RLIMIT_STACK;
    case 4: return RLIMIT_CORE;
    case 5: return RLIMIT_RSS;
    case 6: return RLIMIT_NPROC;
    case 7: return RLIMIT_NOFILE;
    case 8: return RLIMIT_MEMLOCK;
    case 9: return RLIMIT_AS;
    case 10: return RLIMIT_LOCKS;
    case 11: return RLIMIT_SIGPENDING;
    case 12: return RLIMIT_MSGQUEUE;
    case 13: return RLIMIT_NICE;
    case 14: return RLIMIT_RTPRIO;
    default: return code;
    }
}

static void host_to_target_stat(TargetStatX86_64 *target,
                                const struct stat *host)
{
    memset(target, 0, sizeof(*target));
    target->st_dev = host->st_dev;
    target->st_ino = host->st_ino;
    target->st_nlink = host->st_nlink;
    target->st_mode = host->st_mode;
    target->st_uid = host->st_uid;
    target->st_gid = host->st_gid;
    target->st_rdev = host->st_rdev;
    target->st_size = host->st_size;
    target->st_blksize = host->st_blksize;
    target->st_blocks = host->st_blocks;
    target->st_atime_sec = host->st_atim.tv_sec;
    target->st_atime_nsec = host->st_atim.tv_nsec;
    target->st_mtime_sec = host->st_mtim.tv_sec;
    target->st_mtime_nsec = host->st_mtim.tv_nsec;
    target->st_ctime_sec = host->st_ctim.tv_sec;
    target->st_ctime_nsec = host->st_ctim.tv_nsec;
}

static long guest_readlinkat(int dirfd, const char *path, void *buffer,
                             size_t size)
{
    if (!strcmp(path, "/proc/self/exe")) {
        static const char guest_exe[] = "/latc-guest";
        size_t length = sizeof(guest_exe) - 1;
        if (length > size) length = size;
        memcpy(buffer, guest_exe, length);
        return (long)length;
    }
    return readlinkat(dirfd, path, buffer, size);
}

static uint64_t guest_brk(uint64_t requested)
{
    if (!guest_brk_base) {
        guest_brk_capacity = 16 * 1024 * 1024;
        guest_brk_base = mmap(NULL, guest_brk_capacity, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (guest_brk_base == MAP_FAILED) {
            guest_brk_base = NULL;
            guest_brk_capacity = 0;
            return 0;
        }
        guest_brk_current = guest_brk_base;
    }
    if (!requested) return (uint64_t)(uintptr_t)guest_brk_current;
    if (requested < (uint64_t)(uintptr_t)guest_brk_base ||
        requested > (uint64_t)(uintptr_t)guest_brk_base + guest_brk_capacity) {
        return (uint64_t)(uintptr_t)guest_brk_current;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t end = (requested + (uint64_t)page_size - 1) &
                    ~((uint64_t)page_size - 1);
    if (end > (uintptr_t)guest_brk_base &&
        mprotect(guest_brk_base, end - (uintptr_t)guest_brk_base,
                 PROT_READ | PROT_WRITE)) {
        return (uint64_t)(uintptr_t)guest_brk_current;
    }
    guest_brk_current = (void *)(uintptr_t)requested;
    return requested;
}

void lat_x86_linux_user_syscall(unsigned char *env)
{
    uint64_t number = *reg(env, ENV_RAX);
    uint64_t arg1 = *reg(env, ENV_RDI);
    uint64_t arg2 = *reg(env, ENV_RSI);
    uint64_t arg3 = *reg(env, ENV_RDX);
    uint64_t arg4 = *reg(env, ENV_R10);
    uint64_t arg5 = *reg(env, ENV_R8);
    uint64_t arg6 = *reg(env, ENV_R9);
    long result;

    switch (number) {
    case 0:
        result = read((int)arg1, (void *)(uintptr_t)arg2, (size_t)arg3);
        break;
    case 1:
        result = write((int)arg1, (const void *)(uintptr_t)arg2, (size_t)arg3);
        break;
    case 3:
        result = close((int)arg1);
        break;
    case 5: {
        struct stat host;
        result = fstat((int)arg1, &host);
        if (result >= 0) {
            host_to_target_stat((void *)(uintptr_t)arg2, &host);
        }
        break;
    }
    case 9: {
        void *mapped = mmap((void *)(uintptr_t)arg1, (size_t)arg2, (int)arg3,
                            (int)arg4, (int)arg5, (off_t)arg6);
        *reg(env, ENV_RAX) = mapped == MAP_FAILED ?
            target_errno(-1) : (uint64_t)(uintptr_t)mapped;
        return;
    }
    case 10:
        result = mprotect((void *)(uintptr_t)arg1, (size_t)arg2, (int)arg3);
        break;
    case 11:
        result = munmap((void *)(uintptr_t)arg1, (size_t)arg2);
        break;
    case 12:
        *reg(env, ENV_RAX) = guest_brk(arg1);
        return;
    case 60:
        _exit((int)arg1);
    case 89:
        result = guest_readlinkat(AT_FDCWD,
                                  (const void *)(uintptr_t)arg1,
                                  (void *)(uintptr_t)arg2, (size_t)arg3);
        break;
    case 158:
        switch ((uint32_t)arg1) {
        case 0x1001: *reg(env, ENV_GS_BASE) = arg2; result = 0; break;
        case 0x1002: *reg(env, ENV_FS_BASE) = arg2; result = 0; break;
        case 0x1003: *(uint64_t *)(uintptr_t)arg2 = *reg(env, ENV_FS_BASE);
                     result = 0; break;
        case 0x1004: *(uint64_t *)(uintptr_t)arg2 = *reg(env, ENV_GS_BASE);
                     result = 0; break;
        default: errno = EINVAL; result = -1; break;
        }
        break;
    case 218:
        guest_clear_tid = arg1;
        result = syscall(SYS_gettid);
        break;
    case 231:
        _exit((int)arg1);
    case 257:
        result = openat((int)arg1, (const char *)(uintptr_t)arg2,
                        (int)arg3, (mode_t)arg4);
        break;
    case 262: {
        struct stat host;
        result = fstatat((int)arg1, (const char *)(uintptr_t)arg2, &host,
                         (int)arg4);
        if (result >= 0) {
            host_to_target_stat((void *)(uintptr_t)arg3, &host);
        }
        break;
    }
    case 267:
        result = guest_readlinkat((int)arg1,
                                  (const void *)(uintptr_t)arg2,
                                  (void *)(uintptr_t)arg3, (size_t)arg4);
        break;
    case 273:
        errno = ENOSYS;
        result = -1;
        break;
    case 302: {
        int resource = target_to_host_resource((int)arg2);
        HostRlimit64 new_limit;
        HostRlimit64 old_limit;
        HostRlimit64 *new_pointer = NULL;
        if (arg3) {
            const TargetRlimit64 *target = (const void *)(uintptr_t)arg3;
            new_limit.rlim_cur = target->rlim_cur;
            new_limit.rlim_max = target->rlim_max;
            new_pointer = &new_limit;
        }
        result = syscall(SYS_prlimit64, (pid_t)arg1, resource, new_pointer,
                         arg4 ? &old_limit : NULL);
        if (result >= 0 && arg4) {
            TargetRlimit64 *target = (void *)(uintptr_t)arg4;
            target->rlim_cur = old_limit.rlim_cur;
            target->rlim_max = old_limit.rlim_max;
        }
        break;
    }
    case 318:
        result = getrandom((void *)(uintptr_t)arg1, (size_t)arg2,
                           (unsigned)arg3);
        break;
    case 334:
        (void)guest_clear_tid;
        errno = ENOSYS;
        result = -1;
        break;
    default:
        dprintf(STDERR_FILENO, "latc: unsupported x86 syscall %llu\n",
                (unsigned long long)number);
        _exit(127);
    }
    *reg(env, ENV_RAX) = target_errno(result);
}
