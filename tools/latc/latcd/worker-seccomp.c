#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "worker-seccomp.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__loongarch64)
#define WORKER_ARCH AUDIT_ARCH_LOONGARCH64
#elif defined(__x86_64__)
#define WORKER_ARCH AUDIT_ARCH_X86_64
#else
#error unsupported worker seccomp architecture
#endif

/* The bundled Linux headers predate this syscall on both supported ABIs. */
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

#define DENY(n, e) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (e))

int latcd_worker_seccomp_fd(void)
{
    const struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WORKER_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* x32 syscall numbers share AUDIT_ARCH_X86_64. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        DENY(clone3, ENOSYS),
        DENY(io_uring_setup, ENOSYS),
        DENY(io_uring_enter, ENOSYS),
        DENY(io_uring_register, ENOSYS),
        DENY(socket, EPERM),
        DENY(unshare, EPERM), DENY(setns, EPERM),
        DENY(mount, EPERM), DENY(umount2, EPERM), DENY(pivot_root, EPERM),
        DENY(open_tree, EPERM), DENY(move_mount, EPERM),
        DENY(fsopen, EPERM), DENY(fsconfig, EPERM), DENY(fsmount, EPERM),
        DENY(fspick, EPERM), DENY(mount_setattr, EPERM),
        DENY(open_by_handle_at, EPERM), DENY(name_to_handle_at, EPERM),
        DENY(ptrace, EPERM), DENY(process_vm_readv, EPERM),
        DENY(process_vm_writev, EPERM), DENY(pidfd_getfd, EPERM),
        DENY(bpf, EPERM), DENY(perf_event_open, EPERM), DENY(userfaultfd, EPERM),
        DENY(init_module, EPERM), DENY(finit_module, EPERM),
        DENY(delete_module, EPERM), DENY(kexec_load, EPERM),
#ifdef __NR_kexec_file_load
        DENY(kexec_file_load, EPERM),
#endif
        DENY(reboot, EPERM), DENY(swapon, EPERM), DENY(swapoff, EPERM),
#ifdef __NR_mknod
        DENY(mknod, EPERM),
#endif
        DENY(mknodat, EPERM), DENY(add_key, EPERM), DENY(request_key, EPERM),
        DENY(keyctl, EPERM), DENY(chroot, EPERM), DENY(acct, EPERM),
        DENY(quotactl, EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                 CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
                 CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_PARENT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    int fd = syscall(SYS_memfd_create, "latcd-worker-seccomp",
                     MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return -1;
    const char *p = (const char *)filter;
    size_t left = sizeof(filter);
    while (left) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { int saved = n ? errno : EIO; close(fd); errno = saved; return -1; }
        p += n;
        left -= n;
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
              F_SEAL_SEAL) || lseek(fd, 0, SEEK_SET) < 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}
