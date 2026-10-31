#include "qemu/osdep.h"

#include "qemu.h"
#include "latc-aot-v2-runner.h"
#include <dirent.h>
#include <limits.h>
#include <sys/file.h>

void latc_aot_v2_fork_start(void)
{
}

void latc_aot_v2_fork_end(CPUState *cpu, bool child)
{
    (void)cpu;
    (void)child;
}

bool latc_aot_v2_mapping_enabled(void)
{
    return false;
}

void latc_aot_v2_note_mmap(int fd, uint64_t guest_start,
                           uint64_t mapping_size, uint64_t file_offset)
{
    (void)fd;
    (void)guest_start;
    (void)mapping_size;
    (void)file_offset;
    close(fd);
}

void latc_aot_v2_drain_mmaps(void)
{
}

bool latc_aot_v2_revalidate_range(uint64_t guest_start,
                                  uint64_t mapping_size)
{
    (void)guest_start;
    (void)mapping_size;
    return false;
}

bool latc_aot_v2_note_mremap(CPUState *cpu, uint64_t old_start,
                             uint64_t old_size, uint64_t new_start,
                             uint64_t new_size, bool keep_old)
{
    (void)cpu;
    (void)old_start;
    (void)old_size;
    (void)new_start;
    (void)new_size;
    (void)keep_old;
    return false;
}

void latc_aot_v2_note_munmap(CPUState *cpu, uint64_t guest_start,
                             uint64_t mapping_size)
{
    (void)cpu;
    (void)guest_start;
    (void)mapping_size;
}

bool latc_aot_v2_invalidate_range(CPUState *cpu, uint64_t guest_start,
                                  uint64_t mapping_size,
                                  LatcAotV2InvalidationReason reason)
{
    (void)cpu;
    (void)guest_start;
    (void)mapping_size;
    (void)reason;
    return false;
}

void latc_aot_v2_consume_environment(void)
{
}

int latc_aot_v2_retain_inherited_pins(void)
{
    return 0;
}

bool latc_aot_v2_strict_enabled(void)
{
    return false;
}

void latc_aot_v2_report_stats(void)
{
}

void latc_aot_v2_flush_pending_keys(void)
{
}

void latc_aot_v2_flush_deferred_pending(void)
{
}

void latc_aot_v2_start_deferred_submission(void)
{
}

void latc_aot_v2_prepare_submission_channel(void)
{
}

int latc_aot_v2_relocate_source_fd(int fd)
{
    (void)fd;
    return 0;
}

int latc_aot_v2_fd_dup_replace(int oldfd, int newfd, int flags, bool use_dup3)
{
    return use_dup3 ? dup3(oldfd, newfd, flags) : dup2(oldfd, newfd);
}

int latc_aot_v2_fd_snapshot_guest(int fd)
{
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
}

void latc_aot_v2_fd_snapshot_close(int fd)
{
    close(fd);
}

int latc_aot_v2_fd_try_flock(int fd, int operation)
{
    return flock(fd, operation | LOCK_NB);
}

int latc_aot_v2_fd_fcntl(int fd, int command, int argument)
{
    return fcntl(fd, command, argument);
}

int latc_aot_v2_fd_close_guest(int fd)
{
    return close(fd);
}

int latc_aot_v2_fd_guest_begin(int fd)
{
    (void)fd;
    return 0;
}

void latc_aot_v2_fd_guest_end(void)
{
}

int latc_aot_v2_fd_close_range(unsigned first, unsigned last, bool cloexec,
                               LatcAotV2FdRangeProtected extra_protected,
                               void *opaque)
{
#ifdef __NR_close_range
    if (first > last) {
        errno = EINVAL;
        return -1;
    }
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int scan = dirfd(directory);
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            if (errno) result = -1;
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *end = NULL;
        errno = 0;
        unsigned long parsed = strtoul(entry->d_name, &end, 10);
        if (errno || !*entry->d_name || !end || *end || parsed > UINT_MAX ||
            parsed < first || parsed > last || parsed == (unsigned long)scan ||
            (extra_protected && extra_protected((int)parsed, opaque))) continue;
        if (syscall(__NR_close_range, (unsigned)parsed, (unsigned)parsed,
                    cloexec ? 4U : 0U) < 0 && errno != EBADF) {
            result = -1;
            break;
        }
    }
    int saved = errno;
    closedir(directory);
    errno = saved;
    return result;
#else
    (void)first;
    (void)last;
    (void)cloexec;
    (void)extra_protected;
    (void)opaque;
    errno = ENOSYS;
    return -1;
#endif
}

void latc_aot_v2_note_jit_key(target_ulong guest_pc, uint32_t cflags)
{
    (void)guest_pc;
    (void)cflags;
}

void latc_aot_v2_key_scope_enter(CPUState *cpu, uint32_t cflags, bool atomic_step)
{
    (void)cpu; (void)cflags; (void)atomic_step;
}

void latc_aot_v2_key_scope_leave(void) { }
void latc_aot_v2_key_gate(CPUState *cpu, target_ulong pc, uint32_t cflags)
{
    (void)cpu; (void)pc; (void)cflags;
}
void latc_aot_v2_key_publish_check(CPUState *cpu, target_ulong pc, uint32_t cflags)
{
    (void)cpu; (void)pc; (void)cflags;
}
bool latc_aot_v2_key_retry_pending(void) { return false; }
bool latc_aot_v2_key_retry_service(CPUState *cpu) { (void)cpu; return false; }
bool latc_aot_v2_key_resume_jrra(target_ulong pc, uint32_t cflags)
{
    (void)pc; (void)cflags; return false;
}

void latc_aot_v2_collect_existing_jit_tbs(target_ulong guest_begin,
                                          target_ulong guest_end)
{
    (void)guest_begin;
    (void)guest_end;
}

bool latc_aot_v2_is_file_pc(target_ulong guest_pc)
{
    (void)guest_pc;
    return false;
}

int latc_aot_v2_prepare(CPUArchState *env, bool native_replay_domain)
{
    (void)env;
    (void)native_replay_domain;
    return 0;
}

bool latc_aot_v2_find_target(CPUState *cpu, target_ulong guest_pc,
                             uint32_t cflags, LatcAotV2Target *target)
{
    (void)cpu;
    (void)guest_pc;
    (void)cflags;
    (void)target;
    return false;
}

void latc_aot_v2_note_cached_miss(const LatcAotV2Target *target)
{
    (void)target;
}

bool latc_aot_v2_activate_target(CPUState *cpu,
                                 const LatcAotV2Target *target)
{
    (void)cpu;
    (void)target;
    return false;
}

void latc_aot_v2_release_target(CPUState *cpu, LatcAotV2Target *target)
{
    (void)cpu;
    (void)target;
}

void latc_aot_v2_release_current_execution(CPUState *cpu)
{
    (void)cpu;
}

bool latc_aot_v2_contains_host_pc(uintptr_t host_pc)
{
    (void)host_pc;
    return false;
}

bool latc_aot_v2_diagnose_host_pc(CPUState *cpu, uintptr_t host_pc,
                                  LatcAotV2SignalDiagnostic *diagnostic)
{
    (void)cpu;
    (void)host_pc;
    (void)diagnostic;
    return false;
}

bool latc_aot_v2_restore_state(CPUState *cpu, uintptr_t host_pc)
{
    (void)cpu;
    (void)host_pc;
    return false;
}

bool latc_aot_v2_defer_signal_recovery(CPUState *cpu, uintptr_t host_pc,
                                       target_ulong *guest_pc)
{
    (void)cpu;
    (void)host_pc;
    (void)guest_pc;
    return false;
}

void latc_aot_v2_drain_signal_recovery(CPUState *cpu)
{
    (void)cpu;
}
