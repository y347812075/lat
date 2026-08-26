#include "qemu/osdep.h"

#include "qemu.h"
#include "latc-aot-v2-runner.h"

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

void latc_aot_v2_report_stats(void)
{
}

int latc_aot_v2_prepare(CPUArchState *env)
{
    (void)env;
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

bool latc_aot_v2_activate_target(CPUState *cpu,
                                 const LatcAotV2Target *target)
{
    (void)cpu;
    (void)target;
    return false;
}

bool latc_aot_v2_contains_host_pc(uintptr_t host_pc)
{
    (void)host_pc;
    return false;
}

bool latc_aot_v2_restore_state(CPUState *cpu, uintptr_t host_pc)
{
    (void)cpu;
    (void)host_pc;
    return false;
}
