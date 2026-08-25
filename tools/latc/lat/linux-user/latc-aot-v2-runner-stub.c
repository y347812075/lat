#include "qemu/osdep.h"

#include "qemu.h"
#include "latc-aot-v2-runner.h"

int latc_aot_v2_prepare(CPUArchState *env)
{
    (void)env;
    return 0;
}

TranslationBlock *latc_aot_v2_find_tb(CPUState *cpu,
                                      target_ulong guest_pc,
                                      uint32_t flags, uint32_t cflags)
{
    (void)cpu;
    (void)guest_pc;
    (void)flags;
    (void)cflags;
    return NULL;
}
