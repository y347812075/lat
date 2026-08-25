#ifndef LATC_AOT_V2_RUNNER_H
#define LATC_AOT_V2_RUNNER_H

#include "qemu/typedefs.h"
#include "exec/cpu-defs.h"

#include <stdint.h>

int latc_aot_v2_prepare(CPUArchState *env);
TranslationBlock *latc_aot_v2_find_tb(CPUState *cpu,
                                      target_ulong guest_pc,
                                      uint32_t flags, uint32_t cflags);

#endif
