#ifndef LATC_AOT_V2_RUNNER_H
#define LATC_AOT_V2_RUNNER_H

#include "qemu/typedefs.h"
#include "exec/cpu-defs.h"

#include <stdint.h>

bool latc_aot_v2_mapping_enabled(void);
/* Takes ownership of fd. ELF inspection is deferred while mmap is locked. */
void latc_aot_v2_note_mmap(int fd, uint64_t guest_start,
                           uint64_t mapping_size, uint64_t file_offset);
void latc_aot_v2_drain_mmaps(void);
void latc_aot_v2_report_stats(void);
int latc_aot_v2_prepare(CPUArchState *env);
TranslationBlock *latc_aot_v2_find_tb(CPUState *cpu,
                                      target_ulong guest_pc,
                                      uint32_t flags, uint32_t cflags);
bool latc_aot_v2_restore_state(CPUState *cpu, uintptr_t host_pc);

#endif
