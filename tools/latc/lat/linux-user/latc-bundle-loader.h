#ifndef LATC_BUNDLE_LOADER_H
#define LATC_BUNDLE_LOADER_H

#include <stdint.h>

/* Return 1 for a bundle, 0 for a normal runner invocation, or -1 on error. */
int latc_bundle_inject_argv(int *argc, char ***argv);

struct CPUState;
void latc_bundle_pretranslate(struct CPUState *cpu);

/* Called by the copied LAT code generator after a TB is installed. */
void latc_bundle_note_tb_generated(uint64_t guest_pc);

#endif
