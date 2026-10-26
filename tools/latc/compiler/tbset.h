#ifndef LATC_TBSET_H
#define LATC_TBSET_H

#include "cfg_program.h"
#include "lat-tb-key-set.h"

#include <stddef.h>

typedef struct LatcTbClosure LatcTbClosure;

/* In-memory discovery only. The program must remain alive and unchanged until
 * freed. Results are static candidates, not observed requests; only done=true
 * proves the frontier is empty. Total session memory grows with discovery. */
LatcTbClosure *latc_tb_closure_new(const char *source_path,
                                  const CfgProgram *program,
                                  char *error, size_t error_size);
int latc_tb_closure_advance(LatcTbClosure *closure, size_t work_budget,
                             size_t target_budget, CfgTb **targets,
                             size_t *target_count, bool *done,
                             char *error, size_t error_size);
void latc_tb_closure_free(LatcTbClosure *closure);
void latc_tbset_filter_static_keys(const char *source, uint64_t base,
                                    LatTbKey *keys, size_t *count);

int latc_tbset_apply(const char *path, const char *source_path,
                     CfgProgram *program,
                     bool ignore_outside_exec, size_t *matched,
                     size_t *unmatched, size_t *ignored, uint8_t digest[32],
                     char *error, size_t error_size);

int latc_tbset_prepare_discovery(const char *path, const char *source_path,
                                  CfgProgram *program, bool static_input,
                                  uint8_t digest[32],
                                  char *error, size_t error_size);

int latc_tbset_write_static(const char *path, const char *source_path,
                            const CfgProgram *program,
                            size_t *written, char *error, size_t error_size);

#endif
