#ifndef LATC_PROFILE_H
#define LATC_PROFILE_H

#include "cfg_program.h"

#include <stddef.h>

int latc_profile_apply(const char *path, const char *source_path,
                       CfgProgram *program,
                       bool ignore_outside_exec, size_t *matched,
                       size_t *unmatched, size_t *ignored,
                       char *error, size_t error_size);

#endif
