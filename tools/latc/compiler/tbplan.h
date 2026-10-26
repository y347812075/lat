#ifndef LATC_TBPLAN_H
#define LATC_TBPLAN_H

#include <stdbool.h>
#include <stddef.h>

int latc_tbplan_write(const char *source, const char *input, const char *directory,
                       bool static_input, size_t batch_size, size_t work_budget,
                       char *error, size_t error_size);
/* Prints safe relative shard names/modes only after validating the whole plan. */
int latc_tbplan_list(const char *source, const char *directory,
                      char *error, size_t error_size);
int latc_tbplan_validate_module(const char *source, const char *directory,
                                 const char *module, char *error, size_t error_size);

#endif
