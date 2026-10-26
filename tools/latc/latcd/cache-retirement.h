#ifndef LATCD_CACHE_RETIREMENT_H
#define LATCD_CACHE_RETIREMENT_H

#include <stddef.h>

/* The caller owns the cache management lease and the source commit latch.
 * Neither transaction completion nor recovery authorizes file removal. */
int latcd_retirement_prepare(const char *root, const char *source,
                            const char *next, size_t next_size,
                            char **transaction, char *error, size_t error_size);
int latcd_retirement_finish(const char *root, const char *transaction,
                           char *error, size_t error_size);
int latcd_retirement_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size);

#endif
