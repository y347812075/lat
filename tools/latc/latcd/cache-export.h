#ifndef LATCD_CACHE_EXPORT_H
#define LATCD_CACHE_EXPORT_H

#include <stdint.h>

/* Caller holds the source latch and object pin. The expected digest must come
 * from a validated current manifest. Returns an independent sealed fd. */
int latcd_cache_export_copy(int source, const char *sha256, uint64_t max_bytes);

#endif
