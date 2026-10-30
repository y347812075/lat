#ifndef LATCD_CACHE_EXPORT_H
#define LATCD_CACHE_EXPORT_H

#include <stdint.h>

/* Caller holds the object pin captured under the source latch. The expected
 * digest must come from that validated manifest. Returns a sealed copy. */
int latcd_cache_export_copy(int source, const char *sha256, uint64_t max_bytes);

#endif
