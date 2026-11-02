#ifndef LATCD_CACHE_EXPORT_H
#define LATCD_CACHE_EXPORT_H

#include <stdint.h>
#include "broker-source.h"
#include "lat-aot-v2.h"

/* Caller holds the object pin captured under the source latch. The expected
 * digest must come from that validated manifest. Returns a sealed copy. */
int latcd_cache_export_copy(int source, const char *sha256, uint64_t max_bytes);
int latcd_cache_export_copy_bounded(int source, const char *sha256, uint64_t max_bytes,
                                    int64_t deadline_us, LatcdBrokerCancelled cancelled,
                                    void *opaque);

/* Identity validation does not authenticate the producer or authorize execution. */
int latcd_cache_export_config_bounded(int source, const char *sha256,
    uint64_t max_bytes, const LatAotExpectedV2 *expected,
    const LatAotConfigIdentityV2 *config, int64_t deadline_us,
    LatcdBrokerCancelled cancelled, void *opaque, char *error, size_t error_size);

#endif
