#ifndef LATC_NATIVE_TU_PLAN_H
#define LATC_NATIVE_TU_PLAN_H

#include "lat-tb-key-set.h"

/* Metadata closure only, not a configuration compatibility decision. Includes
 * entire TUs, same-key physical aliases, and incoming physical dependencies.
 * Raw code/data extraction must additionally prove all unrecorded code edges. */
int lat_native_tu_plan(const void *data, size_t size, const LatTbKeySet *seeds,
                       LatTbKeySet *result, char *error, size_t error_size);

/* Compare an embedded configuration with a target snapshot, then close affected
 * TUs. An incomplete snapshot permits planning only, never reuse authorization. */
int lat_native_tu_config_plan(const void *data, size_t size,
    const void *target, size_t target_size, LatTbKeySet *result,
    uint64_t *changed, char *error, size_t error_size);

/* Compact the complement of the closed removal plan. Experimental replay images
 * only: the unchanged CONFIG_UNVERIFIED flag prohibits execution/publication.
 * This remaps recorded references, not a certificate of machine-code mobility.
 * Caller releases *output with g_free. Empty complements are rejected. */
int lat_native_tu_extract(const void *data, size_t size,
    const LatTbKeySet *remove, void **output, size_t *output_size,
    char *error, size_t error_size);

#endif
