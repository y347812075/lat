#ifndef LAT_AOT_V2_CACHE_DOMAIN_H
#define LAT_AOT_V2_CACHE_DOMAIN_H

#include <stddef.h>

/*
 * Validate the stable cache-domain marker and lock binding.
 *
 * Returns 1 for a valid managed domain, 0 for a legacy root with neither
 * marker, and -1 for incomplete, malformed, rebound or unsafe metadata.
 * The optional id buffer must hold at least 37 bytes. This validates protocol
 * identity only; it is not access or mount isolation and does not authorize
 * deletion.
 */
int lat_aot_v2_cache_domain_validate(const char *root, char id[37],
                                     char *error, size_t error_size);

#endif
