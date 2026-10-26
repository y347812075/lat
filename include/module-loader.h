#ifndef LAT_AOT_V2_MODULE_LOADER_H
#define LAT_AOT_V2_MODULE_LOADER_H

#include "registry.h"

#include <stddef.h>

/* Startup recognition only; never closes or executes inherited descriptors. */
int lat_aot_v2_module_retain_inherited(uint64_t *count, uint64_t *bytes,
                                      char *error, size_t error_size);

int lat_aot_v2_module_open(const char *path,
                           const LatAotExpectedV2 *expected,
                           LatAotLoadedModuleV2 *module,
                           char *error, size_t error_size);

#endif
