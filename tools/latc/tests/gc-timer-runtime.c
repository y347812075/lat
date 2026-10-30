#include "lat-aot-v2.h"
#include "latc-build-id.h"
#include <stdint.h>
uint32_t lat_aot_runtime_abi_version(void) { return LAT_AOT_V2_ABI_VERSION; }
const char *lat_aot_runtime_build_id(void) { return LATC_BUILD_ID; }
