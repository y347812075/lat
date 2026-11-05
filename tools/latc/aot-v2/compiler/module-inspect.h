#ifndef LATC_AOT_V2_MODULE_INSPECT_H
#define LATC_AOT_V2_MODULE_INSPECT_H

#include "lat-aot-v2.h"
#include "lat-tb-key-set.h"

#include <stddef.h>
#include <stdint.h>

typedef struct LatAotModuleInfoV2 {
    LatAotNoteV2 note;
    uint64_t text_size;
    uint64_t tb_count;
    uint64_t pc_map_count;
    uint64_t guest_slot_records;
} LatAotModuleInfoV2;

int lat_aot_v2_module_inspect_file(const char *path,
                                   LatAotModuleInfoV2 *info,
                                   char *error, size_t error_size);
int lat_aot_v2_module_inspect_config_file(
    const char *path, LatAotModuleInfoV2 *info,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size);
/* Inspects the opened object without taking ownership of fd. */
int lat_aot_v2_module_inspect_fd(int fd, size_t max_size, LatAotModuleInfoV2 *info,
                                 char *error, size_t error_size);

int lat_aot_v2_module_validate_tbset_file(const char *path,
                                          const char *tbset_path,
                                          char *error,
                                          size_t error_size);
int lat_aot_v2_module_inspect_and_validate_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    char *error, size_t error_size);
/* Structural matching only; caller must authenticate the expected identity. */
int lat_aot_v2_module_validate_config_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size);
int lat_aot_v2_module_missing_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    LatTbKeySet *missing, char *error, size_t error_size);

int lat_aot_v2_module_read_tbset_file(
    const char *path, LatAotModuleInfoV2 *info, LatTbKeySet *keys,
    char *error, size_t error_size);
int lat_aot_v2_module_validate_replacement_file(
    const char *previous, const char *replacement,
    char *error, size_t error_size);
/* Compare source and TB keys across codegen identities, not code compatibility. */
int lat_aot_v2_module_validate_rebuild_file(
    const char *previous, const char *replacement,
    char *error, size_t error_size);
/* Structural matching only; caller must authenticate the expected identity. */
int lat_aot_v2_module_validate_config_replacement_file(
    const char *previous, const char *replacement,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size);

#endif
