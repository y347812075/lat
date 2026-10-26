#ifndef LATC_LAT_NATIVE_MIGRATION_V12_H
#define LATC_LAT_NATIVE_MIGRATION_V12_H

#include "lat-native-image.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LAT_NATIVE_MIGRATION_V12_MAGIC "LATMIG12"
#define LAT_NATIVE_MIGRATION_V12_VERSION 12u
#define LAT_NATIVE_MIGRATION_CONTRACT_VERSION 1u

enum LatNativeMigrationAuthorizationV12 {
    LAT_NATIVE_MIGRATION_QUARANTINED = 1,
    LAT_NATIVE_MIGRATION_VERIFIED_TARGET = 2,
};

/* The core image remains in the v11 layout. Version 12 inserts this trailer
 * after the core TU table, followed by TU origin indexes, a config table,
 * proof bytes, and finally the canonical target configuration bytes. */
typedef struct LatNativeMigrationTrailerV12 {
    uint8_t magic[8];
    uint32_t version;
    uint32_t header_size;
    uint32_t authorization_state;
    uint32_t config_count;
    uint32_t dependency_contract_version;
    uint32_t target_config_index;
    uint64_t origin_index_offset;
    uint64_t config_table_offset;
    uint64_t proof_offset;
    uint64_t proof_size;
    uint64_t config_bytes_offset;
    uint64_t config_bytes_size;
    uint64_t changed_fields;
    uint8_t old_native_sha256[32];
    uint8_t delta_native_sha256[32];
    uint8_t old_config_sha256[32];
    uint8_t target_config_sha256[32];
} LatNativeMigrationTrailerV12;

typedef struct LatNativeMigrationConfigEntryV12 {
    uint32_t config_offset;
    uint32_t config_size;
    uint8_t config_sha256[32];
    uint32_t flags;
    uint32_t reserved;
} LatNativeMigrationConfigEntryV12;

enum LatNativeMigrationConfigFlagsV12 {
    LAT_NATIVE_MIGRATION_CONFIG_ORIGIN = 1u << 0,
    LAT_NATIVE_MIGRATION_CONFIG_TARGET = 1u << 1,
};

typedef struct LatNativeMigrationViewV12 {
    LatNativeImageHeaderV2 image;
    LatNativeMigrationTrailerV12 trailer;
    const uint8_t *origin_config_indices;
    const LatNativeMigrationConfigEntryV12 *configs;
    const uint8_t *proof;
    const uint8_t *target_config;
} LatNativeMigrationViewV12;

/* Validate structure, identities, config table, origin references, and the
 * dependency contract. VERIFIED_TARGET is rejected until proof verification is
 * implemented; successful validation of a quarantined image never grants
 * execution or publication. */
int lat_native_migration_v12_validate(const void *data, size_t size,
    LatNativeMigrationViewV12 *view, char *error, size_t error_size);

_Static_assert(sizeof(LatNativeMigrationTrailerV12) == 216,
               "migration trailer size changed");
_Static_assert(sizeof(LatNativeMigrationConfigEntryV12) == 48,
               "migration config entry size changed");

#endif
