#include "lat-native-migration-v12.h"
#include "native-image.h"

#include "lat-translation-config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

static int range_valid(uint64_t offset, uint64_t length, uint64_t size)
{
    return offset <= size && length <= size - offset;
}


static int validate_core(const void *data, uint32_t target_config_size,
                         const uint8_t *target_config,
                         char *error, size_t error_size)
{
    const LatNativeImageHeaderV2 *header = data;
    uint64_t trailer_offset = header->tu_table_offset +
        header->tu_count * sizeof(LatNativeTuV1);
    uint64_t core_size = trailer_offset + target_config_size;
    if (core_size > SIZE_MAX) {
        return fail(error, error_size, "v12 core size overflows");
    }
    uint8_t *core = calloc((size_t)core_size ? (size_t)core_size : 1, 1);
    if (!core) return fail(error, error_size, "cannot allocate v12 core view");
    memcpy(core, data, (size_t)trailer_offset);
    memcpy(core + trailer_offset, target_config, target_config_size);
    LatNativeImageHeaderV2 *core_header = (void *)core;
    core_header->version = LAT_NATIVE_IMAGE_VERSION;
    int result = lat_native_image_validate(core, (size_t)core_size,
                                           error, error_size);
    free(core);
    return result;
}

int lat_native_migration_v12_validate(const void *data, size_t size,
    LatNativeMigrationViewV12 *view, char *error, size_t error_size)
{
    if (view) memset(view, 0, sizeof(*view));
    if (!data || size < sizeof(LatNativeImageHeaderV2)) {
        return fail(error, error_size, "v12 migration image is truncated");
    }
    const LatNativeImageHeaderV2 *header = data;
    if (memcmp(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8) ||
        header->version != LAT_NATIVE_MIGRATION_V12_VERSION ||
        header->header_size != sizeof(*header) ||
        !(header->flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED)) {
        return fail(error, error_size, "invalid v12 migration image header");
    }
    if (header->tu_count > UINT64_MAX / sizeof(LatNativeTuV1)) {
        return fail(error, error_size, "v12 TU table size overflows");
    }
    uint64_t trailer_offset = header->tu_table_offset +
        header->tu_count * sizeof(LatNativeTuV1);
    if (!range_valid(trailer_offset, sizeof(LatNativeMigrationTrailerV12), size)) {
        return fail(error, error_size, "v12 migration trailer is truncated");
    }
    const LatNativeMigrationTrailerV12 *trailer =
        (const void *)((const uint8_t *)data + trailer_offset);
    if (memcmp(trailer->magic, LAT_NATIVE_MIGRATION_V12_MAGIC, 8) ||
        trailer->version != LAT_NATIVE_MIGRATION_V12_VERSION ||
        trailer->header_size != sizeof(*trailer) ||
        trailer->authorization_state != LAT_NATIVE_MIGRATION_QUARANTINED ||
        trailer->dependency_contract_version !=
            LAT_NATIVE_MIGRATION_CONTRACT_VERSION ||
        trailer->changed_fields & ~LAT_CONFIG_ALL_BITS ||
        !trailer->config_count || trailer->config_count > 64 ||
        trailer->target_config_index >= trailer->config_count) {
        return fail(error, error_size, "invalid v12 migration trailer");
    }

    uint64_t cursor = trailer_offset + sizeof(*trailer);
    if (trailer->origin_index_offset != cursor ||
        header->tu_count > UINT64_MAX / sizeof(uint32_t)) {
        return fail(error, error_size, "invalid v12 origin index offset");
    }
    cursor += header->tu_count * sizeof(uint32_t);
    if (trailer->config_table_offset != cursor) {
        return fail(error, error_size, "invalid v12 config table offset");
    }
    cursor += trailer->config_count * sizeof(LatNativeMigrationConfigEntryV12);
    if (trailer->proof_offset != cursor ||
        !range_valid(trailer->proof_offset, trailer->proof_size, size)) {
        return fail(error, error_size, "invalid v12 proof range");
    }
    cursor += trailer->proof_size;
    if (trailer->config_bytes_offset != cursor ||
        !range_valid(trailer->config_bytes_offset,
                     trailer->config_bytes_size, size) ||
        trailer->config_bytes_offset + trailer->config_bytes_size != size ||
        header->translation_config_size > trailer->config_bytes_size) {
        return fail(error, error_size, "invalid v12 config byte range");
    }

    const uint8_t *origin_indices =
        (const uint8_t *)data + trailer->origin_index_offset;
    const LatNativeMigrationConfigEntryV12 *configs =
        (const void *)((const uint8_t *)data + trailer->config_table_offset);
    const uint8_t *config_bytes = (const uint8_t *)data +
                                  trailer->config_bytes_offset;
    const uint8_t *target_config = (const uint8_t *)data + size -
                                   header->translation_config_size;
    if (!header->translation_config_size ||
        !range_valid(config_bytes - (const uint8_t *)data,
                     trailer->config_bytes_size, size)) {
        return fail(error, error_size, "v12 target configuration is missing");
    }

    static const uint8_t zero_digest[32];
    int old_config_seen = 0;
    uint64_t previous_end = 0;
    size_t target_index = trailer->target_config_index;
    for (uint32_t i = 0; i < trailer->config_count; i++) {
        const LatNativeMigrationConfigEntryV12 *entry = &configs[i];
        if (entry->reserved || !entry->config_size ||
            entry->config_size > LAT_NATIVE_CONFIG_CAPACITY ||
            !(entry->flags & (LAT_NATIVE_MIGRATION_CONFIG_ORIGIN |
                              LAT_NATIVE_MIGRATION_CONFIG_TARGET)) ||
            entry->flags & ~(LAT_NATIVE_MIGRATION_CONFIG_ORIGIN |
                             LAT_NATIVE_MIGRATION_CONFIG_TARGET) ||
            entry->config_offset < previous_end ||
            !range_valid(entry->config_offset, entry->config_size,
                         trailer->config_bytes_size)) {
            return fail(error, error_size, "invalid v12 config table entry");
        }
        previous_end = (uint64_t)entry->config_offset + entry->config_size;
        const uint8_t *encoded = config_bytes + entry->config_offset;
        LatTranslationConfig decoded, identity;
        uint8_t digest[32];
        if (lat_translation_config_decode(encoded, entry->config_size, NULL,
                &decoded, error, error_size) ||
            lat_translation_config_digest(&decoded, digest, error, error_size) ||
            memcmp(digest, entry->config_sha256, 32) ||
            lat_translation_config_init(&identity, header->lat_build_id,
                decoded.guest_abi, decoded.feature_count,
                error, error_size) ||
            memcmp(identity.build_id, decoded.build_id, 32)) {
            return fail(error, error_size, "invalid v12 config entry identity");
        }
        if (!memcmp(entry->config_sha256, trailer->old_config_sha256, 32)) {
            if (!(entry->flags & LAT_NATIVE_MIGRATION_CONFIG_ORIGIN)) {
                return fail(error, error_size,
                            "v12 old config is not marked as an origin");
            }
            old_config_seen = 1;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (!memcmp(configs[j].config_sha256, entry->config_sha256, 32)) {
                return fail(error, error_size, "duplicate v12 config identity");
            }
        }
        if (i == target_index &&
            (!(entry->flags & LAT_NATIVE_MIGRATION_CONFIG_TARGET) ||
             entry->config_offset + entry->config_size !=
                 trailer->config_bytes_size ||
             entry->config_size != header->translation_config_size ||
             memcmp(entry->config_sha256,
                    header->translation_config_sha256, 32) ||
             memcmp(entry->config_sha256,
                    trailer->target_config_sha256, 32))) {
            return fail(error, error_size, "v12 target configuration mismatch");
        }
    }
    if (target_index >= trailer->config_count ||
        (!memcmp(trailer->old_native_sha256, zero_digest, 32)) ||
        (!memcmp(trailer->delta_native_sha256, zero_digest, 32)) ||
        memcmp(configs[target_index].config_sha256,
               trailer->target_config_sha256, 32) ||
        memcmp(target_config, config_bytes + configs[target_index].config_offset,
               header->translation_config_size)) {
        return fail(error, error_size, "invalid v12 migration identities");
    }
    if (validate_core(data, configs[target_index].config_size,
                      target_config, error, error_size)) {
        return -1;
    }

    const LatNativeTuV1 *tus = (const void *)((const uint8_t *)data +
                                               header->tu_table_offset);
    for (uint64_t i = 0; i < header->tu_count; i++) {
        uint32_t origin_index;
        memcpy(&origin_index, origin_indices + i * sizeof(uint32_t),
               sizeof(origin_index));
        if (origin_index >= trailer->config_count) {
            return fail(error, error_size, "invalid v12 TU origin index");
        }
        if (origin_index != target_index &&
            (!tus[i].config_dependency_version ||
             (tus[i].config_dependencies & trailer->changed_fields))) {
            return fail(error, error_size,
                        "retained v12 TU depends on changed configuration");
        }
    }
    if (!old_config_seen || memcmp(trailer->old_config_sha256,
                                   trailer->target_config_sha256, 32) == 0) {
        return fail(error, error_size, "v12 migration has no distinct old origin");
    }

    if (view) {
        view->image = *header;
        view->trailer = *trailer;
        view->origin_config_indices = origin_indices;
        view->configs = configs;
        view->proof = (const uint8_t *)data + trailer->proof_offset;
        view->target_config = target_config;
    }
    return 0;
}
