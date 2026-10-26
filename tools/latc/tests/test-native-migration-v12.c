#include "lat-native-migration-v12.h"
#include "native-image.h"
#include "lat-translation-config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void encoded_config_digest(const void *data, size_t size,
                                  uint8_t digest[32])
{
    LatTranslationConfig config;
    char error[256] = {0};
    assert(!lat_translation_config_decode(data, size, NULL, &config,
                                          error, sizeof(error)));
    assert(!lat_translation_config_digest(&config, digest,
                                          error, sizeof(error)));
}

static size_t make_v11(uint8_t *data, const GBytes *target_bytes,
                       LatTranslationConfig *old_config,
                       LatTranslationConfig *target_config)
{
    memset(data, 0, 4096);
    char error[256] = {0};
    LatNativeImageHeaderV2 *header = (void *)data;
    memcpy(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->header_size = sizeof(*header);
    header->flags = LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    memset(header->lat_build_id, '0', 64);
    header->guest_image_offset = sizeof(*header);
    header->guest_image_size = 8;
    header->code_offset = header->guest_image_offset + header->guest_image_size;
    header->code_size = 64;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 1;
    header->relocation_offset = header->tb_table_offset + sizeof(LatNativeTbV1);
    header->pc_map_offset = header->relocation_offset;
    header->pc_map_count = 1;
    header->tu_table_offset = header->pc_map_offset + sizeof(LatNativePcMapV2);
    header->tu_count = 1;

    assert(!lat_translation_config_init(old_config, header->lat_build_id,
        LAT_CONFIG_ABI_X86_64, 1, error, sizeof(error)));
    old_config->native_replay_domain = true;
    old_config->values[LAT_CONFIG_PARALLEL] = 1;
    *target_config = *old_config;
    target_config->values[LAT_CONFIG_CVT_OPT] = 1;
    GBytes *old_bytes = NULL;
    GBytes *encoded_target = NULL;
    assert(!lat_translation_config_encode(old_config, &old_bytes,
                                          error, sizeof(error)));
    assert(!lat_translation_config_encode(target_config, &encoded_target,
                                          error, sizeof(error)));
    size_t old_size = 0, target_size = 0;
    (void)g_bytes_get_data(old_bytes, &old_size);
    const void *target_data = g_bytes_get_data(encoded_target, &target_size);
    assert(old_size == target_size && target_bytes);
    const void *provided_target;
    gsize provided_size;
    provided_target = g_bytes_get_data((GBytes *)target_bytes, &provided_size);
    assert(provided_size == target_size && !memcmp(target_data, provided_target,
                                                    target_size));
    g_bytes_unref(old_bytes);
    g_bytes_unref(encoded_target);

    uint8_t *code = data + header->code_offset;
    uint32_t nop = 0x03400000u;
    uint32_t branch = 0x50000000u;
    memcpy(code, &nop, sizeof(nop));
    memcpy(code + 4, &branch, sizeof(branch));
    LatNativeTbV1 *tb = (void *)(data + header->tb_table_offset);
    *tb = (LatNativeTbV1) {
        .guest_pc = header->preferred_guest_base + 0x10,
        .code_size = 8,
        .flags = 3,
        .tu_index = 0,
    };
    LatNativePcMapV2 *map = (void *)(data + header->pc_map_offset);
    *map = (LatNativePcMapV2) {
        .guest_pc = tb->guest_pc,
        .host_offset_begin = 0,
        .host_offset_end = 8,
        .state_record_offset = (uint32_t)-8,
        .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE |
                 LAT_NATIVE_PC_MAP_STACK_POINTER_DELTA,
    };
    LatNativeTuV1 *tu = (void *)(data + header->tu_table_offset);
    *tu = (LatNativeTuV1) {
        .code_size = 32,
        .search_offset = 24,
        .config_dependency_version = LAT_TRANSLATION_CONFIG_VERSION,
        .config_dependencies = UINT64_C(1) << LAT_CONFIG_ROUNDING_OPT,
    };
    size_t size = header->tu_table_offset + sizeof(*tu);
    const void *target_data_again = g_bytes_get_data((GBytes *)target_bytes,
                                                      &provided_size);
    memcpy(data + size, target_data_again, provided_size);
    header->translation_config_size = provided_size;
    header->translation_config_projection = 1;
    assert(!lat_translation_config_digest(target_config,
        header->translation_config_sha256, error, sizeof(error)));
    assert(!lat_native_image_validate(data, size + provided_size,
                                      error, sizeof(error)));
    return size;
}

static size_t make_v12(uint8_t *output, const uint8_t *v11,
                       const GBytes *old_bytes,
                       const GBytes *target_bytes)
{
    memset(output, 0, 8192);
    const LatNativeImageHeaderV2 *source = (const void *)v11;
    size_t core_end = source->tu_table_offset +
                      source->tu_count * sizeof(LatNativeTuV1);
    memcpy(output, v11, core_end);
    LatNativeImageHeaderV2 *header = (void *)output;
    header->version = LAT_NATIVE_MIGRATION_V12_VERSION;
    size_t trailer_offset = core_end;
    LatNativeMigrationTrailerV12 *trailer = (void *)(output + trailer_offset);
    size_t origin_offset = trailer_offset + sizeof(*trailer);
    size_t config_table_offset = origin_offset + sizeof(uint32_t);
    size_t proof_offset = config_table_offset +
                          sizeof(LatNativeMigrationConfigEntryV12) * 2;
    size_t config_bytes_offset = proof_offset + 4;
    gsize old_size, target_size;
    const void *old_data = g_bytes_get_data((GBytes *)old_bytes, &old_size);
    const void *target_data = g_bytes_get_data((GBytes *)target_bytes,
                                                &target_size);
    size_t config_bytes_size = old_size + target_size;
    size_t size = config_bytes_offset + config_bytes_size;

    memcpy(trailer->magic, LAT_NATIVE_MIGRATION_V12_MAGIC, 8);
    trailer->version = LAT_NATIVE_MIGRATION_V12_VERSION;
    trailer->header_size = sizeof(*trailer);
    trailer->authorization_state = LAT_NATIVE_MIGRATION_QUARANTINED;
    trailer->config_count = 2;
    trailer->dependency_contract_version = LAT_NATIVE_MIGRATION_CONTRACT_VERSION;
    trailer->target_config_index = 1;
    trailer->origin_index_offset = origin_offset;
    trailer->config_table_offset = config_table_offset;
    trailer->proof_offset = proof_offset;
    trailer->proof_size = 4;
    trailer->config_bytes_offset = config_bytes_offset;
    trailer->config_bytes_size = config_bytes_size;
    trailer->changed_fields = UINT64_C(1) << LAT_CONFIG_CVT_OPT;
    memset(trailer->old_native_sha256, 0x11, 32);
    memset(trailer->delta_native_sha256, 0x22, 32);
    encoded_config_digest(old_data, old_size, trailer->old_config_sha256);
    encoded_config_digest(target_data, target_size, trailer->target_config_sha256);
    uint32_t origin = 0;
    memcpy(output + origin_offset, &origin, sizeof(origin));
    LatNativeMigrationConfigEntryV12 *entries =
        (void *)(output + config_table_offset);
    entries[0].config_offset = 0;
    entries[0].config_size = old_size;
    entries[0].flags = LAT_NATIVE_MIGRATION_CONFIG_ORIGIN;
    memcpy(entries[0].config_sha256, trailer->old_config_sha256, 32);
    entries[1].config_offset = old_size;
    entries[1].config_size = target_size;
    entries[1].flags = LAT_NATIVE_MIGRATION_CONFIG_TARGET;
    memcpy(entries[1].config_sha256, trailer->target_config_sha256, 32);
    memset(output + proof_offset, 0x5a, 4);
    memcpy(output + config_bytes_offset, old_data, old_size);
    memcpy(output + config_bytes_offset + old_size, target_data, target_size);
    assert(header->translation_config_size == target_size);
    assert(output + size - header->translation_config_size ==
           output + config_bytes_offset + old_size);
    return size;
}

int main(void)
{
    char error[256] = {0};
    uint8_t v11[4096];
    /* Build target config first so make_v11 can compare the exact bytes. */
    LatTranslationConfig target_seed, unused;
    assert(!lat_translation_config_init(&target_seed,
        "0000000000000000000000000000000000000000000000000000000000000000",
        LAT_CONFIG_ABI_X86_64, 1, error, sizeof(error)));
    target_seed.native_replay_domain = true;
    target_seed.values[LAT_CONFIG_PARALLEL] = 1;
    target_seed.values[LAT_CONFIG_CVT_OPT] = 1;
    GBytes *target_bytes = NULL;
    assert(!lat_translation_config_encode(&target_seed, &target_bytes,
                                          error, sizeof(error)));
    (void)make_v11(v11, target_bytes, &unused, &target_seed);
    LatTranslationConfig old_config = target_seed;
    old_config.values[LAT_CONFIG_CVT_OPT] = 0;
    GBytes *old_bytes = NULL;
    assert(!lat_translation_config_encode(&old_config, &old_bytes,
                                          error, sizeof(error)));

    uint8_t v12[8192];
    size_t size = make_v12(v12, v11, old_bytes, target_bytes);
    LatNativeMigrationViewV12 view;
    int valid = lat_native_migration_v12_validate(v12, size, &view,
                                                   error, sizeof(error));
    if (valid) fprintf(stderr, "v12 validation failed: %s\n", error);
    assert(!valid);
    assert(view.trailer.authorization_state == LAT_NATIVE_MIGRATION_QUARANTINED);
    assert(view.trailer.config_count == 2 && view.trailer.target_config_index == 1);
    assert(view.origin_config_indices[0] == 0);

    uint8_t changed[8192];
    memcpy(changed, v12, size);
    LatNativeMigrationTrailerV12 *trailer = (void *)(changed +
        ((LatNativeImageHeaderV2 *)changed)->tu_table_offset +
        ((LatNativeImageHeaderV2 *)changed)->tu_count * sizeof(LatNativeTuV1));
    trailer->authorization_state = LAT_NATIVE_MIGRATION_VERIFIED_TARGET;
    assert(lat_native_migration_v12_validate(changed, size, NULL,
                                              error, sizeof(error)));

    memcpy(changed, v12, size);
    LatNativeTuV1 *tu = (void *)(changed +
        ((LatNativeImageHeaderV2 *)changed)->tu_table_offset);
    tu->config_dependencies |= UINT64_C(1) << LAT_CONFIG_CVT_OPT;
    assert(lat_native_migration_v12_validate(changed, size, NULL,
                                              error, sizeof(error)));

    memcpy(changed, v12, size);
    trailer = (void *)(changed +
        ((LatNativeImageHeaderV2 *)changed)->tu_table_offset +
        ((LatNativeImageHeaderV2 *)changed)->tu_count * sizeof(LatNativeTuV1));
    uint32_t bad_origin = 9;
    memcpy(changed + trailer->origin_index_offset, &bad_origin, sizeof(bad_origin));
    assert(lat_native_migration_v12_validate(changed, size, NULL,
                                              error, sizeof(error)));

    memcpy(changed, v12, size);
    LatNativeMigrationConfigEntryV12 *entries = (void *)(changed + trailer->config_table_offset);
    entries[1].config_sha256[0] ^= 1;
    assert(lat_native_migration_v12_validate(changed, size, NULL,
                                              error, sizeof(error)));

    memcpy(changed, v12, size);
    entries = (void *)(changed + trailer->config_table_offset);
    entries[0].flags = LAT_NATIVE_MIGRATION_CONFIG_TARGET;
    assert(lat_native_migration_v12_validate(changed, size, NULL,
                                              error, sizeof(error)));
    assert(lat_native_migration_v12_validate(v12, size - 1, NULL,
                                              error, sizeof(error)));

    g_bytes_unref(old_bytes);
    g_bytes_unref(target_bytes);
    puts("test-native-migration-v12: PASS target/origin/table/proof/quarantine/reject");
    return 0;
}
