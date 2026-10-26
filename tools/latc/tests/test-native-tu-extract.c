#include "native-tu-plan.h"
#include "native-image.h"
#include "lat-translation-config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t fixture(uint8_t *data)
{
    memset(data, 0, 8192);
    LatNativeImageHeaderV2 *h = (void *)data;
    memcpy(h->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    h->version = LAT_NATIVE_IMAGE_VERSION;
    h->header_size = sizeof(*h);
    h->flags = LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    memcpy(h->lat_build_id, LATC_BUILD_ID, 65);
    h->guest_image_offset = sizeof(*h);
    h->guest_image_size = 8;
    h->code_offset = sizeof(*h) + 8;
    h->code_size = 512;
    h->tb_table_offset = h->code_offset + h->code_size;
    h->tb_count = 4;
    h->relocation_offset = h->tb_table_offset + 4 * sizeof(LatNativeTbV1);
    h->relocation_count = 5;
    h->pc_map_offset = h->relocation_offset + 5 * sizeof(LatNativeRelocationV1);
    h->pc_map_count = 3;
    h->tu_table_offset = h->pc_map_offset + 3 * sizeof(LatNativePcMapV2);
    h->tu_count = 3;
    LatNativeTuV1 *tus = (void *)(data + h->tu_table_offset);
    LatNativeTbV1 *tbs = (void *)(data + h->tb_table_offset);
    LatNativePcMapV2 *maps = (void *)(data + h->pc_map_offset);
    for (unsigned i = 0; i < 3; i++) {
        tus[i] = (LatNativeTuV1){.code_offset = i * 96, .code_size = 64,
            .search_offset = i * 96 + 56};
        tbs[i] = (LatNativeTbV1){.guest_pc = (i + 1) * 16,
            .code_offset = i * 96, .code_size = 24, .flags = 3, .tu_index = i};
        maps[i] = (LatNativePcMapV2){.guest_pc = (i + 1) * 16,
            .host_offset_begin = i * 96, .host_offset_end = i * 96 + 24,
            .state_record_offset = (uint32_t)-32,
            .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE | LAT_NATIVE_PC_MAP_STACK_POINTER_DELTA};
        for (unsigned j = 0; j < 16; j++) {
            uint32_t word = j == 13 ? 0x50000000u : 0x03400000u;
            memcpy(data + h->code_offset + i * 96 + j * 4, &word, 4);
        }
    }
    tbs[3] = (LatNativeTbV1){.guest_pc = 64, .code_offset = 224,
        .code_size = 24, .flags = 3, .tu_index = 2};
    LatNativeRelocationV1 *rels = (void *)(data + h->relocation_offset);
    const unsigned sites[] = {0, 96, 192, 224};
    for (unsigned i = 0; i < 4; i++) {
        unsigned base = i == 1 ? 448 : 320;
        rels[i] = (LatNativeRelocationV1){.code_offset = sites[i],
            .kind = LAT_NATIVE_RELOC_IMAGE_DATA, .slots = 3,
            .addend = base + 16, .reserved = 48,
            .data_object_offset = base, .data_object_size = 64,
            .data_object_alignment = 64,
            .data_object_flags = LAT_NATIVE_DATA_POINTER_FREE};
        uint32_t words[] = {0x1400000c, 0x0380018c, 0x1600000c};
        memcpy(data + h->code_offset + sites[i], words, sizeof(words));
    }
    rels[4] = (LatNativeRelocationV1){.code_offset = 240, .slots = 1,
        .kind = LAT_NATIVE_RELOC_TB_TARGET, .target = 3, .addend = 32,
        .physical_target_plus_one = 2};
    uint32_t branch = 0x50000000u;
    memcpy(data + h->code_offset + 240, &branch, 4);
    memset(data + h->code_offset + 320, 0xa5, 64);
    memset(data + h->code_offset + 448, 0xb6, 64);
    LatTranslationConfig config;
    char error[256] = {0};
    assert(!lat_translation_config_init(&config, h->lat_build_id,
        LAT_CONFIG_ABI_X86_64, 1, error, sizeof(error)));
    config.native_replay_domain = true;
    config.values[LAT_CONFIG_PARALLEL] = 1;
    GBytes *encoded = NULL;
    assert(!lat_translation_config_encode(&config, &encoded, error, sizeof(error)));
    gsize length;
    const void *snapshot = g_bytes_get_data(encoded, &length);
    size_t size = h->tu_table_offset + 3 * sizeof(*tus);
    memcpy(data + size, snapshot, length);
    h->translation_config_size = length;
    h->translation_config_projection = 1;
    assert(!lat_translation_config_digest(&config, h->translation_config_sha256,
                                          error, sizeof(error)));
    g_bytes_unref(encoded);
    assert(!lat_native_image_validate(data, size + length, error, sizeof(error)));
    return size + length;
}

int main(void)
{
    uint8_t data[8192];
    size_t size = fixture(data), length = 0;
    LatTbKey key = {.guest_rva = 16, .flags = 3};
    LatTbKeySet remove = {.count = 1, .keys = &key};
    void *output = NULL;
    char error[256] = {0};
    assert(!lat_native_tu_extract(data, size, &remove, &output, &length, error, sizeof(error)));
    LatNativeImageHeaderV2 *h = output;
    assert(h->tu_count == 2 && h->tb_count == 3 && h->code_size == 256);
    assert(h->flags == LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED && length < size);
    LatNativeTbV1 *tbs = (void *)((uint8_t *)output + h->tb_table_offset);
    assert(tbs[0].guest_pc == 32 && !tbs[0].code_offset && !tbs[0].tu_index);
    assert(tbs[1].guest_pc == 48 && tbs[1].code_offset == 64 && tbs[1].tu_index == 1);
    LatNativeRelocationV1 *rels = (void *)((uint8_t *)output + h->relocation_offset);
    assert(h->relocation_count == 4 && rels[3].physical_target_plus_one == 1);
    assert(rels[0].data_object_offset == 128 && rels[0].addend == 144);
    assert(rels[1].data_object_offset == 192 && rels[2].data_object_offset == 192);
    assert(!memcmp((uint8_t *)output + h->code_offset + 192,
                   data + ((LatNativeImageHeaderV2 *)data)->code_offset + 320, 64));
    LatNativePcMapV2 *maps = (void *)((uint8_t *)output + h->pc_map_offset);
    assert(h->pc_map_count == 2 && !maps[0].host_offset_begin &&
           maps[1].host_offset_begin == 64 && maps[1].state_record_offset == (uint32_t)-32);
    assert(!memcmp((uint8_t *)output + length - h->translation_config_size,
                   data + size - h->translation_config_size, h->translation_config_size));
    g_free(output);
    /* Removing TU1 closes its incoming TU2; its unique constant must disappear. */
    key.guest_rva = 32;
    assert(!lat_native_tu_extract(data, size, &remove, &output, &length, error, sizeof(error)));
    h = output;
    assert(h->tu_count == 1 && h->tb_count == 1 && h->relocation_count == 1 && h->code_size == 128);
    g_free(output);
    LatTbKey all[] = {{.guest_rva = 16, .flags = 3}, {.guest_rva = 32, .flags = 3}};
    remove.keys = all;
    remove.count = 2;
    assert(lat_native_tu_extract(data, size, &remove, &output, &length, error, sizeof(error)));
    assert(!output && !length && strstr(error, "empty TU complement"));
    remove.keys = &key;
    remove.count = 0;
    assert(!lat_native_tu_extract(data, size, &remove, &output, &length, error, sizeof(error)));
    assert(((LatNativeImageHeaderV2 *)output)->tb_count == 4);
    g_free(output);
    h = (void *)data;
    maps = (void *)(data + h->pc_map_offset);
    maps[0].host_offset_end = 80;
    h->pc_map_count = 3;
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    assert(lat_native_tu_extract(data, size, &remove, &output, &length, error, sizeof(error)));
    assert(strstr(error, "PC map has no complete TU owner"));
    size = fixture(data);
    size_t ordinary_size = size - h->translation_config_size;
    h->flags = 0;
    h->translation_config_size = h->translation_config_projection = 0;
    memset(h->translation_config_sha256, 0, 32);
    assert(!lat_native_image_validate(data, ordinary_size, error, sizeof(error)));
    assert(lat_native_tu_extract(data, ordinary_size,
        &remove, &output, &length, error, sizeof(error)));
    assert(strstr(error, "quarantined configuration replay"));
    puts("test-native-tu-extract: PASS compact/closure/remap/objects/maps/quarantine/reject");
    return 0;
}
