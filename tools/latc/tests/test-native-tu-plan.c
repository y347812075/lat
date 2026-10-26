#include "native-tu-plan.h"
#include "native-image.h"
#include "lat-aot-v2.h"
#include "lat-translation-config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_config_plan(const unsigned char *original, size_t size)
{
    unsigned char data[8192] = {0};
    memcpy(data, original, size);
    LatNativeImageHeaderV2 *h = (void *)data;
    memset(h->lat_build_id, '0', 64);
    h->lat_build_id[64] = 0;
    h->flags |= LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    h->translation_config_projection = 1;
    LatTranslationConfig old, target;
    char error[256] = {0};
    assert(!lat_translation_config_init(&old, h->lat_build_id,
        LAT_CONFIG_ABI_X86_64, 1, error, sizeof(error)));
    old.native_replay_domain = true;
    old.values[LAT_CONFIG_PARALLEL] = 1;
    GBytes *encoded = NULL;
    assert(!lat_translation_config_encode(&old, &encoded, error, sizeof(error)));
    gsize length;
    const void *bytes = g_bytes_get_data(encoded, &length);
    assert(length <= sizeof(data) - size);
    memcpy(data + size, bytes, length);
    h->translation_config_size = length;
    assert(!lat_translation_config_digest(&old, h->translation_config_sha256,
                                          error, sizeof(error)));
    LatNativeTuV1 *tus = (void *)(data + h->tu_table_offset);
    for (unsigned i = 0; i < h->tu_count; i++) {
        tus[i].config_dependency_version = LAT_TRANSLATION_CONFIG_VERSION;
        tus[i].config_dependencies = UINT64_C(1) << LAT_CONFIG_ROUNDING_OPT;
    }
    /* Only alias TU1 reads CVT; it must select TU0 and incoming owners too. */
    tus[1].config_dependencies |= UINT64_C(1) << LAT_CONFIG_CVT_OPT;
    LatTbKeySet plan = {0};
    uint64_t changed;
    assert(!lat_native_tu_config_plan(data, size + length, bytes, length,
        &plan, &changed, error, sizeof(error)));
    assert(!changed && !plan.count);
    lat_tb_key_set_destroy(&plan);
    g_bytes_unref(encoded);
    target = old;
    target.values[LAT_CONFIG_CVT_OPT] = 1;
    assert(!lat_translation_config_encode(&target, &encoded, error, sizeof(error)));
    bytes = g_bytes_get_data(encoded, &length);
    assert(!lat_native_tu_config_plan(data, size + h->translation_config_size,
        bytes, length, &plan, &changed, error, sizeof(error)));
    assert(changed == (UINT64_C(1) << LAT_CONFIG_CVT_OPT) && plan.count == 5);
    const unsigned expected[] = {0x10, 0x20, 0x28, 0x30, 0x40};
    for (unsigned i = 0; i < 5; i++) assert(plan.keys[i].guest_rva == expected[i]);
    lat_tb_key_set_destroy(&plan);
    if (LAT_AOT_V2_TBSET_RECORD_LIMIT >= 6) {
        tus[4].config_dependency_version = 0;
        tus[4].config_dependencies = 0;
        assert(!lat_native_tu_config_plan(data, size + h->translation_config_size,
            bytes, length, &plan, &changed, error, sizeof(error)));
        assert(plan.count == 6);
        lat_tb_key_set_destroy(&plan);
        /* Unknown metadata does not turn an identical snapshot into a change. */
        GBytes *same = NULL;
        assert(!lat_translation_config_encode(&old, &same, error, sizeof(error)));
        gsize same_length;
        const void *same_bytes = g_bytes_get_data(same, &same_length);
        assert(!lat_native_tu_config_plan(data, size + h->translation_config_size,
            same_bytes, same_length, &plan, &changed, error, sizeof(error)));
        assert(!changed && !plan.count);
        lat_tb_key_set_destroy(&plan);
        g_bytes_unref(same);
    }
    assert(lat_native_tu_config_plan(data, size + h->translation_config_size,
        bytes, length - 1, &plan, &changed, error, sizeof(error)));
    g_bytes_unref(encoded);
    target = old;
    target.features[0] = 1;
    assert(!lat_translation_config_encode(&target, &encoded, error, sizeof(error)));
    bytes = g_bytes_get_data(encoded, &length);
    assert(!lat_native_tu_config_plan(data, size + h->translation_config_size,
        bytes, length, &plan, &changed, error, sizeof(error)));
    assert(changed == LAT_CONFIG_CPU_FEATURES_BIT);
    if (LAT_AOT_V2_TBSET_RECORD_LIMIT >= 6) {
        assert(plan.count == 1 && plan.keys[0].guest_rva == 0x50);
    } else {
        assert(!plan.count);
    }
    lat_tb_key_set_destroy(&plan);
    g_bytes_unref(encoded);
    target = old;
    target.native_replay_domain = false;
    assert(!lat_translation_config_encode(&target, &encoded, error, sizeof(error)));
    bytes = g_bytes_get_data(encoded, &length);
    assert(lat_native_tu_config_plan(data, size + h->translation_config_size,
        bytes, length, &plan, &changed, error, sizeof(error)));
    g_bytes_unref(encoded);
    target = old;
    target.build_id[0] ^= 1;
    assert(!lat_translation_config_encode(&target, &encoded, error, sizeof(error)));
    bytes = g_bytes_get_data(encoded, &length);
    assert(lat_native_tu_config_plan(data, size + h->translation_config_size,
        bytes, length, &plan, &changed, error, sizeof(error)));
    g_bytes_unref(encoded);
    for (int domain = 0; domain < 3; domain++) {
        target = old;
        if (domain == 0) target.guest_abi = LAT_CONFIG_ABI_I386;
        if (domain == 1) target.feature_count++;
        if (domain == 2) target.compatibility_complete = true;
        assert(!lat_translation_config_encode(&target, &encoded, error, sizeof(error)));
        bytes = g_bytes_get_data(encoded, &length);
        assert(lat_native_tu_config_plan(data, size + h->translation_config_size,
            bytes, length, &plan, &changed, error, sizeof(error)));
        g_bytes_unref(encoded);
    }
    assert(lat_native_tu_config_plan(original, size, NULL, 0, &plan, &changed,
                                     error, sizeof(error)));
}

int main(void)
{
    unsigned char data[4096] = {0};
    LatNativeImageHeaderV2 *h = (void *)data;
    memcpy(h->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    h->version = LAT_NATIVE_IMAGE_VERSION;
    h->header_size = sizeof(*h);
    h->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    strcpy(h->lat_build_id, "test-build");
    h->guest_image_offset = sizeof(*h);
    h->guest_image_size = 8;
    h->preferred_guest_base = 0x400000;
    h->code_offset = h->guest_image_offset + h->guest_image_size;
    h->code_size = 5 * 32;
    h->tb_table_offset = h->code_offset + h->code_size;
    h->tb_count = 7;
    h->relocation_offset = h->tb_table_offset + h->tb_count * sizeof(LatNativeTbV1);
    h->relocation_count = 2;
    h->pc_map_offset = h->relocation_offset + 2 * sizeof(LatNativeRelocationV1);
    h->tu_table_offset = h->pc_map_offset;
    h->tu_count = 5;
    size_t size = h->tu_table_offset + h->tu_count * sizeof(LatNativeTuV1);
    LatNativeTbV1 *tbs = (void *)(data + h->tb_table_offset);
    LatNativeTuV1 *tus = (void *)(data + h->tu_table_offset);
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    for (unsigned int i = 0; i < 5; i++) {
        tus[i] = (LatNativeTuV1){.code_offset = i * 32, .code_size = 32,
                                .search_offset = i * 32 + 24};
    }
    /* TU0 shares two keys; TU1 aliases the second. TU2 -> TU3 -> TU0.
     * TU4 is unrelated and must remain reusable. */
    const unsigned int owners[] = {0, 0, 1, 1, 2, 3, 4};
    const unsigned int pcs[] = {0x10, 0x20, 0x20, 0x28, 0x30, 0x40, 0x50};
    for (unsigned int i = 0; i < 7; i++) {
        tbs[i] = (LatNativeTbV1){.guest_pc = h->preferred_guest_base + pcs[i],
            .code_offset = owners[i] * 32 + (i == 1 || i == 3 ? 8 : 0),
            .code_size = 8, .flags = 3, .tu_index = owners[i]};
    }
    rel[0] = (LatNativeRelocationV1){.code_offset = 64,
        .kind = LAT_NATIVE_RELOC_TB_TARGET, .slots = 1,
        .physical_target_plus_one = 6};
    rel[1] = (LatNativeRelocationV1){.code_offset = 96,
        .kind = LAT_NATIVE_RELOC_TB_TARGET, .slots = 1,
        .physical_target_plus_one = 1};
    LatTbKey key = {.guest_rva = 0x10, .flags = 3};
    LatTbKeySet seeds = {.count = 1, .keys = &key, .sequence = 42}, plan = {0};
    char error[256] = {0};
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    test_config_plan(data, size);
    assert(!lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    assert(plan.count == 5 && plan.sequence == 42);
    const unsigned int expected[] = {0x10, 0x20, 0x28, 0x30, 0x40};
    for (unsigned int i = 0; i < 5; i++) assert(plan.keys[i].guest_rva == expected[i]);
    lat_tb_key_set_destroy(&plan);
    /* Reverse direction must not pull unchanged outgoing dependencies in. */
    key.guest_rva = 0x30;
    assert(!lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    assert(plan.count == 1 && plan.keys[0].guest_rva == 0x30);
    lat_tb_key_set_destroy(&plan);
    /* Cycle termination: TU0 -> TU3 -> TU0, with TU1 aliasing TU0. */
    rel[0].code_offset = 0;
    rel[0].physical_target_plus_one = 6;
    rel[1].physical_target_plus_one = 1;
    key.guest_rva = 0x10;
    assert(!lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    assert(plan.count == 4 && plan.keys[2].guest_rva == 0x28 &&
           plan.keys[3].guest_rva == 0x40);
    lat_tb_key_set_destroy(&plan);
    seeds.count = 0;
    assert(!lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    assert(!plan.count && plan.sequence == 42);
    lat_tb_key_set_destroy(&plan);
    seeds.count = 1;
    key.guest_rva = 0x99;
    assert(lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    key.guest_rva = 0x10;
    /* An incoming edge to only the alias TU must propagate to its owner. */
    rel[0].code_offset = 64;
    rel[0].physical_target_plus_one = 3;
    rel[1].physical_target_plus_one = 1;
    assert(!lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    assert(plan.count == 5);
    lat_tb_key_set_destroy(&plan);
    seeds.source_sha256[0] = 1;
    assert(lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    seeds.source_sha256[0] = 0;
    rel[0].code_offset = 63;
    assert(lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    rel[0].code_offset = 64;
    rel[0].physical_target_plus_one = 8;
    assert(lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    rel[0].physical_target_plus_one = 3;
    key.flags = 1;
    assert(lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error)));
    key.flags = 3;
    assert(lat_native_tu_plan(data, size - 1, &seeds, &plan, error, sizeof(error)));
    LatTbKey two_keys[] = {{.guest_rva = 0x10, .flags = 3},
                          {.guest_rva = 0x30, .flags = 3}};
    seeds.keys = two_keys;
    seeds.count = 2;
    rel[0].code_offset = 128;
    rel[0].physical_target_plus_one = 1;
    rel[1].physical_target_plus_one = 5;
    int status = lat_native_tu_plan(data, size, &seeds, &plan, error, sizeof(error));
    if (LAT_AOT_V2_TBSET_RECORD_LIMIT >= 6) {
        assert(!status && plan.count == 6);
        lat_tb_key_set_destroy(&plan);
    } else {
        assert(status && strstr(error, "exceeds TB set record limit"));
        assert(!plan.keys && !plan.count);
    }
    puts("test-native-tu-plan: PASS unique-key-limit/physical-alias");
    puts("test-native-tu-plan: PASS shared/alias/incoming/cycle/empty/reject");
    return 0;
}
