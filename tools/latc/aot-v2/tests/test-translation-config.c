#include "lat-translation-config.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static const char build[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void set32(uint8_t *data, uint32_t value)
{
    value = GUINT32_TO_LE(value);
    memcpy(data, &value, sizeof(value));
}

int main(void)
{
    char error[128];
    LatTranslationConfig config, decoded, changed;
    assert(!lat_translation_config_init(&config, build, LAT_CONFIG_ABI_X86_64,
                                        36, error, sizeof(error)));
    for (size_t i = 0; i < LAT_CONFIG_FIELD_COUNT; i++) {
        assert(lat_translation_config_field_name(i));
        for (size_t j = 0; j < i; j++) {
            assert(strcmp(lat_translation_config_field_name(i),
                          lat_translation_config_field_name(j)));
        }
        config.values[i] = (int64_t)i - 20;
    }
    assert(!lat_translation_config_field_name(-1));
    assert(!lat_translation_config_field_name(LAT_CONFIG_FIELD_COUNT));
    config.values[LAT_CONFIG_CVT_OPT] = INT64_MIN;
    config.values[LAT_CONFIG_ROUNDING_OPT] = INT64_MAX;
    config.features[0] = UINT64_MAX;
    config.features[35] = UINT64_C(0x0123456789abcdef);
    GBytes *bytes = NULL;
    assert(!lat_translation_config_encode(&config, &bytes, error, sizeof(error)));
    size_t size;
    const uint8_t *data = g_bytes_get_data(bytes, &size);
    assert(size == 64 + 8 * (LAT_CONFIG_FIELD_COUNT + 36));
    assert(!memcmp(data, "LATCFG1", 8));
    assert(data[8] == 1 && data[9] == 0 && data[12] == (size & 255));
    assert(data[64 + 8 * LAT_CONFIG_CVT_OPT + 7] == 0x80);
    assert(!lat_translation_config_decode(data, size, config.build_id, &decoded,
                                          error, sizeof(error)));
    GBytes *again = NULL;
    assert(!lat_translation_config_encode(&decoded, &again, error, sizeof(error)));
    assert(g_bytes_equal(bytes, again));
    g_bytes_unref(again);
    uint8_t digest[32], other_digest[32];
    assert(!lat_translation_config_digest(&config, digest, error, sizeof(error)));
    uint64_t difference = UINT64_MAX;
    assert(!lat_translation_config_diff(&config, &decoded, &difference,
                                        error, sizeof(error)) && !difference);
    assert(!lat_translation_config_compatible(&config, &decoded));
    config.compatibility_complete = decoded.compatibility_complete = true;
    assert(lat_translation_config_compatible(&config, &decoded));
    changed = config;
    changed.values[LAT_CONFIG_CVT_OPT]++;
    assert(!lat_translation_config_diff(&config, &changed, &difference,
                                        error, sizeof(error)));
    assert(difference == (UINT64_C(1) << LAT_CONFIG_CVT_OPT));
    assert(!lat_translation_config_compatible(&config, &changed));
    changed = config;
    changed.features[35] ^= 1;
    assert(!lat_translation_config_diff(&config, &changed, &difference,
                                        error, sizeof(error)));
    assert(difference == LAT_CONFIG_CPU_FEATURES_BIT);
    changed = config;
    changed.build_id[0] ^= 1;
    assert(lat_translation_config_diff(&config, &changed, &difference,
                                       error, sizeof(error)));
    assert(difference == LAT_CONFIG_ALL_BITS);
    assert(!lat_translation_config_digest(&config, digest, error, sizeof(error)));
    assert(!lat_translation_config_digest(&changed, other_digest, error, sizeof(error)));
    assert(!memcmp(digest, other_digest, 32));
    for (size_t i = 0; i < LAT_CONFIG_FIELD_COUNT; i++) {
        changed = config;
        changed.values[i] ^= 1;
        assert(!lat_translation_config_diff(&config, &changed, &difference,
                                            error, sizeof(error)));
        assert(difference == (UINT64_C(1) << i));
        assert(!lat_translation_config_digest(&changed, other_digest,
                                              error, sizeof(error)));
        assert(memcmp(digest, other_digest, 32));
    }
    changed = config;
    changed.features[63] = 1;
    assert(!lat_translation_config_digest(&changed, other_digest, error, sizeof(error)));
    assert(!memcmp(digest, other_digest, 32));
    assert(lat_translation_config_compatible(&config, &changed));
    changed = config;
    changed.values[LAT_CONFIG_CVT_OPT]++;
    assert(!lat_translation_config_digest(&changed, other_digest, error, sizeof(error)));
    assert(memcmp(digest, other_digest, 32));
    changed = config;
    changed.guest_abi = LAT_CONFIG_ABI_I386;
    assert(lat_translation_config_diff(&config, &changed, &difference,
                                       error, sizeof(error)));
    changed = config;
    changed.feature_count--;
    assert(lat_translation_config_diff(&config, &changed, &difference,
                                       error, sizeof(error)));
    changed = config;
    changed.native_replay_domain = true;
    assert(lat_translation_config_diff(&config, &changed, &difference,
                                       error, sizeof(error)));
    assert(!lat_translation_config_encode(&changed, &again, error, sizeof(error)));
    size_t domain_size;
    const void *domain_data = g_bytes_get_data(again, &domain_size);
    assert(!lat_translation_config_decode(domain_data, domain_size, NULL, &decoded,
                                          error, sizeof(error)));
    assert(decoded.native_replay_domain && decoded.compatibility_complete);
    g_bytes_unref(again);
    changed = config;
    changed.compatibility_complete = false;
    assert(lat_translation_config_diff(&config, &changed, &difference,
                                       error, sizeof(error)));

    for (size_t i = 0; i < size; i++) {
        memset(&decoded, 0xff, sizeof(decoded));
        assert(lat_translation_config_decode(data, i, NULL, &decoded,
                                              error, sizeof(error)));
        assert(decoded.version == 0 && decoded.feature_count == 0);
    }
    uint8_t *unaligned = g_malloc(size + 2);
    memcpy(unaligned + 1, data, size);
    assert(!lat_translation_config_decode(unaligned + 1, size, NULL, &decoded,
                                          error, sizeof(error)));
    const uint32_t offsets[] = {8, 12, 16, 20, 24, 28};
    const uint32_t bad_values[] = {2, 0, 4, 3, LAT_CONFIG_FIELD_COUNT + 1, 65};
    for (size_t i = 0; i < G_N_ELEMENTS(offsets); i++) {
        memcpy(unaligned + 1, data, size);
        set32(unaligned + 1 + offsets[i], bad_values[i]);
        assert(lat_translation_config_decode(unaligned + 1, size, NULL,
                                              &decoded, error, sizeof(error)));
    }
    memcpy(unaligned + 1, data, size);
    unaligned[1] ^= 1;
    assert(lat_translation_config_decode(unaligned + 1, size, NULL, &decoded,
                                          error, sizeof(error)));
    assert(lat_translation_config_decode(data, size + 1, NULL, &decoded,
                                          error, sizeof(error)));
    uint8_t wrong_build[32] = {0};
    assert(lat_translation_config_decode(data, size, wrong_build, &decoded,
                                          error, sizeof(error)));
    assert(lat_translation_config_decode(NULL, size, NULL, &decoded, NULL, 0));
    assert(lat_translation_config_init(&decoded, "bad", LAT_CONFIG_ABI_X86_64,
                                       36, error, sizeof(error)));
    assert(lat_translation_config_init(&decoded,
        "z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        LAT_CONFIG_ABI_X86_64, 36, error, sizeof(error)));
    assert(lat_translation_config_init(&decoded, build, LAT_CONFIG_ABI_X86_64,
                                       0, error, sizeof(error)));
    assert(lat_translation_config_init(&decoded, build, LAT_CONFIG_ABI_X86_64,
                                       65, error, sizeof(error)));
    assert(!lat_translation_config_compatible(NULL, &config));
    g_free(unaligned);
    g_bytes_unref(bytes);
    puts("translation configuration codec/diff tests: PASS");
    return 0;
}
