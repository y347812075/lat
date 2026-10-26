/*
 * SPDX-FileCopyrightText: 2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "lat-translation-config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

G_STATIC_ASSERT(LAT_CONFIG_FIELD_COUNT < 63);

static const uint8_t magic[8] = {'L', 'A', 'T', 'C', 'F', 'G', '1', 0};

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, size, format, arguments);
        va_end(arguments);
    }
    errno = EINVAL;
    return -1;
}

const char *lat_translation_config_field_name(LatTranslationConfigField field)
{
    static const char *const names[] = {
#define FIELD(id, name) #name,
        LAT_TRANSLATION_CONFIG_FIELDS(FIELD)
#undef FIELD
    };
    return (unsigned int)field < LAT_CONFIG_FIELD_COUNT ? names[field] : NULL;
}

static int validate(const LatTranslationConfig *config,
                    char *error, size_t error_size)
{
    if (!config || config->version != LAT_TRANSLATION_CONFIG_VERSION ||
        (config->guest_abi != LAT_CONFIG_ABI_X86_64 &&
         config->guest_abi != LAT_CONFIG_ABI_I386) ||
        !config->feature_count ||
        config->feature_count > LAT_TRANSLATION_CONFIG_FEATURE_LIMIT) {
        return fail(error, error_size, "invalid translation configuration");
    }
    return 0;
}

int lat_translation_config_init(LatTranslationConfig *config,
    const char *build_id, LatTranslationGuestAbi abi, uint32_t feature_count,
    char *error, size_t error_size)
{
    if (!config) return fail(error, error_size, "missing configuration output");
    memset(config, 0, sizeof(*config));
    if (!build_id || strlen(build_id) != 64) {
        return fail(error, error_size, "invalid translation build identity");
    }
    LatTranslationConfig candidate = {
        .version = LAT_TRANSLATION_CONFIG_VERSION,
        .guest_abi = abi,
        .feature_count = feature_count,
    };
    for (size_t i = 0; i < 32; i++) {
        int hi = g_ascii_xdigit_value(build_id[2 * i]);
        int lo = g_ascii_xdigit_value(build_id[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return fail(error, error_size, "invalid translation build identity");
        }
        candidate.build_id[i] = (hi << 4) | lo;
    }
    if (validate(&candidate, error, error_size)) return -1;
    *config = candidate;
    return 0;
}

static void put32(uint8_t *data, uint32_t value)
{
    value = GUINT32_TO_LE(value);
    memcpy(data, &value, sizeof(value));
}

static void put64(uint8_t *data, uint64_t value)
{
    value = GUINT64_TO_LE(value);
    memcpy(data, &value, sizeof(value));
}

static uint32_t get32(const uint8_t *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return GUINT32_FROM_LE(value);
}

static uint64_t get64(const uint8_t *data)
{
    uint64_t value;
    memcpy(&value, data, sizeof(value));
    return GUINT64_FROM_LE(value);
}

int lat_translation_config_encode(const LatTranslationConfig *config,
    GBytes **bytes, char *error, size_t error_size)
{
    if (!bytes) return fail(error, error_size, "missing configuration bytes output");
    *bytes = NULL;
    if (validate(config, error, error_size)) return -1;
    size_t size = LAT_TRANSLATION_CONFIG_HEADER_SIZE +
        8 * (LAT_CONFIG_FIELD_COUNT + config->feature_count);
    uint8_t *data = g_malloc0(size);
    memcpy(data, magic, sizeof(magic));
    put32(data + 8, config->version);
    put32(data + 12, size);
    put32(data + 16, (config->compatibility_complete ? 1 : 0) |
                    (config->native_replay_domain ? 2 : 0));
    put32(data + 20, config->guest_abi);
    put32(data + 24, LAT_CONFIG_FIELD_COUNT);
    put32(data + 28, config->feature_count);
    memcpy(data + 32, config->build_id, 32);
    size_t offset = LAT_TRANSLATION_CONFIG_HEADER_SIZE;
    for (size_t i = 0; i < LAT_CONFIG_FIELD_COUNT; i++, offset += 8) {
        put64(data + offset, (uint64_t)config->values[i]);
    }
    for (size_t i = 0; i < config->feature_count; i++, offset += 8) {
        put64(data + offset, config->features[i]);
    }
    *bytes = g_bytes_new_take(data, size);
    return 0;
}

int lat_translation_config_decode(const void *input, size_t size,
    const uint8_t expected_build[32], LatTranslationConfig *config,
    char *error, size_t error_size)
{
    if (!config) return fail(error, error_size, "missing configuration output");
    memset(config, 0, sizeof(*config));
    if (!input || size < LAT_TRANSLATION_CONFIG_HEADER_SIZE) {
        return fail(error, error_size, "truncated translation configuration");
    }
    const uint8_t *data = input;
    uint32_t features = get32(data + 28);
    if (memcmp(data, magic, sizeof(magic)) ||
        get32(data + 8) != LAT_TRANSLATION_CONFIG_VERSION ||
        get32(data + 12) != size || get32(data + 16) > 3 ||
        get32(data + 24) != LAT_CONFIG_FIELD_COUNT || !features ||
        features > LAT_TRANSLATION_CONFIG_FEATURE_LIMIT ||
        size != LAT_TRANSLATION_CONFIG_HEADER_SIZE +
            8 * (LAT_CONFIG_FIELD_COUNT + features) ||
        (expected_build && memcmp(data + 32, expected_build, 32))) {
        return fail(error, error_size, "invalid translation configuration header");
    }
    LatTranslationConfig candidate = {
        .version = get32(data + 8),
        .compatibility_complete = (get32(data + 16) & 1) != 0,
        .native_replay_domain = (get32(data + 16) & 2) != 0,
        .guest_abi = get32(data + 20),
        .feature_count = features,
    };
    memcpy(candidate.build_id, data + 32, 32);
    size_t offset = LAT_TRANSLATION_CONFIG_HEADER_SIZE;
    for (size_t i = 0; i < LAT_CONFIG_FIELD_COUNT; i++, offset += 8) {
        uint64_t bits = get64(data + offset);
        memcpy(&candidate.values[i], &bits, sizeof(bits));
    }
    for (size_t i = 0; i < features; i++, offset += 8) {
        candidate.features[i] = get64(data + offset);
    }
    if (validate(&candidate, error, error_size)) return -1;
    *config = candidate;
    return 0;
}

int lat_translation_config_digest(const LatTranslationConfig *config,
    uint8_t digest[32], char *error, size_t error_size)
{
    GBytes *bytes = NULL;
    if (!digest) return fail(error, error_size, "missing configuration digest");
    memset(digest, 0, 32);
    if (lat_translation_config_encode(config, &bytes, error, error_size)) return -1;
    size_t size;
    const uint8_t *data = g_bytes_get_data(bytes, &size);
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    /* Build identity is checked separately; this hash describes configuration. */
    g_checksum_update(checksum, data, 32);
    g_checksum_update(checksum, data + LAT_TRANSLATION_CONFIG_HEADER_SIZE,
                      size - LAT_TRANSLATION_CONFIG_HEADER_SIZE);
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    g_checksum_free(checksum);
    g_bytes_unref(bytes);
    return 0;
}

int lat_translation_config_diff(const LatTranslationConfig *old_config,
    const LatTranslationConfig *new_config, uint64_t *changed,
    char *error, size_t error_size)
{
    if (!changed) return fail(error, error_size, "missing configuration difference");
    *changed = LAT_CONFIG_ALL_BITS;
    if (validate(old_config, error, error_size) ||
        validate(new_config, error, error_size)) return -1;
    if (old_config->guest_abi != new_config->guest_abi ||
        old_config->feature_count != new_config->feature_count ||
        old_config->compatibility_complete != new_config->compatibility_complete ||
        old_config->native_replay_domain != new_config->native_replay_domain ||
        memcmp(old_config->build_id, new_config->build_id, 32)) {
        return fail(error, error_size, "translation configuration domain differs");
    }
    *changed = 0;
    for (size_t i = 0; i < LAT_CONFIG_FIELD_COUNT; i++) {
        if (old_config->values[i] != new_config->values[i]) {
            *changed |= UINT64_C(1) << i;
        }
    }
    if (memcmp(old_config->features, new_config->features,
               old_config->feature_count * sizeof(uint64_t))) {
        *changed |= LAT_CONFIG_CPU_FEATURES_BIT;
    }
    return 0;
}

bool lat_translation_config_compatible(const LatTranslationConfig *left,
    const LatTranslationConfig *right)
{
    uint64_t changed;
    return left && right && left->compatibility_complete &&
        right->compatibility_complete &&
        !lat_translation_config_diff(left, right, &changed, NULL, 0) && !changed;
}
