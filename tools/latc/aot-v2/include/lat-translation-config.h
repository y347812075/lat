/*
 * SPDX-FileCopyrightText: 2026 LAT Project Authors
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LAT_TRANSLATION_CONFIG_H
#define LAT_TRANSLATION_CONFIG_H

#include <glib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LAT_TRANSLATION_CONFIG_VERSION 1
#define LAT_TRANSLATION_CONFIG_FEATURE_LIMIT 64
#define LAT_TRANSLATION_CONFIG_HEADER_SIZE 64

/* Field order, count, and meanings are frozen within a schema version. */
#define LAT_TRANSLATION_CONFIG_FIELDS(X) \
    X(ANONYM, anonym) \
    X(AVX512_SUPPORTED, avx512_supported) \
    X(AVX_BUILD, avx_build) \
    X(AVX_CPUID, avx_cpuid) \
    X(CLOSE_PARALLEL, close_parallel) \
    X(CVT_OPT, cvt_opt) \
    X(ENABLE_FCSR_EXC, enable_fcsr_exc) \
    X(ENABLE_LASX, enable_lasx) \
    X(FAST_ATOMIC, fast_atomic) \
    X(FLAG_REDUCTION, flag_reduction) \
    X(FPUTAG, fputag) \
    X(HOST_ATOMIC, host_atomic) \
    X(HOST_HWCAP, host_hwcap) \
    X(HOST_SCQ, host_scq) \
    X(IMM_COMPLEX, imm_complex) \
    X(IMM_PRECACHE, imm_precache) \
    X(IMM_REG, imm_reg) \
    X(IMM_RIP, imm_rip) \
    X(INSTPTN, instptn) \
    X(JR_RA, jr_ra) \
    X(JR_RA_STACK, jr_ra_stack) \
    X(LATIVE, lative) \
    X(LEGACY_AOT, legacy_aot) \
    X(MEM_TEST, mem_test) \
    X(MINKE_16K_PAGE_CHECK, minke_16k_page_check) \
    X(MONITOR_SHARED_MEM, monitor_shared_mem) \
    X(PARALLEL, parallel) \
    X(ROUNDING_OPT, rounding_opt) \
    X(SAVE_XMM, save_xmm) \
    X(SMC_OPT, smc_opt) \
    X(SMC_RELOAD, smc_reload) \
    X(SOFTFPU, softfpu) \
    X(SOFTFPU_FAST, softfpu_fast) \
    X(SPLIT_TB, split_tb) \
    X(TU_BUILD, tu_build) \
    X(TUNNEL_LIB, tunnel_lib) \
    X(VPAES, vpaes) \
    X(X86_CPUID_LEVEL, x86_cpuid_level) \
    X(X86_CPUID_LEVEL_FUNC7, x86_cpuid_level_func7) \
    X(X86_CPUID_VERSION, x86_cpuid_version) \
    X(X86_CPUID_XLEVEL, x86_cpuid_xlevel) \
    X(X86_CPUID_XLEVEL2, x86_cpuid_xlevel2)

typedef enum LatTranslationConfigField {
#define FIELD(id, name) LAT_CONFIG_##id,
    LAT_TRANSLATION_CONFIG_FIELDS(FIELD)
#undef FIELD
    LAT_CONFIG_FIELD_COUNT,
} LatTranslationConfigField;

#define LAT_CONFIG_CPU_FEATURES_BIT (UINT64_C(1) << LAT_CONFIG_FIELD_COUNT)
#define LAT_CONFIG_ALL_BITS ((LAT_CONFIG_CPU_FEATURES_BIT << 1) - 1)

typedef enum LatTranslationGuestAbi {
    LAT_CONFIG_ABI_X86_64 = 1,
    LAT_CONFIG_ABI_I386 = 2,
} LatTranslationGuestAbi;

/* In-memory representation only. The wire format never copies C padding. */
typedef struct LatTranslationConfig {
    uint32_t version;
    bool compatibility_complete;
    /* Captured in the restricted native-export domain, not cache compatibility. */
    bool native_replay_domain;
    LatTranslationGuestAbi guest_abi;
    uint8_t build_id[32];
    uint32_t feature_count;
    int64_t values[LAT_CONFIG_FIELD_COUNT];
    uint64_t features[LAT_TRANSLATION_CONFIG_FEATURE_LIMIT];
} LatTranslationConfig;

const char *lat_translation_config_field_name(LatTranslationConfigField field);
int lat_translation_config_init(LatTranslationConfig *config,
    const char *build_id, LatTranslationGuestAbi abi, uint32_t feature_count,
    char *error, size_t error_size);
int lat_translation_config_encode(const LatTranslationConfig *config,
    GBytes **bytes, char *error, size_t error_size);
int lat_translation_config_decode(const void *data, size_t size,
    const uint8_t expected_build[32], LatTranslationConfig *config,
    char *error, size_t error_size);
int lat_translation_config_digest(const LatTranslationConfig *config,
    uint8_t digest[32], char *error, size_t error_size);
int lat_translation_config_diff(const LatTranslationConfig *old_config,
    const LatTranslationConfig *new_config, uint64_t *changed,
    char *error, size_t error_size);
bool lat_translation_config_compatible(const LatTranslationConfig *left,
    const LatTranslationConfig *right);

#endif
