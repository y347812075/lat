/*
 * SPDX-FileCopyrightText: 2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "latx-config.h"
#include "latx-options.h"
#include "latc-build-id.h"
#include "latc-translation-capabilities.h"
#include "lat-translation-config.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qlist.h"
#include <sys/auxv.h>
#include <sys/mman.h>
#include "translate.h"
#include "lsenv.h"

G_STATIC_ASSERT(FEATURE_WORDS <= LAT_TRANSLATION_CONFIG_FEATURE_LIMIT);

#ifdef CONFIG_LATX_KZT
extern int wine_option_kzt;
#endif

bool latx_translation_config_native_domain(void)
{
#if defined(CONFIG_LATX_DEBUG) || defined(CONFIG_DEBUG_TCG)
    return false;
#else
#ifdef CONFIG_LATX_KZT
    if (option_kzt || wine_option_kzt) return false;
#endif
    return !option_real_maps && !option_begin_trace_addr &&
           !option_end_trace_addr && !imm_skip_pc && !option_softfpu &&
           !option_jr_ra && !option_anonym && !option_mem_test &&
           !option_minke_16k_page_check;
#endif
}

static bool native_replay;
static uint8_t native_replay_digest[32];
static GBytes *native_replay_bytes;
static const LatTranslationConfig *native_replay_config;

bool latx_translation_native_replay(void)
{
    return native_replay;
}

int latx_translation_cvt_opt(void)
{
    TranslationBlock *tb = lsenv->tr_data->curr_tb;
    if (tb) {
        tb->translation_config_dependencies |= UINT64_C(1) << LAT_CONFIG_CVT_OPT;
    }
    return native_replay ? native_replay_config->values[LAT_CONFIG_CVT_OPT] : option_cvt_opt;
}

int latx_translation_rounding_opt(void)
{
    return native_replay ? native_replay_config->values[LAT_CONFIG_ROUNDING_OPT] : option_set_rounding_opt;
}

int latx_translation_vpaes(void)
{
    return native_replay ? native_replay_config->values[LAT_CONFIG_VPAES] : option_vpaes;
}

int latx_translation_fast_atomic(void)
{
    return native_replay ? native_replay_config->values[LAT_CONFIG_FAST_ATOMIC] : option_fast_atomic;
}

int latx_translation_enable_lasx(void)
{
    return native_replay ? native_replay_config->values[LAT_CONFIG_ENABLE_LASX] : option_enable_lasx;
}

int latx_translation_host_scq(void)
{
    return native_replay ? native_replay_config->values[LAT_CONFIG_HOST_SCQ] : !!have_scq();
}

#define IMM_ACCESSOR(name, field, option) \
    int latx_translation_##name(void) \
    { \
        return native_replay ? native_replay_config->values[LAT_CONFIG_##field] : option; \
    }
IMM_ACCESSOR(imm_reg, IMM_REG, option_imm_reg)
IMM_ACCESSOR(imm_rip, IMM_RIP, option_imm_rip)
IMM_ACCESSOR(imm_precache, IMM_PRECACHE, option_imm_precache)
IMM_ACCESSOR(imm_complex, IMM_COMPLEX, option_imm_complex)
IMM_ACCESSOR(fputag, FPUTAG, option_fputag)
IMM_ACCESSOR(save_xmm, SAVE_XMM, option_save_xmm)
IMM_ACCESSOR(enable_fcsr_exc, ENABLE_FCSR_EXC, option_enable_fcsr_exc)
#undef IMM_ACCESSOR

void latx_translation_config_set_native_replay(const LatTranslationConfig *config)
{
    char error[128];
    LatTranslationConfig *frozen;

    if (native_replay_config) {
        g_error("native replay configuration already frozen");
    }

    if (lat_translation_config_digest(config, native_replay_digest,
                                      error, sizeof(error))) {
        g_error("cannot digest native replay configuration: %s", error);
    }
    if (lat_translation_config_encode(config, &native_replay_bytes,
                                      error, sizeof(error))) {
        g_error("cannot encode native replay configuration: %s", error);
    }
    frozen = mmap(NULL, sizeof(*frozen), PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (frozen == MAP_FAILED) {
        g_error("cannot allocate native replay configuration: %s", strerror(errno));
    }
    *frozen = *config;
    if (mprotect(frozen, sizeof(*frozen), PROT_READ)) {
        g_error("cannot freeze native replay configuration: %s", strerror(errno));
    }
    native_replay_config = frozen;
    native_replay = true;
}

GBytes *latx_translation_config_native_replay_bytes(void)
{
    return native_replay_bytes;
}

bool latx_translation_config_native_replay_digest(uint8_t digest[32])
{
    if (native_replay) {
        memcpy(digest, native_replay_digest, sizeof(native_replay_digest));
    }
    return native_replay;
}

void latx_translation_config_capture(CPUX86State *env, uint32_t cflags,
                                    LatTranslationConfig *output)
{
    LatTranslationConfig snapshot;
    char error[128];

    if (lat_translation_config_init(&snapshot, LATC_BUILD_ID,
#ifdef TARGET_X86_64
                                    LAT_CONFIG_ABI_X86_64,
#else
                                    LAT_CONFIG_ABI_I386,
#endif
                                    FEATURE_WORDS, error, sizeof(error))) {
        g_error("cannot initialize translation configuration: %s", error);
    }

    /* Export parsed integers, never raw environment text or its provenance. */
#define VALUE(id, value) snapshot.values[LAT_CONFIG_##id] = (int64_t)(value)
    VALUE(ANONYM, option_anonym);
    VALUE(AVX512_SUPPORTED, LATC_TRANSLATOR_AVX512_SUPPORTED);
#ifdef CONFIG_LATX_AVX_OPT
    VALUE(AVX_BUILD, 1);
    VALUE(AVX_CPUID, option_avx_cpuid);
#else
    VALUE(AVX_BUILD, 0);
    VALUE(AVX_CPUID, 0);
#endif
    VALUE(CLOSE_PARALLEL, close_latx_parallel);
    VALUE(CVT_OPT, option_cvt_opt);
    VALUE(ENABLE_FCSR_EXC, option_enable_fcsr_exc);
    VALUE(ENABLE_LASX, option_enable_lasx);
    VALUE(FAST_ATOMIC, option_fast_atomic);
#ifdef CONFIG_LATX_FLAG_REDUCTION
    VALUE(FLAG_REDUCTION, option_flag_reduction);
#else
    VALUE(FLAG_REDUCTION, 0);
#endif
    VALUE(FPUTAG, option_fputag);
    VALUE(HOST_ATOMIC, !!have_am());
    VALUE(HOST_HWCAP, qemu_getauxval(AT_HWCAP));
    VALUE(HOST_SCQ, !!have_scq());
    VALUE(IMM_COMPLEX, option_imm_complex);
    VALUE(IMM_PRECACHE, option_imm_precache);
    VALUE(IMM_REG, option_imm_reg);
    VALUE(IMM_RIP, option_imm_rip);
#ifdef CONFIG_LATX_INSTS_PATTERN
    VALUE(INSTPTN, option_instptn);
#else
    VALUE(INSTPTN, 0);
#endif
    VALUE(JR_RA, option_jr_ra);
    VALUE(JR_RA_STACK, option_jr_ra_stack);
    VALUE(LATIVE, option_lative);
    VALUE(LEGACY_AOT, option_aot);
    VALUE(MEM_TEST, option_mem_test);
    VALUE(MINKE_16K_PAGE_CHECK, option_minke_16k_page_check);
    VALUE(MONITOR_SHARED_MEM, option_monitor_shared_mem);
    VALUE(PARALLEL, !!(cflags & CF_PARALLEL));
    VALUE(ROUNDING_OPT, option_set_rounding_opt);
    VALUE(SAVE_XMM, option_save_xmm);
    VALUE(SMC_OPT, option_smc_opt);
    VALUE(SMC_RELOAD, option_smc_reload);
    VALUE(SOFTFPU, option_softfpu);
    VALUE(SOFTFPU_FAST, option_softfpu_fast);
    VALUE(SPLIT_TB, option_split_tb);
#ifdef CONFIG_LATX_TU
    VALUE(TU_BUILD, 1);
#else
    VALUE(TU_BUILD, 0);
#endif
    VALUE(TUNNEL_LIB, option_tunnel_lib);
    VALUE(VPAES, option_vpaes);
    VALUE(X86_CPUID_LEVEL, env->cpuid_level);
    VALUE(X86_CPUID_LEVEL_FUNC7, env->cpuid_level_func7);
    VALUE(X86_CPUID_VERSION, env->cpuid_version);
    VALUE(X86_CPUID_XLEVEL, env->cpuid_xlevel);
    VALUE(X86_CPUID_XLEVEL2, env->cpuid_xlevel2);
#undef VALUE
    memcpy(snapshot.features, env->features, sizeof(env->features));
    *output = snapshot;
}

GString *latx_translation_config_json(const LatTranslationConfig *snapshot)
{
    QDict *info = qdict_new();
    QDict *values = qdict_new();
    QList *features = qlist_new();
    char error[128];

    qdict_put_int(info, "schema_version", snapshot->version);
    qdict_put_bool(info, "compatibility_complete", snapshot->compatibility_complete);
    qdict_put_bool(info, "native_replay_domain", snapshot->native_replay_domain);
    qdict_put_str(info, "build_id", LATC_BUILD_ID);
    qdict_put_str(info, "guest_abi", latx_runtime_guest_abi());
    qdict_put_obj(info, "values", QOBJECT(values));
    qdict_put_obj(info, "x86_features", QOBJECT(features));
    for (size_t field = 0; field < LAT_CONFIG_FIELD_COUNT; field++) {
        qdict_put_int(values, lat_translation_config_field_name(field),
                      snapshot->values[field]);
    }
    for (size_t i = 0; i < snapshot->feature_count; i++) {
        char hex[17];

        snprintf(hex, sizeof(hex), "%016" PRIx64, snapshot->features[i]);
        qlist_append_str(features, hex);
    }
    uint8_t digest[32];
    char digest_hex[65];
    if (lat_translation_config_digest(snapshot, digest, error, sizeof(error))) {
        g_error("cannot digest translation configuration: %s", error);
    }
    for (size_t i = 0; i < 32; i++) {
        snprintf(digest_hex + 2 * i, 3, "%02x", digest[i]);
    }
    qdict_put_str(info, "configuration_sha256", digest_hex);
    GString *json = qobject_to_json(QOBJECT(info));
    qobject_unref(info);
    return json;
}

/* Only writable option values are replayed. Build/host/CPU fields are verified. */
#define REPLAY_OPTIONS(X) \
    X(ANONYM, option_anonym) \
    X(CLOSE_PARALLEL, close_latx_parallel) \
    X(CVT_OPT, option_cvt_opt) \
    X(ENABLE_FCSR_EXC, option_enable_fcsr_exc) \
    X(ENABLE_LASX, option_enable_lasx) \
    X(FAST_ATOMIC, option_fast_atomic) \
    X(FPUTAG, option_fputag) \
    X(IMM_COMPLEX, option_imm_complex) \
    X(IMM_PRECACHE, option_imm_precache) \
    X(IMM_REG, option_imm_reg) \
    X(IMM_RIP, option_imm_rip) \
    X(JR_RA, option_jr_ra) \
    X(JR_RA_STACK, option_jr_ra_stack) \
    X(LATIVE, option_lative) \
    X(LEGACY_AOT, option_aot) \
    X(MEM_TEST, option_mem_test) \
    X(MINKE_16K_PAGE_CHECK, option_minke_16k_page_check) \
    X(MONITOR_SHARED_MEM, option_monitor_shared_mem) \
    X(ROUNDING_OPT, option_set_rounding_opt) \
    X(SAVE_XMM, option_save_xmm) \
    X(SMC_OPT, option_smc_opt) \
    X(SMC_RELOAD, option_smc_reload) \
    X(SOFTFPU, option_softfpu) \
    X(SOFTFPU_FAST, option_softfpu_fast) \
    X(SPLIT_TB, option_split_tb) \
    X(TUNNEL_LIB, option_tunnel_lib) \
    X(VPAES, option_vpaes)

int latx_translation_config_apply(const LatTranslationConfig *config,
                                 char *error, size_t error_size)
{
    /* Validate all assignable values before changing any option. */
#define CHECK(id, variable) \
    if (config->values[LAT_CONFIG_##id] < INT_MIN || \
        config->values[LAT_CONFIG_##id] > INT_MAX) { \
        snprintf(error, error_size, "configuration field %s is out of range", \
                 lat_translation_config_field_name(LAT_CONFIG_##id)); \
        return -1; \
    }
    REPLAY_OPTIONS(CHECK)
#ifdef CONFIG_LATX_FLAG_REDUCTION
    CHECK(FLAG_REDUCTION, option_flag_reduction)
#endif
#ifdef CONFIG_LATX_INSTS_PATTERN
    CHECK(INSTPTN, option_instptn)
#endif
#ifdef CONFIG_LATX_AVX_OPT
    CHECK(AVX_CPUID, option_avx_cpuid)
#endif
#undef CHECK
#define ASSIGN(id, variable) variable = config->values[LAT_CONFIG_##id];
    REPLAY_OPTIONS(ASSIGN)
#ifdef CONFIG_LATX_FLAG_REDUCTION
    ASSIGN(FLAG_REDUCTION, option_flag_reduction)
#endif
#ifdef CONFIG_LATX_INSTS_PATTERN
    ASSIGN(INSTPTN, option_instptn)
#endif
#ifdef CONFIG_LATX_AVX_OPT
    ASSIGN(AVX_CPUID, option_avx_cpuid)
#endif
#undef ASSIGN
    return 0;
}

int latx_translation_config_verify(CPUX86State *env, uint32_t cflags,
    const LatTranslationConfig *expected, char *error, size_t error_size)
{
    LatTranslationConfig actual;
    uint64_t changed;

    latx_translation_config_capture(env, cflags, &actual);
    if (lat_translation_config_diff(expected, &actual, &changed,
                                    error, error_size)) return -1;
    if (!changed) return 0;
    for (size_t field = 0; field < LAT_CONFIG_FIELD_COUNT; field++) {
        if (changed & (UINT64_C(1) << field)) {
            snprintf(error, error_size, "configuration replay mismatch: %s",
                     lat_translation_config_field_name(field));
            return -1;
        }
    }
    snprintf(error, error_size, "configuration replay mismatch: CPU features");
    return -1;
}
