#include "qemu/osdep.h"

#include "qemu.h"
#include "exec/exec-all.h"
#include "exec/tb-hash.h"
#ifdef CONFIG_LATX_FAST_JMPCACHE
#include "exec/fasttb.h"
#endif
#include "latc-aot-v2-runner.h"
#include "latc-bundle-loader.h"
#include "latc-build-id.h"
#include "latcd-client.h"
#include "latcd-protocol.h"
#include "guest-elf-map.h"
#include "module-loader.h"
#include "qemu-def.h"
#include "translate.h"

#include <elf.h>
#include <glib.h>

typedef struct LatAotV2RuntimeModule {
    LatAotLoadedModuleV2 loaded;
    char *path;
    struct LatAotV2RuntimeModule *next;
} LatAotV2RuntimeModule;

typedef enum LatAotV2ModuleState {
    LAT_AOT_V2_MODULE_MISSING,
    LAT_AOT_V2_MODULE_REJECTED,
    LAT_AOT_V2_MODULE_REGISTERED,
    LAT_AOT_V2_MODULE_INACTIVE,
} LatAotV2ModuleState;

typedef struct LatAotV2ModuleStats {
    uint8_t source_sha256[32];
    uint64_t guest_begin;
    uint64_t guest_end;
    LatAotV2ModuleState state;
    _Atomic uint64_t aot_lookups;
    _Atomic uint64_t jit_fallbacks;
    struct LatAotV2ModuleStats *next;
} LatAotV2ModuleStats;

typedef struct LatAotV2RuntimeInstance {
    LatAotModuleInstanceV2 instance;
    LatAotV2RuntimeModule *runtime_module;
    LatAotV2ModuleStats *stats;
    uint64_t guest_slots[LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT];
    uint64_t guest_slot_count;
    uint64_t handled_invalidation_generation;
    struct LatAotV2RuntimeInstance *next;
} LatAotV2RuntimeInstance;

typedef struct LatAotV2HostModuleSnapshot {
    size_t count;
    LatAotV2RuntimeModule **modules;
    struct LatAotV2HostModuleSnapshot *retired_next;
} LatAotV2HostModuleSnapshot;

#define LAT_AOT_V2_TARGET_CACHE_BITS 16
#define LAT_AOT_V2_TARGET_CACHE_SIZE (1u << LAT_AOT_V2_TARGET_CACHE_BITS)

typedef struct LatAotV2TargetCacheEntry {
    target_ulong guest_pc;
    uint32_t cflags;
    uint64_t generation;
    const void *host_address;
    LatAotModuleInstanceV2 *instance;
} LatAotV2TargetCacheEntry;

static LatAotRegistryV2 registry;
static LatAotV2RuntimeModule *runtime_modules;
static LatAotV2RuntimeInstance *runtime_instances;
static _Atomic(LatAotV2HostModuleSnapshot *) host_modules_current;
static LatAotV2HostModuleSnapshot *host_modules_retired;
static LatAotV2ModuleStats *module_stats;
static bool prepared;
static bool active;
static bool registry_initialized;
static bool runtime_bound;
static LatGuestElfTrackerV2 *elf_tracker;
static pthread_mutex_t elf_tracker_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct LatAotV2PendingMapping {
    int fd;
    uint64_t guest_start;
    uint64_t mapping_size;
    uint64_t file_offset;
    struct LatAotV2PendingMapping *next;
} LatAotV2PendingMapping;
static LatAotV2PendingMapping *pending_mapping_head;
static LatAotV2PendingMapping **pending_mapping_tail = &pending_mapping_head;
static __thread LatAotModuleInstanceV2 *aot_v2_current_instance;
static __thread LatAotV2TargetCacheEntry *aot_v2_target_cache;
static _Atomic uint64_t direct_targets;
static _Atomic uint64_t compiler_submissions;
static _Atomic uint64_t compiler_submission_failures;
static _Atomic uint64_t compiler_submission_duplicates;
static _Atomic uint64_t compiler_request_sequence;
static _Atomic uint64_t invalidated_instances;
static _Atomic uint64_t invalidated_exec_ranges;
static _Atomic uint64_t invalidation_reasons[4];
static _Atomic uint64_t signal_pc_lookups;
static _Atomic uint64_t signal_pc_hits;
static _Atomic uint64_t signal_pc_misses;
static uint64_t discovered_elfs;
static GHashTable *submitted_sources;

static int register_discovered_module(const LatGuestElfInfoV2 *info,
                                      LatAotV2RuntimeInstance **instance,
                                      char *error, size_t error_size);
static void digest_hex(const uint8_t digest[32], char output[65]);

static int compare_host_module(const void *left, const void *right)
{
    const LatAotV2RuntimeModule *a =
        *(LatAotV2RuntimeModule *const *)left;
    const LatAotV2RuntimeModule *b =
        *(LatAotV2RuntimeModule *const *)right;
    uintptr_t a_begin = (uintptr_t)a->loaded.descriptor->text_begin;
    uintptr_t b_begin = (uintptr_t)b->loaded.descriptor->text_begin;
    return a_begin < b_begin ? -1 : a_begin > b_begin;
}

static int register_host_module(LatAotV2RuntimeModule *module)
{
    LatAotV2HostModuleSnapshot *old = atomic_load_explicit(
        &host_modules_current, memory_order_acquire);
    size_t old_count = old ? old->count : 0;
    LatAotV2HostModuleSnapshot *replacement = g_new0(
        LatAotV2HostModuleSnapshot, 1);
    if (!replacement) {
        errno = ENOMEM;
        return -1;
    }
    replacement->modules = g_new0(LatAotV2RuntimeModule *, old_count + 1);
    if (!replacement->modules) {
        g_free(replacement);
        errno = ENOMEM;
        return -1;
    }
    replacement->count = old_count + 1;
    if (old_count) {
        memcpy(replacement->modules, old->modules,
               old_count * sizeof(*replacement->modules));
    }
    replacement->modules[old_count] = module;
    qsort(replacement->modules, replacement->count,
          sizeof(*replacement->modules), compare_host_module);
    for (size_t i = 1; i < replacement->count; i++) {
        const LatAotModuleV2 *previous =
            replacement->modules[i - 1]->loaded.descriptor;
        const LatAotModuleV2 *current =
            replacement->modules[i]->loaded.descriptor;
        if ((uintptr_t)previous->text_end >
            (uintptr_t)current->text_begin) {
            g_free(replacement->modules);
            g_free(replacement);
            errno = EEXIST;
            return -1;
        }
    }
    old = atomic_exchange_explicit(&host_modules_current, replacement,
                                   memory_order_acq_rel);
    if (old) {
        old->retired_next = host_modules_retired;
        host_modules_retired = old;
    }
    return 0;
}

static LatAotV2RuntimeModule *find_host_module(uintptr_t host_pc)
{
    LatAotV2HostModuleSnapshot *snapshot = atomic_load_explicit(
        &host_modules_current, memory_order_acquire);
    size_t left = 0;
    size_t right = snapshot ? snapshot->count : 0;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        const LatAotModuleV2 *module =
            snapshot->modules[middle]->loaded.descriptor;
        if ((uintptr_t)module->text_begin <= host_pc) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (!left) {
        return NULL;
    }
    LatAotV2RuntimeModule *module = snapshot->modules[left - 1];
    return host_pc < (uintptr_t)module->loaded.descriptor->text_end ?
           module : NULL;
}

static const char *module_state_name(LatAotV2ModuleState state)
{
    switch (state) {
    case LAT_AOT_V2_MODULE_REGISTERED: return "registered";
    case LAT_AOT_V2_MODULE_INACTIVE: return "inactive";
    case LAT_AOT_V2_MODULE_REJECTED: return "rejected";
    default: return "missing";
    }
}

static const char *invalidation_reason_name(LatcAotV2InvalidationReason reason)
{
    switch (reason) {
    case LATC_AOT_V2_INVALIDATE_UNMAP: return "unmap";
    case LATC_AOT_V2_INVALIDATE_MAP_FIXED: return "map-fixed";
    case LATC_AOT_V2_INVALIDATE_PROTECTION: return "protection";
    case LATC_AOT_V2_INVALIDATE_CODE_WRITE: return "code-write";
    default: return "unknown";
    }
}

void latc_aot_v2_report_stats(void)
{
    static _Atomic bool reported;
    if (atomic_exchange(&reported, true) ||
        !getenv("LATX_AOT_V2_REPORT")) {
        return;
    }
    fprintf(stderr,
            "latx: AOT v2 runtime stats direct_targets=%llu "
            "compat_tb_allocations=0 compiler_submissions=%llu "
            "compiler_submission_failures=%llu "
            "compiler_submission_duplicates=%llu "
            "invalidated_instances=%llu invalidated_exec_ranges=%llu "
            "invalidation_unmap=%llu "
            "invalidation_map_fixed=%llu invalidation_protection=%llu "
            "invalidation_code_write=%llu signal_pc_lookups=%llu "
            "signal_pc_hits=%llu signal_pc_misses=%llu\n",
            (unsigned long long)atomic_load(&direct_targets),
            (unsigned long long)atomic_load(&compiler_submissions),
            (unsigned long long)atomic_load(&compiler_submission_failures),
            (unsigned long long)atomic_load(&compiler_submission_duplicates),
            (unsigned long long)atomic_load(&invalidated_instances),
            (unsigned long long)atomic_load(&invalidated_exec_ranges),
            (unsigned long long)atomic_load(
                &invalidation_reasons[LATC_AOT_V2_INVALIDATE_UNMAP]),
            (unsigned long long)atomic_load(
                &invalidation_reasons[LATC_AOT_V2_INVALIDATE_MAP_FIXED]),
            (unsigned long long)atomic_load(
                &invalidation_reasons[LATC_AOT_V2_INVALIDATE_PROTECTION]),
            (unsigned long long)atomic_load(
                &invalidation_reasons[LATC_AOT_V2_INVALIDATE_CODE_WRITE]),
            (unsigned long long)atomic_load(&signal_pc_lookups),
            (unsigned long long)atomic_load(&signal_pc_hits),
            (unsigned long long)atomic_load(&signal_pc_misses));
    for (LatAotV2ModuleStats *stats = module_stats; stats;
         stats = stats->next) {
        char source[65];
        digest_hex(stats->source_sha256, source);
        fprintf(stderr,
                "latx: AOT v2 module stats source=%s range=0x%llx-0x%llx "
                "module=%s aot_lookups=%llu jit_fallbacks=%llu\n",
                source,
                (unsigned long long)stats->guest_begin,
                (unsigned long long)stats->guest_end,
                module_state_name(stats->state),
                (unsigned long long)atomic_load(&stats->aot_lookups),
                (unsigned long long)atomic_load(&stats->jit_fallbacks));
    }
}

static LatAotV2ModuleStats *add_module_stats(
    const LatGuestElfInfoV2 *info, LatAotV2ModuleState state)
{
    LatAotV2ModuleStats *stats = g_new0(LatAotV2ModuleStats, 1);
    if (!stats) {
        return NULL;
    }
    memcpy(stats->source_sha256, info->source_sha256,
           sizeof(stats->source_sha256));
    stats->guest_begin = info->guest_begin;
    stats->guest_end = info->guest_end;
    stats->state = state;
    stats->next = module_stats;
    module_stats = stats;
    return stats;
}

static LatAotV2ModuleStats *module_stats_for_pc(uint64_t guest_pc)
{
    for (LatAotV2ModuleStats *stats = module_stats; stats;
         stats = stats->next) {
        if (guest_pc >= stats->guest_begin && guest_pc < stats->guest_end) {
            return stats;
        }
    }
    return NULL;
}

bool latc_aot_v2_mapping_enabled(void)
{
    const char *cache = getenv("LATX_AOT_V2_CACHE_DIR");
    const char *module = getenv("LATX_AOT_V2_MODULE");
    const char *socket = getenv("LATX_AOT_V2_LATCD_SOCKET");
    return (cache && *cache) || (module && *module) || (socket && *socket);
}

static void submit_missing_module(int fd, const LatGuestElfInfoV2 *info,
                                  uint32_t priority)
{
    const char *socket = getenv("LATX_AOT_V2_LATCD_SOCKET");
    if (!socket || !*socket) {
        return;
    }
    if (!submitted_sources) {
        submitted_sources = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, NULL);
        if (!submitted_sources) {
            atomic_fetch_add(&compiler_submission_failures, 1);
            return;
        }
    }
    char source[65];
    digest_hex(info->source_sha256, source);
    if (g_hash_table_contains(submitted_sources, source)) {
        atomic_fetch_add(&compiler_submission_duplicates, 1);
        return;
    }
    g_hash_table_add(submitted_sources, g_strdup(source));
    uint64_t sequence = atomic_fetch_add(&compiler_request_sequence, 1) + 1;
    uint64_t request_id = ((uint64_t)getpid() << 32) ^ sequence;
    char error[256] = {0};
    if (latcd_client_submit_fd(socket, fd, priority, request_id,
                               error, sizeof(error))) {
        atomic_fetch_add(&compiler_submission_failures, 1);
        if (getenv("LATX_AOT_V2_REPORT")) {
            fprintf(stderr,
                    "latx: AOT v2 compiler submission failed source=%s: %s\n",
                    source, error[0] ? error : strerror(errno));
        }
        return;
    }
    atomic_fetch_add(&compiler_submissions, 1);
    if (getenv("LATX_AOT_V2_REPORT")) {
        fprintf(stderr,
                "latx: AOT v2 compiler submitted source=%s priority=%u\n",
                source, priority);
    }
}

static void drain_mappings(void)
{
    if (have_mmap_lock()) {
        return;
    }
    for (;;) {
        pthread_mutex_lock(&elf_tracker_lock);
        LatAotV2PendingMapping *pending = pending_mapping_head;
        if (!pending) {
            pthread_mutex_unlock(&elf_tracker_lock);
            break;
        }
        pending_mapping_head = pending->next;
        if (!pending_mapping_head) {
            pending_mapping_tail = &pending_mapping_head;
        }
        if (!elf_tracker) {
            elf_tracker = lat_guest_elf_tracker_new_v2();
        }
        const LatGuestElfInfoV2 *info = NULL;
        int added = 0;
        char error[256] = {0};
        int result = !elf_tracker || lat_guest_elf_tracker_note_v2(
            elf_tracker, pending->fd, pending->guest_start,
            pending->mapping_size, pending->file_offset, TARGET_PAGE_SIZE,
            &info, &added, error, sizeof(error));
        if (!result && added) {
            discovered_elfs++;
            LatAotV2RuntimeInstance *instance = NULL;
            int registered = register_discovered_module(
                info, &instance, error, sizeof(error));
            if (registered <= 0) {
                submit_missing_module(
                    pending->fd, info,
                    discovered_elfs <= 2 ? LATCD_PRIORITY_STARTUP :
                                           LATCD_PRIORITY_LIBRARY);
            }
            LatAotV2ModuleStats *stats = add_module_stats(
                info, registered > 0 ? LAT_AOT_V2_MODULE_REGISTERED :
                registered == 0 ? LAT_AOT_V2_MODULE_MISSING :
                                  LAT_AOT_V2_MODULE_REJECTED);
            if (instance) {
                instance->stats = stats;
            }
            if (getenv("LATX_AOT_V2_REPORT")) {
                fprintf(stderr,
                        "latx: AOT v2 discovered ELF dev=%llu ino=%llu "
                        "bias=0x%llx range=0x%llx-0x%llx exec_ranges=%u "
                        "module=%s%s%s\n",
                        (unsigned long long)info->device,
                        (unsigned long long)info->inode,
                        (unsigned long long)info->load_bias,
                        (unsigned long long)info->guest_begin,
                        (unsigned long long)info->guest_end,
                        info->exec_range_count,
                        registered > 0 ? "registered" :
                        registered == 0 ? "missing" : "rejected",
                        error[0] ? " reason=" : "",
                        error);
            }
        } else if (result && getenv("LATX_AOT_V2_REPORT")) {
            fprintf(stderr,
                    "latx: AOT v2 ignored file mapping "
                    "start=0x%llx size=0x%llx offset=0x%llx: %s\n",
                    (unsigned long long)pending->guest_start,
                    (unsigned long long)pending->mapping_size,
                    (unsigned long long)pending->file_offset,
                    error[0] ? error : strerror(errno));
        }
        close(pending->fd);
        free(pending);
        pthread_mutex_unlock(&elf_tracker_lock);
    }
}

void latc_aot_v2_drain_mmaps(void)
{
    drain_mappings();
}

void latc_aot_v2_note_mmap(int fd, uint64_t guest_start,
                           uint64_t mapping_size, uint64_t file_offset)
{
    if (!latc_aot_v2_mapping_enabled()) {
        close(fd);
        return;
    }
    LatAotV2PendingMapping *pending = g_new0(LatAotV2PendingMapping, 1);
    if (!pending) {
        close(fd);
        return;
    }
    *pending = (LatAotV2PendingMapping) {
        .fd = fd,
        .guest_start = guest_start,
        .mapping_size = mapping_size,
        .file_offset = file_offset,
    };
    pthread_mutex_lock(&elf_tracker_lock);
    *pending_mapping_tail = pending;
    pending_mapping_tail = &pending->next;
    pthread_mutex_unlock(&elf_tracker_lock);
    drain_mappings();
}

static uint32_t instance_exec_range_overlap_count(
    const LatAotModuleInstanceV2 *instance, uint64_t guest_start,
    uint64_t guest_end)
{
    if (!instance->exec_range_count) {
        return guest_start < instance->guest_end &&
               guest_end > instance->guest_begin;
    }
    uint32_t overlaps = 0;
    for (uint32_t i = 0; i < instance->exec_range_count; i++) {
        if (guest_start < instance->exec_ranges[i].end &&
            guest_end > instance->exec_ranges[i].begin) {
            overlaps++;
        }
    }
    return overlaps;
}

bool latc_aot_v2_invalidate_range(CPUState *cpu, uint64_t guest_start,
                                  uint64_t mapping_size,
                                  LatcAotV2InvalidationReason reason)
{
    if (!mapping_size || guest_start > UINT64_MAX - mapping_size ||
        reason > LATC_AOT_V2_INVALIDATE_CODE_WRITE) {
        return false;
    }
    uint64_t guest_end = guest_start + mapping_size;
    bool current_invalidated = false;
    pthread_mutex_lock(&elf_tracker_lock);
    if (elf_tracker && reason != LATC_AOT_V2_INVALIDATE_CODE_WRITE) {
        lat_guest_elf_tracker_remove_range_v2(elf_tracker, guest_start,
                                              mapping_size);
    }
    size_t deactivated = 0;
    size_t deactivated_exec_ranges = 0;
    if (registry_initialized &&
        lat_aot_v2_registry_deactivate_range(&registry, guest_start, guest_end,
                                             &deactivated)) {
        pthread_mutex_unlock(&elf_tracker_lock);
        return false;
    }
    for (LatAotV2RuntimeInstance *runtime = runtime_instances; runtime;
         runtime = runtime->next) {
        LatAotModuleInstanceV2 *instance = &runtime->instance;
        uint32_t overlaps = instance_exec_range_overlap_count(
            instance, guest_start, guest_end);
        uint64_t generation = atomic_load_explicit(
            &instance->generation, memory_order_acquire);
        if (!overlaps ||
            atomic_load_explicit(&instance->active, memory_order_acquire) ||
            runtime->handled_invalidation_generation == generation) {
            continue;
        }
        runtime->handled_invalidation_generation = generation;
        deactivated_exec_ranges += overlaps;
        bool was_current = aot_v2_current_instance == instance;
#ifdef CONFIG_LATX_FAST_JMPCACHE
        if (cpu) {
            was_current |= ((CPUArchState *)cpu->env_ptr)
                ->aot_v2_current_context == instance;
        }
#endif
        current_invalidated |= was_current;
        if (runtime->stats &&
            runtime->stats->state == LAT_AOT_V2_MODULE_REGISTERED) {
            runtime->stats->state = LAT_AOT_V2_MODULE_INACTIVE;
        }
        if (was_current) {
            aot_v2_current_instance = NULL;
#ifdef CONFIG_LATX_FAST_JMPCACHE
            if (cpu) {
                latx_aot_v2_fast_jmp_cache_set_context(cpu, NULL);
            }
#endif
        }
        if (getenv("LATX_AOT_V2_REPORT")) {
            fprintf(stderr,
                    "latx: AOT v2 deactivated range=0x%llx-0x%llx "
                    "generation=%llu reason=%s\n",
                    (unsigned long long)instance->guest_begin,
                    (unsigned long long)instance->guest_end,
                    (unsigned long long)generation,
                    invalidation_reason_name(reason));
        }
    }
    if (deactivated) {
        atomic_fetch_add(&invalidated_instances, deactivated);
        atomic_fetch_add(&invalidated_exec_ranges, deactivated_exec_ranges);
        atomic_fetch_add(&invalidation_reasons[reason], 1);
    }
    pthread_mutex_unlock(&elf_tracker_lock);
    return current_invalidated;
}

void latc_aot_v2_note_munmap(CPUState *cpu, uint64_t guest_start,
                             uint64_t mapping_size)
{
    latc_aot_v2_invalidate_range(cpu, guest_start, mapping_size,
                                 LATC_AOT_V2_INVALIDATE_UNMAP);
}

static int bind_runtime_targets(void)
{
    LatAotRuntimeTargetsV2 targets = {
        .struct_size = sizeof(targets),
    };
    targets.target[LAT_AOT_TARGET_EPILOGUE_RET_ID_1] =
        context_switch_native_to_bt_ret_id_1;
    targets.target[LAT_AOT_TARGET_EPILOGUE_RET_ID_0] =
        context_switch_native_to_bt_ret_id_0;
    targets.target[LAT_AOT_TARGET_JIRL_EPILOGUE_RET_ID_1] =
        context_switch_native_to_bt_ret_id_1;
    targets.target[LAT_AOT_TARGET_JIRL_EPILOGUE_RET_ID_0] =
        context_switch_native_to_bt_ret_id_0;
    targets.target[LAT_AOT_TARGET_EPILOGUE_RET_0] =
        context_switch_native_to_bt_ret_0;
    targets.target[LAT_AOT_TARGET_UPDATE_MXCSR_STATUS] =
        (uintptr_t)update_mxcsr_status;
    targets.target[LAT_AOT_TARGET_FXSAVE] = (uintptr_t)helper_fxsave;
    targets.target[LAT_AOT_TARGET_FXRSTOR] = (uintptr_t)helper_fxrstor;
    targets.target[LAT_AOT_TARGET_FPREGS_X80_TO_64] =
        (uintptr_t)convert_fpregs_x80_to_64;
    targets.target[LAT_AOT_TARGET_FPREGS_64_TO_X80] =
        (uintptr_t)convert_fpregs_64_to_x80;
    targets.target[LAT_AOT_TARGET_UPDATE_FP_STATUS] =
        (uintptr_t)update_fp_status;
    targets.target[LAT_AOT_TARGET_CPUID] = (uintptr_t)helper_cpuid;
    targets.target[LAT_AOT_TARGET_RAISE_ILLOP] =
        (uintptr_t)helper_raise_illop;
    targets.target[LAT_AOT_TARGET_RAISE_GPF] =
        (uintptr_t)helper_raise_gpf;
    targets.target[LAT_AOT_TARGET_PCMPISTRI_XMM] =
        (uintptr_t)helper_pcmpistri_xmm;
    targets.target[LAT_AOT_TARGET_PCMPISTRM_XMM] =
        (uintptr_t)helper_pcmpistrm_xmm;
    return lat_aot_runtime_bind_targets(&targets);
}

static void raise_syscall_through_lat(void *opaque)
{
    (void)opaque;
    helper_raise_syscall();
    abort();
}

static void digest_bytes(const void *data, size_t size, uint8_t digest[32])
{
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, data, size);
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    g_checksum_free(checksum);
}

static void digest_hex(const uint8_t digest[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 15];
    }
    output[64] = '\0';
}

static int ensure_registry(void)
{
    if (!registry_initialized) {
        if (lat_aot_v2_registry_init(&registry)) {
            return -1;
        }
        registry_initialized = true;
    }
    if (!runtime_bound) {
        if (bind_runtime_targets() ||
            lat_aot_runtime_bind_syscall(raise_syscall_through_lat, NULL)) {
            return -1;
        }
        runtime_bound = true;
    }
    return 0;
}

static LatAotV2RuntimeModule *find_runtime_module(const uint8_t digest[32])
{
    for (LatAotV2RuntimeModule *module = runtime_modules; module;
         module = module->next) {
        if (!memcmp(module->loaded.note.source_sha256, digest, 32)) {
            return module;
        }
    }
    return NULL;
}

static int register_module_instance(LatAotV2RuntimeModule *module,
                                    uint64_t load_bias,
                                    uint64_t guest_begin,
                                    uint64_t guest_end,
                                    const LatGuestElfRangeV2 *exec_ranges,
                                    uint32_t exec_range_count,
                                    LatAotV2RuntimeInstance **result)
{
    LatAotV2RuntimeInstance *runtime_instance = g_new0(
        LatAotV2RuntimeInstance, 1);
    if (!runtime_instance) {
        errno = ENOMEM;
        return -1;
    }
    runtime_instance->runtime_module = module;
    runtime_instance->instance = (LatAotModuleInstanceV2) {
        .module = &module->loaded,
        .guest_load_bias = load_bias,
        .guest_begin = guest_begin,
        .guest_end = guest_end,
    };
    if (exec_range_count > LAT_AOT_V2_MAX_EXEC_RANGES) {
        g_free(runtime_instance);
        errno = E2BIG;
        return -1;
    }
    if (exec_range_count) {
        runtime_instance->instance.exec_range_count = exec_range_count;
        for (uint32_t i = 0; i < exec_range_count; i++) {
            runtime_instance->instance.exec_ranges[i] =
                (LatAotGuestRangeV2) {
                    .begin = exec_ranges[i].begin,
                    .end = exec_ranges[i].end,
                };
        }
    } else {
        runtime_instance->instance.exec_range_count = 1;
        runtime_instance->instance.exec_ranges[0] = (LatAotGuestRangeV2) {
            .begin = guest_begin,
            .end = guest_end,
        };
    }
    const LatAotModuleV2 *descriptor = module->loaded.descriptor;
    runtime_instance->guest_slot_count =
        descriptor->guest_slot_end - descriptor->guest_slot_begin;
    if (lat_aot_v2_context_apply_guest_slots(
            descriptor, load_bias,
            runtime_instance->guest_slots +
                LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT)) {
        g_free(runtime_instance);
        return -1;
    }
    if (lat_aot_v2_registry_register(&registry,
                                     &runtime_instance->instance)) {
        g_free(runtime_instance);
        return -1;
    }
    runtime_instance->next = runtime_instances;
    runtime_instances = runtime_instance;
    if (result) {
        *result = runtime_instance;
    }
    active = true;
    return 0;
}

static int register_discovered_module(const LatGuestElfInfoV2 *info,
                                      LatAotV2RuntimeInstance **instance,
                                      char *error, size_t error_size)
{
    const char *cache = getenv("LATX_AOT_V2_CACHE_DIR");
    if (!cache || !*cache) {
        return 0;
    }
    if (instance) {
        *instance = NULL;
    }
    if (ensure_registry()) {
        snprintf(error, error_size, "cannot initialize AOT v2 registry: %s",
                 strerror(errno));
        return -1;
    }
    LatAotV2RuntimeModule *module = find_runtime_module(info->source_sha256);
    if (!module) {
        char source_hex[65];
        digest_hex(info->source_sha256, source_hex);
        char *basename = g_strdup_printf("%s.so", source_hex);
        char *path = g_build_filename(cache, basename, NULL);
        g_free(basename);
        if (!path) {
            errno = ENOMEM;
            return -1;
        }
        LatAotExpectedV2 expected = {0};
        memcpy(expected.source_sha256, info->source_sha256,
               sizeof(expected.source_sha256));
        digest_bytes(LATC_BUILD_ID, strlen(LATC_BUILD_ID),
                     expected.codegen_id);
        expected.available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES |
                                      LAT_AOT_FEATURE_LASX;
        module = g_new0(LatAotV2RuntimeModule, 1);
        if (!module) {
            g_free(path);
            errno = ENOMEM;
            return -1;
        }
        errno = 0;
        if (lat_aot_v2_module_open(path, &expected, &module->loaded,
                                   error, error_size)) {
            int saved_errno = errno;
            g_free(module);
            g_free(path);
            if (saved_errno == ENOENT) {
                error[0] = '\0';
                return 0;
            }
            errno = saved_errno;
            return -1;
        }
        if (register_host_module(module)) {
            snprintf(error, error_size,
                     "cannot index AOT v2 host module: %s", strerror(errno));
            g_free(path);
            return -1;
        }
        module->path = path;
        module->next = runtime_modules;
        runtime_modules = module;
    }
    if (info->load_bias > UINT64_MAX - info->preferred_base) {
        snprintf(error, error_size, "AOT v2 descriptor load bias overflows");
        errno = EOVERFLOW;
        return -1;
    }
    if (register_module_instance(module,
                                 info->load_bias + info->preferred_base,
                                 info->guest_begin, info->guest_end,
                                 info->exec_ranges, info->exec_range_count,
                                 instance)) {
        snprintf(error, error_size, "cannot register AOT v2 instance: %s",
                 strerror(errno));
        return -1;
    }
    return 1;
}

static int inspect_source(const char *path, LatAotExpectedV2 *expected,
                          uint64_t *guest_base, uint64_t *guest_end,
                          LatGuestElfRangeV2 *exec_ranges,
                          uint32_t *exec_range_count,
                          char *error, size_t error_size)
{
    int bundled = latc_bundle_verified_guest(expected->source_sha256,
                                              guest_base, guest_end);
    *exec_range_count = 0;
    if (bundled < 0) {
        snprintf(error, error_size, "cannot read verified bundle identity");
        return -1;
    }
    if (bundled) {
        digest_bytes(LATC_BUILD_ID, strlen(LATC_BUILD_ID),
                     expected->codegen_id);
        expected->available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES |
                                       LAT_AOT_FEATURE_LASX;
    }
    gchar *file = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &file, &size, NULL) ||
        size < sizeof(Elf64_Ehdr)) {
        if (bundled) {
            exec_ranges[0] = (LatGuestElfRangeV2) {
                .begin = *guest_base,
                .end = *guest_end,
            };
            *exec_range_count = 1;
            g_free(file);
            return 0;
        }
        snprintf(error, error_size, "cannot read x86 source ELF");
        g_free(file);
        return -1;
    }
    const Elf64_Ehdr *elf = (const void *)file;
    if (memcmp(elf->e_ident, ELFMAG, SELFMAG) ||
        elf->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf->e_machine != EM_X86_64 ||
        elf->e_type != ET_EXEC ||
        elf->e_phentsize != sizeof(Elf64_Phdr) || !elf->e_phnum ||
        elf->e_phoff > size ||
        elf->e_phnum > (size - elf->e_phoff) / sizeof(Elf64_Phdr)) {
        snprintf(error, error_size, "source is not a supported x86-64 ELF");
        g_free(file);
        return -1;
    }
    const Elf64_Phdr *phdrs = (const void *)(file + elf->e_phoff);
    uint64_t begin = UINT64_MAX;
    uint64_t end = 0;
    for (uint16_t i = 0; i < elf->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        begin = MIN(begin, phdrs[i].p_vaddr);
        if (phdrs[i].p_vaddr > UINT64_MAX - phdrs[i].p_memsz) {
            snprintf(error, error_size, "source load range overflows");
            g_free(file);
            return -1;
        }
        end = MAX(end, phdrs[i].p_vaddr + phdrs[i].p_memsz);
        if (phdrs[i].p_flags & PF_X) {
            uint64_t exec_begin = phdrs[i].p_vaddr & TARGET_PAGE_MASK;
            uint64_t exec_end = TARGET_PAGE_ALIGN(
                phdrs[i].p_vaddr + phdrs[i].p_memsz);
            if (!exec_end || exec_end <= exec_begin ||
                (*exec_range_count &&
                 exec_begin < exec_ranges[*exec_range_count - 1].begin)) {
                snprintf(error, error_size,
                         "source executable ranges are invalid");
                g_free(file);
                return -1;
            }
            if (*exec_range_count &&
                exec_begin <= exec_ranges[*exec_range_count - 1].end) {
                exec_ranges[*exec_range_count - 1].end = MAX(
                    exec_ranges[*exec_range_count - 1].end, exec_end);
            } else {
                if (*exec_range_count == LAT_GUEST_ELF_MAX_EXEC_RANGES) {
                    snprintf(error, error_size,
                             "source has too many executable ranges");
                    g_free(file);
                    return -1;
                }
                exec_ranges[(*exec_range_count)++] = (LatGuestElfRangeV2) {
                    .begin = exec_begin,
                    .end = exec_end,
                };
            }
        }
    }
    if (begin == UINT64_MAX || end <= begin || !*exec_range_count) {
        snprintf(error, error_size,
                 "source has no loadable executable range");
        g_free(file);
        return -1;
    }
    if (!bundled) {
        digest_bytes(file, size, expected->source_sha256);
        digest_bytes(LATC_BUILD_ID, strlen(LATC_BUILD_ID),
                     expected->codegen_id);
        expected->available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES |
                                       LAT_AOT_FEATURE_LASX;
    }
    *guest_base = begin;
    *guest_end = end;
    g_free(file);
    return 0;
}

int latc_aot_v2_prepare(CPUArchState *env)
{
    const char *module_path = getenv("LATX_AOT_V2_MODULE");
    const char *source_path = getenv("LATX_AOT_V2_SOURCE");
    bool strict = getenv("LATX_AOT_V2_STRICT") != NULL;
    if (latc_aot_v2_mapping_enabled() && ensure_registry()) {
        fprintf(stderr, "latx: cannot initialize AOT v2 registry: %s\n",
                strerror(errno));
        return strict ? -1 : 0;
    }
    drain_mappings();
    if (prepared || !module_path || !*module_path) {
        return 0;
    }
    prepared = true;
    char error[256] = {0};
    LatAotExpectedV2 expected = {0};
    uint64_t guest_base;
    uint64_t guest_end;
    LatGuestElfRangeV2 exec_ranges[LAT_GUEST_ELF_MAX_EXEC_RANGES];
    uint32_t exec_range_count;
    LatAotV2RuntimeModule *module = g_new0(LatAotV2RuntimeModule, 1);
    if (!source_path || !*source_path ||
        !module ||
        inspect_source(source_path, &expected, &guest_base, &guest_end,
                       exec_ranges, &exec_range_count,
                       error, sizeof(error)) ||
        lat_aot_v2_module_open(module_path, &expected, &module->loaded,
                               error, sizeof(error))) {
        fprintf(stderr, "latx: cannot prepare AOT v2 module: %s\n",
                error[0] ? error : strerror(errno));
        g_free(module);
        return strict ? -1 : 0;
    }
    module->path = g_strdup(module_path);
    if (register_host_module(module)) {
        fprintf(stderr, "latx: cannot index AOT v2 host module: %s\n",
                strerror(errno));
        return strict ? -1 : 0;
    }
    module->next = runtime_modules;
    runtime_modules = module;
    if (register_module_instance(module, guest_base, guest_base, guest_end,
                                 exec_ranges, exec_range_count,
                                 NULL) ||
        lat_aot_v2_context_apply_guest_slots(
            module->loaded.descriptor, guest_base, env->tb_jmp_cache_ptr)) {
        fprintf(stderr, "latx: cannot register AOT v2 module: %s\n",
                strerror(errno));
        return strict ? -1 : 0;
    }

    if (getenv("LATX_AOT_V2_REPORT")) {
        size_t count = (size_t)(module->loaded.descriptor->tb_end -
                                module->loaded.descriptor->tb_begin);
        fprintf(stderr, "latx: AOT v2 registered module with %zu TBs from %s\n",
                count, module_path);
    }
    return 0;
}

bool latc_aot_v2_find_target(CPUState *cpu, target_ulong guest_pc,
                             uint32_t cflags, LatcAotV2Target *result)
{
    if (!registry_initialized || !result) {
        return false;
    }
    LatAotV2ModuleStats *stats = module_stats_for_pc(guest_pc);
    if (!active) {
        if (stats) {
            atomic_fetch_add(&stats->jit_fallbacks, 1);
        }
        return false;
    }
    if (!aot_v2_target_cache) {
        aot_v2_target_cache = g_new0(LatAotV2TargetCacheEntry,
                                     LAT_AOT_V2_TARGET_CACHE_SIZE);
        if (!aot_v2_target_cache) {
            return false;
        }
    }
    uint32_t hash = (uint32_t)((guest_pc ^
        (guest_pc >> LAT_AOT_V2_TARGET_CACHE_BITS) ^ cflags) &
        (LAT_AOT_V2_TARGET_CACHE_SIZE - 1));
    LatAotV2TargetCacheEntry *entry = &aot_v2_target_cache[hash];
    LatAotModuleInstanceV2 *instance = entry->instance;
    if (entry->guest_pc != guest_pc || entry->cflags != cflags || !instance ||
        !atomic_load_explicit(&instance->active, memory_order_acquire) ||
        entry->generation != atomic_load_explicit(
            &instance->generation, memory_order_acquire)) {
        LatAotTargetV2 target;
        if (lat_aot_v2_registry_lookup(&registry, guest_pc, cflags, &target)) {
            if (stats) {
                atomic_fetch_add(&stats->jit_fallbacks, 1);
            }
            return false;
        }
        entry->guest_pc = guest_pc;
        entry->cflags = cflags;
        entry->generation = target.generation;
        entry->host_address = (const void *)target.host_address;
        entry->instance = target.instance;
        instance = target.instance;
    }
    LatAotV2RuntimeInstance *runtime_instance = (void *)instance;
    if (runtime_instance->stats) {
        stats = runtime_instance->stats;
    }
    result->host_address = entry->host_address;
    result->context = instance;
    result->generation_address = &instance->generation;
    result->guest_pc = guest_pc;
    result->generation = entry->generation;
    result->cflags = cflags;
    result->guest_slots_end = runtime_instance->guest_slots +
        LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT;
    result->guest_slot_count = runtime_instance->guest_slot_count;
    if (!latc_aot_v2_activate_target(cpu, result)) {
        if (stats) {
            atomic_fetch_add(&stats->jit_fallbacks, 1);
        }
        return false;
    }
    if (stats) {
        atomic_fetch_add(&stats->aot_lookups, 1);
    }
#ifdef CONFIG_LATX_FAST_JMPCACHE
    if (!getenv("LATX_AOT_V2_CACHE_DIR")) {
        uint32_t jump_hash = tb_jmp_cache_hash_func(guest_pc);
        FastTB *jump_cache = ((CPUArchState *)cpu->env_ptr)->tb_jmp_cache_ptr;
        qatomic_set(&jump_cache[jump_hash].ptr, result->host_address);
        qatomic_set(&jump_cache[jump_hash].pc, guest_pc);
    }
#endif
    atomic_fetch_add(&direct_targets, 1);
    return true;
}

bool latc_aot_v2_activate_target(CPUState *cpu,
                                 const LatcAotV2Target *target)
{
    LatAotModuleInstanceV2 *instance = (void *)target->context;
    if (!cpu || !instance ||
        !atomic_load_explicit(&instance->active, memory_order_acquire) ||
        target->generation != atomic_load_explicit(
            &instance->generation, memory_order_acquire)) {
        return false;
    }
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    const void *current_context = aot_v2_current_instance;
#ifdef CONFIG_LATX_FAST_JMPCACHE
    current_context = env->aot_v2_current_context;
#endif
    if (current_context != instance) {
        uint64_t count = target->guest_slot_count;
        memcpy((uint64_t *)env->tb_jmp_cache_ptr - count,
               target->guest_slots_end - count,
               count * sizeof(uint64_t));
    }
    aot_v2_current_instance = instance;
#ifdef CONFIG_LATX_FAST_JMPCACHE
    latx_aot_v2_fast_jmp_cache_set_context(cpu, instance);
    if (getenv("LATX_AOT_V2_CACHE_DIR")) {
        uint32_t hash = tb_jmp_cache_hash_func(target->guest_pc);
        latx_aot_v2_fast_jmp_cache_add(
            cpu, hash, target->guest_pc, target->host_address,
            target->context, (const uint64_t *)target->generation_address,
            target->generation, target->guest_slots_end,
            target->guest_slot_count);
    }
#endif
    return true;
}

bool latc_aot_v2_contains_host_pc(uintptr_t host_pc)
{
    return active && find_host_module(host_pc);
}

bool latc_aot_v2_restore_state(CPUState *cpu, uintptr_t host_pc)
{
    if (!active || host_pc < GETPC_ADJ) {
        return false;
    }
    atomic_fetch_add(&signal_pc_lookups, 1);
    uintptr_t searched_pc = host_pc - GETPC_ADJ;
    LatAotV2RuntimeModule *runtime_module = find_host_module(searched_pc);
    if (!runtime_module) {
        atomic_fetch_add(&signal_pc_misses, 1);
        return false;
    }
    const LatAotModuleV2 *module = runtime_module->loaded.descriptor;
    uintptr_t text_begin = (uintptr_t)module->text_begin;
    uint64_t host_offset = searched_pc - text_begin;
    size_t count = (size_t)(module->pc_map_end - module->pc_map_begin);
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (module->pc_map_begin[middle].host_offset_begin <= host_offset) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (!left) {
        atomic_fetch_add(&signal_pc_misses, 1);
        return false;
    }
    const LatAotPcMapV2 *map = &module->pc_map_begin[left - 1];
    if (host_offset >= map->host_offset_end ||
        map->flags != LAT_AOT_PC_MAP_DYNAMIC_STATE ||
        map->state_record_offset) {
        atomic_fetch_add(&signal_pc_misses, 1);
        return false;
    }
    LatAotModuleInstanceV2 *instance = aot_v2_current_instance;
#ifdef CONFIG_LATX_FAST_JMPCACHE
    instance = (LatAotModuleInstanceV2 *)
        ((CPUArchState *)cpu->env_ptr)->aot_v2_current_context;
#endif
    if (!instance || instance->module != &runtime_module->loaded) {
        instance = NULL;
        for (LatAotV2RuntimeInstance *candidate = runtime_instances; candidate;
             candidate = candidate->next) {
            if (candidate->runtime_module == runtime_module &&
                atomic_load_explicit(&candidate->instance.active,
                                     memory_order_acquire)) {
                if (instance) {
                    atomic_fetch_add(&signal_pc_misses, 1);
                    return false;
                }
                instance = &candidate->instance;
            }
        }
    }
    if (!instance) {
        atomic_fetch_add(&signal_pc_misses, 1);
        return false;
    }
    if (map->guest_rva > UINT64_MAX - instance->guest_load_bias) {
        atomic_fetch_add(&signal_pc_misses, 1);
        return false;
    }
    target_ulong data[TARGET_INSN_START_WORDS] = {
        instance->guest_load_bias + map->guest_rva,
        CC_OP_DYNAMIC,
    };
    TranslationBlock tb = {
        .pc = data[0],
    };
    restore_state_to_opc(cpu->env_ptr, &tb, data);
    atomic_fetch_add(&signal_pc_hits, 1);
    return true;
}
