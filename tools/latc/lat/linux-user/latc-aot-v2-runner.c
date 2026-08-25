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

typedef struct LatAotV2RuntimeInstance {
    LatAotModuleInstanceV2 instance;
    LatAotV2RuntimeModule *runtime_module;
    struct LatAotV2RuntimeInstance *next;
} LatAotV2RuntimeInstance;

typedef struct LatAotV2ProxySet {
    const LatAotLoadedModuleV2 *module;
    TranslationBlock **proxies;
    size_t count;
    struct LatAotV2ProxySet *next;
} LatAotV2ProxySet;

static LatAotRegistryV2 registry;
static LatAotV2RuntimeModule *runtime_modules;
static LatAotV2RuntimeInstance *runtime_instances;
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
static __thread LatAotV2ProxySet *aot_v2_proxy_sets;
static __thread LatAotModuleInstanceV2 *aot_v2_current_instance;

static int register_discovered_module(const LatGuestElfInfoV2 *info,
                                      char *error, size_t error_size);

bool latc_aot_v2_mapping_enabled(void)
{
    const char *cache = getenv("LATX_AOT_V2_CACHE_DIR");
    const char *module = getenv("LATX_AOT_V2_MODULE");
    return (cache && *cache) || (module && *module);
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
            int registered = register_discovered_module(info, error,
                                                        sizeof(error));
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
                                    uint64_t guest_end)
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
    if (lat_aot_v2_registry_register(&registry,
                                     &runtime_instance->instance)) {
        g_free(runtime_instance);
        return -1;
    }
    runtime_instance->next = runtime_instances;
    runtime_instances = runtime_instance;
    active = true;
    return 0;
}

static int register_discovered_module(const LatGuestElfInfoV2 *info,
                                      char *error, size_t error_size)
{
    const char *cache = getenv("LATX_AOT_V2_CACHE_DIR");
    if (!cache || !*cache) {
        return 0;
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
                                 info->guest_begin, info->guest_end)) {
        snprintf(error, error_size, "cannot register AOT v2 instance: %s",
                 strerror(errno));
        return -1;
    }
    return 1;
}

static int inspect_source(const char *path, LatAotExpectedV2 *expected,
                          uint64_t *guest_base, uint64_t *guest_end,
                          char *error, size_t error_size)
{
    int bundled = latc_bundle_verified_guest(expected->source_sha256,
                                              guest_base, guest_end);
    if (bundled < 0) {
        snprintf(error, error_size, "cannot read verified bundle identity");
        return -1;
    }
    if (bundled) {
        digest_bytes(LATC_BUILD_ID, strlen(LATC_BUILD_ID),
                     expected->codegen_id);
        expected->available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES |
                                       LAT_AOT_FEATURE_LASX;
        return 0;
    }
    gchar *file = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &file, &size, NULL) ||
        size < sizeof(Elf64_Ehdr)) {
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
    }
    if (begin == UINT64_MAX || end <= begin) {
        snprintf(error, error_size, "source has no loadable range");
        g_free(file);
        return -1;
    }
    digest_bytes(file, size, expected->source_sha256);
    digest_bytes(LATC_BUILD_ID, strlen(LATC_BUILD_ID), expected->codegen_id);
    expected->available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES |
                                   LAT_AOT_FEATURE_LASX;
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
    LatAotV2RuntimeModule *module = g_new0(LatAotV2RuntimeModule, 1);
    if (!source_path || !*source_path ||
        !module ||
        inspect_source(source_path, &expected, &guest_base, &guest_end,
                       error, sizeof(error)) ||
        lat_aot_v2_module_open(module_path, &expected, &module->loaded,
                               error, sizeof(error))) {
        fprintf(stderr, "latx: cannot prepare AOT v2 module: %s\n",
                error[0] ? error : strerror(errno));
        g_free(module);
        return strict ? -1 : 0;
    }
    module->path = g_strdup(module_path);
    module->next = runtime_modules;
    runtime_modules = module;
    if (register_module_instance(module, guest_base, guest_base, guest_end) ||
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

static const LatAotTbV2 *find_descriptor_tb(const LatAotModuleV2 *module,
                                            uint64_t guest_rva,
                                            uint32_t cflags)
{
    size_t left = 0;
    size_t right = (size_t)(module->tb_end - module->tb_begin);
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (module->tb_begin[middle].guest_rva < guest_rva) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    while (left != (size_t)(module->tb_end - module->tb_begin) &&
           module->tb_begin[left].guest_rva == guest_rva &&
           module->tb_begin[left].flags < cflags) {
        left++;
    }
    if (left == (size_t)(module->tb_end - module->tb_begin) ||
        module->tb_begin[left].guest_rva != guest_rva ||
        module->tb_begin[left].flags != cflags) {
        return NULL;
    }
    return &module->tb_begin[left];
}

static LatAotV2ProxySet *proxy_set_for(const LatAotLoadedModuleV2 *module)
{
    for (LatAotV2ProxySet *set = aot_v2_proxy_sets; set; set = set->next) {
        if (set->module == module) {
            return set;
        }
    }
    size_t count = (size_t)(module->descriptor->tb_end -
                            module->descriptor->tb_begin);
    LatAotV2ProxySet *set = g_new0(LatAotV2ProxySet, 1);
    if (!set) {
        return NULL;
    }
    set->proxies = g_new0(TranslationBlock *, count);
    if (!set->proxies) {
        g_free(set);
        return NULL;
    }
    set->module = module;
    set->count = count;
    set->next = aot_v2_proxy_sets;
    aot_v2_proxy_sets = set;
    return set;
}

TranslationBlock *latc_aot_v2_find_tb(CPUState *cpu,
                                      target_ulong guest_pc,
                                      uint32_t flags, uint32_t cflags)
{
    if (!active) {
        return NULL;
    }
    LatAotTargetV2 target;
    if (lat_aot_v2_registry_lookup(&registry, guest_pc, cflags, &target)) {
        return NULL;
    }
    const LatAotModuleV2 *module = target.instance->module->descriptor;
    uint64_t guest_rva = guest_pc - target.instance->guest_load_bias;
    const LatAotTbV2 *descriptor_tb = find_descriptor_tb(module, guest_rva,
                                                          cflags);
    LatAotV2ProxySet *proxy_set = proxy_set_for(target.instance->module);
    if (!descriptor_tb || !proxy_set ||
        lat_aot_v2_context_apply_guest_slots(
            module, target.instance->guest_load_bias,
            ((CPUArchState *)cpu->env_ptr)->tb_jmp_cache_ptr)) {
        return NULL;
    }
    aot_v2_current_instance = target.instance;
    size_t index = (size_t)(descriptor_tb - module->tb_begin);
    TranslationBlock *tb = proxy_set->proxies[index];
    if (!tb) {
        tb = g_new0(TranslationBlock, 1);
        tb->s_data = g_new0(struct separated_data, 1);
        tb->s_data->_top_out = -1;
        tb->s_data->_top_in = -1;
        tb->s_data->rel_start = -1;
        tb->s_data->rel_end = -1;
        qemu_spin_init(&tb->jmp_lock);
        tb->tc.ptr = (void *)target.host_address;
        tb->tc.size = descriptor_tb->host_size;
        tb->pc = guest_pc;
        tb->flags = flags;
        tb->cflags = cflags;
        tb->size = 1;
        tb->icount = 1;
        tb->bool_flags = IS_AOT_TB;
        tb->jmp_target_arg[0] = TB_JMP_RESET_OFFSET_INVALID;
        tb->jmp_target_arg[1] = TB_JMP_RESET_OFFSET_INVALID;
        tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
        tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
        tb->jmp_stub_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
        tb->jmp_stub_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
        tb->first_jmp_align = TB_JMP_RESET_OFFSET_INVALID;
        proxy_set->proxies[index] = tb;
    } else if (tb->flags != flags || tb_cflags(tb) != cflags ||
               tb->tc.ptr != target.host_address) {
        return NULL;
    }
    uint32_t hash = tb_jmp_cache_hash_func(guest_pc);
#ifdef CONFIG_LATX_FAST_JMPCACHE
    latx_fast_jmp_cache_add(cpu, hash, tb);
#endif
    qatomic_set(&cpu->tb_jmp_cache[hash], tb);
    return tb;
}

bool latc_aot_v2_restore_state(CPUState *cpu, uintptr_t host_pc)
{
    if (!active || host_pc < GETPC_ADJ) {
        return false;
    }
    uintptr_t searched_pc = host_pc - GETPC_ADJ;
    LatAotV2RuntimeModule *runtime_module = NULL;
    for (LatAotV2RuntimeModule *candidate = runtime_modules; candidate;
         candidate = candidate->next) {
        const LatAotModuleV2 *descriptor = candidate->loaded.descriptor;
        if (searched_pc >= (uintptr_t)descriptor->text_begin &&
            searched_pc < (uintptr_t)descriptor->text_end) {
            runtime_module = candidate;
            break;
        }
    }
    if (!runtime_module) {
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
        return false;
    }
    const LatAotPcMapV2 *map = &module->pc_map_begin[left - 1];
    if (host_offset >= map->host_offset_end ||
        map->flags != LAT_AOT_PC_MAP_DYNAMIC_STATE ||
        map->state_record_offset) {
        return false;
    }
    LatAotModuleInstanceV2 *instance = aot_v2_current_instance;
    if (!instance || instance->module != &runtime_module->loaded) {
        instance = NULL;
        for (LatAotV2RuntimeInstance *candidate = runtime_instances; candidate;
             candidate = candidate->next) {
            if (candidate->runtime_module == runtime_module) {
                if (instance) {
                    return false;
                }
                instance = &candidate->instance;
            }
        }
    }
    if (!instance) {
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
    return true;
}
