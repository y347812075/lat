#include "qemu/osdep.h"

#include "qemu.h"
#include "exec/exec-all.h"
#include "exec/tb-hash.h"
#ifdef CONFIG_LATX_FAST_JMPCACHE
#include "exec/fasttb.h"
#endif
#include "latc-aot-v2-runner.h"
#include "latc-build-id.h"
#include "module-loader.h"
#include "qemu-def.h"
#include "translate.h"

#include <elf.h>
#include <glib.h>

static LatAotLoadedModuleV2 loaded_module;
static LatAotModuleInstanceV2 module_instance;
static LatAotRegistryV2 registry;
static bool prepared;
static bool active;
static __thread TranslationBlock **aot_v2_tb_proxies;
static __thread size_t aot_v2_tb_proxy_count;

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

static int inspect_source(const char *path, LatAotExpectedV2 *expected,
                          uint64_t *guest_base, uint64_t *guest_end,
                          char *error, size_t error_size)
{
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
    if (prepared || !module_path || !*module_path) {
        return 0;
    }
    prepared = true;
    char error[256] = {0};
    LatAotExpectedV2 expected = {0};
    uint64_t guest_base;
    uint64_t guest_end;
    if (!source_path || !*source_path ||
        inspect_source(source_path, &expected, &guest_base, &guest_end,
                       error, sizeof(error)) ||
        lat_aot_v2_module_open(module_path, &expected, &loaded_module,
                               error, sizeof(error)) ||
        bind_runtime_targets() ||
        lat_aot_runtime_bind_syscall(raise_syscall_through_lat, NULL)) {
        fprintf(stderr, "latx: cannot prepare AOT v2 module: %s\n",
                error[0] ? error : strerror(errno));
        return strict ? -1 : 0;
    }
    module_instance.module = &loaded_module;
    module_instance.guest_load_bias = guest_base;
    module_instance.guest_begin = guest_base;
    module_instance.guest_end = guest_end;
    if (lat_aot_v2_registry_init(&registry) ||
        lat_aot_v2_registry_register(&registry, &module_instance) ||
        lat_aot_v2_context_apply_guest_slots(
            loaded_module.descriptor, module_instance.guest_load_bias,
            env->tb_jmp_cache_ptr)) {
        fprintf(stderr, "latx: cannot register AOT v2 module: %s\n",
                strerror(errno));
        return strict ? -1 : 0;
    }
    active = true;

    if (getenv("LATX_AOT_V2_REPORT")) {
        size_t count = (size_t)(loaded_module.descriptor->tb_end -
                                loaded_module.descriptor->tb_begin);
        fprintf(stderr, "latx: AOT v2 registered module with %zu TBs from %s\n",
                count, module_path);
    }
    return 0;
}

static const LatAotTbV2 *find_descriptor_tb(uint64_t guest_rva,
                                            uint32_t cflags)
{
    const LatAotModuleV2 *module = loaded_module.descriptor;
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

TranslationBlock *latc_aot_v2_find_tb(CPUState *cpu,
                                      target_ulong guest_pc,
                                      uint32_t flags, uint32_t cflags)
{
    if (!active || !loaded_module.descriptor ||
        guest_pc < module_instance.guest_load_bias) {
        return NULL;
    }
    uint64_t guest_rva = guest_pc - module_instance.guest_load_bias;
    const LatAotTbV2 *descriptor_tb = find_descriptor_tb(guest_rva, cflags);
    if (!descriptor_tb) {
        return NULL;
    }
    LatAotTargetV2 target;
    if (lat_aot_v2_registry_lookup(&registry, guest_pc,
                                   descriptor_tb->flags, &target)) {
        return NULL;
    }
    size_t count = (size_t)(loaded_module.descriptor->tb_end -
                            loaded_module.descriptor->tb_begin);
    size_t index = (size_t)(descriptor_tb - loaded_module.descriptor->tb_begin);
    if (!aot_v2_tb_proxies) {
        aot_v2_tb_proxies = g_new0(TranslationBlock *, count);
        aot_v2_tb_proxy_count = count;
    }
    if (aot_v2_tb_proxy_count != count) {
        return NULL;
    }
    TranslationBlock *tb = aot_v2_tb_proxies[index];
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
        aot_v2_tb_proxies[index] = tb;
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
    if (!active || !loaded_module.descriptor || host_pc < GETPC_ADJ) {
        return false;
    }
    const LatAotModuleV2 *module = loaded_module.descriptor;
    uintptr_t text_begin = (uintptr_t)module->text_begin;
    uintptr_t searched_pc = host_pc - GETPC_ADJ;
    if (searched_pc < text_begin ||
        searched_pc >= (uintptr_t)module->text_end) {
        return false;
    }
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
    target_ulong data[TARGET_INSN_START_WORDS] = {
        module_instance.guest_load_bias + map->guest_rva,
        CC_OP_DYNAMIC,
    };
    TranslationBlock tb = {
        .pc = data[0],
    };
    restore_state_to_opc(cpu->env_ptr, &tb, data);
    return true;
}
