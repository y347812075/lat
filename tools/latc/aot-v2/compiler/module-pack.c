#include "module-pack.h"

#include "lat-aot-v2.h"
#include "native-image.h"

#include <errno.h>
#include <glib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert((unsigned int)LAT_NATIVE_PC_MAP_DYNAMIC_STATE ==
               (unsigned int)LAT_AOT_PC_MAP_DYNAMIC_STATE,
               "native and AOT PC map flags differ");

typedef struct ModulePack {
    const LatNativeImageHeaderV2 *header;
    const LatNativeTbV1 *tbs;
    const LatNativeRelocationV1 *relocations;
    const LatNativePcMapV2 *pc_maps;
    unsigned char *code;
    unsigned char *supported;
    GArray *code_order;
    GArray *guest_rvas;
    GHashTable *guest_rva_indexes;
    int three_level_guest_slots;
    uint64_t runtime_trampolines;
    uint64_t pf_table;
} ModulePack;

static gint compare_tb_code(gconstpointer left, gconstpointer right)
{
    const LatNativeTbV1 *a = *(const LatNativeTbV1 *const *)left;
    const LatNativeTbV1 *b = *(const LatNativeTbV1 *const *)right;
    if (a->code_offset != b->code_offset) {
        return a->code_offset < b->code_offset ? -1 : 1;
    }
    return 0;
}

static int find_code_tb(const ModulePack *pack, uint64_t code_offset)
{
    guint left = 0;
    guint right = pack->code_order->len;
    while (left < right) {
        guint middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = g_array_index(
            pack->code_order, const LatNativeTbV1 *, middle);
        if (tb->code_offset <= code_offset) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (!left) {
        return -1;
    }
    const LatNativeTbV1 *tb = g_array_index(
        pack->code_order, const LatNativeTbV1 *, left - 1);
    if (code_offset >= tb->code_offset + tb->code_size) {
        return -1;
    }
    return (int)(tb - pack->tbs);
}

static int pc_map_in_tb(const LatNativePcMapV2 *map,
                        const LatNativeTbV1 *tb)
{
    return map->host_offset_begin >= tb->code_offset &&
           map->host_offset_end <= tb->code_offset + tb->code_size;
}

static size_t selected_pc_map_count(const ModulePack *pack)
{
    size_t count = 0;
    for (uint64_t i = 0; i < pack->header->pc_map_count; i++) {
        int owner = find_code_tb(pack, pack->pc_maps[i].host_offset_begin);
        if (owner >= 0 && pack->supported[owner] &&
            pc_map_in_tb(&pack->pc_maps[i], &pack->tbs[owner])) {
            count++;
        }
    }
    return count;
}

static int selected_tb_ranges_valid(const ModulePack *pack)
{
    uint64_t previous_end = 0;
    int have_previous = 0;
    for (guint i = 0; i < pack->code_order->len; i++) {
        const LatNativeTbV1 *tb = g_array_index(
            pack->code_order, const LatNativeTbV1 *, i);
        size_t index = (size_t)(tb - pack->tbs);
        if (!pack->supported[index] || !tb->code_size) {
            continue;
        }
        if (have_previous && tb->code_offset < previous_end) {
            return 0;
        }
        previous_end = tb->code_offset + tb->code_size;
        have_previous = 1;
    }
    return 1;
}

static int all_tb_ranges_valid(const ModulePack *pack)
{
    uint64_t previous_end = 0;
    int have_previous = 0;
    for (guint i = 0; i < pack->code_order->len; i++) {
        const LatNativeTbV1 *tb = g_array_index(
            pack->code_order, const LatNativeTbV1 *, i);
        if (!tb->code_size) {
            continue;
        }
        if (have_previous && tb->code_offset < previous_end) {
            return 0;
        }
        previous_end = tb->code_offset + tb->code_size;
        have_previous = 1;
    }
    return 1;
}

static int tb_pc_maps_complete(const ModulePack *pack, uint64_t index)
{
        uint64_t expected = pack->tbs[index].code_offset;
        uint64_t left = 0;
        uint64_t right = pack->header->pc_map_count;
        while (left < right) {
            uint64_t middle = left + (right - left) / 2;
            if (pack->pc_maps[middle].host_offset_begin < expected) {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        for (uint64_t j = left; j < pack->header->pc_map_count; j++) {
            const LatNativePcMapV2 *map = &pack->pc_maps[j];
            if (!pc_map_in_tb(map, &pack->tbs[index])) {
                break;
            }
            if (map->guest_pc < pack->header->preferred_guest_base ||
                map->state_record_offset != 0 ||
                map->flags != LAT_NATIVE_PC_MAP_DYNAMIC_STATE ||
                map->host_offset_begin != expected) {
                return 0;
            }
            expected = map->host_offset_end;
        }
        if (expected != pack->tbs[index].code_offset +
                        pack->tbs[index].code_size) {
            return 0;
        }
        return 1;
}

static int selected_pc_maps_complete(const ModulePack *pack)
{
    for (uint64_t i = 0; i < pack->header->tb_count; i++) {
        if (pack->supported[i] && !tb_pc_maps_complete(pack, i)) {
            return 0;
        }
    }
    return 1;
}

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

void lat_aot_v2_codegen_digest(const char *build_id, uint8_t digest[32])
{
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)build_id, strlen(build_id));
    gsize size = 32;
    g_checksum_get_digest(checksum, digest, &size);
    g_checksum_free(checksum);
}

static int write_all(const char *path, const void *data, size_t size,
                     char *error, size_t error_size)
{
    FILE *file = fopen(path, "wb");
    if (!file) {
        return fail(error, error_size, "cannot create %s: %s", path,
                    strerror(errno));
    }
    int result = 0;
    if (size && fwrite(data, size, 1, file) != 1) {
        result = fail(error, error_size, "cannot write %s", path);
    }
    if (fclose(file) && !result) {
        result = fail(error, error_size, "cannot close %s", path);
    }
    return result;
}

static const char *runtime_entry(uint32_t symbol)
{
    switch (symbol) {
    case LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_1:
        return "lat_aot_runtime_epilogue_ret_id_1";
    case LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0:
        return "lat_aot_runtime_epilogue_ret_id_0";
    case LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1:
        return "lat_aot_runtime_jirl_epilogue_ret_id_1";
    case LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0:
        return "lat_aot_runtime_jirl_epilogue_ret_id_0";
    case LAT_NATIVE_SYMBOL_EPILOGUE_RET_0:
        return "lat_aot_runtime_epilogue_ret_0";
    case LAT_NATIVE_SYMBOL_UPDATE_MXCSR_STATUS:
        return "lat_aot_runtime_update_mxcsr_status";
    case LAT_NATIVE_SYMBOL_FXSAVE:
        return "lat_aot_runtime_fxsave";
    case LAT_NATIVE_SYMBOL_FXRSTOR:
        return "lat_aot_runtime_fxrstor";
    case LAT_NATIVE_SYMBOL_FPREGS_X80_TO_64:
        return "lat_aot_runtime_fpregs_x80_to_64";
    case LAT_NATIVE_SYMBOL_FPREGS_64_TO_X80:
        return "lat_aot_runtime_fpregs_64_to_x80";
    case LAT_NATIVE_SYMBOL_UPDATE_FP_STATUS:
        return "lat_aot_runtime_update_fp_status";
    case LAT_NATIVE_SYMBOL_CPUID:
        return "lat_aot_runtime_cpuid";
    case LAT_NATIVE_SYMBOL_RAISE_ILLOP:
        return "lat_aot_runtime_raise_illop";
    case LAT_NATIVE_SYMBOL_RAISE_GPF:
        return "lat_aot_runtime_raise_gpf";
    case LAT_NATIVE_SYMBOL_RAISE_SYSCALL:
        return LAT_AOT_V2_RUNTIME_SYSCALL_SYMBOL;
    case LAT_NATIVE_SYMBOL_PCMPISTRI_XMM:
        return "lat_aot_runtime_pcmpistri_xmm";
    case LAT_NATIVE_SYMBOL_PCMPISTRM_XMM:
        return "lat_aot_runtime_pcmpistrm_xmm";
    case LAT_NATIVE_SYMBOL_EFLAGTF:
        return "lat_aot_runtime_eflagtf";
    case LAT_NATIVE_SYMBOL_LOG2:
        return "lat_aot_runtime_log2";
    case LAT_NATIVE_SYMBOL_POW:
        return "lat_aot_runtime_pow";
    case LAT_NATIVE_SYMBOL_SIN:
        return "lat_aot_runtime_sin";
    case LAT_NATIVE_SYMBOL_COS:
        return "lat_aot_runtime_cos";
    case LAT_NATIVE_SYMBOL_ATAN2:
        return "lat_aot_runtime_atan2";
    case LAT_NATIVE_SYMBOL_LOGB:
        return "lat_aot_runtime_logb";
    case LAT_NATIVE_SYMBOL_SINCOS:
        return "lat_aot_runtime_sincos";
    case LAT_NATIVE_SYMBOL_FPATAN: return "lat_aot_runtime_fpatan";
    case LAT_NATIVE_SYMBOL_FPTAN: return "lat_aot_runtime_fptan";
    case LAT_NATIVE_SYMBOL_FPREM: return "lat_aot_runtime_fprem";
    case LAT_NATIVE_SYMBOL_FPREM1: return "lat_aot_runtime_fprem1";
    case LAT_NATIVE_SYMBOL_FRNDINT: return "lat_aot_runtime_frndint";
    case LAT_NATIVE_SYMBOL_F2XM1: return "lat_aot_runtime_f2xm1";
    case LAT_NATIVE_SYMBOL_FXTRACT: return "lat_aot_runtime_fxtract";
    case LAT_NATIVE_SYMBOL_FYL2X: return "lat_aot_runtime_fyl2x";
    case LAT_NATIVE_SYMBOL_FYL2XP1: return "lat_aot_runtime_fyl2xp1";
    case LAT_NATIVE_SYMBOL_FSINCOS: return "lat_aot_runtime_fsincos";
    case LAT_NATIVE_SYMBOL_FSIN: return "lat_aot_runtime_fsin";
    case LAT_NATIVE_SYMBOL_FCOS: return "lat_aot_runtime_fcos";
    case LAT_NATIVE_SYMBOL_FBLD_ST0: return "lat_aot_runtime_fbld_st0";
    case LAT_NATIVE_SYMBOL_FBST_ST0: return "lat_aot_runtime_fbst_st0";
    case LAT_NATIVE_SYMBOL_AESIMC_XMM:
        return "lat_aot_runtime_aesimc_xmm";
    case LAT_NATIVE_SYMBOL_AESKEYGENASSIST_XMM:
        return "lat_aot_runtime_aeskeygenassist_xmm";
    case LAT_NATIVE_SYMBOL_AESDEC_XMM:
        return "lat_aot_runtime_aesdec_xmm";
    case LAT_NATIVE_SYMBOL_AESDECLAST_XMM:
        return "lat_aot_runtime_aesdeclast_xmm";
    case LAT_NATIVE_SYMBOL_AESENC_XMM:
        return "lat_aot_runtime_aesenc_xmm";
    case LAT_NATIVE_SYMBOL_AESENCLAST_XMM:
        return "lat_aot_runtime_aesenclast_xmm";
    case LAT_NATIVE_SYMBOL_SHA1NEXTE: return "lat_aot_runtime_sha1nexte";
    case LAT_NATIVE_SYMBOL_SHA1MSG1: return "lat_aot_runtime_sha1msg1";
    case LAT_NATIVE_SYMBOL_SHA1MSG2: return "lat_aot_runtime_sha1msg2";
    case LAT_NATIVE_SYMBOL_SHA256MSG1: return "lat_aot_runtime_sha256msg1";
    case LAT_NATIVE_SYMBOL_SHA256MSG2: return "lat_aot_runtime_sha256msg2";
    case LAT_NATIVE_SYMBOL_SHA1RNDS4_F0:
        return "lat_aot_runtime_sha1rnds4_f0";
    case LAT_NATIVE_SYMBOL_SHA1RNDS4_F1:
        return "lat_aot_runtime_sha1rnds4_f1";
    case LAT_NATIVE_SYMBOL_SHA1RNDS4_F2:
        return "lat_aot_runtime_sha1rnds4_f2";
    case LAT_NATIVE_SYMBOL_SHA1RNDS4_F3:
        return "lat_aot_runtime_sha1rnds4_f3";
    case LAT_NATIVE_SYMBOL_SHA256RNDS2_XMM0:
        return "lat_aot_runtime_sha256rnds2_xmm0";
    case LAT_NATIVE_SYMBOL_RAISE_INT: return "lat_aot_runtime_raise_int";
    case LAT_NATIVE_SYMBOL_RAISE_TRAPOP:
        return "lat_aot_runtime_raise_trapop";
    case LAT_NATIVE_SYMBOL_RAISE_INTO: return "lat_aot_runtime_raise_into";
    case LAT_NATIVE_SYMBOL_RAISE_BOUND: return "lat_aot_runtime_raise_bound";
    case LAT_NATIVE_SYMBOL_XGETBV: return "lat_aot_runtime_xgetbv";
    case LAT_NATIVE_SYMBOL_KZT_GET_ALTERNATE:
        return "lat_aot_runtime_kzt_get_alternate";
    default:
        return NULL;
    }
}

static int runtime_symbol_supported(uint32_t symbol)
{
    return symbol == LAT_NATIVE_SYMBOL_PFTABLE || runtime_entry(symbol);
}

static int instruction_falls_through(uint32_t instruction)
{
    uint32_t opcode = instruction & 0xfc000000u;
    if (opcode == 0x50000000u) {
        return 0;
    }
    if (opcode == 0x4c000000u && !(instruction & 0x1f)) {
        return 0;
    }
    return 1;
}

static int find_tb(const ModulePack *pack, uint64_t guest_pc, uint32_t flags)
{
    uint64_t left = 0;
    uint64_t right = pack->header->tb_count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = &pack->tbs[middle];
        if (tb->guest_pc < guest_pc ||
            (tb->guest_pc == guest_pc && tb->flags < flags)) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < pack->header->tb_count &&
        pack->tbs[left].guest_pc == guest_pc &&
        pack->tbs[left].flags == flags) {
        return (int)left;
    }
    return -1;
}

static int guest_slot(ModulePack *pack, uint64_t guest_rva);
static int patch_tb_target_pair(uint32_t *instructions,
                                uint64_t patch, uint64_t target);
static int patch_runtime_target(uint32_t *instructions, uint32_t slots,
                                uint64_t patch, uint64_t target);

static void select_supported_tbs(ModulePack *pack)
{
    memset(pack->supported, 1, pack->header->tb_count);
    for (uint64_t i = 0; i < pack->header->tb_count; i++) {
        if (pack->tbs[i].guest_pc < pack->header->preferred_guest_base ||
            !tb_pc_maps_complete(pack, i)) {
            pack->supported[i] = 0;
        }
    }
    for (uint64_t i = 0; i < pack->header->relocation_count; i++) {
        const LatNativeRelocationV1 *relocation = &pack->relocations[i];
        int owner = find_code_tb(pack, relocation->code_offset);
        if (owner < 0) {
            continue;
        }
        if ((relocation->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
             !runtime_symbol_supported(relocation->target)) ||
            relocation->kind == LAT_NATIVE_RELOC_JRRA_TARGET) {
            pack->supported[owner] = 0;
            continue;
        }
        if (relocation->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL) {
            if (!relocation->slots || relocation->slots > 3) {
                pack->supported[owner] = 0;
                continue;
            }
            uint32_t instructions[3] = {0};
            memcpy(instructions, pack->code + relocation->code_offset,
                   relocation->slots * sizeof(*instructions));
            uint64_t target = relocation->target == LAT_NATIVE_SYMBOL_PFTABLE ?
                pack->pf_table : pack->runtime_trampolines +
                relocation->target * sizeof(uint32_t);
            if (patch_runtime_target(instructions, relocation->slots,
                                     relocation->code_offset, target)) {
                pack->supported[owner] = 0;
            }
        }
    }
    int changed;
    do {
        changed = 0;
        g_array_set_size(pack->guest_rvas, 0);
        g_hash_table_remove_all(pack->guest_rva_indexes);
        pack->three_level_guest_slots = 0;
        if (pack->header->flags & LAT_NATIVE_IMAGE_PIE) {
            for (uint64_t i = 0; i < pack->header->relocation_count; i++) {
                const LatNativeRelocationV1 *relocation =
                    &pack->relocations[i];
                if (relocation->kind != LAT_NATIVE_RELOC_GUEST_ADDRESS) {
                    continue;
                }
                int owner = find_code_tb(pack, relocation->code_offset);
                if (owner < 0 || !pack->supported[owner]) {
                    continue;
                }
                if ((uint64_t)relocation->addend <
                        pack->header->preferred_guest_base ||
                    guest_slot(pack, (uint64_t)relocation->addend -
                               pack->header->preferred_guest_base) < 0) {
                    pack->supported[owner] = 0;
                    changed = 1;
                }
            }
            pack->three_level_guest_slots =
                pack->guest_rvas->len >
                LAT_AOT_V2_TWO_LEVEL_GUEST_ADDRESS_LIMIT;
            if (pack->three_level_guest_slots) {
                for (uint64_t i = 0;
                     i < pack->header->relocation_count; i++) {
                    const LatNativeRelocationV1 *relocation =
                        &pack->relocations[i];
                    if (relocation->kind != LAT_NATIVE_RELOC_GUEST_ADDRESS ||
                        relocation->slots >= 3) {
                        continue;
                    }
                    int owner = find_code_tb(pack, relocation->code_offset);
                    if (owner >= 0 && pack->supported[owner]) {
                        pack->supported[owner] = 0;
                        changed = 1;
                    }
                }
            }
        }
        for (uint64_t i = 0; i < pack->header->relocation_count; i++) {
            const LatNativeRelocationV1 *relocation = &pack->relocations[i];
            if (relocation->kind != LAT_NATIVE_RELOC_TB_TARGET) {
                continue;
            }
            int owner = find_code_tb(pack, relocation->code_offset);
            if (owner < 0 || !pack->supported[owner]) {
                continue;
            }
            int target = find_tb(pack, (uint64_t)relocation->addend,
                                 relocation->target);
            if (target >= 0 && !pack->supported[target]) {
                pack->supported[owner] = 0;
                changed = 1;
                continue;
            }
            if (!relocation->slots || relocation->slots > 3) {
                pack->supported[owner] = 0;
                changed = 1;
                continue;
            }
            uint32_t instructions[3] = {0};
            memcpy(instructions, pack->code + relocation->code_offset,
                   relocation->slots * sizeof(*instructions));
            int patchable;
            if (target < 0) {
                patchable = runtime_entry(relocation->reserved) &&
                    !patch_runtime_target(
                        instructions, relocation->slots,
                        relocation->code_offset,
                        pack->runtime_trampolines + relocation->reserved * 4);
            } else {
                int direct_pair = relocation->slots == 2 &&
                    (instructions[0] & 0xfe00001fu) == 0x1e00000cu &&
                    (instructions[1] & 0xfc0003e0u) == 0x4c000180u;
                patchable = direct_pair ?
                    !patch_tb_target_pair(instructions,
                        relocation->code_offset,
                        pack->tbs[target].code_offset) :
                    !patch_runtime_target(instructions, relocation->slots,
                        relocation->code_offset,
                        pack->tbs[target].code_offset);
            }
            if (!patchable) {
                pack->supported[owner] = 0;
                changed = 1;
            }
        }
        for (guint i = 0; i + 1 < pack->code_order->len; i++) {
            const LatNativeTbV1 *owner = g_array_index(
                pack->code_order, const LatNativeTbV1 *, i);
            size_t owner_index = (size_t)(owner - pack->tbs);
            if (!owner->code_size || !pack->supported[owner_index]) {
                continue;
            }
            uint64_t end = owner->code_offset + owner->code_size;
            const LatNativeTbV1 *next = NULL;
            for (guint j = i + 1; j < pack->code_order->len; j++) {
                const LatNativeTbV1 *candidate = g_array_index(
                    pack->code_order, const LatNativeTbV1 *, j);
                if (candidate->code_offset > end) {
                    break;
                }
                if (candidate->code_offset == end && candidate->code_size) {
                    next = candidate;
                    break;
                }
            }
            uint32_t last_instruction;
            memcpy(&last_instruction,
                   pack->code + end - sizeof(last_instruction),
                   sizeof(last_instruction));
            if (next && instruction_falls_through(last_instruction) &&
                !pack->supported[next - pack->tbs]) {
                pack->supported[owner_index] = 0;
                changed = 1;
            }
        }
    } while (changed);
}

static int patch_branch(uint32_t *instruction, uint64_t patch, uint64_t target)
{
    int64_t difference = (int64_t)target - (int64_t)patch;
    if (difference & 3) {
        return -1;
    }
    int64_t offset = difference >> 2;
    uint32_t opcode = *instruction & 0xfc000000u;
    if (opcode == 0x50000000u || opcode == 0x54000000u) {
        if (offset < -(1 << 25) || offset >= (1 << 25)) {
            return -1;
        }
        *instruction = opcode | ((uint32_t)offset & 0xffffu) << 10 |
                       (((uint32_t)offset >> 16) & 0x3ffu);
        return 0;
    }
    uint32_t opcode20 = *instruction & 0xfc000100u;
    if (opcode == 0x40000000u || opcode == 0x44000000u ||
        opcode20 == 0x48000000u || opcode20 == 0x48000100u) {
        if (offset < -(1 << 19) || offset >= (1 << 19)) {
            return -1;
        }
        *instruction = (*instruction & 0xfc0003e0u) |
                       ((uint32_t)offset & 0xffffu) << 10 |
                       (((uint32_t)offset >> 16) & 0x1fu);
        return 0;
    }
    if (opcode >= 0x58000000u && opcode <= 0x6c000000u) {
        if (offset < -(1 << 15) || offset >= (1 << 15)) {
            return -1;
        }
        *instruction = (*instruction & 0xfc0003ffu) |
                       ((uint32_t)offset & 0xffffu) << 10;
        return 0;
    }
    return -1;
}

static int patch_address(uint32_t *instructions, uint32_t slots,
                         uint64_t patch, uint64_t target)
{
    if (slots == 2 &&
        (instructions[0] & 0xfe000000u) == 0x1e000000u &&
        (instructions[1] & 0xfc000000u) == 0x4c000000u) {
        int64_t difference = (int64_t)target - (int64_t)patch;
        if (difference & 3) {
            return -1;
        }
        int64_t offset = difference >> 2;
        uint32_t base = instructions[0] & 0x1f;
        uint32_t destination = instructions[1] & 0x1f;
        uint32_t upper = (uint32_t)((offset + (1 << 15)) >> 16) & 0xfffff;
        uint32_t lower = (uint32_t)offset & 0xffff;
        instructions[0] = 0x1e000000u | upper << 5 | base;
        instructions[1] = 0x4c000000u | lower << 10 |
                          base << 5 | destination;
        return 0;
    }
    if (slots < 2 || slots > 3 ||
        (instructions[0] & 0xfe000000u) != 0x14000000u ||
        (instructions[1] & 0xffc00000u) != 0x03800000u) {
        return -1;
    }
    int64_t pages = ((int64_t)(target & ~(uint64_t)0xfff) -
                     (int64_t)(patch & ~(uint64_t)0xfff)) >> 12;
    if (pages < -(1 << 19) || pages >= (1 << 19)) {
        return -1;
    }
    uint32_t destination = instructions[0] & 0x1f;
    instructions[0] = 0x1a000000u |
        ((uint32_t)pages & 0xfffff) << 5 | destination;
    instructions[1] = 0x03800000u | ((uint32_t)target & 0xfff) << 10 |
        destination << 5 | destination;
    if (slots == 3) {
        instructions[2] = 0x03400000u;
    }
    return 0;
}

static int patch_tb_target_pair(uint32_t *instructions,
                                uint64_t patch, uint64_t target)
{
    if ((instructions[0] & 0xfe00001fu) == 0x1e00000cu &&
        (instructions[1] & 0xfc0003e0u) == 0x4c000180u) {
        int64_t difference = (int64_t)target - (int64_t)(patch + 4);
        int64_t offset = difference >> 2;
        if (!(difference & 3) && offset >= -(1 << 25) &&
            offset < (1 << 25)) {
            uint32_t destination = instructions[1] & 0x1fu;
            instructions[0] = destination ?
                0x18000040u | destination : 0x03400000u;
            instructions[1] = 0x50000000u |
                ((uint32_t)offset & 0xffffu) << 10 |
                (((uint32_t)offset >> 16) & 0x3ffu);
            return 0;
        }
    }
    return patch_address(instructions, 2, patch, target);
}

static int patch_runtime_target(uint32_t *instructions, uint32_t slots,
                                uint64_t patch, uint64_t target)
{
    if ((instructions[0] & 0xfc000000u) == 0x50000000u ||
        (instructions[0] & 0xfc000000u) == 0x54000000u ||
        (instructions[0] & 0xfc000000u) == 0x40000000u ||
        (instructions[0] & 0xfc000000u) == 0x44000000u ||
        ((instructions[0] & 0xfc000000u) == 0x48000000u &&
         ((instructions[0] >> 8) & 3u) <= 1u) ||
        ((instructions[0] & 0xfc000000u) >= 0x58000000u &&
         (instructions[0] & 0xfc000000u) <= 0x6c000000u)) {
        return patch_branch(instructions, patch, target);
    }
    return patch_address(instructions, slots, patch, target);
}

static int guest_slot(ModulePack *pack, uint64_t guest_rva)
{
    gpointer found = g_hash_table_lookup(pack->guest_rva_indexes, &guest_rva);
    if (found) {
        return (int)GPOINTER_TO_UINT(found) - 1;
    }
    if (pack->guest_rvas->len >= LAT_AOT_V2_GUEST_ADDRESS_LIMIT) {
        return -1;
    }
    uint64_t *key = g_new(uint64_t, 1);
    *key = guest_rva;
    g_array_append_val(pack->guest_rvas, guest_rva);
    guint index = pack->guest_rvas->len - 1;
    g_hash_table_insert(pack->guest_rva_indexes, key,
                        GUINT_TO_POINTER(index + 1));
    return (int)index;
}

static int patch_absolute_guest_address(uint32_t *instructions,
                                        uint32_t slots, uint64_t target)
{
    if (slots < 2 || slots > 3 ||
        (instructions[0] & 0xfe000000u) != 0x14000000u ||
        (instructions[1] & 0xffc00000u) != 0x03800000u ||
        (slots == 3 &&
         (instructions[2] & 0xfe000000u) != 0x16000000u) ||
        (slots == 2 && target >> 32)) {
        return -1;
    }
    uint32_t destination = instructions[0] & 0x1f;
    instructions[0] = 0x14000000u |
                      ((uint32_t)(target >> 12) & 0xfffff) << 5 |
                      destination;
    instructions[1] = 0x03800000u | ((uint32_t)target & 0xfff) << 10 |
                      destination << 5 | destination;
    if (slots == 3) {
        instructions[2] = 0x16000000u |
                          ((uint32_t)(target >> 32) & 0xfffff) << 5 |
                          destination;
    }
    return 0;
}

static int patch_guest_address(ModulePack *pack,
                               const LatNativeRelocationV1 *relocation)
{
    if ((uint64_t)relocation->addend < pack->header->preferred_guest_base) {
        return -1;
    }
    uint64_t target = (uint64_t)relocation->addend;
    uint32_t *instructions = (void *)(pack->code + relocation->code_offset);
    if (!(pack->header->flags & LAT_NATIVE_IMAGE_PIE)) {
        return patch_absolute_guest_address(instructions, relocation->slots,
                                            target);
    }
    uint64_t guest_rva = target - pack->header->preferred_guest_base;
    int slot = guest_slot(pack, guest_rva);
    if (slot < 0 || relocation->slots < 2 || relocation->slots > 3 ||
        (pack->three_level_guest_slots && relocation->slots < 3)) {
        return -1;
    }
    uint32_t destination = instructions[0] & 0x1f;
    uint32_t page = (uint32_t)slot / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
    uint32_t entry = (uint32_t)slot % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
    uint32_t root = pack->three_level_guest_slots ?
        page / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT : page;
    uint32_t middle = page % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
    int32_t offset = -(int32_t)((root + 1) * 8);
    instructions[0] = 0x28c00000u | ((uint32_t)offset & 0xfff) << 10 |
                      22u << 5 | destination;
    instructions[1] = 0x28c00000u |
                      ((pack->three_level_guest_slots ? middle : entry) * 8)
                          << 10 |
                      destination << 5 | destination;
    if (pack->three_level_guest_slots) {
        instructions[2] = 0x28c00000u | (entry * 8) << 10 |
                          destination << 5 | destination;
    } else {
        for (uint32_t i = 2; i < relocation->slots; i++) {
            instructions[i] = 0x03400000u;
        }
    }
    return 0;
}

static int patch_relocations(ModulePack *pack, char *error, size_t error_size)
{
    for (uint64_t i = 0; i < pack->header->tb_count; i++) {
        if (!pack->supported[i]) {
            memset(pack->code + pack->tbs[i].code_offset, 0,
                   pack->tbs[i].code_size);
        }
    }
    for (uint64_t i = 0; i < pack->header->relocation_count; i++) {
        const LatNativeRelocationV1 *relocation = &pack->relocations[i];
        int owner = find_code_tb(pack, relocation->code_offset);
        if (owner < 0 || !pack->supported[owner]) {
            continue;
        }
        uint32_t *instructions = (void *)(pack->code +
                                          relocation->code_offset);
        int result = -1;
        if (relocation->kind == LAT_NATIVE_RELOC_GUEST_ADDRESS) {
            result = patch_guest_address(pack, relocation);
        } else if (relocation->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                   relocation->target == LAT_NATIVE_SYMBOL_PFTABLE) {
            result = patch_runtime_target(instructions, relocation->slots,
                                          relocation->code_offset,
                                          pack->pf_table);
        } else if (relocation->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                   runtime_entry(relocation->target)) {
            result = patch_runtime_target(
                instructions, relocation->slots, relocation->code_offset,
                pack->runtime_trampolines + relocation->target * 4);
        } else if (relocation->kind == LAT_NATIVE_RELOC_TB_TARGET) {
            int target = find_tb(pack, (uint64_t)relocation->addend,
                                 relocation->target);
            if (target >= 0 && pack->supported[target]) {
                int direct_pair = relocation->slots == 2 &&
                    (instructions[0] & 0xfe00001fu) == 0x1e00000cu &&
                    (instructions[1] & 0xfc0003e0u) == 0x4c000180u;
                result = direct_pair ?
                    patch_tb_target_pair(
                        instructions, relocation->code_offset,
                        pack->tbs[target].code_offset) :
                    patch_runtime_target(
                        instructions, relocation->slots,
                        relocation->code_offset,
                        pack->tbs[target].code_offset);
            } else if (target < 0 && runtime_entry(relocation->reserved)) {
                result = patch_runtime_target(
                    instructions, relocation->slots,
                    relocation->code_offset,
                    pack->runtime_trampolines + relocation->reserved * 4);
            }
        }
        if (result) {
            return fail(error, error_size,
                        "cannot convert relocation %llu at code offset 0x%llx "
                        "(kind=%u target=%u slots=%u insn=%08x,%08x)",
                        (unsigned long long)i,
                        (unsigned long long)relocation->code_offset,
                        relocation->kind, relocation->target,
                        relocation->slots, instructions[0], instructions[1]);
        }
    }
    return 0;
}

static void print_bytes(FILE *file, const uint8_t bytes[32])
{
    for (size_t i = 0; i < 32; i++) {
        fprintf(file, "%s0x%02x", i ? ", " : "", bytes[i]);
    }
}

static int emit_metadata(const char *path, const ModulePack *pack,
                         char *error, size_t error_size)
{
    FILE *file = fopen(path, "w");
    if (!file) {
        return fail(error, error_size, "cannot create %s: %s", path,
                    strerror(errno));
    }
    uint8_t codegen[32];
    lat_aot_v2_codegen_digest(pack->header->lat_build_id, codegen);
    const char *guest_slot_flag = pack->three_level_guest_slots ?
        "LAT_AOT_MODULE_THREE_LEVEL_GUEST_SLOTS" :
        "LAT_AOT_MODULE_TWO_LEVEL_GUEST_SLOTS";
    fprintf(file,
        "#include \"lat-aot-v2.h\"\n#include <elf.h>\n"
        "#define MAGIC { 'L','A','T','A','O','T','2',0 }\n"
        "extern const uint8_t lat_aot_generated_text_begin[];\n"
        "extern const uint8_t lat_aot_generated_text_end[];\n"
        "typedef struct { Elf64_Nhdr h; char name[4]; LatAotNoteV2 d; } Note;\n"
        "__attribute__((section(\".note.lat.aot\"),aligned(4),used))\n"
        "static const Note note = { {4,sizeof(LatAotNoteV2),0x4c415432},"
        "\"LAT\", { MAGIC,2,sizeof(LatAotNoteV2),"
        "LAT_AOT_MODULE_PARTIAL|LAT_AOT_MODULE_READONLY_TEXT|"
        "LAT_AOT_MODULE_PRECISE_PC_MAP|%s,"
        "LAT_AOT_V2_REQUIRED_BASE_FEATURES|LAT_AOT_FEATURE_LASX,{ ",
        guest_slot_flag);
    print_bytes(file, pack->header->guest_sha256);
    fprintf(file, " },{ ");
    print_bytes(file, codegen);
    fprintf(file, " },{0} } };\n");

    fprintf(file,
        "extern const LatAotTbV2 lat_aot_generated_tbs_begin[];\n"
        "extern const LatAotTbV2 lat_aot_generated_tbs_end[];\n"
        "extern const LatAotPcMapV2 lat_aot_generated_maps_begin[];\n"
        "extern const LatAotPcMapV2 lat_aot_generated_maps_end[];\n"
        "extern const LatAotGuestSlotV2 lat_aot_generated_slots_begin[];\n"
        "extern const LatAotGuestSlotV2 lat_aot_generated_slots_end[];\n"
        "__attribute__((visibility(\"default\"),"
        "section(\".data.rel.ro.lat.module\"),used))\n"
        "const LatAotModuleV2 lat_aot_module_v2 = {"
        "MAGIC,2,sizeof(LatAotModuleV2),"
        "LAT_AOT_MODULE_PARTIAL|LAT_AOT_MODULE_READONLY_TEXT|"
        "LAT_AOT_MODULE_PRECISE_PC_MAP|%s,"
        "LAT_AOT_V2_REQUIRED_BASE_FEATURES|LAT_AOT_FEATURE_LASX,{ ",
        guest_slot_flag);
    print_bytes(file, pack->header->guest_sha256);
    fprintf(file, " },{ ");
    print_bytes(file, codegen);
    fprintf(file,
        " },{0},lat_aot_generated_text_begin,lat_aot_generated_text_end,"
        "lat_aot_generated_tbs_begin,lat_aot_generated_tbs_end,"
        "lat_aot_generated_maps_begin,lat_aot_generated_maps_end,"
        "lat_aot_generated_slots_begin,lat_aot_generated_slots_end};\n");
    int result = 0;
    if (fclose(file)) {
        result = fail(error, error_size, "cannot close %s", path);
    }
    return result;
}

static int emit_tables(const char *directory, const ModulePack *pack,
                       char *error, size_t error_size)
{
    char *tb_path = g_build_filename(directory, "tbs.bin", NULL);
    char *map_path = g_build_filename(directory, "pc-maps.bin", NULL);
    char *slot_path = g_build_filename(directory, "guest-slots.bin", NULL);
    FILE *tb_file = fopen(tb_path, "wb");
    FILE *map_file = fopen(map_path, "wb");
    FILE *slot_file = fopen(slot_path, "wb");
    int result = 0;
    if (!tb_file || !map_file || !slot_file) {
        result = fail(error, error_size, "cannot create binary module tables");
        goto out;
    }
    for (uint64_t i = 0; i < pack->header->tb_count; i++) {
        if (!pack->supported[i]) {
            continue;
        }
        LatAotTbV2 tb = {
            .guest_rva = pack->tbs[i].guest_pc -
                         pack->header->preferred_guest_base,
            .host_offset = pack->tbs[i].code_offset,
            .host_size = pack->tbs[i].code_size,
            .flags = pack->tbs[i].flags,
        };
        if (fwrite(&tb, sizeof(tb), 1, tb_file) != 1) {
            result = fail(error, error_size, "cannot write binary TB table");
            goto out;
        }
    }
    for (uint64_t i = 0; i < pack->header->pc_map_count; i++) {
        int owner = find_code_tb(pack, pack->pc_maps[i].host_offset_begin);
        if (owner < 0 || !pack->supported[owner] ||
            !pc_map_in_tb(&pack->pc_maps[i], &pack->tbs[owner])) {
            continue;
        }
        LatAotPcMapV2 map = {
            .guest_rva = pack->pc_maps[i].guest_pc -
                         pack->header->preferred_guest_base,
            .host_offset_begin = pack->pc_maps[i].host_offset_begin,
            .host_offset_end = pack->pc_maps[i].host_offset_end,
            .state_record_offset = pack->pc_maps[i].state_record_offset,
            .flags = pack->pc_maps[i].flags,
        };
        if (fwrite(&map, sizeof(map), 1, map_file) != 1) {
            result = fail(error, error_size, "cannot write binary PC map");
            goto out;
        }
    }
    for (guint i = 0; i < pack->guest_rvas->len; i++) {
        guint page = i / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
        guint root = pack->three_level_guest_slots ?
            page / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT : page;
        guint middle_offset = pack->three_level_guest_slots ?
            (page % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT) * 8 : 0;
        guint entry_offset =
            (i % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT) * 8;
        LatAotGuestSlotV2 slot = {
            .guest_rva = g_array_index(pack->guest_rvas, uint64_t, i),
            .fp_offset = -(int32_t)((root + 1) * 8),
            .reserved = pack->three_level_guest_slots ?
                (middle_offset << 16) | entry_offset : entry_offset,
        };
        if (fwrite(&slot, sizeof(slot), 1, slot_file) != 1) {
            result = fail(error, error_size, "cannot write binary guest slots");
            goto out;
        }
    }
out:
    if (tb_file && fclose(tb_file) && !result) result = -1;
    if (map_file && fclose(map_file) && !result) result = -1;
    if (slot_file && fclose(slot_file) && !result) result = -1;
    g_free(tb_path);
    g_free(map_path);
    g_free(slot_path);
    return result;
}

static int emit_assembly(const char *path, char *error, size_t error_size)
{
    FILE *file = fopen(path, "w");
    if (!file) {
        return fail(error, error_size, "cannot create %s: %s", path,
                    strerror(errno));
    }
    fprintf(file,
        ".section .text.lat.tu,\"ax\",@progbits\n.p2align 12\n"
        ".global lat_aot_generated_text_begin\n"
        ".hidden lat_aot_generated_text_begin\n"
        "lat_aot_generated_text_begin:\n.incbin \"text.bin\"\n.align 2\n");
    for (uint32_t symbol = 0; symbol < LAT_NATIVE_SYMBOL_COUNT; symbol++) {
        const char *entry = runtime_entry(symbol);
        fprintf(file, ".Llat_aot_runtime_%u:\n", symbol);
        if (entry) {
            fprintf(file, "b %s\n", entry);
        } else {
            fprintf(file, "nop\n");
        }
    }
    fprintf(file, ".Llat_aot_pf_table:\n");
    for (unsigned int value = 0; value < 256; value++) {
        unsigned int bits = value;
        unsigned int parity = 0;
        while (bits) {
            parity ^= bits & 1;
            bits >>= 1;
        }
        fprintf(file, "%s%u%s", value % 16 ? "," : ".byte ",
                parity ? 0 : 4, value % 16 == 15 ? "\n" : "");
    }
    fprintf(file,
        ".hidden lat_aot_generated_abi_anchor\n"
        "lat_aot_generated_abi_anchor:\n"
        "b lat_aot_runtime_abi_version\n"
        ".global lat_aot_generated_text_end\n"
        ".hidden lat_aot_generated_text_end\n"
        "lat_aot_generated_text_end:\n"
        ".section .rodata.lat.tb,\"a\",@progbits\n.p2align 3\n"
        ".global lat_aot_generated_tbs_begin\n.hidden lat_aot_generated_tbs_begin\n"
        "lat_aot_generated_tbs_begin:\n.incbin \"tbs.bin\"\n"
        ".global lat_aot_generated_tbs_end\n.hidden lat_aot_generated_tbs_end\n"
        "lat_aot_generated_tbs_end:\n"
        ".section .rodata.lat.map,\"a\",@progbits\n.p2align 3\n"
        ".global lat_aot_generated_maps_begin\n.hidden lat_aot_generated_maps_begin\n"
        "lat_aot_generated_maps_begin:\n.incbin \"pc-maps.bin\"\n"
        ".global lat_aot_generated_maps_end\n.hidden lat_aot_generated_maps_end\n"
        "lat_aot_generated_maps_end:\n"
        ".section .rodata.lat.guest,\"a\",@progbits\n.p2align 3\n"
        ".global lat_aot_generated_slots_begin\n.hidden lat_aot_generated_slots_begin\n"
        "lat_aot_generated_slots_begin:\n.incbin \"guest-slots.bin\"\n"
        ".global lat_aot_generated_slots_end\n.hidden lat_aot_generated_slots_end\n"
        "lat_aot_generated_slots_end:\n.zero 16\n");
    int result = 0;
    if (fclose(file)) {
        result = fail(error, error_size, "cannot close %s", path);
    }
    return result;
}

int lat_aot_v2_emit_module_sources(const char *native_image,
                                   const char *output_directory,
                                   char *error, size_t error_size)
{
    gchar *image = NULL;
    gsize image_size = 0;
    if (!native_image || !output_directory ||
        !g_file_get_contents(native_image, &image, &image_size, NULL)) {
        return fail(error, error_size, "cannot read native image %s",
                    native_image ? native_image : "(null)");
    }
    if (lat_native_image_validate(image, image_size, error, error_size)) {
        g_free(image);
        return -1;
    }
    if (g_mkdir_with_parents(output_directory, 0700)) {
        g_free(image);
        return fail(error, error_size, "cannot create output directory %s",
                    output_directory);
    }
    const LatNativeImageHeaderV2 *header = (const void *)image;
    ModulePack pack = {
        .header = header,
        .tbs = (const void *)(image + header->tb_table_offset),
        .relocations = (const void *)(image + header->relocation_offset),
        .pc_maps = (const void *)(image + header->pc_map_offset),
        .code = g_malloc(header->code_size),
        .supported = g_malloc0(header->tb_count),
        .code_order = g_array_sized_new(FALSE, FALSE,
                                        sizeof(const LatNativeTbV1 *),
                                        header->tb_count),
        .guest_rvas = g_array_new(FALSE, FALSE, sizeof(uint64_t)),
        .guest_rva_indexes = g_hash_table_new_full(
            g_int64_hash, g_int64_equal, g_free, NULL),
        .runtime_trampolines = (header->code_size + 3) & ~(uint64_t)3,
    };
    pack.pf_table = pack.runtime_trampolines +
                    LAT_NATIVE_SYMBOL_COUNT * sizeof(uint32_t);
    for (uint64_t i = 0; i < header->tb_count; i++) {
        const LatNativeTbV1 *tb = &pack.tbs[i];
        g_array_append_val(pack.code_order, tb);
    }
    g_array_sort(pack.code_order, compare_tb_code);
    memcpy(pack.code, image + header->code_offset, header->code_size);
    int all_ranges_valid = all_tb_ranges_valid(&pack);
    select_supported_tbs(&pack);
    size_t supported_count = 0;
    for (uint64_t i = 0; i < header->tb_count; i++) {
        supported_count += pack.supported[i] != 0;
    }
    int result = 0;
    size_t pc_map_count = selected_pc_map_count(&pack);
    if (!all_ranges_valid) {
        result = fail(error, error_size,
                      "native image has overlapping TB host ranges");
    } else if (!supported_count) {
        result = fail(error, error_size,
                      "native image has no TB supported by AOT v2 M1");
    } else if (!selected_tb_ranges_valid(&pack)) {
        result = fail(error, error_size,
                      "supported AOT v2 TB host ranges overlap");
    } else if (!pc_map_count || !selected_pc_maps_complete(&pack)) {
        result = fail(error, error_size,
                      "supported AOT v2 TBs have no complete PC map");
    } else if (patch_relocations(&pack, error, error_size)) {
        result = -1;
    } else {
        char *text_path = g_build_filename(output_directory, "text.bin", NULL);
        char *metadata_path = g_build_filename(output_directory, "module.c", NULL);
        char *assembly_path = g_build_filename(output_directory, "module.S", NULL);
        if (write_all(text_path, pack.code, header->code_size,
                      error, error_size) ||
            emit_tables(output_directory, &pack, error, error_size) ||
            emit_metadata(metadata_path, &pack, error, error_size) ||
            emit_assembly(assembly_path, error, error_size)) {
            result = -1;
        }
        g_free(text_path);
        g_free(metadata_path);
        g_free(assembly_path);
    }
    g_hash_table_destroy(pack.guest_rva_indexes);
    g_array_free(pack.guest_rvas, TRUE);
    g_array_free(pack.code_order, TRUE);
    g_free(pack.supported);
    g_free(pack.code);
    g_free(image);
    return result;
}
