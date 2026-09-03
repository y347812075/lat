#include "native-image.h"

#include <elf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct NativeMergeInput {
    unsigned char *data;
    size_t size;
    const LatNativeImageHeaderV2 *header;
    uint64_t code_base;
} NativeMergeInput;

typedef struct NativeCodeMove {
    uint64_t old_begin;
    uint64_t old_end;
    uint64_t new_begin;
} NativeCodeMove;

static int invalid(char *error, size_t error_size, const char *format, ...)
{
    va_list args;

    if (error && error_size) {
        va_start(args, format);
        vsnprintf(error, error_size, format, args);
        va_end(args);
    }
    return -1;
}

static int range_valid(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static int write_image(const char *path, const void *data, size_t size,
                       char *error, size_t error_size)
{
    FILE *file = fopen(path, "wb");
    if (!file) return invalid(error, error_size, "cannot create %s", path);
    int result = size && fwrite(data, size, 1, file) != 1 ?
        invalid(error, error_size, "cannot write %s", path) : 0;
    if (fclose(file) && !result) {
        result = invalid(error, error_size, "cannot close %s", path);
    }
    return result;
}

static int tb_target_valid(const LatNativeTbV1 *tbs, uint64_t count,
                           uint64_t guest_pc, uint32_t flags)
{
    uint64_t left = 0;
    uint64_t right = count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = &tbs[middle];
        if (tb->guest_pc < guest_pc ||
            (tb->guest_pc == guest_pc && tb->flags < flags)) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < count && tbs[left].guest_pc == guest_pc &&
        tbs[left].flags == flags) {
        return 1;
    }
    left = 0;
    right = count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        if (tbs[middle].guest_pc < guest_pc) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    return left < count && tbs[left].guest_pc == guest_pc &&
        (left + 1 == count || tbs[left + 1].guest_pc != guest_pc);
}

static int tb_fallback_symbol_valid(uint32_t symbol)
{
    return symbol == LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_1 ||
           symbol == LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0 ||
           symbol == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1 ||
           symbol == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0 ||
           symbol == LAT_NATIVE_SYMBOL_EPILOGUE_RET_0;
}

int lat_native_image_validate(const void *data, size_t size,
                              char *error, size_t error_size)
{
    const LatNativeImageHeaderV2 *header = data;
    const LatNativeTbV1 *tbs;
    const LatNativeRelocationV1 *relocations;
    const LatNativePcMapV2 *pc_maps;
    uint64_t table_size;

    if (!data || size < sizeof(*header)) {
        return invalid(error, error_size, "native image is truncated");
    }
    if (memcmp(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8) != 0 ||
        header->version != LAT_NATIVE_IMAGE_VERSION ||
        header->header_size != sizeof(*header)) {
        return invalid(error, error_size, "invalid native image header");
    }
    if (!header->lat_build_id[0] ||
        header->lat_build_id[LAT_NATIVE_BUILD_ID_SIZE - 1] != '\0') {
        return invalid(error, error_size, "invalid LAT build ID");
    }
    if (!header->guest_image_size || !header->code_size || !header->tb_count ||
        header->guest_image_offset < sizeof(*header)) {
        return invalid(error, error_size, "native image has an empty section");
    }
    if (!range_valid(header->guest_image_offset, header->guest_image_size,
                     size) ||
        !range_valid(header->code_offset, header->code_size, size)) {
        return invalid(error, error_size, "native image payload is truncated");
    }
    if (header->code_offset <
        header->guest_image_offset + header->guest_image_size) {
        return invalid(error, error_size, "native image sections overlap");
    }
    if (header->tb_count > UINT64_MAX / sizeof(*tbs)) {
        return invalid(error, error_size, "native TB table is too large");
    }
    table_size = header->tb_count * sizeof(*tbs);
    if (!range_valid(header->tb_table_offset, table_size, size)) {
        return invalid(error, error_size, "native TB table is truncated");
    }
    if (header->tb_table_offset < header->code_offset + header->code_size) {
        return invalid(error, error_size, "native image sections overlap");
    }
    if (header->relocation_count > UINT64_MAX / sizeof(*relocations)) {
        return invalid(error, error_size,
                       "native relocation table is too large");
    }
    table_size = header->relocation_count * sizeof(*relocations);
    if (!range_valid(header->relocation_offset, table_size, size)) {
        return invalid(error, error_size,
                       "native relocation table is truncated");
    }
    if (header->relocation_offset <
            header->tb_table_offset +
            header->tb_count * sizeof(*tbs) ||
        header->relocation_offset + table_size != header->pc_map_offset) {
        return invalid(error, error_size,
                       "native image has invalid section boundaries");
    }
    if (header->pc_map_count > UINT64_MAX / sizeof(*pc_maps)) {
        return invalid(error, error_size, "native PC map is too large");
    }
    table_size = header->pc_map_count * sizeof(*pc_maps);
    if (!range_valid(header->pc_map_offset, table_size, size) ||
        header->pc_map_offset + table_size != size) {
        return invalid(error, error_size, "native PC map is truncated");
    }
    if (!header->pc_map_count &&
        !(header->flags & LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP)) {
        return invalid(error, error_size, "native image has no precise PC map");
    }

    tbs = (const void *)((const unsigned char *)data +
                         header->tb_table_offset);
    for (uint64_t i = 0; i < header->tb_count; i++) {
        if (tbs[i].code_offset >= header->code_size ||
            tbs[i].code_size > header->code_size - tbs[i].code_offset) {
            return invalid(error, error_size,
                           "native TB %llu has an invalid code range",
                           (unsigned long long)i);
        }
        if (i && (tbs[i - 1].guest_pc > tbs[i].guest_pc ||
                  (tbs[i - 1].guest_pc == tbs[i].guest_pc &&
                   tbs[i - 1].flags >= tbs[i].flags))) {
            return invalid(error, error_size,
                           "native TB table is not sorted by guest PC and flags");
        }
    }

    relocations = (const void *)((const unsigned char *)data +
                                 header->relocation_offset);
    for (uint64_t i = 0; i < header->relocation_count; i++) {
        if (relocations[i].code_offset >= header->code_size ||
            !relocations[i].slots || relocations[i].slots > 4 ||
            relocations[i].slots * 4 >
                header->code_size - relocations[i].code_offset ||
            relocations[i].kind < LAT_NATIVE_RELOC_RUNTIME_SYMBOL ||
            relocations[i].kind > LAT_NATIVE_RELOC_JRRA_TARGET) {
            return invalid(error, error_size,
                           "native relocation %llu is invalid "
                           "(kind=%u slots=%u offset=0x%llx)",
                           (unsigned long long)i, relocations[i].kind,
                           relocations[i].slots,
                           (unsigned long long)relocations[i].code_offset);
        }
        if (relocations[i].kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
            (relocations[i].target <= LAT_NATIVE_SYMBOL_INVALID ||
             relocations[i].target >= LAT_NATIVE_SYMBOL_COUNT)) {
            return invalid(error, error_size,
                           "native relocation %llu has an invalid runtime symbol",
                           (unsigned long long)i);
        }
        if (relocations[i].kind == LAT_NATIVE_RELOC_GUEST_ADDRESS &&
            relocations[i].target != 0) {
            return invalid(error, error_size,
                           "native relocation %llu has an invalid guest target",
                           (unsigned long long)i);
        }
        if (relocations[i].kind == LAT_NATIVE_RELOC_JRRA_TARGET &&
            relocations[i].slots != 4) {
            return invalid(error, error_size,
                           "native JRRA relocation %llu must use 4 slots",
                           (unsigned long long)i);
        }
        if ((header->flags & LAT_NATIVE_IMAGE_X86_STATIC_EXEC) &&
            (relocations[i].kind == LAT_NATIVE_RELOC_TB_TARGET ||
             relocations[i].kind == LAT_NATIVE_RELOC_JRRA_TARGET) &&
            !tb_target_valid(tbs, header->tb_count,
                             (uint64_t)relocations[i].addend,
                             relocations[i].target) &&
            (!(header->flags & LAT_NATIVE_IMAGE_CROSS_MODULE_TARGETS) ||
             relocations[i].kind != LAT_NATIVE_RELOC_TB_TARGET ||
             !tb_fallback_symbol_valid(relocations[i].reserved))) {
            return invalid(error, error_size,
                           "native relocation %llu targets a missing TB",
                           (unsigned long long)i);
        }
    }

    pc_maps = (const void *)((const unsigned char *)data +
                             header->pc_map_offset);
    for (uint64_t i = 0; i < header->pc_map_count; i++) {
        if (!pc_maps[i].guest_pc ||
            pc_maps[i].host_offset_begin >= pc_maps[i].host_offset_end ||
            pc_maps[i].host_offset_end > header->code_size ||
            pc_maps[i].state_record_offset != 0 ||
            pc_maps[i].flags != LAT_NATIVE_PC_MAP_DYNAMIC_STATE ||
            (i && pc_maps[i - 1].host_offset_end >
                  pc_maps[i].host_offset_begin)) {
            return invalid(error, error_size,
                           "native PC map entry %llu is invalid",
                           (unsigned long long)i);
        }
    }
    return 0;
}

int lat_native_image_inspect_file(const char *path,
                                  LatNativeImageHeaderV2 *header,
                                  char *error, size_t error_size)
{
    FILE *input = fopen(path, "rb");
    void *data = NULL;
    int result = -1;

    if (!input) {
        return invalid(error, error_size, "cannot open native image");
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        goto out;
    }
    long end = ftell(input);
    if (end < 0 || fseek(input, 0, SEEK_SET) != 0) {
        goto out;
    }
    size_t size = (size_t)end;
    if ((long)size != end || !(data = malloc(size ? size : 1)) ||
        (size && fread(data, size, 1, input) != 1)) {
        goto out;
    }
    if (lat_native_image_validate(data, size, error, error_size) != 0) {
        goto out;
    }
    if (header) {
        memcpy(header, data, sizeof(*header));
    }
    result = 0;
out:
    if (result && error && error_size && !error[0]) {
        snprintf(error, error_size, "cannot read native image");
    }
    free(data);
    fclose(input);
    return result;
}

static uint64_t align16(uint64_t value)
{
    return (value + 15) & ~(uint64_t)15;
}

static int compare_native_tb(const void *left, const void *right)
{
    const LatNativeTbV1 *a = left, *b = right;
    if (a->guest_pc != b->guest_pc) return a->guest_pc < b->guest_pc ? -1 : 1;
    return (a->flags > b->flags) - (a->flags < b->flags);
}

static int compare_code_move(const void *left, const void *right)
{
    const NativeCodeMove *a = left, *b = right;
    return (a->old_begin > b->old_begin) - (a->old_begin < b->old_begin);
}

static const NativeCodeMove *find_code_move(const NativeCodeMove *moves,
                                             uint64_t count,
                                             uint64_t offset)
{
    uint64_t left = 0, right = count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        if (moves[middle].old_begin <= offset) left = middle + 1;
        else right = middle;
    }
    if (!left || offset >= moves[left - 1].old_end) return NULL;
    return &moves[left - 1];
}

int lat_native_image_merge_files(const char *const *paths, size_t path_count,
                                 const char *output,
                                 char *error, size_t error_size)
{
    if (!paths || path_count < 2 || !output) {
        return invalid(error, error_size, "at least two native images are required");
    }
    NativeMergeInput *inputs = calloc(path_count, sizeof(*inputs));
    uint64_t total_code = 0, total_tbs = 0, total_relocs = 0, total_maps = 0;
    int result = -1;
    for (size_t i = 0; i < path_count; i++) {
        FILE *file = fopen(paths[i], "rb");
        if (!file || fseek(file, 0, SEEK_END)) {
            if (file) fclose(file);
            invalid(error, error_size, "cannot open native fragment %s", paths[i]);
            goto out;
        }
        long end = ftell(file);
        if (end < 0 || fseek(file, 0, SEEK_SET) ||
            !(inputs[i].data = malloc((size_t)end)) ||
            fread(inputs[i].data, (size_t)end, 1, file) != 1) {
            fclose(file);
            invalid(error, error_size, "cannot read native fragment %s", paths[i]);
            goto out;
        }
        fclose(file);
        inputs[i].size = (size_t)end;
        if (lat_native_image_validate(inputs[i].data, inputs[i].size,
                                      error, error_size)) goto out;
        inputs[i].header = (const void *)inputs[i].data;
        const LatNativeImageHeaderV2 *h = inputs[i].header;
        if (i && (h->guest_entry != inputs[0].header->guest_entry ||
                  h->preferred_guest_base != inputs[0].header->preferred_guest_base ||
                  h->guest_image_size != inputs[0].header->guest_image_size ||
                  memcmp(h->guest_sha256, inputs[0].header->guest_sha256, 32) ||
                  strcmp(h->lat_build_id, inputs[0].header->lat_build_id) ||
                  memcmp(inputs[i].data + h->guest_image_offset,
                         inputs[0].data + inputs[0].header->guest_image_offset,
                         h->guest_image_size))) {
            invalid(error, error_size, "native fragments do not describe the same guest");
            goto out;
        }
        inputs[i].code_base = total_code;
        if (UINT64_MAX - total_code < align16(h->code_size) ||
            UINT64_MAX - total_tbs < h->tb_count ||
            UINT64_MAX - total_relocs < h->relocation_count ||
            UINT64_MAX - total_maps < h->pc_map_count) {
            invalid(error, error_size, "merged native image is too large");
            goto out;
        }
        total_code += align16(h->code_size);
        total_tbs += h->tb_count;
        total_relocs += h->relocation_count;
        total_maps += h->pc_map_count;
    }
    const LatNativeImageHeaderV2 *first = inputs[0].header;
    uint64_t guest_offset = align16(sizeof(*first));
    uint64_t code_offset = align16(guest_offset + first->guest_image_size);
    uint64_t tb_offset = code_offset + total_code;
    uint64_t reloc_offset = tb_offset + total_tbs * sizeof(LatNativeTbV1);
    uint64_t map_offset = reloc_offset + total_relocs * sizeof(LatNativeRelocationV1);
    uint64_t total_size = map_offset + total_maps * sizeof(LatNativePcMapV2);
    if (total_size > SIZE_MAX) {
        invalid(error, error_size, "merged native image is too large");
        goto out;
    }
    unsigned char *merged = calloc(1, (size_t)total_size);
    if (!merged) {
        invalid(error, error_size, "out of memory merging native images");
        goto out;
    }
    LatNativeImageHeaderV2 *header = (void *)merged;
    *header = *first;
    header->guest_image_offset = guest_offset;
    header->code_offset = code_offset;
    header->code_size = total_code;
    header->tb_table_offset = tb_offset;
    header->tb_count = total_tbs;
    header->relocation_offset = reloc_offset;
    header->relocation_count = total_relocs;
    header->pc_map_offset = map_offset;
    header->pc_map_count = total_maps;
    memcpy(merged + guest_offset, inputs[0].data + first->guest_image_offset,
           first->guest_image_size);
    LatNativeTbV1 *out_tbs = (void *)(merged + tb_offset);
    LatNativeRelocationV1 *out_relocs = (void *)(merged + reloc_offset);
    LatNativePcMapV2 *out_maps = (void *)(merged + map_offset);
    uint64_t tb_pos = 0, reloc_pos = 0, map_pos = 0;
    for (size_t i = 0; i < path_count; i++) {
        const LatNativeImageHeaderV2 *h = inputs[i].header;
        memcpy(merged + code_offset + inputs[i].code_base,
               inputs[i].data + h->code_offset, h->code_size);
        const LatNativeTbV1 *tbs = (const void *)(inputs[i].data + h->tb_table_offset);
        for (uint64_t j = 0; j < h->tb_count; j++) {
            out_tbs[tb_pos] = tbs[j];
            out_tbs[tb_pos++].code_offset += inputs[i].code_base;
        }
        const LatNativeRelocationV1 *relocs =
            (const void *)(inputs[i].data + h->relocation_offset);
        for (uint64_t j = 0; j < h->relocation_count; j++) {
            out_relocs[reloc_pos] = relocs[j];
            out_relocs[reloc_pos++].code_offset += inputs[i].code_base;
        }
        const LatNativePcMapV2 *maps =
            (const void *)(inputs[i].data + h->pc_map_offset);
        for (uint64_t j = 0; j < h->pc_map_count; j++) {
            out_maps[map_pos] = maps[j];
            out_maps[map_pos].host_offset_begin += inputs[i].code_base;
            out_maps[map_pos++].host_offset_end += inputs[i].code_base;
        }
    }
    qsort(out_tbs, total_tbs, sizeof(*out_tbs), compare_native_tb);
    uint64_t unique_tbs = 0;
    for (uint64_t i = 0; i < total_tbs; i++) {
        if (unique_tbs &&
            out_tbs[unique_tbs - 1].guest_pc == out_tbs[i].guest_pc &&
            out_tbs[unique_tbs - 1].flags == out_tbs[i].flags) {
            continue;
        }
        out_tbs[unique_tbs++] = out_tbs[i];
    }
    header->tb_count = unique_tbs;

    NativeCodeMove *moves = calloc(unique_tbs, sizeof(*moves));
    if (!moves) {
        free(merged);
        invalid(error, error_size, "out of memory compacting native images");
        goto out;
    }
    uint64_t compact_code_size = 0;
    for (uint64_t i = 0; i < unique_tbs; i++) {
        uint64_t old_begin = out_tbs[i].code_offset;
        uint64_t old_end = old_begin + out_tbs[i].code_size;
        moves[i] = (NativeCodeMove) {
            .old_begin = old_begin,
            .old_end = old_end,
        };
    }
    qsort(moves, unique_tbs, sizeof(*moves), compare_code_move);
    uint64_t previous_old_end = UINT64_MAX;
    for (uint64_t i = 0; i < unique_tbs; i++) {
        if (moves[i].old_begin != previous_old_end) {
            compact_code_size = align16(compact_code_size);
        }
        moves[i].new_begin = compact_code_size;
        compact_code_size += moves[i].old_end - moves[i].old_begin;
        previous_old_end = moves[i].old_end;
    }
    compact_code_size = align16(compact_code_size);
    uint64_t compact_relocs = 0, compact_maps = 0;
    for (uint64_t i = 0; i < total_relocs; i++) {
        if (find_code_move(moves, unique_tbs, out_relocs[i].code_offset)) {
            compact_relocs++;
        }
    }
    for (uint64_t i = 0; i < total_maps; i++) {
        const NativeCodeMove *move = find_code_move(
            moves, unique_tbs, out_maps[i].host_offset_begin);
        if (move && out_maps[i].host_offset_end <= move->old_end) compact_maps++;
    }
    uint64_t compact_tb_offset = code_offset + compact_code_size;
    uint64_t compact_reloc_offset = compact_tb_offset +
        unique_tbs * sizeof(LatNativeTbV1);
    uint64_t compact_map_offset = compact_reloc_offset +
        compact_relocs * sizeof(LatNativeRelocationV1);
    uint64_t compact_size = compact_map_offset +
        compact_maps * sizeof(LatNativePcMapV2);
    unsigned char *compact = calloc(1, (size_t)compact_size);
    if (!compact) {
        free(moves);
        free(merged);
        invalid(error, error_size, "out of memory compacting native images");
        goto out;
    }
    LatNativeImageHeaderV2 *compact_header = (void *)compact;
    *compact_header = *header;
    compact_header->code_size = compact_code_size;
    compact_header->tb_table_offset = compact_tb_offset;
    compact_header->relocation_offset = compact_reloc_offset;
    compact_header->relocation_count = compact_relocs;
    compact_header->pc_map_offset = compact_map_offset;
    compact_header->pc_map_count = compact_maps;
    memcpy(compact + guest_offset, merged + guest_offset,
           first->guest_image_size);
    for (uint64_t i = 0; i < unique_tbs; i++) {
        memcpy(compact + code_offset + moves[i].new_begin,
               merged + code_offset + moves[i].old_begin,
               moves[i].old_end - moves[i].old_begin);
    }
    LatNativeTbV1 *compact_tbs = (void *)(compact + compact_tb_offset);
    memcpy(compact_tbs, out_tbs, unique_tbs * sizeof(*compact_tbs));
    for (uint64_t i = 0; i < unique_tbs; i++) {
        const NativeCodeMove *move = find_code_move(
            moves, unique_tbs, compact_tbs[i].code_offset);
        compact_tbs[i].code_offset = move->new_begin;
    }
    LatNativeRelocationV1 *compact_relocation_table =
        (void *)(compact + compact_reloc_offset);
    uint64_t compact_pos = 0;
    for (uint64_t i = 0; i < total_relocs; i++) {
        const NativeCodeMove *move = find_code_move(
            moves, unique_tbs, out_relocs[i].code_offset);
        if (!move) continue;
        compact_relocation_table[compact_pos] = out_relocs[i];
        compact_relocation_table[compact_pos++].code_offset =
            move->new_begin + out_relocs[i].code_offset - move->old_begin;
    }
    LatNativePcMapV2 *compact_map_table =
        (void *)(compact + compact_map_offset);
    compact_pos = 0;
    for (uint64_t i = 0; i < total_maps; i++) {
        const NativeCodeMove *move = find_code_move(
            moves, unique_tbs, out_maps[i].host_offset_begin);
        if (!move || out_maps[i].host_offset_end > move->old_end) continue;
        compact_map_table[compact_pos] = out_maps[i];
        compact_map_table[compact_pos].host_offset_begin = move->new_begin +
            out_maps[i].host_offset_begin - move->old_begin;
        compact_map_table[compact_pos++].host_offset_end = move->new_begin +
            out_maps[i].host_offset_end - move->old_begin;
    }
    free(moves);
    free(merged);
    if (lat_native_image_validate(compact, (size_t)compact_size,
                                  error, error_size) ||
        write_image(output, compact, (size_t)compact_size,
                    error, error_size)) {
        free(compact);
        goto out;
    }
    free(compact);
    result = 0;
out:
    for (size_t i = 0; i < path_count; i++) free(inputs[i].data);
    free(inputs);
    return result;
}

static int validate_static_x86_guest(const LatNativeImageHeaderV2 *header,
                                     const unsigned char *data, size_t size,
                                     char *error, size_t error_size)
{
    if (!range_valid(header->guest_image_offset, header->guest_image_size,
                     size) || header->guest_image_size < sizeof(Elf64_Ehdr)) {
        return invalid(error, error_size, "embedded x86 ELF is truncated");
    }
    const unsigned char *guest = data + header->guest_image_offset;
    const Elf64_Ehdr *elf = (const void *)guest;
    if (memcmp(elf->e_ident, ELFMAG, SELFMAG) ||
        elf->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf->e_ident[EI_DATA] != ELFDATA2LSB ||
        elf->e_machine != EM_X86_64 ||
        (elf->e_type != ET_EXEC && elf->e_type != ET_DYN) ||
        elf->e_entry != header->guest_entry ||
        elf->e_phentsize != sizeof(Elf64_Phdr) || !elf->e_phnum ||
        elf->e_phoff > header->guest_image_size ||
        elf->e_phnum > (header->guest_image_size - elf->e_phoff) /
                       sizeof(Elf64_Phdr)) {
        return invalid(error, error_size,
                       "embedded guest is not a supported x86-64 ELF");
    }
    const Elf64_Phdr *phdrs = (const void *)(guest + elf->e_phoff);
    int entry_is_executable = 0;
    for (uint16_t i = 0; i < elf->e_phnum; i++) {
        if (phdrs[i].p_type == PT_INTERP) {
            return invalid(error, error_size,
                           "embedded x86 ELF is dynamically linked");
        }
        if (phdrs[i].p_type == PT_LOAD && (phdrs[i].p_flags & PF_X) &&
            elf->e_entry >= phdrs[i].p_vaddr &&
            elf->e_entry - phdrs[i].p_vaddr < phdrs[i].p_memsz) {
            entry_is_executable = 1;
        }
    }
    if (!entry_is_executable) {
        return invalid(error, error_size,
                       "embedded x86 ELF entry is not executable");
    }
    return 0;
}

int lat_native_image_mark_x86_static_file(const char *path,
                                          char *error, size_t error_size)
{
    FILE *image = fopen(path, "r+b");
    unsigned char *data = NULL;
    int result = -1;
    if (!image) {
        return invalid(error, error_size, "cannot open native image");
    }
    if (fseek(image, 0, SEEK_END)) goto out;
    long end = ftell(image);
    if (end < 0 || fseek(image, 0, SEEK_SET)) {
        goto out;
    }
    size_t size = (size_t)end;
    if ((long)size != end || !(data = malloc(size ? size : 1)) ||
        (size && fread(data, size, 1, image) != 1)) {
        goto out;
    }
    if (lat_native_image_validate(data, size, error, error_size) ||
        validate_static_x86_guest((const void *)data, data, size,
                                  error, error_size)) {
        goto out;
    }
    LatNativeImageHeaderV2 *header = (void *)data;
    header->flags |= LAT_NATIVE_IMAGE_X86_STATIC_EXEC;
    if (lat_native_image_validate(data, size, error, error_size)) {
        goto out;
    }
    if (fseek(image, 0, SEEK_SET) ||
        fwrite(header, sizeof(*header), 1, image) != 1 || fflush(image)) {
        goto out;
    }
    result = 0;
out:
    if (result && error && error_size && !error[0]) {
        snprintf(error, error_size, "cannot update native image");
    }
    free(data);
    if (image) fclose(image);
    return result;
}
