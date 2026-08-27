#include "qemu/osdep.h"

#include "latc_native_export.h"
#include "lat-native-image.h"
#include "latc-build-id.h"

#include <elf.h>
#include <glib.h>

static uint64_t align_up(uint64_t value, uint64_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static gint compare_native_tb(gconstpointer left, gconstpointer right)
{
    const LatNativeTbV1 *a = left;
    const LatNativeTbV1 *b = right;
    if (a->guest_pc != b->guest_pc) {
        return a->guest_pc < b->guest_pc ? -1 : 1;
    }
    if (a->flags != b->flags) {
        return a->flags < b->flags ? -1 : 1;
    }
    return 0;
}

static gint compare_uint64(gconstpointer left, gconstpointer right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : a > b;
}

static gint compare_native_pc_map(gconstpointer left, gconstpointer right)
{
    const LatNativePcMapV2 *a = left;
    const LatNativePcMapV2 *b = right;
    if (a->host_offset_begin != b->host_offset_begin) {
        return a->host_offset_begin < b->host_offset_begin ? -1 : 1;
    }
    if (a->host_offset_end != b->host_offset_end) {
        return a->host_offset_end < b->host_offset_end ? -1 : 1;
    }
    return 0;
}

static bool native_tb_target_exists(const GArray *tbs, uint64_t guest_pc,
                                    uint32_t flags)
{
    guint left = 0;
    guint right = tbs->len;
    while (left < right) {
        guint middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = &g_array_index(
            tbs, LatNativeTbV1, middle);
        if (tb->guest_pc < guest_pc ||
            (tb->guest_pc == guest_pc && tb->flags < flags)) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < tbs->len) {
        const LatNativeTbV1 *tb = &g_array_index(
            tbs, LatNativeTbV1, left);
        if (tb->guest_pc == guest_pc && tb->flags == flags) {
            return true;
        }
    }

    left = 0;
    right = tbs->len;
    while (left < right) {
        guint middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = &g_array_index(
            tbs, LatNativeTbV1, middle);
        if (tb->guest_pc < guest_pc) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left >= tbs->len) {
        return false;
    }
    const LatNativeTbV1 *tb = &g_array_index(tbs, LatNativeTbV1, left);
    if (tb->guest_pc != guest_pc) {
        return false;
    }
    return left + 1 == tbs->len ||
        g_array_index(tbs, LatNativeTbV1, left + 1).guest_pc != guest_pc;
}

static bool guest_executable_address(const GByteArray *guest, uint64_t pc,
                                     uint64_t load_bias)
{
    if (pc < load_bias) {
        return false;
    }
    pc -= load_bias;
    const Elf64_Ehdr *elf = (const void *)guest->data;
    const Elf64_Phdr *program_headers =
        (const void *)(guest->data + elf->e_phoff);
    for (uint16_t i = 0; i < elf->e_phnum; i++) {
        const Elf64_Phdr *header = &program_headers[i];
        if (header->p_type == PT_LOAD && (header->p_flags & PF_X) &&
            pc >= header->p_vaddr && pc - header->p_vaddr < header->p_memsz) {
            return true;
        }
    }
    return false;
}

static int runtime_symbol(aot_rel_kind kind)
{
    switch (kind) {
    case B_EPILOGUE_RET_ID_1: return LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_1;
    case B_EPILOGUE_RET_ID_0: return LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0;
    case JIRL_EPILOGUE_RET_ID_1:
        return LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1;
    case JIRL_EPILOGUE_RET_ID_0:
        return LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0;
    case B_EPILOGUE_RET_0: return LAT_NATIVE_SYMBOL_EPILOGUE_RET_0;
    case LOAD_HELPER_UPDATE_MXCSR_STATUS:
        return LAT_NATIVE_SYMBOL_UPDATE_MXCSR_STATUS;
    case LOAD_HELPER_FXSAVE: return LAT_NATIVE_SYMBOL_FXSAVE;
    case LOAD_HELPER_FXRSTOR: return LAT_NATIVE_SYMBOL_FXRSTOR;
    case LOAD_HELPER_CONVERT_FPREGS_X80_TO_64:
        return LAT_NATIVE_SYMBOL_FPREGS_X80_TO_64;
    case LOAD_HELPER_CONVERT_FPREGS_64_TO_X80:
        return LAT_NATIVE_SYMBOL_FPREGS_64_TO_X80;
    case LOAD_HELPER_UPDATE_FP_STATUS:
        return LAT_NATIVE_SYMBOL_UPDATE_FP_STATUS;
    case LOAD_HELPER_CPUID: return LAT_NATIVE_SYMBOL_CPUID;
    case LOAD_HELPER_RAISE_ILLOP: return LAT_NATIVE_SYMBOL_RAISE_ILLOP;
    case LOAD_HELPER_RAISE_GPF: return LAT_NATIVE_SYMBOL_RAISE_GPF;
    case LOAD_HELPER_RAISE_SYSCALL: return LAT_NATIVE_SYMBOL_RAISE_SYSCALL;
    case LOAD_HOST_PFTABLE: return LAT_NATIVE_SYMBOL_PFTABLE;
    case LOAD_HELPER_PCMPISTRI_XMM:
        return LAT_NATIVE_SYMBOL_PCMPISTRI_XMM;
    case LOAD_HELPER_PCMPISTRM_XMM:
        return LAT_NATIVE_SYMBOL_PCMPISTRM_XMM;
    case LOAD_HELPER_EFLAGTF: return LAT_NATIVE_SYMBOL_EFLAGTF;
    default: return LAT_NATIVE_SYMBOL_INVALID;
    }
}

static const aot_segment *find_tb_segment(const aot_header *header,
        const aot_segment *segments, const aot_tb *tb)
{
    uintptr_t address = (uintptr_t)tb;
    for (uint32_t i = 0; i < header->segments_num; i++) {
        uintptr_t first = (uintptr_t)header + segments[i].segment_tbs_offset;
        uintptr_t end = first +
            (uint64_t)segments[i].segment_tbs_num * sizeof(*tb);
        if (address >= first && address < end) {
            return &segments[i];
        }
    }
    return NULL;
}

static int copy_guest(const char *path, GByteArray **guest,
        uint64_t *entry, uint64_t *base, uint8_t digest[32])
{
    gchar *data = NULL;
    gsize size = 0;
    GError *error = NULL;
    if (!g_file_get_contents(path, &data, &size, &error)) {
        fprintf(stderr, "latc: cannot read native guest %s: %s\n", path,
                error ? error->message : "unknown error");
        g_clear_error(&error);
        return -1;
    }
    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "latc: native guest is not ELF64\n");
        g_free(data);
        return -1;
    }
    const Elf64_Ehdr *elf = (const void *)data;
    if (memcmp(elf->e_ident, ELFMAG, SELFMAG) ||
        elf->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf->e_machine != EM_X86_64) {
        fprintf(stderr, "latc: native guest is not an x86-64 ELF\n");
        g_free(data);
        return -1;
    }
    if (elf->e_phentsize != sizeof(Elf64_Phdr) ||
        elf->e_phoff > size ||
        (uint64_t)elf->e_phnum * sizeof(Elf64_Phdr) > size - elf->e_phoff) {
        fprintf(stderr, "latc: native guest has an invalid program header table\n");
        g_free(data);
        return -1;
    }
    const Elf64_Phdr *program_headers =
        (const void *)((const uint8_t *)data + elf->e_phoff);
    *base = UINT64_MAX;
    for (uint16_t i = 0; i < elf->e_phnum; i++) {
        if (program_headers[i].p_type == PT_LOAD &&
            program_headers[i].p_vaddr < *base) {
            *base = program_headers[i].p_vaddr;
        }
    }
    if (*base == UINT64_MAX) {
        fprintf(stderr, "latc: native guest has no loadable segments\n");
        g_free(data);
        return -1;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, (const guchar *)data, size);
    gsize digest_size = 32;
    g_checksum_get_digest(sum, digest, &digest_size);
    g_checksum_free(sum);
    *entry = elf->e_entry;
    *guest = g_byte_array_new_take((guint8 *)data, size);
    return 0;
}

static int find_guest_load_bias(const GByteArray *guest,
                                const aot_header *header,
                                const aot_segment *segments,
                                uint64_t *load_bias)
{
    const Elf64_Ehdr *elf = (const void *)guest->data;
    if (elf->e_type == ET_EXEC) {
        *load_bias = 0;
        return 0;
    }
    if (elf->e_type != ET_DYN) {
        return -1;
    }

    const Elf64_Phdr *phdrs =
        (const void *)(guest->data + elf->e_phoff);
    bool found = false;
    uint64_t bias = 0;
    for (uint32_t i = 0; i < header->segments_num; i++) {
        const aot_segment *segment = &segments[i];
        for (uint16_t j = 0; j < elf->e_phnum; j++) {
            const Elf64_Phdr *phdr = &phdrs[j];
            if (phdr->p_type != PT_LOAD ||
                (phdr->p_offset & TARGET_PAGE_MASK) !=
                    segment->details.file_offset) {
                continue;
            }
            uint64_t preferred = phdr->p_vaddr & TARGET_PAGE_MASK;
            if (segment->details.seg_begin < preferred) {
                return -1;
            }
            uint64_t candidate = segment->details.seg_begin - preferred;
            if (found && candidate != bias) {
                return -1;
            }
            bias = candidate;
            found = true;
            break;
        }
    }
    if (!found) {
        return -1;
    }
    *load_bias = bias;
    return 0;
}

static bool direct_tb_target(const aot_tb *tb, const aot_segment *segment,
        aot_rel_kind kind, uint64_t *guest_pc)
{
    int32_t offset = -1;
    bool exit_id_0 = kind == JIRL_EPILOGUE_RET_ID_0 ||
                     kind == B_EPILOGUE_RET_ID_0;
    bool exit_id_1 = kind == JIRL_EPILOGUE_RET_ID_1 ||
                     kind == B_EPILOGUE_RET_ID_1;
    if (exit_id_0) {
        offset = tb->next_tb_pc_offset >= 0 ?
            tb->next_tb_pc_offset : tb->target_tb_pc_offset;
    } else if (exit_id_1) {
        offset = tb->target_tb_pc_offset >= 0 ?
            tb->target_tb_pc_offset : tb->next_tb_pc_offset;
    }
    if (offset >= 0) {
        *guest_pc = segment->details.seg_begin + (uint32_t)offset;
        return true;
    }
    int exit_id = exit_id_1 ? 1 : 0;
    uint64_t current_pc = segment->details.seg_begin + tb->offset_in_segment;
    uint64_t target_pc = current_pc + tb->lazypc[exit_id];
    if ((!exit_id_0 && !exit_id_1) ||
        (!tb->lazypc[exit_id] && tb->tu_jmp[exit_id] == UINT16_MAX) ||
        target_pc < segment->details.seg_begin ||
        target_pc >= segment->details.seg_end) {
        return false;
    }
    *guest_pc = target_pc;
    return true;
}

static int append_relocation(GArray *output, const aot_rel *source,
        const aot_tb *tb, uint64_t tb_code_offset,
        const aot_segment *segment, uint64_t load_bias)
{
    LatNativeRelocationV1 relocation = {
        .code_offset = tb_code_offset + source->tc_offset,
        .slots = source->rel_slots_num,
    };
    uint64_t guest_pc;
    if (source->kind == LOAD_CALL_TARGET) {
        relocation.kind = LAT_NATIVE_RELOC_GUEST_ADDRESS;
        relocation.addend = segment->details.seg_begin + source->extra_addend;
    } else if (direct_tb_target(tb, segment, source->kind, &guest_pc)) {
        relocation.kind = LAT_NATIVE_RELOC_TB_TARGET;
        relocation.addend = guest_pc;
        relocation.target = tb->cflags;
        relocation.reserved = runtime_symbol(source->kind);
    } else {
        int symbol = runtime_symbol(source->kind);
        if (symbol == LAT_NATIVE_SYMBOL_INVALID) {
            fprintf(stderr, "latc: unsupported native relocation kind %d\n",
                    source->kind);
            return -1;
        }
        relocation.kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;
        relocation.target = symbol;
        relocation.addend = source->extra_addend;
    }
    if ((relocation.kind == LAT_NATIVE_RELOC_GUEST_ADDRESS ||
         relocation.kind == LAT_NATIVE_RELOC_TB_TARGET) &&
        relocation.addend < load_bias) {
        return -1;
    }
    if (relocation.kind == LAT_NATIVE_RELOC_GUEST_ADDRESS ||
        relocation.kind == LAT_NATIVE_RELOC_TB_TARGET) {
        relocation.addend -= load_bias;
    }
    g_array_append_val(output, relocation);
    return 0;
}

static bool has_relocation_at(const GArray *relocations, uint64_t code_offset)
{
    for (guint i = 0; i < relocations->len; i++) {
        const LatNativeRelocationV1 *relocation = &g_array_index(
            relocations, LatNativeRelocationV1, i);
        if (relocation->code_offset == code_offset) return true;
    }
    return false;
}

static void append_tu_relocations(GArray *output, const aot_tb *tb,
        uint64_t tb_code_offset, uint64_t guest_pc)
{
#ifdef CONFIG_LATX_TU
    for (int edge = 0; edge < 2; edge++) {
        if (tb->tu_jmp[edge] == UINT16_MAX) continue;
        uint64_t code_offset = tb_code_offset + tb->tu_jmp[edge];
        if (has_relocation_at(output, code_offset)) continue;
        LatNativeRelocationV1 relocation = {
            .code_offset = code_offset,
            .addend = guest_pc + tb->lazypc[edge],
            .kind = LAT_NATIVE_RELOC_TB_TARGET,
            .target = tb->cflags,
            .slots = 1,
        };
        g_array_append_val(output, relocation);
    }
#else
    (void)output;
    (void)tb;
    (void)tb_code_offset;
    (void)guest_pc;
#endif
}

static void append_jrra_relocation(GArray *output, const aot_tb *tb,
        uint64_t tb_code_offset, const aot_segment *segment,
        const GByteArray *guest, uint64_t load_bias)
{
#ifdef CONFIG_LATX_JRRA
    if (!tb->return_target_ptr_offset) {
        return;
    }
    uint64_t target_pc = segment->details.seg_begin + tb->next_86_pc_offset;
    if (!guest_executable_address(guest, target_pc, load_bias) ||
        target_pc < load_bias) {
        return;
    }
    LatNativeRelocationV1 relocation = {
        .code_offset = tb_code_offset + tb->return_target_ptr_offset,
        .addend = target_pc - load_bias,
        .kind = LAT_NATIVE_RELOC_JRRA_TARGET,
        .target = tb->cflags,
        .slots = 4,
    };
    g_array_append_val(output, relocation);
#else
    (void)output;
    (void)tb;
    (void)tb_code_offset;
    (void)segment;
    (void)guest;
#endif
}

static int decode_sleb128_checked(const uint8_t **cursor, const uint8_t *end,
                                  int64_t *value)
{
    const uint8_t *p = *cursor;
    uint64_t result = 0;
    unsigned int shift = 0;

    for (unsigned int i = 0; i < 10 && p < end; i++) {
        uint8_t byte = *p++;
        uint64_t payload = byte & 0x7f;
        if (shift == 63 && payload != 0 && payload != 0x7f) {
            return -1;
        }
        if (shift < 64) {
            result |= payload << shift;
        }
        shift += 7;
        if (!(byte & 0x80)) {
            if (shift < 64 && (byte & 0x40)) {
                result |= UINT64_MAX << shift;
            }
            *cursor = p;
            *value = (int64_t)result;
            return 0;
        }
    }
    return -1;
}

static int add_signed_u64(uint64_t *value, int64_t delta)
{
    if ((delta >= 0 && (uint64_t)delta > UINT64_MAX - *value) ||
        (delta < 0 && (uint64_t)(-(delta + 1)) + 1 > *value)) {
        return -1;
    }
    *value += delta;
    return 0;
}

static int append_tb_pc_map(GArray *output, const uint8_t *code,
                            uint64_t code_size, const aot_tb *tb,
                            uint64_t code_offset, uint64_t guest_pc,
                            uint64_t search_limit)
{
    if (!tb->icount || !tb->tb_cache_size) {
        return 0;
    }
    if (code_offset > code_size ||
        tb->tu_search_addr_offset > code_size - code_offset) {
        return -1;
    }
    uint64_t search_offset = code_offset + tb->tu_search_addr_offset;
    if (search_offset >= search_limit || search_limit > code_size) {
        return -1;
    }
    const uint8_t *cursor = code + search_offset;
    const uint8_t *end = code + search_limit;
    uint64_t current_guest_pc = guest_pc;
    uint64_t encoded_host_end = 0;
    guint first_map = output->len;
    bool truncated_unlink_stub = false;

    for (uint16_t i = 0; i < tb->icount; i++) {
        int64_t guest_delta;
        int64_t state_delta;
        int64_t host_delta;
        if (decode_sleb128_checked(&cursor, end, &guest_delta) ||
            decode_sleb128_checked(&cursor, end, &state_delta) ||
            decode_sleb128_checked(&cursor, end, &host_delta) ||
            state_delta != 0 || host_delta < 0 ||
            add_signed_u64(&current_guest_pc, guest_delta) ||
            (uint64_t)host_delta > UINT64_MAX - encoded_host_end) {
            return -1;
        }
        if (!host_delta) {
            continue;
        }
        uint64_t host_begin = encoded_host_end;
        encoded_host_end += host_delta;
        uint64_t host_end = encoded_host_end;
        if (host_end > tb->tb_cache_size) {
            if (!(tb->bool_flags & IS_TU_TB) || truncated_unlink_stub ||
                host_begin >= tb->tb_cache_size) {
                return -1;
            }
            /* TU construction moves this terminal unlink stub out of the TB. */
            host_end = tb->tb_cache_size;
            truncated_unlink_stub = true;
        }
        LatNativePcMapV2 map = {
            .guest_pc = current_guest_pc,
            .host_offset_begin = code_offset + host_begin,
            .host_offset_end = code_offset + host_end,
            .state_record_offset = 0,
            .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE,
        };
        g_array_append_val(output, map);
    }
    if (output->len > first_map) {
        LatNativePcMapV2 *last = &g_array_index(
            output, LatNativePcMapV2, output->len - 1);
        last->host_offset_end = code_offset + tb->tb_cache_size;
    }
    return 0;
}

static int extract_native_pc_maps(GArray *output, const uint8_t *code,
                                  uint64_t code_size, const aot_header *header,
                                  const aot_segment *segments,
                                  const aot_tb *tbs, size_t tb_count,
                                  uint64_t aot_code_offset,
                                  uint64_t load_bias)
{
    for (size_t i = 0; i < tb_count;) {
        if (!tbs[i].is_first_tb ||
            tbs[i].tb_cache_offset < aot_code_offset) {
            return -1;
        }
        uint64_t tu_begin = tbs[i].tb_cache_offset - aot_code_offset;
        uint64_t tu_end = tu_begin + tbs[i].tu_size;
        if (tu_begin > code_size || tu_end < tu_begin || tu_end > code_size) {
            return -1;
        }
        size_t next = i + 1;
        while (next < tb_count && !tbs[next].is_first_tb) {
            next++;
        }
        for (size_t j = i; j < next; j++) {
            const aot_segment *segment = find_tb_segment(header, segments,
                                                        &tbs[j]);
            if (!segment || tbs[j].tb_cache_offset < aot_code_offset) {
                return -1;
            }
            uint64_t code_offset = tbs[j].tb_cache_offset - aot_code_offset;
            uint64_t guest_pc = segment->details.seg_begin +
                                tbs[j].offset_in_segment;
            if (guest_pc < load_bias) {
                return -1;
            }
            guest_pc -= load_bias;
            if (append_tb_pc_map(output, code, code_size, &tbs[j],
                                 code_offset, guest_pc, tu_end)) {
                return -1;
            }
        }
        i = next;
    }
    g_array_sort(output, compare_native_pc_map);
    for (guint i = 1; i < output->len; i++) {
        const LatNativePcMapV2 *previous = &g_array_index(
            output, LatNativePcMapV2, i - 1);
        const LatNativePcMapV2 *current = &g_array_index(
            output, LatNativePcMapV2, i);
        if (previous->host_offset_end > current->host_offset_begin) {
            return -1;
        }
    }
    return 0;
}

static int strip_process_local_search_data(uint8_t *code, uint64_t code_size,
        const aot_tb *tbs, size_t tb_count, uint64_t aot_code_offset)
{
#ifdef CONFIG_LATX_TU
    for (size_t i = 0; i < tb_count; i++) {
        if (!tbs[i].is_first_tb) {
            continue;
        }
        if (tbs[i].tb_cache_offset < aot_code_offset) {
            fprintf(stderr, "latc: invalid TU code offset at TB %zu\n", i);
            return -1;
        }
        uint64_t tu_begin = tbs[i].tb_cache_offset - aot_code_offset;
        uint64_t tu_end = tu_begin + tbs[i].tu_size;
        uint64_t search_begin = tu_end;
        for (size_t j = i; j < tb_count; j++) {
            if (j != i && tbs[j].is_first_tb) {
                break;
            }
            if (tbs[j].tb_cache_offset < aot_code_offset) {
                fprintf(stderr, "latc: invalid TU code offset at TB %zu\n", j);
                return -1;
            }
            uint64_t tb_begin = tbs[j].tb_cache_offset - aot_code_offset;
            uint64_t candidate = tb_begin + tbs[j].tu_search_addr_offset;
            if (candidate < search_begin) {
                search_begin = candidate;
            }
        }
        if (tu_begin > code_size || tu_end > code_size ||
            search_begin < tu_begin || search_begin > tu_end) {
            fprintf(stderr, "latc: invalid TU search data range at TB %zu\n", i);
            return -1;
        }
        memset(code + search_begin, 0, tu_end - search_begin);
    }
#else
    (void)code;
    (void)code_size;
    (void)tbs;
    (void)tb_count;
    (void)aot_code_offset;
#endif
    return 0;
}

int latc_native_export(const char *path, const char *guest_path,
        const aot_header *header, const aot_segment *segments,
        const aot_tb *tbs, uintptr_t tb_table_end,
        const void *code, uint64_t code_size, uint64_t aot_code_offset)
{
    GByteArray *guest = NULL;
    GArray *native_tbs = NULL;
    GArray *native_relocations = NULL;
    GArray *native_pc_maps = NULL;
    uint8_t *native_code = NULL;
    uint64_t guest_entry = 0;
    uint64_t guest_base = 0;
    uint64_t guest_load_bias = 0;
    uint8_t guest_digest[32];
    int result = -1;

    if (!path || !*path || !guest_path || !header || !segments || !tbs ||
        !code || (uintptr_t)tbs > tb_table_end ||
        (tb_table_end - (uintptr_t)tbs) % sizeof(*tbs)) {
        fprintf(stderr, "latc: invalid native export arguments\n");
        return -1;
    }
    if (copy_guest(guest_path, &guest, &guest_entry, &guest_base,
                   guest_digest)) {
        return -1;
    }
    if (find_guest_load_bias(guest, header, segments, &guest_load_bias)) {
        fprintf(stderr, "latc: cannot determine native guest load bias\n");
        goto out;
    }
    native_tbs = g_array_new(FALSE, FALSE, sizeof(LatNativeTbV1));
    native_relocations = g_array_new(FALSE, FALSE,
                                     sizeof(LatNativeRelocationV1));
    native_pc_maps = g_array_new(FALSE, FALSE, sizeof(LatNativePcMapV2));
    size_t tb_count = (tb_table_end - (uintptr_t)tbs) / sizeof(*tbs);
    native_code = g_malloc(code_size);
    memcpy(native_code, code, code_size);
    if (extract_native_pc_maps(native_pc_maps, native_code, code_size,
            header, segments, tbs, tb_count, aot_code_offset,
            guest_load_bias) ||
        strip_process_local_search_data(native_code, code_size,
            tbs, tb_count, aot_code_offset)) {
        fprintf(stderr, "latc: cannot export stable native PC map\n");
        goto out;
    }
    const aot_rel *source_relocations =
        (const void *)((const uint8_t *)header + header->rel_table_offset);

    for (size_t i = 0; i < tb_count; i++) {
        const aot_segment *segment = find_tb_segment(header, segments, &tbs[i]);
        uint64_t pc = segment ?
            segment->details.seg_begin + tbs[i].offset_in_segment : 0;
        if (!segment || pc < guest_load_bias ||
            tbs[i].tb_cache_offset < aot_code_offset) {
            fprintf(stderr, "latc: invalid native TB %zu\n", i);
            goto out;
        }
        uint64_t code_offset = tbs[i].tb_cache_offset - aot_code_offset;
        if (code_offset > code_size ||
            tbs[i].tb_cache_size > code_size - code_offset) {
            fprintf(stderr, "latc: native TB %zu code range is invalid\n", i);
            goto out;
        }
        LatNativeTbV1 native_tb = {
            .guest_pc = pc - guest_load_bias,
            .code_offset = code_offset,
            .code_size = tbs[i].tb_cache_size,
            .flags = tbs[i].cflags,
        };
        g_array_append_val(native_tbs, native_tb);

        if (tbs[i].rel_start_index == -1) {
            append_tu_relocations(native_relocations, &tbs[i], code_offset,
                                  pc - guest_load_bias);
            append_jrra_relocation(native_relocations, &tbs[i], code_offset,
                                   segment, guest, guest_load_bias);
            continue;
        }
        if (tbs[i].rel_start_index < 0 ||
            tbs[i].rel_end_index < tbs[i].rel_start_index ||
            (uint32_t)tbs[i].rel_end_index >= header->rel_entry_num) {
            fprintf(stderr, "latc: native TB %zu relocation range is invalid\n", i);
            goto out;
        }
        for (int rel = tbs[i].rel_start_index;
             rel <= tbs[i].rel_end_index; rel++) {
            if (append_relocation(native_relocations, &source_relocations[rel],
                                  &tbs[i], code_offset, segment,
                                  guest_load_bias)) {
                goto out;
            }
        }
        append_tu_relocations(native_relocations, &tbs[i], code_offset,
                              pc - guest_load_bias);
        append_jrra_relocation(native_relocations, &tbs[i], code_offset,
                               segment, guest, guest_load_bias);
    }

    g_array_sort(native_tbs, compare_native_tb);
    for (guint i = 1; i < native_tbs->len; i++) {
        const LatNativeTbV1 *previous = &g_array_index(
            native_tbs, LatNativeTbV1, i - 1);
        const LatNativeTbV1 *current = &g_array_index(
            native_tbs, LatNativeTbV1, i);
        if (previous->guest_pc == current->guest_pc &&
            previous->flags == current->flags) {
            fprintf(stderr, "latc: duplicate native TB pc=0x%llx flags=0x%x\n",
                    (unsigned long long)current->guest_pc, current->flags);
            goto out;
        }
    }
    for (guint i = 0; i < native_relocations->len; i++) {
        LatNativeRelocationV1 *relocation = &g_array_index(
            native_relocations, LatNativeRelocationV1, i);
        if (relocation->kind != LAT_NATIVE_RELOC_TB_TARGET ||
            guest_executable_address(guest, relocation->addend, 0)) {
            continue;
        }
        if (relocation->reserved == LAT_NATIVE_SYMBOL_INVALID) {
            fprintf(stderr,
                    "latc: native TB target 0x%llx is outside executable segments\n",
                    (unsigned long long)relocation->addend);
            goto out;
        }
        relocation->kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;
        relocation->target = relocation->reserved;
        relocation->reserved = 0;
        relocation->addend = 0;
    }

    GArray *missing_targets = g_array_new(FALSE, FALSE, sizeof(uint64_t));
    GHashTable *missing_seen = g_hash_table_new(g_direct_hash, g_direct_equal);
    for (guint i = 0; i < native_relocations->len; i++) {
        const LatNativeRelocationV1 *relocation = &g_array_index(
            native_relocations, LatNativeRelocationV1, i);
        if ((relocation->kind == LAT_NATIVE_RELOC_TB_TARGET ||
             relocation->kind == LAT_NATIVE_RELOC_JRRA_TARGET) &&
            !native_tb_target_exists(native_tbs,
                                     (uint64_t)relocation->addend,
                                     relocation->target)) {
            gpointer key = (gpointer)(uintptr_t)relocation->addend;
            if (!g_hash_table_contains(missing_seen, key)) {
                uint64_t pc = relocation->addend;
                g_hash_table_add(missing_seen, key);
                g_array_append_val(missing_targets, pc);
            }
        }
    }
    g_hash_table_destroy(missing_seen);
    if (missing_targets->len) {
        g_array_sort(missing_targets, compare_uint64);
        const char *missing_path = getenv("LATC_NATIVE_MISSING_OUT");
        if (missing_path && *missing_path) {
            FILE *missing = fopen(missing_path, "w");
            if (!missing) {
                fprintf(stderr, "latc: cannot create missing-target list %s: %s\n",
                        missing_path, strerror(errno));
                g_array_free(missing_targets, TRUE);
                goto out;
            }
            for (guint i = 0; i < missing_targets->len; i++) {
                fprintf(missing, "0x%llx 1\n", (unsigned long long)
                        g_array_index(missing_targets, uint64_t, i));
            }
            if (fclose(missing)) {
                fprintf(stderr, "latc: cannot write missing-target list %s\n",
                        missing_path);
                g_array_free(missing_targets, TRUE);
                goto out;
            }
        }
        fprintf(stderr, "latc: native image has %u missing TB targets; first pc=0x%llx\n",
                missing_targets->len, (unsigned long long)
                g_array_index(missing_targets, uint64_t, 0));
        g_array_free(missing_targets, TRUE);
        goto out;
    }
    g_array_free(missing_targets, TRUE);

    LatNativeImageHeaderV2 native_header = {0};
    memcpy(native_header.magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    native_header.version = LAT_NATIVE_IMAGE_VERSION;
    native_header.header_size = sizeof(native_header);
    const Elf64_Ehdr *guest_elf = (const void *)guest->data;
    native_header.flags = (guest_elf->e_type == ET_DYN ?
                               LAT_NATIVE_IMAGE_PIE : 0) |
                          LAT_NATIVE_IMAGE_NEEDS_FALLBACK |
                          LAT_NATIVE_IMAGE_LBT | LAT_NATIVE_IMAGE_LSX |
                          LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    native_header.guest_entry = guest_entry;
    native_header.preferred_guest_base = guest_base;
    native_header.guest_image_offset = sizeof(native_header);
    native_header.guest_image_size = guest->len;
    native_header.code_offset = align_up(native_header.guest_image_offset +
                                         native_header.guest_image_size, 8);
    native_header.code_size = code_size;
    native_header.tb_table_offset = align_up(native_header.code_offset +
                                             code_size, 8);
    native_header.tb_count = native_tbs->len;
    native_header.relocation_offset = native_header.tb_table_offset +
        native_tbs->len * sizeof(LatNativeTbV1);
    native_header.relocation_count = native_relocations->len;
    native_header.pc_map_offset = native_header.relocation_offset +
        native_relocations->len * sizeof(LatNativeRelocationV1);
    native_header.pc_map_count = native_pc_maps->len;
    memcpy(native_header.guest_sha256, guest_digest, sizeof(guest_digest));
    snprintf(native_header.lat_build_id, sizeof(native_header.lat_build_id),
             "%s", LATC_BUILD_ID);

    FILE *output = fopen(path, "wb");
    if (!output) {
        fprintf(stderr, "latc: cannot create native image %s: %s\n",
                path, strerror(errno));
        goto out;
    }
    if (fwrite(&native_header, sizeof(native_header), 1, output) != 1 ||
        fwrite(guest->data, guest->len, 1, output) != 1) {
        goto write_error;
    }
    uint64_t position = sizeof(native_header) + guest->len;
    static const uint8_t zero[8] = {0};
    if (native_header.code_offset > position &&
        fwrite(zero, native_header.code_offset - position, 1, output) != 1) {
        goto write_error;
    }
    if (fwrite(native_code, code_size, 1, output) != 1) {
        goto write_error;
    }
    position = native_header.code_offset + code_size;
    if (native_header.tb_table_offset > position &&
        fwrite(zero, native_header.tb_table_offset - position, 1, output) != 1) {
        goto write_error;
    }
    if ((native_tbs->len && fwrite(native_tbs->data,
            sizeof(LatNativeTbV1), native_tbs->len, output) != native_tbs->len) ||
        (native_relocations->len && fwrite(native_relocations->data,
            sizeof(LatNativeRelocationV1), native_relocations->len, output) !=
            native_relocations->len) ||
        (native_pc_maps->len && fwrite(native_pc_maps->data,
            sizeof(LatNativePcMapV2), native_pc_maps->len, output) !=
            native_pc_maps->len)) {
        goto write_error;
    }
    if (fclose(output)) {
        goto write_error_unclosed;
    }
    result = 0;
    goto out;

write_error:
    fclose(output);
write_error_unclosed:
    unlink(path);
    fprintf(stderr, "latc: cannot write native image %s\n", path);
out:
    if (native_tbs) g_array_free(native_tbs, TRUE);
    if (native_relocations) g_array_free(native_relocations, TRUE);
    if (native_pc_maps) g_array_free(native_pc_maps, TRUE);
    g_free(native_code);
    if (guest) g_byte_array_unref(guest);
    return result;
}
