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

static int append_relocation(GArray *output, const aot_rel *source,
        uint64_t tb_code_offset, uint64_t segment_base)
{
    LatNativeRelocationV1 relocation = {
        .code_offset = tb_code_offset + source->tc_offset,
        .slots = source->rel_slots_num,
    };
    if (source->kind == LOAD_CALL_TARGET) {
        relocation.kind = LAT_NATIVE_RELOC_GUEST_ADDRESS;
        relocation.addend = segment_base + source->extra_addend;
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
    g_array_append_val(output, relocation);
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
    uint8_t *native_code = NULL;
    uint64_t guest_entry = 0;
    uint64_t guest_base = 0;
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
    native_tbs = g_array_new(FALSE, FALSE, sizeof(LatNativeTbV1));
    native_relocations = g_array_new(FALSE, FALSE,
                                     sizeof(LatNativeRelocationV1));
    size_t tb_count = (tb_table_end - (uintptr_t)tbs) / sizeof(*tbs);
    native_code = g_malloc(code_size);
    memcpy(native_code, code, code_size);
    if (strip_process_local_search_data(native_code, code_size,
            tbs, tb_count, aot_code_offset)) {
        goto out;
    }
    const aot_rel *source_relocations =
        (const void *)((const uint8_t *)header + header->rel_table_offset);

    for (size_t i = 0; i < tb_count; i++) {
        const aot_segment *segment = find_tb_segment(header, segments, &tbs[i]);
        uint64_t pc = segment ?
            segment->details.seg_begin + tbs[i].offset_in_segment : 0;
        if (!segment || tbs[i].tb_cache_offset < aot_code_offset) {
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
            .guest_pc = pc,
            .code_offset = code_offset,
            .code_size = tbs[i].tb_cache_size,
            .flags = tbs[i].cflags,
        };
        g_array_append_val(native_tbs, native_tb);

        if (tbs[i].rel_start_index == -1) {
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
                                  code_offset, segment->details.seg_begin)) {
                goto out;
            }
        }
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

    LatNativeImageHeaderV1 native_header = {0};
    memcpy(native_header.magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    native_header.version = LAT_NATIVE_IMAGE_VERSION;
    native_header.header_size = sizeof(native_header);
    native_header.flags = LAT_NATIVE_IMAGE_PIE |
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
            native_relocations->len)) {
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
    g_free(native_code);
    if (guest) g_byte_array_unref(guest);
    return result;
}
