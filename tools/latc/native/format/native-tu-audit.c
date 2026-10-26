#include "native-tu-audit.h"
#include "native-image.h"

#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list args;
        va_start(args, format);
        vsnprintf(error, size, format, args);
        va_end(args);
    }
    return -1;
}

static gboolean branch_word(uint32_t word)
{
    uint32_t op = word & 0xfc000000u;
    return op == 0x50000000u || op == 0x54000000u ||
        op == 0x40000000u || op == 0x44000000u ||
        (word & 0xfc000300u) == 0x48000000u ||
        (word & 0xfc000300u) == 0x48000100u ||
        (op >= 0x58000000u && op <= 0x6c000000u);
}

static gboolean absolute_words(const uint32_t *words, uint32_t slots)
{
    uint32_t reg = words[0] & 31;
    return reg && (slots == 2 || slots == 3) &&
        (words[0] & 0xfe000000u) == 0x14000000u &&
        (words[1] & 0xffc003ffu) == (0x03800000u | reg << 5 | reg) &&
        (slots == 2 || (words[2] & 0xfe00001fu) == (0x16000000u | reg));
}

static gboolean far_words(const uint32_t *words)
{
    uint32_t reg = words[0] & 31;
    return reg && (words[0] & 0xfe000000u) == 0x1e000000u &&
        (words[1] & 0xfc0003e0u) == (0x4c000000u | reg << 5);
}

static gboolean patch_valid(const LatNativeRelocationV1 *rel,
                             const uint32_t *words)
{
    if (rel->kind == LAT_NATIVE_RELOC_JRRA_TARGET) {
        uint32_t reg = words[0] & 31;
        return rel->slots == 4 && reg &&
            (words[0] & 0xfe000000u) == 0x1a000000u &&
            (words[1] & 0xffc003ffu) == (0x03800000u | reg << 5 | reg) &&
            words[2] == (0x801u | reg << 5) &&
            (words[3] & ~0x3e0u) == 0x800u;
    }
    if (rel->kind == LAT_NATIVE_RELOC_GUEST_ADDRESS ||
        rel->kind == LAT_NATIVE_RELOC_IMAGE_DATA) {
        return absolute_words(words, rel->slots);
    }
    if (rel->slots == 1) return branch_word(words[0]);
    if (rel->slots == 2 && (far_words(words) ||
        ((words[0] & 0xfc000000u) == 0x50000000u && words[1] == 0x03400000u))) {
        return TRUE;
    }
    if (rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL) {
        if (absolute_words(words, rel->slots)) return TRUE;
        /* The packer recognizes this reserved nonreturning helper window. */
        return rel->slots == 3 && !words[0] && !words[1] && !words[2] &&
            (rel->target == LAT_NATIVE_SYMBOL_RAISE_ILLOP ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_GPF ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_SYSCALL ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_INT ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_TRAPOP ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_INTO ||
             rel->target == LAT_NATIVE_SYMBOL_RAISE_BOUND);
    }
    return FALSE;
}

static gint compare_patch(gconstpointer a, gconstpointer b)
{
    const LatNativeRelocationV1 *left = *(const LatNativeRelocationV1 *const *)a;
    const LatNativeRelocationV1 *right = *(const LatNativeRelocationV1 *const *)b;
    return left->code_offset < right->code_offset ? -1 :
           left->code_offset > right->code_offset;
}

static gboolean local_target(const LatNativeTuV1 *tu, uint64_t site,
                               int64_t delta)
{
    if (delta < 0 && (uint64_t)-delta > site) return FALSE;
    if (delta >= 0 && (uint64_t)delta > UINT64_MAX - site) return FALSE;
    uint64_t target = site + delta;
    return !(target & 3) && target >= tu->code_offset && target < tu->search_offset;
}

int lat_native_tu_audit_references(const void *data, size_t size,
    LatNativeTuReferenceAudit *audit, char *error, size_t error_size)
{
    if (!audit) return fail(error, error_size, "missing TU reference audit output");
    *audit = (LatNativeTuReferenceAudit){0};
    if (lat_native_image_validate(data, size, error, error_size)) return -1;
    const LatNativeImageHeaderV2 *h = data;
    const uint8_t *bytes = data, *code = bytes + h->code_offset;
    const LatNativeTuV1 *tus = (const void *)(bytes + h->tu_table_offset);
    const LatNativeRelocationV1 *rels = (const void *)(bytes + h->relocation_offset);
    if (!h->tu_count || h->relocation_count > G_MAXUINT) {
        return fail(error, error_size, "missing or oversized TU reference layout");
    }
    g_autoptr(GPtrArray) patches = g_ptr_array_new();
    for (uint64_t i = 0; i < h->relocation_count; i++) {
        g_ptr_array_add(patches, (gpointer)&rels[i]);
    }
    g_ptr_array_sort(patches, compare_patch);
    guint patch_index = 0;
    for (uint64_t i = 0; i < h->tu_count; i++) {
        const LatNativeTuV1 *tu = &tus[i];
        if ((tu->code_offset | tu->code_size | tu->search_offset) & 3) {
            return fail(error, error_size, "unaligned TU reference layout");
        }
        for (uint64_t site = tu->code_offset; site < tu->search_offset; site += 4) {
            uint32_t words[4] = {0};
            memcpy(words, code + site, 4);
            if (patch_index < patches->len) {
                const LatNativeRelocationV1 *rel = g_ptr_array_index(patches, patch_index);
                if (rel->code_offset < site) {
                    return fail(error, error_size, "overlapping or unowned TU patch at 0x%llx",
                                (unsigned long long)rel->code_offset);
                }
                if (rel->code_offset == site) {
                    if (rel->slots * 4 > tu->search_offset - site) {
                        return fail(error, error_size, "TU patch crosses executable prefix");
                    }
                    memcpy(words, code + site, rel->slots * 4);
                    if (!patch_valid(rel, words)) {
                        return fail(error, error_size, "unsupported TU patch template at 0x%llx",
                                    (unsigned long long)site);
                    }
                    site += rel->slots * 4 - 4;
                    patch_index++;
                    audit->patch_windows++;
                    continue;
                }
            }
            audit->instructions++;
            uint64_t target;
            /* LBT JISCR0/1 use the branch21 opcode family but are not covered
             * by the currently audited branch templates. Never ignore them. */
            if ((words[0] & 0xfc000200u) == 0x48000200u) {
                return fail(error, error_size, "unsupported TU JISCR reference at 0x%llx",
                            (unsigned long long)site);
            }
            if (branch_word(words[0])) {
                if (!lat_native_decode_local_branch_target(words, 1, site,
                        h->code_size, &target) || target < tu->code_offset ||
                    target >= tu->search_offset) {
                    return fail(error, error_size, "unrecorded nonlocal TU branch at 0x%llx",
                                (unsigned long long)site);
                }
                audit->local_branches++;
                continue;
            }
            uint32_t op = words[0] & 0xfe000000u;
            if (op < 0x18000000u || op > 0x1e000000u) continue;
            int64_t upper = (words[0] >> 5) & 0xfffff;
            if (upper & (1 << 19)) upper -= 1 << 20;
            if (op == 0x18000000u) {
                if (!local_target(tu, site, upper * 4)) goto unknown_address;
            } else if (op == 0x1e000000u) {
                if (tu->search_offset - site < 8) goto unknown_address;
                if (patch_index < patches->len &&
                    ((const LatNativeRelocationV1 *)g_ptr_array_index(patches, patch_index))->code_offset < site + 8) {
                    goto unknown_address;
                }
                memcpy(&words[1], code + site + 4, 4);
                if (!far_words(words) || !local_target(tu, site,
                        upper * (INT64_C(1) << 18) + (int16_t)(words[1] >> 10) * 4)) {
                    goto unknown_address;
                }
                site += 4;
                audit->instructions++;
            } else {
                /* PCALAU12I rounds pages; arbitrary TU motion is not invariant.
                 * PCADDU12I uses require a separate audited consumer pattern. */
                goto unknown_address;
            }
            audit->local_addresses++;
            continue;
unknown_address:
            return fail(error, error_size, "unrecorded or unsupported TU PC-relative address at 0x%llx",
                        (unsigned long long)site);
        }
    }
    if (patch_index != patches->len) {
        return fail(error, error_size, "TU patch outside executable prefixes");
    }
    return 0;
}

typedef struct ExecutionEntry {
    uint64_t offset;
    uint32_t tu;
    uint32_t dispatch;
} ExecutionEntry;

static gint compare_entry(gconstpointer a, gconstpointer b)
{
    const ExecutionEntry *left = a, *right = b;
    if (left->tu != right->tu) return left->tu < right->tu ? -1 : 1;
    return left->offset < right->offset ? -1 : left->offset > right->offset;
}

static gboolean exit_symbol(uint32_t symbol)
{
    return symbol >= LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_1 &&
           symbol <= LAT_NATIVE_SYMBOL_EPILOGUE_RET_0;
}

static gboolean nonreturn_symbol(uint32_t symbol)
{
    return symbol == LAT_NATIVE_SYMBOL_RAISE_ILLOP ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_GPF ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_SYSCALL ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_INT ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_TRAPOP ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_INTO ||
        symbol == LAT_NATIVE_SYMBOL_RAISE_BOUND;
}

typedef struct ExecutionWindow {
    uint64_t site;
    uint32_t words;
    gboolean fallthrough;
    gboolean helper;
    gboolean dispatch;
} ExecutionWindow;

static gint compare_window(gconstpointer a, gconstpointer b)
{
    const ExecutionWindow *left = a, *right = b;
    return left->site < right->site ? -1 : left->site > right->site;
}

static uint32_t code_word(const uint8_t *code, uint64_t offset)
{
    uint32_t word;
    memcpy(&word, code + offset, sizeof(word));
    return word;
}

static int execution_enqueue(const LatNativeTuV1 *tu, uint64_t site,
    uint8_t *states, GArray *queue, char *error, size_t error_size)
{
    if ((site & 3) || site < tu->code_offset || site >= tu->search_offset) {
        return fail(error, error_size, "TU execution crosses executable boundary at 0x%llx",
                    (unsigned long long)site);
    }
    uint64_t index = (site - tu->code_offset) / 4;
    if (states[index] == 2) {
        return fail(error, error_size, "TU execution enters window interior at 0x%llx",
                    (unsigned long long)site);
    }
    if (!states[index]) {
        states[index] = 1;
        g_array_append_val(queue, site);
    }
    return 0;
}

int lat_native_tu_audit_execution(const void *data, size_t size,
    LatNativeTuExecutionAudit *audit, char *error, size_t error_size)
{
    if (!audit) return fail(error, error_size, "missing TU execution audit output");
    *audit = (LatNativeTuExecutionAudit){0};
    LatNativeTuReferenceAudit references;
    if (lat_native_tu_audit_references(data, size, &references, error, error_size)) return -1;
    const LatNativeImageHeaderV2 *h = data;
    const uint8_t *bytes = data, *code = bytes + h->code_offset;
    const LatNativeTuV1 *tus = (const void *)(bytes + h->tu_table_offset);
    const LatNativeTbV1 *tbs = (const void *)(bytes + h->tb_table_offset);
    const LatNativeRelocationV1 *rels = (const void *)(bytes + h->relocation_offset);
    if (h->tb_count > G_MAXUINT) return fail(error, error_size, "oversized TU entry layout");
    g_autoptr(GArray) entries = g_array_new(FALSE, FALSE, sizeof(ExecutionEntry));
    g_autoptr(GPtrArray) patches = g_ptr_array_new();
    for (uint64_t i = 0; i < h->tb_count; i++) {
        ExecutionEntry entry = {tbs[i].code_offset, tbs[i].tu_index,
                                tbs[i].indirect_exit_offset};
        g_array_append_val(entries, entry);
    }
    for (uint64_t i = 0; i < h->relocation_count; i++) {
        g_ptr_array_add(patches, (gpointer)&rels[i]);
    }
    g_array_sort(entries, compare_entry);
    g_ptr_array_sort(patches, compare_patch);
    guint entry_index = 0, patch_index = 0;
    for (uint64_t i = 0; i < h->tu_count; i++) {
        const LatNativeTuV1 *tu = &tus[i];
        uint64_t count = (tu->search_offset - tu->code_offset) / 4;
        if (count > G_MAXUINT) return fail(error, error_size, "oversized TU execution layout");
        g_autofree uint8_t *states = g_new0(uint8_t, count);
        g_autoptr(GArray) queue = g_array_new(FALSE, FALSE, sizeof(uint64_t));
        g_autoptr(GArray) windows = g_array_new(FALSE, FALSE, sizeof(ExecutionWindow));
        guint first_entry = entry_index;
        while (entry_index < entries->len &&
               g_array_index(entries, ExecutionEntry, entry_index).tu == i) {
            const ExecutionEntry *entry = &g_array_index(entries, ExecutionEntry, entry_index++);
            if (entry->dispatch) {
                uint64_t site = entry->offset + entry->dispatch - 1;
                if (site < tu->code_offset || site >= tu->search_offset) {
                    return fail(error, error_size, "TU dispatch outside executable prefix");
                }
                unsigned words = lat_native_indirect_exit_words(code + site,
                    tu->search_offset - site);
                if (!words) return fail(error, error_size, "unsupported TU dispatch template");
                ExecutionWindow window = {site, words, TRUE, FALSE, TRUE};
                g_array_append_val(windows, window);
            }
        }
        while (patch_index < patches->len) {
            const LatNativeRelocationV1 *rel = g_ptr_array_index(patches, patch_index);
            if (rel->code_offset >= tu->search_offset) break;
            patch_index++;
            uint64_t site = rel->code_offset;
            uint32_t word = code_word(code, site), op = word & 0xfc000000u;
            uint32_t tail = code_word(code, site + (rel->slots - 1) * 4);
            ExecutionWindow window = {site, rel->slots, TRUE, FALSE, FALSE};
            if (rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                rel->target != LAT_NATIVE_SYMBOL_PFTABLE && rel->addend) {
                return fail(error, error_size, "unsupported TU runtime entry addend");
            }
            if (branch_word(word)) {
                if (op != 0x54000000u && rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                    !exit_symbol(rel->target) && !nonreturn_symbol(rel->target)) {
                    return fail(error, error_size, "unlinked returning TU helper transfer");
                }
                window.fallthrough = op != 0x50000000u;
                if (op == 0x54000000u && rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                    (exit_symbol(rel->target) || nonreturn_symbol(rel->target))) {
                    window.fallthrough = FALSE;
                }
            } else if (rel->slots == 2 && (word & 0xfe000000u) == 0x1e000000u) {
                unsigned rd = tail & 31;
                gboolean exit = rel->kind == LAT_NATIVE_RELOC_TB_TARGET ?
                    exit_symbol(rel->reserved) : rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                    (exit_symbol(rel->target) || nonreturn_symbol(rel->target));
                gboolean epilogue_rd4 = rd == 4 &&
                    (rel->kind == LAT_NATIVE_RELOC_TB_TARGET ?
                     rel->reserved == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0 ||
                     rel->reserved == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1 :
                     rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                     (rel->target == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0 ||
                      rel->target == LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1));
                if (rd && rd != 1 && !epilogue_rd4) {
                    return fail(error, error_size, "unknown TU transfer return convention at 0x%llx",
                                (unsigned long long)site);
                }
                if (!rd && rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL && !exit) {
                    return fail(error, error_size, "unlinked returning TU helper transfer");
                }
                window.fallthrough = rd && !exit;
            } else if (rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL && !word) {
                window.fallthrough = FALSE; /* validated reserved noreturn window */
            } else if (rel->kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
                       rel->target != LAT_NATIVE_SYMBOL_PFTABLE &&
                       absolute_words((const uint32_t *)(code + site), rel->slots)) {
                /* Existing helper ABI loads a relocated address, optionally sets
                 * one argument with OR, then JIRL ra, address, 0. Consume the
                 * complete sequence so no alternate entry can bypass the load. */
                unsigned reg = word & 31;
                uint64_t call = site + rel->slots * 4;
                uint32_t next = call < tu->search_offset ? code_word(code, call) : 0;
                if ((next & 0xffff8000u) == 0x00150000u &&
                    (next & 31) != reg &&
                    call + 4 < tu->search_offset) call += 4;
                uint32_t transfer = call < tu->search_offset ? code_word(code, call) : 0;
                if (transfer == (0x4c000001u | reg << 5) ||
                    transfer == (0x4c000000u | reg << 5)) {
                    if (!(transfer & 31) && !nonreturn_symbol(rel->target) &&
                        !exit_symbol(rel->target)) {
                        return fail(error, error_size, "unlinked returning TU helper transfer");
                    }
                    window.words = (call - site) / 4 + 1;
                    window.helper = TRUE;
                    window.fallthrough = (transfer & 31) &&
                        !nonreturn_symbol(rel->target) && !exit_symbol(rel->target);
                }
            }
            g_array_append_val(windows, window);
        }
        /* Unrecorded far pairs are also indivisible: entering at JIRL would
         * bypass the PC-relative base calculation. */
        g_array_sort(windows, compare_window);
        uint64_t previous_end = tu->code_offset;
        for (guint j = 0; j < windows->len; j++) {
            const ExecutionWindow *w = &g_array_index(windows, ExecutionWindow, j);
            if (w->site < previous_end) {
                const ExecutionWindow *previous = j ?
                    &g_array_index(windows, ExecutionWindow, j - 1) : NULL;
                if (previous && w->site == previous->site && w->words == previous->words &&
                    w->dispatch && previous->dispatch) {
                    g_array_remove_index(windows, j--);
                    continue;
                }
                return fail(error, error_size, "overlapping TU execution windows");
            }
            if (w->words > (tu->search_offset - w->site) / 4) {
                return fail(error, error_size, "TU execution window crosses executable boundary");
            }
            previous_end = w->site + w->words * 4;
            for (uint32_t k = 1; k < w->words; k++) {
                states[(w->site - tu->code_offset) / 4 + k] = 2;
            }
        }
        guint cursor = 0;
        for (uint64_t site = tu->code_offset; site < tu->search_offset; site += 4) {
            if (cursor < windows->len) {
                const ExecutionWindow *w = &g_array_index(windows, ExecutionWindow, cursor);
                if (w->site == site) {
                    site += w->words * 4 - 4;
                    cursor++;
                    continue;
                }
            }
            if ((code_word(code, site) & 0xfe000000u) == 0x1e000000u) {
                states[(site - tu->code_offset) / 4 + 1] = 2;
                site += 4;
            }
        }
        for (guint j = first_entry; j < entry_index; j++) {
            uint64_t site = g_array_index(entries, ExecutionEntry, j).offset;
            if (execution_enqueue(tu, site, states, queue, error, error_size)) return -1;
            audit->entries++;
        }
        for (guint j = 0; j < queue->len; j++) {
            uint64_t site = g_array_index(queue, uint64_t, j), target;
            uint32_t word = code_word(code, site), op = word & 0xfc000000u;
            gboolean fallthrough = TRUE;
            unsigned consumed = 1;
            ExecutionWindow key = {.site = site};
            ExecutionWindow *w = bsearch(&key, windows->data, windows->len,
                                        sizeof(key), compare_window);
            if (w) {
                consumed = w->words;
                fallthrough = w->fallthrough;
                audit->recorded_transfers += !w->helper && !w->dispatch;
                audit->helper_calls += w->helper;
                audit->dispatch_windows += w->dispatch;
            } else if (branch_word(word) || (word & 0xfe000000u) == 0x1e000000u) {
                consumed = branch_word(word) ? 1 : 2;
                uint32_t words[2] = {word, consumed == 2 ? code_word(code, site + 4) : 0};
                if (!lat_native_decode_local_branch_target(words, consumed, site, h->code_size, &target)) {
                    return fail(error, error_size, "invalid TU execution branch");
                }
                if (execution_enqueue(tu, target, states, queue, error, error_size)) return -1;
                unsigned rd = consumed == 2 ? words[1] & 31 : 0;
                if (consumed == 2 && rd && rd != 1) {
                    return fail(error, error_size, "unknown local TU return convention");
                }
                fallthrough = consumed == 2 ? rd == 1 : op != 0x50000000u;
                audit->local_transfers++;
            } else if (op == 0x4c000000u) {
                return fail(error, error_size, "unresolved TU indirect transfer at 0x%llx",
                            (unsigned long long)site);
            }
            audit->reachable_words += consumed;
            if (fallthrough && execution_enqueue(tu, site + consumed * 4,
                states, queue, error, error_size)) return -1;
        }
    }
    return 0;
}
