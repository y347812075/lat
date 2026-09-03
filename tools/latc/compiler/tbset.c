#define _GNU_SOURCE

#include "tbset.h"
#include "lat-tb-key-set.h"

#include <elf.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

typedef struct TbTemplateKey {
    uint64_t pc;
    uint32_t flags;
} TbTemplateKey;

static guint tb_template_hash(gconstpointer value)
{
    const TbTemplateKey *key = value;
    uint64_t mixed = key->pc ^ ((uint64_t)key->flags << 32);
    return (guint)(mixed ^ (mixed >> 32));
}

static gboolean tb_template_equal(gconstpointer left, gconstpointer right)
{
    const TbTemplateKey *a = left;
    const TbTemplateKey *b = right;
    return a->pc == b->pc && a->flags == b->flags;
}

static int fail(char *error, size_t size, const char *message)
{
    if (error && size) snprintf(error, size, "%s", message);
    return -1;
}

static int source_digest(const char *path, uint8_t digest[32],
                         char *error, size_t error_size)
{
    gchar *contents = NULL;
    gsize size = 0;
    GError *gerror = NULL;
    if (!g_file_get_contents(path, &contents, &size, &gerror)) {
        if (error && error_size) {
            snprintf(error, error_size, "%s: %s", path,
                     gerror ? gerror->message : "cannot read source");
        }
        g_clear_error(&gerror);
        return -1;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)contents, size);
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    g_checksum_free(checksum);
    g_free(contents);
    return digest_size == 32 ? 0 : -1;
}

static int source_load_base(const char *path, uint64_t *base,
                            char *error, size_t error_size)
{
    gchar *contents = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &contents, &size, NULL)) {
        if (error && error_size) snprintf(error, error_size,
                                          "%s: cannot read source", path);
        return -1;
    }
    Elf64_Ehdr header;
    if (size < sizeof(header)) goto malformed;
    memcpy(&header, contents, sizeof(header));
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
        header.e_phoff > size ||
        header.e_phnum > (size - header.e_phoff) / sizeof(Elf64_Phdr)) {
        goto malformed;
    }
    uint64_t result = UINT64_MAX;
    for (uint16_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;
        memcpy(&phdr, contents + header.e_phoff + i * sizeof(phdr),
               sizeof(phdr));
        if (phdr.p_type == PT_LOAD && phdr.p_memsz && phdr.p_vaddr < result) {
            result = phdr.p_vaddr;
        }
    }
    if (result == UINT64_MAX) goto malformed;
    g_free(contents);
    *base = result;
    return 0;

malformed:
    g_free(contents);
    if (error && error_size) {
        snprintf(error, error_size,
                 "%s: cannot determine preferred guest base", path);
    }
    return -1;
}

static int add_parallel_dynamic_entries(const char *path, CfgProgram *program,
                                        char *error, size_t error_size)
{
    gchar *contents = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &contents, &size, NULL) ||
        size < sizeof(Elf64_Ehdr)) {
        g_free(contents);
        return fail(error, error_size, "cannot read ELF dynamic symbols");
    }
    const unsigned char *file = (const void *)contents;
    const Elf64_Ehdr *header = (const void *)file;
    if (header->e_shentsize != sizeof(Elf64_Shdr) ||
        header->e_shoff > size ||
        header->e_shnum > (size - header->e_shoff) / sizeof(Elf64_Shdr)) {
        g_free(contents);
        return fail(error, error_size, "invalid ELF section table");
    }
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    const char *section_names = NULL;
    size_t section_names_size = 0;
    if (header->e_shstrndx < header->e_shnum) {
        const Elf64_Shdr *names = &sections[header->e_shstrndx];
        if (names->sh_offset <= size && names->sh_size <= size - names->sh_offset) {
            section_names = (const void *)(file + names->sh_offset);
            section_names_size = names->sh_size;
        }
    }
    GHashTable *parallel_pcs = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, g_free, NULL);
    for (size_t i = 0; i < program->tb_count; i++) {
        if (program->tbs[i].semantic_flags !=
            (CFG_TB_CODE64 | CFG_TB_PARALLEL)) {
            continue;
        }
        uint64_t *key = g_new(uint64_t, 1);
        *key = program->tbs[i].start;
        g_hash_table_add(parallel_pcs, key);
    }
    for (uint16_t section = 0; section < header->e_shnum; section++) {
        const Elf64_Shdr *symbols = &sections[section];
        if (symbols->sh_type != SHT_DYNSYM ||
            symbols->sh_entsize != sizeof(Elf64_Sym) ||
            symbols->sh_offset > size ||
            symbols->sh_size > size - symbols->sh_offset) {
            continue;
        }
        size_t count = symbols->sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *entries = (const void *)(file + symbols->sh_offset);
        if (count > (SIZE_MAX / sizeof(*program->tbs)) - program->tb_count) {
            g_hash_table_destroy(parallel_pcs);
            g_free(contents);
            return fail(error, error_size,
                        "too many dynamic function entries");
        }
        CfgTb *next = realloc(program->tbs,
                              (program->tb_count + count) * sizeof(*next));
        if (!next && count) {
            g_hash_table_destroy(parallel_pcs);
            g_free(contents);
            return fail(error, error_size,
                        "out of memory adding dynamic function entry");
        }
        program->tbs = next;
        for (size_t i = 0; i < count; i++) {
            unsigned int type = ELF64_ST_TYPE(entries[i].st_info);
            uint64_t pc = entries[i].st_value;
            if ((type != STT_FUNC && type != STT_GNU_IFUNC) || !pc ||
                !cfg_program_address_is_executable(program, pc)) {
                continue;
            }
            if (g_hash_table_contains(parallel_pcs, &pc)) {
                continue;
            }
            program->tbs[program->tb_count++] = (CfgTb) {
                .start = pc,
                .end = pc + 1,
                .terminator_pc = pc,
                .selected = true,
                .semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL |
                                  CFG_TB_BOUNDED,
                .terminator = CFG_TB_FALLTHROUGH,
            };
            uint64_t *key = g_new(uint64_t, 1);
            *key = pc;
            g_hash_table_add(parallel_pcs, key);
        }
    }

    /* A classic x86-64 PLT entry has a second entry point at byte 6.  The
     * dynamic linker returns there on the first call, so it is a real runtime
     * TB even though no direct branch in the ELF points to it.  Strict AOT can
     * be the first user of a symbol itself; do not require a profiling run to
     * have happened to exercise every lazy binding. */
    if (header->e_machine == EM_X86_64 && section_names) {
        size_t candidate_count = 0;
        for (uint16_t section = 0; section < header->e_shnum; section++) {
            const Elf64_Shdr *plt = &sections[section];
            if (plt->sh_name >= section_names_size ||
                strcmp(section_names + plt->sh_name, ".plt") ||
                plt->sh_offset > size || plt->sh_size > size - plt->sh_offset) {
                continue;
            }
            size_t entry_size = plt->sh_entsize ? plt->sh_entsize : 16;
            if (entry_size >= 16) candidate_count += plt->sh_size / entry_size;
        }
        if (candidate_count > (SIZE_MAX / sizeof(*program->tbs)) -
                              program->tb_count) {
            g_hash_table_destroy(parallel_pcs);
            g_free(contents);
            return fail(error, error_size, "too many PLT runtime entries");
        }
        CfgTb *next = realloc(
            program->tbs,
            (program->tb_count + candidate_count) * sizeof(*next));
        if (!next && candidate_count) {
            g_hash_table_destroy(parallel_pcs);
            g_free(contents);
            return fail(error, error_size,
                        "out of memory adding PLT runtime entries");
        }
        program->tbs = next;
        for (uint16_t section = 0; section < header->e_shnum; section++) {
            const Elf64_Shdr *plt = &sections[section];
            if (plt->sh_name >= section_names_size ||
                strcmp(section_names + plt->sh_name, ".plt") ||
                plt->sh_offset > size || plt->sh_size > size - plt->sh_offset) {
                continue;
            }
            size_t entry_size = plt->sh_entsize ? plt->sh_entsize : 16;
            if (entry_size < 16) continue;
            const uint8_t *bytes = file + plt->sh_offset;
            for (size_t offset = 0; offset + 16 <= plt->sh_size;
                 offset += entry_size) {
                /* push imm32; jmp rel32 is the lazy-binding continuation. */
                if (bytes[offset + 6] != 0x68 || bytes[offset + 11] != 0xe9) {
                    continue;
                }
                uint64_t pc = plt->sh_addr + offset + 6;
                if (g_hash_table_contains(parallel_pcs, &pc)) continue;
                program->tbs[program->tb_count++] = (CfgTb) {
                    .start = pc,
                    .end = pc + 1,
                    .terminator_pc = pc,
                    .selected = true,
                    .semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL |
                                      CFG_TB_BOUNDED,
                    .terminator = CFG_TB_FALLTHROUGH,
                };
                uint64_t *key = g_new(uint64_t, 1);
                *key = pc;
                g_hash_table_add(parallel_pcs, key);
            }
        }
    }
    g_hash_table_destroy(parallel_pcs);
    g_free(contents);
    return 0;
}

static int expand_bounded_parallel_functions(CfgProgram *program,
                                             size_t template_count,
                                             char *error, size_t error_size)
{
    GHashTable *parallel_pcs = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, g_free, NULL);
    for (size_t i = template_count; i < program->tb_count; i++) {
        if (!(program->tbs[i].semantic_flags & CFG_TB_PARALLEL)) continue;
        uint64_t *pc = g_new(uint64_t, 1);
        *pc = program->tbs[i].start;
        g_hash_table_add(parallel_pcs, pc);
    }
    if (template_count > (SIZE_MAX / sizeof(*program->tbs)) -
                         program->tb_count) {
        g_hash_table_destroy(parallel_pcs);
        return fail(error, error_size,
                    "too many bounded parallel CFG blocks");
    }
    CfgTb *expanded = realloc(
        program->tbs,
        (program->tb_count + template_count) * sizeof(*expanded));
    if (!expanded && template_count) {
        g_hash_table_destroy(parallel_pcs);
        return fail(error, error_size,
                    "out of memory adding bounded parallel CFG blocks");
    }
    program->tbs = expanded;
    size_t bounded_entry_count = program->tb_count;
    for (size_t i = template_count; i < bounded_entry_count; i++) {
        CfgTb *entry = &program->tbs[i];
        if (!(entry->semantic_flags & CFG_TB_BOUNDED)) continue;
        for (size_t f = 0; f < program->function_count; f++) {
            const CfgProgramFunction *fn = &program->functions[f];
            if (fn->start != entry->start || !fn->tb_count) continue;
            /* Preserve the real CFG block at the function entry instead of
             * the one-byte synthetic dynamic-symbol placeholder. */
            CfgTb real_entry = program->tbs[fn->first_tb];
            real_entry.selected = true;
            real_entry.semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL |
                                        CFG_TB_BOUNDED;
            real_entry.first_edge = 0;
            real_entry.edge_count = 0;
            *entry = real_entry;
            for (size_t j = 0; j < fn->tb_count; j++) {
                const CfgTb *source = &program->tbs[fn->first_tb + j];
                if (g_hash_table_contains(parallel_pcs, &source->start)) {
                    continue;
                }
                CfgTb added = *source;
                added.selected = true;
                added.semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL |
                                       CFG_TB_BOUNDED;
                added.first_edge = 0;
                added.edge_count = 0;
                program->tbs[program->tb_count++] = added;
                uint64_t *pc = g_new(uint64_t, 1);
                *pc = source->start;
                g_hash_table_add(parallel_pcs, pc);
            }
            break;
        }
    }
    g_hash_table_destroy(parallel_pcs);
    return 0;
}

int latc_tbset_apply(const char *path, const char *source_path,
                     CfgProgram *program,
                     bool ignore_outside_exec, size_t *matched,
                     size_t *unmatched, size_t *ignored,
                     char *error, size_t error_size)
{
    uint8_t digest[32];
    uint64_t load_base;
    LatTbKeySet set;
    if (source_digest(source_path, digest, error, error_size) ||
        source_load_base(source_path, &load_base, error, error_size) ||
        lat_tb_key_set_read_file(path, digest, &set, error, error_size)) {
        return -1;
    }
    size_t hit = 0, miss = 0, skip = 0;
    bool has_parallel = false;
    size_t template_count = program->tb_count;
    if (set.count > (SIZE_MAX / sizeof(*program->tbs)) - program->tb_count) {
        lat_tb_key_set_destroy(&set);
        return fail(error, error_size, "too many TB key entries");
    }
    CfgTb *reserved = realloc(
        program->tbs, (program->tb_count + set.count) * sizeof(*reserved));
    if (!reserved && set.count) {
        lat_tb_key_set_destroy(&set);
        return fail(error, error_size, "out of memory adding TB key entries");
    }
    program->tbs = reserved;
    GHashTable *templates = g_hash_table_new_full(
        tb_template_hash, tb_template_equal, g_free, NULL);
    GHashTable *templates_by_pc = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, g_free, NULL);
    for (size_t i = 0; i < template_count; i++) {
        TbTemplateKey *key = g_new(TbTemplateKey, 1);
        key->pc = program->tbs[i].start;
        key->flags = program->tbs[i].semantic_flags;
        g_hash_table_insert(templates, key, GSIZE_TO_POINTER(i + 1));
        if (!g_hash_table_contains(templates_by_pc, &key->pc)) {
            uint64_t *pc = g_new(uint64_t, 1);
            *pc = key->pc;
            g_hash_table_insert(templates_by_pc, pc,
                                GSIZE_TO_POINTER(i + 1));
        }
    }
    for (size_t record = 0; record < set.count; record++) {
        const LatTbKey *key = &set.keys[record];
        has_parallel |= !!(key->flags & CFG_TB_PARALLEL);
        if (key->guest_rva > UINT64_MAX - load_base) {
            g_hash_table_destroy(templates_by_pc);
            g_hash_table_destroy(templates);
            lat_tb_key_set_destroy(&set);
            return fail(error, error_size, "TB key address overflows");
        }
        uint64_t pc = key->guest_rva + load_base;
        TbTemplateKey wanted = { .pc = pc, .flags = key->flags };
        gpointer exact = g_hash_table_lookup(templates, &wanted);
        gpointer same_pc = g_hash_table_lookup(templates_by_pc, &pc);
        bool found = exact != NULL;
        size_t template_index = same_pc ?
            GPOINTER_TO_SIZE(same_pc) - 1 : SIZE_MAX;
        if (template_index != SIZE_MAX) {
            /* A parallel observation still seeds the ordinary CFG graph. */
            program->tbs[template_index].selected = true;
        }
        /* The on-disk key set is already unique.  Only pre-existing CFG
         * templates can match; entries appended by this loop cannot. */
        if (found) {
            size_t index = GPOINTER_TO_SIZE(exact) - 1;
            program->tbs[index].selected = true;
        }
        if (found) {
            hit++;
        } else if (cfg_program_address_is_executable(program, pc)) {
            CfgTb added = template_index != SIZE_MAX ?
                program->tbs[template_index] : (CfgTb) {
                    .start = pc,
                    .end = pc + 1,
                    .terminator_pc = pc,
                    .terminator = CFG_TB_FALLTHROUGH,
                };
            added.selected = true;
            added.semantic_flags = key->flags;
            added.first_edge = 0;
            added.edge_count = 0;
            program->tbs[program->tb_count++] = added;
            miss++;
        } else if (ignore_outside_exec) {
            skip++;
        } else {
            if (error && error_size) {
                snprintf(error, error_size,
                         "%s: key %zu address 0x%" PRIx64
                         " is outside executable ELF sections",
                         path, record, pc);
            }
            g_hash_table_destroy(templates_by_pc);
            g_hash_table_destroy(templates);
            lat_tb_key_set_destroy(&set);
            return -1;
        }
    }
    /* A JIT hit proves that its containing function is in use.  Compile that
     * whole function so untaken internal branches are covered, but do not use
     * a direct call as a reason to recursively select another function: an
     * executed call target already has its own JIT key. */
    for (size_t f = 0; f < program->function_count; f++) {
        const CfgProgramFunction *fn = &program->functions[f];
        bool function_selected = false;
        for (size_t j = 0; j < fn->tb_count; j++) {
            if (program->tbs[fn->first_tb + j].selected) {
                function_selected = true;
                break;
            }
        }
        if (!function_selected) continue;
        for (size_t j = 0; j < fn->tb_count; j++) {
            CfgTb *tb = &program->tbs[fn->first_tb + j];
            if (!tb->selected) {
                tb->selected = true;
                tb->semantic_flags |= CFG_TB_BOUNDED;
            }
        }
    }
    if (has_parallel && add_parallel_dynamic_entries(
            source_path, program, error, error_size)) {
        g_hash_table_destroy(templates_by_pc);
        g_hash_table_destroy(templates);
        lat_tb_key_set_destroy(&set);
        return -1;
    }
    if (has_parallel && expand_bounded_parallel_functions(
            program, template_count, error, error_size)) {
        g_hash_table_destroy(templates_by_pc);
        g_hash_table_destroy(templates);
        lat_tb_key_set_destroy(&set);
        return -1;
    }
    /* Starting from addresses observed by JIT, add every statically reachable
     * CFG block.  Exported functions are emitted separately as bounded bodies
     * so their calls do not recursively select the whole program. */
    GQueue reachable = G_QUEUE_INIT;
    for (size_t i = 0; i < template_count; i++) {
        if (program->tbs[i].selected) {
            g_queue_push_tail(&reachable, GSIZE_TO_POINTER(i + 1));
        }
    }
    while (!g_queue_is_empty(&reachable)) {
        size_t index = GPOINTER_TO_SIZE(g_queue_pop_head(&reachable)) - 1;
        const CfgTb *tb = &program->tbs[index];
        for (size_t edge_index = tb->first_edge;
             edge_index < tb->first_edge + tb->edge_count; edge_index++) {
            const CfgProgramEdge *edge = &program->edges[edge_index];
            if (edge->resolution != CFG_EDGE_STATIC ||
                edge->kind == CFG_EDGE_CALL) continue;
            gpointer target = g_hash_table_lookup(templates_by_pc, &edge->to);
            if (!target) continue;
            size_t target_index = GPOINTER_TO_SIZE(target) - 1;
            if (!program->tbs[target_index].selected) {
                program->tbs[target_index].selected = true;
                program->tbs[target_index].semantic_flags |= CFG_TB_BOUNDED;
                g_queue_push_tail(&reachable,
                                  GSIZE_TO_POINTER(target_index + 1));
            }
        }
    }
    if (has_parallel && template_count) {
        GHashTable *parallel_pcs = g_hash_table_new_full(
            g_int64_hash, g_int64_equal, g_free, NULL);
        GHashTable *bounded_pcs = g_hash_table_new_full(
            g_int64_hash, g_int64_equal, g_free, NULL);
        for (size_t i = template_count; i < program->tb_count; i++) {
            if (!program->tbs[i].selected ||
                !(program->tbs[i].semantic_flags & CFG_TB_PARALLEL)) {
                continue;
            }
            if (program->tbs[i].semantic_flags & CFG_TB_BOUNDED) {
                uint64_t *pc = g_new(uint64_t, 1);
                *pc = program->tbs[i].start;
                g_hash_table_insert(bounded_pcs, pc,
                                    GSIZE_TO_POINTER(i + 1));
            } else {
                uint64_t *pc = g_new(uint64_t, 1);
                *pc = program->tbs[i].start;
                g_hash_table_add(parallel_pcs, pc);
            }
        }
        CfgTb *expanded = realloc(
            program->tbs,
            (program->tb_count + template_count) * sizeof(*expanded));
        if (!expanded) {
            g_hash_table_destroy(bounded_pcs);
            g_hash_table_destroy(parallel_pcs);
            g_hash_table_destroy(templates_by_pc);
            g_hash_table_destroy(templates);
            lat_tb_key_set_destroy(&set);
            return fail(error, error_size,
                        "out of memory adding parallel CFG blocks");
        }
        program->tbs = expanded;
        for (size_t i = 0; i < template_count; i++) {
            if (!program->tbs[i].selected) {
                continue;
            }
            if (g_hash_table_contains(parallel_pcs,
                                      &program->tbs[i].start)) continue;
            gpointer bounded = g_hash_table_lookup(
                bounded_pcs, &program->tbs[i].start);
            if (bounded) {
                if (program->tbs[i].semantic_flags & CFG_TB_BOUNDED) {
                    continue;
                }
                size_t index = GPOINTER_TO_SIZE(bounded) - 1;
                program->tbs[index].semantic_flags &= ~CFG_TB_BOUNDED;
                uint64_t *pc = g_new(uint64_t, 1);
                *pc = program->tbs[i].start;
                g_hash_table_add(parallel_pcs, pc);
                continue;
            }
            CfgTb added = program->tbs[i];
            added.semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL |
                (program->tbs[i].semantic_flags & CFG_TB_BOUNDED);
            added.first_edge = 0;
            added.edge_count = 0;
            program->tbs[program->tb_count++] = added;
        }
        g_hash_table_destroy(bounded_pcs);
        g_hash_table_destroy(parallel_pcs);
    }
    g_hash_table_destroy(templates_by_pc);
    g_hash_table_destroy(templates);
    lat_tb_key_set_destroy(&set);
    if (matched) *matched = hit;
    if (unmatched) *unmatched = miss;
    if (ignored) *ignored = skip;
    return 0;
}
