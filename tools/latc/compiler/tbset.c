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

int latc_tbset_read_leaders(const char *path, const char *source_path,
                            uint64_t **leaders, size_t *leader_count,
                            char *error, size_t error_size)
{
    uint8_t digest[32];
    uint64_t load_base;
    LatTbKeySet set;
    if (!leaders || !leader_count ||
        source_digest(source_path, digest, error, error_size) ||
        source_load_base(source_path, &load_base, error, error_size) ||
        lat_tb_key_set_read_file(path, digest, &set, error, error_size)) {
        return -1;
    }
    uint64_t *result = calloc(set.count, sizeof(*result));
    if (!result && set.count) {
        lat_tb_key_set_destroy(&set);
        return fail(error, error_size, "out of memory reading TB leaders");
    }
    for (size_t i = 0; i < set.count; i++) {
        if (set.keys[i].guest_rva > UINT64_MAX - load_base) {
            free(result);
            lat_tb_key_set_destroy(&set);
            return fail(error, error_size, "TB key address overflows");
        }
        result[i] = set.keys[i].guest_rva + load_base;
    }
    *leaders = result;
    *leader_count = set.count;
    lat_tb_key_set_destroy(&set);
    return 0;
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
            CfgTb added = {
                .start = pc,
                .end = pc + 1,
                .terminator_pc = pc,
                .selected = true,
                .semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL,
                .terminator = CFG_TB_FALLTHROUGH,
            };
            for (size_t j = 0; j < program->tb_count; j++) {
                if (program->tbs[j].start == pc) {
                    added = program->tbs[j];
                    added.selected = true;
                    added.semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL;
                    break;
                }
            }
            program->tbs[program->tb_count++] = added;
            uint64_t *key = g_new(uint64_t, 1);
            *key = pc;
            g_hash_table_add(parallel_pcs, key);
        }
    }
    g_hash_table_destroy(parallel_pcs);
    g_free(contents);
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
    for (size_t record = 0; record < set.count; record++) {
        const LatTbKey *key = &set.keys[record];
        has_parallel |= !!(key->flags & CFG_TB_PARALLEL);
        if (key->guest_rva > UINT64_MAX - load_base) {
            lat_tb_key_set_destroy(&set);
            return fail(error, error_size, "TB key address overflows");
        }
        uint64_t pc = key->guest_rva + load_base;
        bool found = false;
        size_t template_index = SIZE_MAX;
        /* The on-disk key set is already unique.  Only pre-existing CFG
         * templates can match; entries appended by this loop cannot. */
        for (size_t i = 0; i < template_count; i++) {
            if (program->tbs[i].start != pc) continue;
            if (template_index == SIZE_MAX) template_index = i;
            if (program->tbs[i].semantic_flags == key->flags) {
                program->tbs[i].selected = true;
                found = true;
                break;
            }
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
            lat_tb_key_set_destroy(&set);
            return -1;
        }
    }
    if (has_parallel && add_parallel_dynamic_entries(
            source_path, program, error, error_size)) {
        lat_tb_key_set_destroy(&set);
        return -1;
    }
    lat_tb_key_set_destroy(&set);
    if (matched) *matched = hit;
    if (unmatched) *unmatched = miss;
    if (ignored) *ignored = skip;
    return 0;
}

typedef struct TbIdentity {
    uint64_t pc;
    uint32_t flags;
} TbIdentity;

static guint tb_identity_hash(gconstpointer opaque)
{
    const TbIdentity *key = opaque;
    return (guint)(key->pc ^ (key->pc >> 32) ^ key->flags);
}

static gboolean tb_identity_equal(gconstpointer left, gconstpointer right)
{
    const TbIdentity *a = left, *b = right;
    return a->pc == b->pc && a->flags == b->flags;
}

static size_t tb_map_find(GHashTable *map, uint64_t pc, uint32_t flags)
{
    TbIdentity key = { .pc = pc, .flags = flags };
    gpointer value = g_hash_table_lookup(map, &key);
    return value ? (size_t)(uintptr_t)value - 1 : SIZE_MAX;
}

static void tb_map_insert(GHashTable *map, const CfgTb *tb, size_t index)
{
    TbIdentity *key = g_new(TbIdentity, 1);
    *key = (TbIdentity) { .pc = tb->start, .flags = tb->semantic_flags };
    g_hash_table_replace(map, key, (gpointer)(uintptr_t)(index + 1));
}

int latc_tbset_expand_cfg(CfgProgram *program,
                          char *error, size_t error_size)
{
    size_t queue_count = 0, queue_pos = 0;
    size_t queue_cap = program->tb_count ? program->tb_count : 1;
    size_t *queue = malloc(queue_cap * sizeof(*queue));
    if (!queue) return fail(error, error_size,
                            "out of memory expanding TB CFG");
    GHashTable *map = g_hash_table_new_full(tb_identity_hash,
                                            tb_identity_equal, g_free, NULL);
    for (size_t i = 0; i < program->tb_count; i++) {
        tb_map_insert(map, &program->tbs[i], i);
        if (program->tbs[i].selected) queue[queue_count++] = i;
    }
    while (queue_pos < queue_count) {
        size_t source_index = queue[queue_pos++];
        CfgTb source = program->tbs[source_index];
        for (size_t e = source.first_edge;
             e < source.first_edge + source.edge_count; e++) {
            if (e >= program->edge_count) {
                free(queue);
                g_hash_table_destroy(map);
                return fail(error, error_size, "invalid TB CFG edge range");
            }
            const CfgProgramEdge *edge = &program->edges[e];
            if (!edge->to || edge->resolution != CFG_EDGE_STATIC) continue;
            size_t target = tb_map_find(map, edge->to,
                                        source.semantic_flags);
            if (target == SIZE_MAX) {
                size_t template = tb_map_find(map, edge->to, CFG_TB_CODE64);
                if (template == SIZE_MAX) continue;
                if (program->tb_count == SIZE_MAX / sizeof(*program->tbs)) {
                    free(queue);
                    g_hash_table_destroy(map);
                    return fail(error, error_size, "too many expanded TBs");
                }
                CfgTb *next = realloc(program->tbs,
                    (program->tb_count + 1) * sizeof(*next));
                if (!next) {
                    free(queue);
                    g_hash_table_destroy(map);
                    return fail(error, error_size,
                                "out of memory expanding TB CFG");
                }
                program->tbs = next;
                target = program->tb_count++;
                program->tbs[target] = program->tbs[template];
                program->tbs[target].selected = false;
                program->tbs[target].semantic_flags = source.semantic_flags;
                tb_map_insert(map, &program->tbs[target], target);
            }
            if (program->tbs[target].selected) continue;
            program->tbs[target].selected = true;
            if (queue_count == queue_cap) {
                size_t next_cap = queue_cap * 2;
                size_t *next = realloc(queue, next_cap * sizeof(*next));
                if (!next) {
                    free(queue);
                    g_hash_table_destroy(map);
                    return fail(error, error_size,
                                "out of memory expanding TB CFG");
                }
                queue = next;
                queue_cap = next_cap;
            }
            queue[queue_count++] = target;
        }
    }
    free(queue);
    g_hash_table_destroy(map);
    program->exact_selection = true;
    return 0;
}
