#define _GNU_SOURCE
#include "tbset.h"
#include "lat-tb-key-set.h"
#include "elf_image.h"

#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t selected(const char *guest, const char *input,
                       const char *selection, const char *limit)
{
    CfgProgram program = {0};
    CfgAnalyzeOptions options = {.resolve_jump_tables = true};
    char error[256] = {0};
    uint8_t digest[32];
    size_t matched, unmatched, ignored;
    if (selection) setenv("LATC_TBSET_SELECTION", selection, 1);
    else unsetenv("LATC_TBSET_SELECTION");
    if (limit) setenv("LATC_TBSET_CLOSURE_LIMIT", limit, 1);
    else unsetenv("LATC_TBSET_CLOSURE_LIMIT");
    unsetenv("LATC_TBSET_EXPAND_FUNCTIONS");
    g_assert_cmpint(cfg_analyze_elf(guest, &options, &program, error, sizeof(error)), ==, 0);
    g_assert_cmpint(latc_tbset_apply(input, guest, &program, false, &matched,
        &unmatched, &ignored, digest, error, sizeof(error)), ==, 0);
    size_t count = 0;
    for (size_t i = 0; i < program.tb_count; i++) {
        count += program.tbs[i].selected &&
                 (program.tbs[i].semantic_flags & CFG_TB_PARALLEL);
    }
    cfg_program_destroy(&program);
    return count;
}

static void check_pic_cases(const char *guest, const char *input)
{
    CfgProgram program = {0};
    CfgAnalyzeOptions options = {.resolve_jump_tables = true};
    char error[256];
    uint8_t digest[32];
    size_t matched, unmatched, ignored;
    setenv("LATC_TBSET_SELECTION", "bounded", 1);
    setenv("LATC_TBSET_CLOSURE_LIMIT", "20000", 1);
    g_assert_cmpint(cfg_analyze_elf(guest, &options, &program,
        error, sizeof(error)), ==, 0);
    char *static_path = NULL;
    int static_fd = g_file_open_tmp("tbset-static-pic-XXXXXX", &static_path,
                                     NULL);
    g_assert_cmpint(static_fd, >=, 0);
    close(static_fd);
    size_t written;
    g_assert_cmpint(latc_tbset_write_static(static_path, guest, &program,
        &written, error, sizeof(error)), ==, 0);
    LatTbKeySet static_keys;
    g_assert_cmpint(lat_tb_key_set_read_file(static_path, NULL, &static_keys,
        error, sizeof(error)), ==, 0);
    g_assert_cmpint(latc_tbset_apply(input, guest, &program, false, &matched,
        &unmatched, &ignored, digest, error, sizeof(error)), ==, 0);
    ElfFile elf;
    elf_load(guest, &elf);
    uint64_t image_base = UINT64_MAX;
    const Elf64_Phdr *phdrs = (const void *)(elf.data + elf.eh->e_phoff);
    for (unsigned i = 0; i < elf.eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < image_base) {
            image_base = phdrs[i].p_vaddr;
        }
    }
    unsigned cases = 0, guards = 0;
    CfgProgram unresolved = {0};
    CfgAnalyzeOptions no_tables = {.resolve_jump_tables = false};
    g_assert_cmpint(cfg_analyze_elf(guest, &no_tables, &unresolved,
        error, sizeof(error)), ==, 0);
    for (unsigned i = 0; i < elf.eh->e_shnum; i++) {
        const Elf64_Shdr *section = &elf.sh[i];
        if (section->sh_type != SHT_SYMTAB) {
            continue;
        }
        const Elf64_Sym *symbols = (const void *)(elf.data + section->sh_offset);
        const char *strings = (const void *)(elf.data +
            elf.sh[section->sh_link].sh_offset);
        for (size_t j = 0; j < section->sh_size / sizeof(*symbols); j++) {
            if (!strcmp(strings + symbols[j].st_name, "bounded_guard")) {
                g_assert_true(lat_tb_key_set_contains(&static_keys,
                    symbols[j].st_value - image_base, 3));
                guards++;
            }
            if (strncmp(strings + symbols[j].st_name, "bounded_case", 12)) {
                continue;
            }
            bool found = false;
            for (size_t k = 0; k < program.tb_count; k++) {
                found |= program.tbs[k].selected &&
                    (program.tbs[k].semantic_flags & CFG_TB_PARALLEL) &&
                    program.tbs[k].start == symbols[j].st_value;
            }
            g_assert_true(found);
            for (size_t k = 0; k < unresolved.tb_count; k++) {
                g_assert_cmpuint(unresolved.tbs[k].start, !=,
                    symbols[j].st_value);
            }
            g_assert_true(lat_tb_key_set_contains(&static_keys,
                symbols[j].st_value - image_base, 3));
            cases++;
        }
    }
    g_assert_cmpuint(cases, ==, 3);
    g_assert_cmpuint(guards, ==, 1);
    elf_free(&elf);
    lat_tb_key_set_destroy(&static_keys);
    g_unlink(static_path);
    g_free(static_path);
    cfg_program_destroy(&program);
    cfg_program_destroy(&unresolved);
}

int main(int argc, char **argv)
{
    g_assert_true(argc == 2 || argc == 3);
    ElfFile elf;
    elf_load(argv[1], &elf);
    uint64_t entry = elf.eh->e_entry;
    uint64_t base = UINT64_MAX;
    const Elf64_Phdr *phdrs = (const void *)(elf.data + elf.eh->e_phoff);
    for (unsigned i = 0; i < elf.eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < base)
            base = phdrs[i].p_vaddr;
    }
    elf_free(&elf);
    gchar *data = NULL;
    gsize size = 0;
    g_assert_true(g_file_get_contents(argv[1], &data, &size, NULL));
    LatTbKeySet keys = {0};
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, (guchar *)data, size);
    gsize digest_size = 32;
    g_checksum_get_digest(sum, keys.source_sha256, &digest_size);
    g_checksum_free(sum);
    g_free(data);
    LatTbKey key = {.guest_rva = entry - base, .flags = 3};
    keys.keys = &key;
    keys.count = 1;
    char *path = NULL;
    int fd = g_file_open_tmp("tbset-selection-XXXXXX", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    char error[256];
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &keys, error, sizeof(error)), ==, 0);
    close(fd);
    size_t cfg_zero = selected(argv[1], path, "cfg", "0");
    size_t cfg_default = selected(argv[1], path, NULL, "0");
    size_t cfg_budget = selected(argv[1], path, "cfg", "20000");
    size_t bounded_zero = selected(argv[1], path, "bounded", "0");
    size_t bounded_budget = selected(argv[1], path, "bounded", "20000");
    g_assert_cmpuint(cfg_zero, ==, cfg_default);
    g_assert_cmpuint(cfg_budget, >=, cfg_zero);
    g_assert_cmpuint(cfg_zero, >, bounded_zero);
    g_assert_cmpuint(bounded_budget, >=, bounded_zero);
    g_assert_cmpuint(selected(argv[1], path, "exact", "20000"), ==, 1);
    g_assert_cmpuint(selected(argv[1], path, "exact-static", "20000"), ==, 1);
    if (argc == 3) {
        g_unlink(path);
        g_free(path);
        path = NULL;
        elf_load(argv[2], &elf);
        entry = elf.eh->e_entry;
        base = UINT64_MAX;
        phdrs = (const void *)(elf.data + elf.eh->e_phoff);
        for (unsigned i = 0; i < elf.eh->e_phnum; i++) {
            if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < base) {
                base = phdrs[i].p_vaddr;
            }
        }
        elf_free(&elf);
        g_assert_true(g_file_get_contents(argv[2], &data, &size, NULL));
        sum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(sum, (guchar *)data, size);
        digest_size = 32;
        g_checksum_get_digest(sum, keys.source_sha256, &digest_size);
        g_checksum_free(sum);
        g_free(data);
        key.guest_rva = entry - base;
        fd = g_file_open_tmp("tbset-pic-XXXXXX", &path, NULL);
        g_assert_cmpint(fd, >=, 0);
        g_assert_cmpint(lat_tb_key_set_write_fd(fd, &keys,
            error, sizeof(error)), ==, 0);
        close(fd);
        size_t without = selected(argv[2], path, "bounded", "0");
        size_t with = selected(argv[2], path, "bounded", "20000");
        g_assert_cmpuint(with, >, without + 3);
        check_pic_cases(argv[2], path);
        printf("test-tbset-selection: PIC closure=%zu/%zu\n", without, with);
    }
    printf("test-tbset-selection: PASS cfg=%zu/%zu bounded=%zu/%zu\n",
           cfg_zero, cfg_budget, bounded_zero, bounded_budget);
    g_unlink(path);
    g_free(path);
    return 0;
}
