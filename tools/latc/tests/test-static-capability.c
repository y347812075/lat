#define _GNU_SOURCE
#include "tbset.h"
#include "lat-tb-key-set.h"
#include "elf_image.h"

#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

static void check(const char *fixture, const unsigned char vector[6],
                  bool excluded)
{
    gchar *contents;
    gsize length;
    g_assert_true(g_file_get_contents(fixture, &contents, &length, NULL));
    ElfFile original;
    elf_load(fixture, &original);
    uint64_t entry = original.eh->e_entry, offset;
    unsigned section;
    g_assert_true(elf_find_exec_section_for_range(&original, entry, 11, &section));
    g_assert_true(elf_function_file_offset(&original, entry, 11, section, &offset));
    uint64_t base = UINT64_MAX;
    const Elf64_Phdr *ph = (const void *)(original.data + original.eh->e_phoff);
    for (unsigned i = 0; i < original.eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < base) {
            base = ph[i].p_vaddr;
        }
    }
    elf_free(&original);
    /* Both edges reach ordinary code; the other edge enters the ISA variant. */
    const unsigned char branches[] = {0x74, 8, 0xeb, 0};
    memcpy(contents + offset, branches, sizeof(branches));
    memcpy(contents + offset + 4, vector, 6);
    contents[offset + 10] = 0xc3;
    char *guest, *static_path, *input;
    int fd = g_file_open_tmp("static-capability-guest-XXXXXX", &guest, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);
    g_assert_true(g_file_set_contents(guest, contents, length, NULL));
    g_free(contents);
    fd = g_file_open_tmp("static-capability-set-XXXXXX", &static_path, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);
    fd = g_file_open_tmp("static-capability-input-XXXXXX", &input, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);

    char error[256];
    CfgProgram program = {0};
    CfgAnalyzeOptions options = {.resolve_jump_tables = true};
    g_assert_cmpint(cfg_analyze_elf(guest, &options, &program,
        error, sizeof(error)), ==, 0);
    size_t written;
    g_assert_cmpint(latc_tbset_write_static(static_path, guest, &program,
        &written, error, sizeof(error)), ==, 0);
    LatTbKeySet keys;
    g_assert_cmpint(lat_tb_key_set_read_file(static_path, NULL, &keys,
        error, sizeof(error)), ==, 0);
    g_assert_cmpint(lat_tb_key_set_contains(&keys, entry + 4 - base, 3), ==,
                    !excluded);
    g_assert_true(lat_tb_key_set_contains(&keys, entry - base, 3));
    g_assert_true(lat_tb_key_set_contains(&keys, entry + 10 - base, 3));
    cfg_program_destroy(&program);

    LatTbKey request[2] = {{.guest_rva = entry - base, .flags = 3},
                          {.guest_rva = entry + 4 - base, .flags = 3}};
    LatTbKeySet requested = {.keys = request, .count = 1};
    memcpy(requested.source_sha256, keys.source_sha256, 32);
    for (unsigned mode = 0; mode < 2; mode++) {
        setenv("LATC_TBSET_SELECTION", mode ? "bounded" : "cfg", 1);
        setenv("LATC_TBSET_CLOSURE_LIMIT", "20000", 1);
        unsetenv("LATC_TBSET_EXPAND_FUNCTIONS");
        for (unsigned explicit = 0; explicit < 2; explicit++) {
            requested.count = explicit ? 2 : 1;
            fd = g_open(input, O_WRONLY | O_TRUNC, 0600);
            g_assert_cmpint(fd, >=, 0);
            g_assert_cmpint(lat_tb_key_set_write_fd(fd, &requested,
                error, sizeof(error)), ==, 0);
            close(fd);
            g_assert_cmpint(cfg_analyze_elf(guest, &options, &program,
                error, sizeof(error)), ==, 0);
            size_t matched, unmatched, ignored;
            uint8_t digest[32];
            g_assert_cmpint(latc_tbset_apply(input, guest, &program, false,
                &matched, &unmatched, &ignored, digest, error, sizeof(error)), ==, 0);
            bool found = false, ordinary = false;
            for (size_t i = 0; i < program.tb_count; i++) {
                CfgTb *tb = &program.tbs[i];
                found |= tb->selected && tb->start == entry + 4;
                ordinary |= tb->selected && tb->start == entry + 10;
            }
            g_assert_cmpint(found, ==, explicit || !excluded);
            g_assert_true(ordinary);
            cfg_program_destroy(&program);
        }
    }
    LatTbKey exact_keys[] = {
        {.guest_rva = entry - base, .flags = 3},
        {.guest_rva = entry + 4 - base, .flags = 3},
        {.guest_rva = entry + 10 - base, .flags = 3},
    };
    requested.keys = exact_keys;
    requested.count = G_N_ELEMENTS(exact_keys);
    fd = g_open(input, O_WRONLY | O_TRUNC, 0600);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &requested,
        error, sizeof(error)), ==, 0);
    close(fd);
    for (unsigned mode = 0; mode < 4; mode++) {
        bool static_mode = mode & 1;
        setenv("LATC_TBSET_SELECTION", static_mode ? "exact-static" : "exact", 1);
        setenv("LATC_TBSET_CLOSURE_LIMIT", "20000", 1);
        setenv("LATC_TBSET_EXPAND_FUNCTIONS", "1", 1);
        int rc = mode < 2 ?
            cfg_analyze_elf(guest, &options, &program, error, sizeof(error)) :
            cfg_load_exec_ranges(guest, &program, error, sizeof(error));
        g_assert_cmpint(rc, ==, 0);
        size_t matched, unmatched, ignored;
        uint8_t digest[32];
        g_assert_cmpint(latc_tbset_apply(input, guest, &program, false,
            &matched, &unmatched, &ignored, digest, error, sizeof(error)), ==, 0);
        size_t selected_count = 0;
        for (size_t i = 0; i < program.tb_count; i++) {
            CfgTb *tb = &program.tbs[i];
            if (!tb->selected) continue;
            g_assert_true(lat_tb_key_set_contains(&requested, tb->start - base, 3));
            g_assert_cmpint(tb->observed, ==, !static_mode);
            if (static_mode && excluded) g_assert_cmpuint(tb->start, !=, entry + 4);
            selected_count++;
        }
        g_assert_cmpuint(selected_count, ==, 3 - (static_mode && excluded));
        cfg_program_destroy(&program);
    }
    unsetenv("LATC_TBSET_EXPAND_FUNCTIONS");
    lat_tb_key_set_destroy(&keys);
    g_unlink(guest);
    g_unlink(static_path);
    g_unlink(input);
    g_free(guest);
    g_free(static_path);
    g_free(input);
}

int main(int argc, char **argv)
{
    g_assert_cmpint(argc, ==, 2);
    const unsigned char evex[] = {0x62, 0xf1, 0xfd, 0x48, 0x6f, 0xc8};
    const unsigned char low_evex[] = {0x62, 0xf1, 0xfd, 0x08, 0x6f, 0xc8};
    const unsigned char mask[] = {0xc5, 0xf8, 0x92, 0xc8, 0x90, 0x90};
    const unsigned char ordinary[] = {0xc5, 0xf9, 0xef, 0xc0, 0x90, 0x90};
    check(argv[1], evex, true);
    check(argv[1], low_evex, true);
    check(argv[1], mask, true);
    check(argv[1], ordinary, false);
    puts("test-static-capability: PASS");
    return 0;
}
