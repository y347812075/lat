#define _GNU_SOURCE
#include "tbset.h"

#include <elf.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char *fixture(const unsigned char *code, size_t size,
                     const int32_t *table, size_t table_count)
{
    unsigned char data[2048] = {0};
    Elf64_Ehdr *header = (void *)data;
    memcpy(header->e_ident, ELFMAG, SELFMAG);
    header->e_ident[EI_CLASS] = ELFCLASS64;
    header->e_ident[EI_DATA] = ELFDATA2LSB;
    header->e_machine = EM_X86_64;
    header->e_shoff = sizeof(*header);
    header->e_shentsize = sizeof(Elf64_Shdr);
    header->e_shnum = 3;
    header->e_phoff = 256;
    header->e_phentsize = sizeof(Elf64_Phdr);
    header->e_phnum = 2;
    Elf64_Phdr *loads = (void *)(data + header->e_phoff);
    loads[0] = (Elf64_Phdr) {.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
        .p_offset = 512, .p_vaddr = 0x1000, .p_filesz = size, .p_memsz = size};
    loads[1] = (Elf64_Phdr) {.p_type = PT_LOAD, .p_flags = PF_R,
        .p_offset = 1536, .p_vaddr = 0x2000,
        .p_filesz = table_count * sizeof(*table),
        .p_memsz = table_count * sizeof(*table)};
    Elf64_Shdr *sections = (void *)(data + header->e_shoff);
    sections[1] = (Elf64_Shdr) {.sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC | SHF_EXECINSTR, .sh_addr = 0x1000,
        .sh_offset = 512, .sh_size = size};
    sections[2] = (Elf64_Shdr) {.sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC, .sh_addr = 0x2000,
        .sh_offset = 1536, .sh_size = table_count * sizeof(*table)};
    g_assert_cmpuint(size, <=, 1024);
    g_assert_cmpuint(table_count * sizeof(*table), <=, 512);
    memcpy(data + 512, code, size);
    if (table_count) memcpy(data + 1536, table, table_count * sizeof(*table));
    char *path;
    int fd = g_file_open_tmp("tb-closure-XXXXXX", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(write(fd, data, sizeof(data)), ==, sizeof(data));
    g_assert_cmpint(close(fd), ==, 0);
    return path;
}

static GArray *discover(const char *path, const CfgProgram *program,
                        size_t work, size_t batch)
{
    char error[256];
    LatcTbClosure *closure = latc_tb_closure_new(path, program,
                                                error, sizeof(error));
    g_assert_nonnull(closure);
    GArray *result = g_array_new(FALSE, FALSE, sizeof(uint64_t));
    bool done = false;
    size_t iterations = 0;
    while (!done) {
        CfgTb *targets;
        size_t count;
        g_assert_cmpint(latc_tb_closure_advance(closure, work, batch,
            &targets, &count, &done, error, sizeof(error)), ==, 0);
        g_assert_cmpuint(count, <=, batch);
        for (size_t i = 0; i < count; i++) {
            g_assert_true(targets[i].selected);
            g_assert_false(targets[i].observed);
            g_assert_cmpuint(targets[i].semantic_flags, ==,
                CFG_TB_CODE64 | CFG_TB_PARALLEL | CFG_TB_BOUNDED);
            g_array_append_val(result, targets[i].start);
        }
        g_free(targets);
        g_assert_cmpuint(++iterations, <, 10000);
    }
    CfgTb *targets;
    size_t count;
    g_assert_cmpint(latc_tb_closure_advance(closure, work, batch,
        &targets, &count, &done, error, sizeof(error)), ==, 0);
    g_assert_true(done);
    g_assert_cmpuint(count, ==, 0);
    g_free(targets);
    g_assert_cmpint(latc_tb_closure_advance(closure, 0, batch,
        &targets, &count, &done, error, sizeof(error)), ==, -1);
    latc_tb_closure_free(closure);
    return result;
}

static void check(const unsigned char *code, size_t size,
                   const int32_t *table, size_t table_count,
                   const uint64_t *expected, size_t count)
{
    char *path = fixture(code, size, table, table_count);
    CfgTb roots[] = {
        {.start = 0x1000, .selected = true, .semantic_flags = 3},
        {.start = 0x1000, .selected = true, .semantic_flags = 3},
        {.start = 0x1001, .selected = false, .semantic_flags = 3},
    };
    CfgExecRange range = {.start = 0x1000, .size = size};
    CfgProgram program = {.tbs = roots, .tb_count = G_N_ELEMENTS(roots),
        .exec_ranges = &range, .exec_range_count = 1};
    GArray *full = discover(path, &program, SIZE_MAX, 1024);
    g_assert_cmpuint(full->len, ==, count);
    if (count) g_assert_cmpmem(full->data, count * sizeof(uint64_t),
                              expected, count * sizeof(uint64_t));
    for (size_t work = 1; work <= 7; work++) {
        for (size_t batch = 1; batch <= 3; batch++) {
            GArray *sliced = discover(path, &program, work, batch);
            g_assert_cmpuint(sliced->len, ==, full->len);
            if (count) g_assert_cmpmem(sliced->data, count * sizeof(uint64_t),
                                      full->data, count * sizeof(uint64_t));
            g_array_free(sliced, TRUE);
        }
    }
    g_array_free(full, TRUE);
    g_assert_cmpint(g_unlink(path), ==, 0);
    g_free(path);
}

int main(void)
{
    /* A diamond joins a cycle; an unreferenced byte must not become a root. */
    const unsigned char diamond[] = {
        0x75, 0x04, 0xeb, 0x04, 0x90, 0x90, 0xeb, 0x00, 0xeb, 0xf6,
    };
    const uint64_t diamond_expected[] = {0x1006, 0x1002, 0x1008};
    check(diamond, sizeof(diamond), NULL, 0,
          diamond_expected, G_N_ELEMENTS(diamond_expected));
    const unsigned char outside[] = {0xe9, 0xfb, 0x0f, 0, 0};
    check(outside, sizeof(outside), NULL, 0, NULL, 0);
    const unsigned char indirect[] = {0xff, 0xe0, 0x90, 0xc3};
    check(indirect, sizeof(indirect), NULL, 0, NULL, 0);
    const unsigned char truncated[] = {0x0f};
    check(truncated, sizeof(truncated), NULL, 0, NULL, 0);
    /* All PIC cases must survive a target slice in the middle of one node. */
    const unsigned char pic[] = {
        0x83, 0xf8, 2, 0x77, 24,
        0x89, 0xc0, 0xc7, 0x07, 1, 0, 0, 0,
        0x48, 0x8d, 0x0d, 0xec, 0x0f, 0, 0,
        0x48, 0x63, 0x14, 0x81, 0x48, 0x01, 0xca, 0xff, 0xe2,
        0xc3, 0xc3, 0xc3,
    };
    const int32_t table[] = {-0xfe3, -0xfe2, -0xfe1};
    const uint64_t pic_expected[] = {0x101d, 0x1005, 0x101e, 0x101f};
    check(pic, sizeof(pic), table, G_N_ELEMENTS(table),
          pic_expected, G_N_ELEMENTS(pic_expected));
    const uint64_t unresolved[] = {0x101d, 0x1005};
    check(pic, sizeof(pic), table, 2, unresolved, G_N_ELEMENTS(unresolved));
    unsigned char wrong_base[sizeof(pic)];
    memcpy(wrong_base, pic, sizeof(pic));
    wrong_base[16]++;
    check(wrong_base, sizeof(wrong_base), table, G_N_ELEMENTS(table),
          unresolved, G_N_ELEMENTS(unresolved));
    int32_t outside_table[] = {-0xfe3, -0xfe2, 1};
    check(pic, sizeof(pic), outside_table, G_N_ELEMENTS(outside_table),
          unresolved, G_N_ELEMENTS(unresolved));
    puts("test-tb-closure: PASS");
    return 0;
}
