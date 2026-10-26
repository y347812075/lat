#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "elf-fixture.h"
#include "module-inspect.h"

#include <elf.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static uint8_t command_codegen[32];

static void write_module(const char *path, const LatAotTbV2 *tbs, size_t count,
                         int identity_change)
{
    unsigned char file[4096] = {0};
    lat_aot_test_build_elf(file);
    Elf64_Ehdr *header = (void *)file;
    Elf64_Shdr original[5];
    memcpy(original, file + header->e_shoff, sizeof(original));
    header->e_shoff = 0x800;
    header->e_shnum = 9;
    header->e_shstrndx = 8;
    Elf64_Shdr *sections = (void *)(file + header->e_shoff);
    memcpy(sections, original, sizeof(original));
    const char names[] = "\0.text.lat.tu\0.rodata.lat.tb\0.rodata.lat.map\0.rodata.lat.guest\0";
    memcpy(file + 0xb00, names, sizeof(names));
    sections[3].sh_name = 1;
    sections[5] = (Elf64_Shdr) {.sh_name = 14, .sh_type = SHT_PROGBITS,
        .sh_offset = 0xc00, .sh_size = count * sizeof(*tbs), .sh_addralign = 8};
    sections[6] = (Elf64_Shdr) {.sh_name = 29, .sh_type = SHT_PROGBITS};
    sections[7] = (Elf64_Shdr) {.sh_name = 45, .sh_type = SHT_PROGBITS};
    sections[8] = (Elf64_Shdr) {.sh_type = SHT_STRTAB, .sh_offset = 0xb00,
        .sh_size = sizeof(names), .sh_addralign = 1};
    memcpy(file + 0xc00, tbs, count * sizeof(*tbs));
    if (identity_change) {
        LatAotNoteV2 *note = (void *)(file + LAT_AOT_TEST_NOTE_OFFSET + 16);
        if (identity_change == 1) note->source_sha256[0] ^= 1;
        else if (identity_change >= 3) {
            memcpy(note->codegen_id, command_codegen, sizeof(command_codegen));
            if (identity_change == 4) note->source_sha256[0] ^= 1;
        } else note->codegen_id[0] ^= 1;
    }
    g_assert_true(g_file_set_contents(path, (void *)file, sizeof(file), NULL));
    g_assert_cmpint(g_chmod(path, 0444), ==, 0);
}

static void write_large_module(const char *path, size_t count)
{
    LatAotTbV2 seed = {.guest_rva = 1, .flags = 3};
    write_module(path, &seed, 1, 0);
    g_assert_cmpint(g_chmod(path, 0600), ==, 0);
    int fd = g_open(path, O_RDWR, 0);
    g_assert_cmpint(fd, >=, 0);
    size_t size = 4096 + count * sizeof(LatAotTbV2);
    g_assert_cmpint(ftruncate(fd, size), ==, 0);
    unsigned char *file = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd, 0);
    g_assert_true(file != MAP_FAILED);
    Elf64_Ehdr *header = (void *)file;
    Elf64_Shdr *sections = (void *)(file + header->e_shoff);
    sections[5].sh_offset = 4096;
    sections[5].sh_size = count * sizeof(LatAotTbV2);
    LatAotTbV2 *tbs = (void *)(file + 4096);
    for (size_t i = 0; i < count; i++) {
        tbs[i] = (LatAotTbV2) {.guest_rva = i + 1, .flags = 3};
    }
    g_assert_cmpint(munmap(file, size), ==, 0);
    close(fd);
    g_assert_cmpint(g_chmod(path, 0444), ==, 0);
}

static bool run_missing(const char *latc, const char *module, const char *input,
                        const char *output);

static void test_large_coverage(const char *directory, const char *latc)
{
    char *old = g_build_filename(directory, "large-old.so", NULL);
    char *next = g_build_filename(directory, "large-next.so", NULL);
    char *input = g_build_filename(directory, "large-input.tbset", NULL);
    size_t count = LAT_AOT_V2_TBSET_RECORD_LIMIT + 1;
    write_large_module(old, count);
    write_large_module(next, count + 1);
    char error[256];
    int result = lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error));
    if (result) g_printerr("large coverage: %s\n", error);
    g_assert_cmpint(result, ==, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, old, error, sizeof(error)), ==, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        next, old, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "missing=1"));

    LatAotModuleInfoV2 info;
    LatTbKeySet exported = {0};
    g_assert_cmpint(lat_aot_v2_module_read_tbset_file(old, &info, &exported,
        error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "export limit"));
    g_assert_null(exported.keys);
    LatTbKey request[] = {{.guest_rva = 1, .flags = 3},
                          {.guest_rva = count, .flags = 3},
                          {.guest_rva = count + 1, .flags = 3}};
    LatTbKeySet keys = {.keys = request, .count = G_N_ELEMENTS(request),
                        .sequence = 17};
    memset(keys.source_sha256, 0x11, 32);
    int fd = g_open(input, O_RDWR | O_CREAT | O_EXCL, 0600);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &keys, error, sizeof(error)), ==, 0);
    close(fd);
    g_assert_cmpint(lat_aot_v2_module_validate_tbset_file(next, input,
        error, sizeof(error)), ==, 0);
    LatTbKeySet missing = {0};
    g_assert_cmpint(lat_aot_v2_module_missing_tbset_file(old, input, &info,
        &missing, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(missing.count, ==, 1);
    g_assert_cmpuint(missing.keys[0].guest_rva, ==, count + 1);
    g_assert_cmpuint(missing.sequence, ==, 17);
    lat_tb_key_set_destroy(&missing);
    g_assert_cmpint(lat_aot_v2_module_validate_tbset_file(old, input,
        error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "covered=2 total=3"));
    if (latc) {
        g_assert_cmpint(g_chmod(old, 0600), ==, 0);
        int module_fd = g_open(old, O_RDWR, 0);
        g_assert_cmpint(module_fd, >=, 0);
        off_t offset = LAT_AOT_TEST_NOTE_OFFSET + 16 +
            G_STRUCT_OFFSET(LatAotNoteV2, codegen_id);
        g_assert_cmpint(pwrite(module_fd, command_codegen,
            sizeof(command_codegen), offset), ==, sizeof(command_codegen));
        g_assert_cmpint(close(module_fd), ==, 0);
        g_assert_cmpint(g_chmod(old, 0444), ==, 0);
        char *output = g_build_filename(directory, "large-delta.tbset", NULL);
        g_assert_true(run_missing(latc, old, input, output));
        g_assert_cmpint(lat_tb_key_set_read_file(output, keys.source_sha256,
            &missing, error, sizeof(error)), ==, 0);
        g_assert_cmpuint(missing.count, ==, 1);
        g_assert_cmpuint(missing.keys[0].guest_rva, ==, count + 1);
        g_assert_cmpuint(missing.keys[0].flags, ==, 3);
        g_assert_cmpuint(missing.sequence, ==, 17);
        lat_tb_key_set_destroy(&missing);
        g_unlink(output);
        g_free(output);
    }
    g_unlink(old);
    g_unlink(next);
    g_unlink(input);
    g_free(old);
    g_free(next);
    g_free(input);
}

static bool run_missing(const char *latc, const char *module, const char *input,
                        const char *output)
{
    gchar *arguments[] = {(char *)latc, "missing-module-tbset",
        (char *)module, (char *)input, "-o", (char *)output, NULL};
    gint status;
    gchar *out = NULL, *err = NULL;
    GError *error = NULL;
    g_assert_true(g_spawn_sync(NULL, arguments, NULL, 0, NULL, NULL,
                               &out, &err, &status, &error));
    g_assert_no_error(error);
    bool success = g_spawn_check_wait_status(status, NULL);
    if (!success) g_assert_nonnull(strstr(err, "latc:"));
    else g_assert_true(g_str_has_prefix(out, "missing_tb_keys="));
    g_free(out);
    g_free(err);
    return success;
}

static void limit_output(gpointer data)
{
    (void)data;
    struct rlimit limit = {.rlim_cur = 64, .rlim_max = 64};
    if (setrlimit(RLIMIT_FSIZE, &limit) || signal(SIGXFSZ, SIG_IGN) == SIG_ERR)
        _exit(99);
}

static void test_missing_command(const char *directory, const char *latc)
{
    char *module = g_build_filename(directory, "cli.so", NULL);
    char *input = g_build_filename(directory, "cli.tbset", NULL);
    char *output = g_build_filename(directory, "delta.tbset", NULL);
    LatAotTbV2 actual[] = {{.guest_rva = 0x100, .flags = 3},
                           {.guest_rva = 0x300, .flags = 3}};
    LatTbKey wanted[] = {{.guest_rva = 0x100, .flags = 3},
                          {.guest_rva = 0x200, .flags = 3},
                          {.guest_rva = 0x300, .flags = 3},
                          {.guest_rva = 0x400, .flags = 3}};
    LatTbKeySet request = {.keys = wanted, .count = G_N_ELEMENTS(wanted),
                           .sequence = 91};
    memset(request.source_sha256, 0x11, 32);
    char error[256] = {0};
    for (unsigned mode = 0; mode < 5; mode++) {
        request.keys = wanted;
        request.count = G_N_ELEMENTS(wanted);
        write_module(module, actual, mode == 1 || mode == 3 ? 2 : 1, 3);
        if (mode == 1) request.count = 1; /* Entire request already covered. */
        if (mode == 2) { /* No requested key covered. */
            request.keys = wanted + 1;
            request.count = 1;
        }
        if (mode == 4) request.count = 0;
        int fd = g_open(input, O_WRONLY | O_CREAT | O_EXCL, 0600);
        g_assert_cmpint(fd, >=, 0);
        g_assert_cmpint(lat_tb_key_set_write_fd(fd, &request,
            error, sizeof(error)), ==, 0);
        g_assert_cmpint(close(fd), ==, 0);
        g_assert_true(run_missing(latc, module, input, output));
        LatTbKeySet delta = {0};
        g_assert_cmpint(lat_tb_key_set_read_file(output, request.source_sha256,
            &delta, error, sizeof(error)), ==, 0);
        g_assert_cmpuint(delta.sequence, ==, 91);
        size_t expected = mode == 0 ? 3 : mode == 1 || mode == 4 ? 0 :
            mode == 2 ? 1 : 2;
        g_assert_cmpuint(delta.count, ==, expected);
        if (delta.count) {
            g_assert_cmpuint(delta.keys[0].guest_rva, ==, 0x200);
            g_assert_cmpuint(delta.keys[0].flags, ==, 3);
        }
        if (mode == 0) {
            g_assert_cmpuint(delta.keys[1].guest_rva, ==, 0x300);
            g_assert_cmpuint(delta.keys[2].guest_rva, ==, 0x400);
        }
        if (mode == 3) g_assert_cmpuint(delta.keys[1].guest_rva, ==, 0x400);
        gchar *raw = NULL;
        gsize raw_size;
        g_assert_true(g_file_get_contents(output, &raw, &raw_size, NULL));
        g_assert_cmpuint(raw_size, ==, sizeof(LatTbKeyFileHeader) +
                        expected * sizeof(LatTbKey));
        LatTbKeyFileHeader header;
        memcpy(&header, raw, sizeof(header));
        g_assert_cmpuint(header.record_count, ==, expected);
        if (expected) {
            g_assert_cmpmem(raw + sizeof(header), expected * sizeof(LatTbKey),
                            delta.keys, expected * sizeof(LatTbKey));
        }
        g_free(raw);
        lat_tb_key_set_destroy(&delta);
        gchar *before = NULL, *after = NULL;
        gsize before_size, after_size;
        g_assert_true(g_file_get_contents(output, &before, &before_size, NULL));
        g_assert_false(run_missing(latc, module, input, output));
        g_assert_true(g_file_get_contents(output, &after, &after_size, NULL));
        g_assert_cmpmem(before, before_size, after, after_size);
        g_free(before);
        g_free(after);
        g_unlink(output);
        g_assert_cmpint(symlink(input, output), ==, 0);
        g_assert_false(run_missing(latc, module, input, output));
        g_assert_true(g_file_test(output, G_FILE_TEST_IS_SYMLINK));
        g_unlink(output);
        g_assert_cmpint(symlink("missing-target", output), ==, 0);
        g_assert_false(run_missing(latc, module, input, output));
        g_assert_true(g_file_test(output, G_FILE_TEST_IS_SYMLINK));
        g_unlink(output);
        if (expected) {
            gchar *arguments[] = {(char *)latc, "missing-module-tbset",
                module, input, "-o", output, NULL};
            gint status;
            gchar *out = NULL, *err = NULL;
            g_assert_true(g_spawn_sync(NULL, arguments, NULL, 0, limit_output,
                NULL, &out, &err, &status, NULL));
            g_assert_false(g_spawn_check_wait_status(status, NULL));
            g_assert_nonnull(strstr(err, "cannot write TB key set"));
            g_assert_false(g_file_test(output, G_FILE_TEST_EXISTS));
            g_free(out);
            g_free(err);
        }
        /* A pre-existing input is never removed or overwritten either. */
        g_assert_false(run_missing(latc, module, input, input));
        for (unsigned broken = 0; broken < 4; broken++) {
            write_module(module, actual, 1,
                         broken == 0 ? 4 : broken == 1 ? 2 : 3);
            if (broken == 2) g_assert_cmpint(g_chmod(module, 0666), ==, 0);
            if (broken == 3) {
                g_assert_true(g_file_set_contents(input, "bad", 3, NULL));
            }
            g_assert_false(run_missing(latc, module, input, output));
            g_assert_false(g_file_test(output, G_FILE_TEST_EXISTS));
        }
        g_unlink(input);
    }
    g_unlink(module);
    g_free(module);
    g_free(input);
    g_free(output);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        gchar *arguments[] = {argv[1], "build-id", NULL};
        gchar *out = NULL;
        gint status;
        g_assert_true(g_spawn_sync(NULL, arguments, NULL, 0, NULL, NULL,
                                   &out, NULL, &status, NULL));
        g_assert_true(g_spawn_check_wait_status(status, NULL));
        g_strchomp(out);
        g_assert_cmpuint(strlen(out), ==, 64);
        GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(checksum, (const guchar *)out, strlen(out));
        gsize size = sizeof(command_codegen);
        g_checksum_get_digest(checksum, command_codegen, &size);
        g_checksum_free(checksum);
        g_free(out);
    }
    char error[256] = {0};
    char *directory = g_dir_make_tmp("latc-coverage-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *old = g_build_filename(directory, "old.so", NULL);
    char *next = g_build_filename(directory, "next.so", NULL);
    LatAotTbV2 tbs[] = {{.guest_rva = 0x100, .flags = 3},
                        {.guest_rva = 0x200, .flags = 3},
                        {.guest_rva = 0x300, .flags = 3}};
    write_module(old, tbs, 2, 0);
    write_module(next, tbs, 3, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error)), ==, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, old, error, sizeof(error)), ==, 0);
    write_module(next, tbs + 1, 2, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "first_missing_rva=0x100"));
    for (int identity = 1; identity <= 2; identity++) {
        write_module(next, tbs, 3, identity);
        g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
            old, next, error, sizeof(error)), ==, -1);
        g_assert_nonnull(strstr(error, "identity mismatch"));
    }
    tbs[0].flags = 1;
    write_module(next, tbs, 3, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error)), ==, -1);
    g_assert_cmpint(error[0], !=, '\0');
    LatTbKeySet keys = {0};
    LatAotModuleInfoV2 info;
    g_assert_cmpint(lat_aot_v2_module_read_tbset_file(
        old, &info, &keys, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(keys.count, ==, 2);
    g_assert_cmpuint(keys.keys[0].guest_rva, ==, 0x100);
    lat_tb_key_set_destroy(&keys);
    g_assert_cmpint(g_chmod(old, 0666), ==, 0);
    g_assert_cmpint(lat_aot_v2_module_inspect_file(old, &info,
        error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "permissions are unsafe"));
    g_assert_cmpint(lat_aot_v2_module_read_tbset_file(old, &info, &keys,
        error, sizeof(error)), ==, -1);
    g_assert_cmpint(g_chmod(old, 0444), ==, 0);
    /* Reject malformed order instead of silently sorting a runtime table. */
    tbs[0] = (LatAotTbV2) {.guest_rva = 0x200, .flags = 3};
    tbs[1] = (LatAotTbV2) {.guest_rva = 0x100, .flags = 3};
    write_module(next, tbs, 2, 0);
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "unordered"));
    tbs[1] = tbs[0];
    write_module(next, tbs, 2, 0);
    g_assert_cmpint(lat_aot_v2_module_read_tbset_file(next, &info, &keys,
        error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "unordered"));
    g_assert_null(keys.keys);
    g_unlink(next);
    g_assert_true(g_file_set_contents(next, "bad", 3, NULL));
    g_assert_cmpint(lat_aot_v2_module_validate_replacement_file(
        old, next, error, sizeof(error)), ==, -1);
    test_large_coverage(directory, argc == 2 ? argv[1] : NULL);
    if (argc == 2) test_missing_command(directory, argv[1]);
    g_unlink(old);
    g_unlink(next);
    g_rmdir(directory);
    g_free(old);
    g_free(next);
    g_free(directory);
    puts("test-module-coverage: PASS");
    return 0;
}
