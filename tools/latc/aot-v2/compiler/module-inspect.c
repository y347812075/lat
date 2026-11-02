#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "module-inspect.h"

#include "elf-validate.h"
#include "lat-tb-key-set.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

static const Elf64_Shdr *find_section(const unsigned char *file,
                                      const Elf64_Ehdr *header,
                                      const char *names, size_t names_size,
                                      const char *wanted)
{
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    for (uint16_t i = 0; i < header->e_shnum; i++) {
        if (sections[i].sh_name >= names_size) {
            return NULL;
        }
        const char *name = names + sections[i].sh_name;
        if (!memchr(name, '\0', names_size - sections[i].sh_name)) {
            return NULL;
        }
        if (!strcmp(name, wanted)) {
            return &sections[i];
        }
    }
    return NULL;
}

static int module_inspect_memory(const unsigned char *file, size_t size,
                                 LatAotModuleInfoV2 *info,
                                 const LatAotExpectedV2 *expected,
                                 const LatAotConfigIdentityV2 *config,
                                 char *error, size_t error_size)
{
    memset(info, 0, sizeof(*info));
    if (config) {
        LatAotConfigNoteV2 note;
        if (lat_aot_v2_elf_validate_config_memory(file, size, expected, config,
                                                  &note, error, error_size)) return -1;
        info->note = note.base;
    } else if (lat_aot_v2_elf_validate_memory(file, size, NULL, &info->note,
                                               error, error_size)) {
        return -1;
    }
    const Elf64_Ehdr *header = (const void *)file;
    if (header->e_shentsize != sizeof(Elf64_Shdr) || !header->e_shnum ||
        header->e_shstrndx >= header->e_shnum ||
        header->e_shoff > size ||
        header->e_shnum > (size - header->e_shoff) / sizeof(Elf64_Shdr)) {
        return fail(error, error_size, "AOT section table is invalid");
    }
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    const Elf64_Shdr *names_section = &sections[header->e_shstrndx];
    if (names_section->sh_offset > size ||
        names_section->sh_size > size - names_section->sh_offset) {
        return fail(error, error_size, "AOT section names are invalid");
    }
    const char *names = (const void *)(file + names_section->sh_offset);
    const Elf64_Shdr *text = find_section(file, header, names,
        names_section->sh_size, ".text.lat.tu");
    const Elf64_Shdr *tbs = find_section(file, header, names,
        names_section->sh_size, ".rodata.lat.tb");
    const Elf64_Shdr *maps = find_section(file, header, names,
        names_section->sh_size, ".rodata.lat.map");
    const Elf64_Shdr *slots = find_section(file, header, names,
        names_section->sh_size, ".rodata.lat.guest");
    if (!text || !text->sh_size || !tbs || !tbs->sh_size ||
        tbs->sh_size % sizeof(LatAotTbV2) || !maps ||
        maps->sh_size % sizeof(LatAotPcMapV2) || !slots ||
        slots->sh_size % sizeof(LatAotGuestSlotV2) ||
        text->sh_offset > size || text->sh_size > size - text->sh_offset ||
        tbs->sh_offset > size || tbs->sh_size > size - tbs->sh_offset ||
        maps->sh_offset > size || maps->sh_size > size - maps->sh_offset ||
        slots->sh_offset > size || slots->sh_size > size - slots->sh_offset ||
        ((info->note.module_flags & LAT_AOT_MODULE_PRECISE_PC_MAP) &&
         !maps->sh_size)) {
        return fail(error, error_size, "AOT module sections are incomplete");
    }
    info->text_size = text->sh_size;
    info->tb_count = tbs->sh_size / sizeof(LatAotTbV2);
    info->pc_map_count = maps->sh_size / sizeof(LatAotPcMapV2);
    info->guest_slot_records = slots->sh_size / sizeof(LatAotGuestSlotV2);
    return 0;
}

static GMappedFile *module_map_fd(int fd, char *error, size_t error_size)
{
    struct stat status;
    if (fstat(fd, &status) || status.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        fail(error, error_size, "cannot stat AOT ELF");
        return NULL;
    }
    if (!S_ISREG(status.st_mode) || (status.st_mode & (S_IWGRP | S_IWOTH))) {
        fail(error, error_size, "AOT ELF permissions are unsafe");
        return NULL;
    }
    GError *mapping_error = NULL;
    GMappedFile *mapping = g_mapped_file_new_from_fd(fd, FALSE, &mapping_error);
    if (!mapping) {
        fail(error, error_size, "cannot map AOT module: %s",
             mapping_error ? mapping_error->message : "unknown error");
        g_clear_error(&mapping_error);
    }
    return mapping;
}

static GMappedFile *module_map(const char *path, char *error, size_t error_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fail(error, error_size, "cannot open AOT module: %s", strerror(errno));
        return NULL;
    }
    GMappedFile *mapping = module_map_fd(fd, error, error_size);
    close(fd);
    return mapping;
}

int lat_aot_v2_module_inspect_fd(int fd, size_t max_size, LatAotModuleInfoV2 *info,
                                 char *error, size_t error_size)
{
    struct stat before, after;
    int flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
    if (!info || flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        (before.st_mode & (S_IWGRP | S_IWOTH)) ||
        before.st_size < (off_t)sizeof(Elf64_Ehdr) ||
        (uintmax_t)before.st_size > max_size) {
        return fail(error, error_size, "invalid or unsafe module descriptor");
    }
    size_t size = (size_t)before.st_size;
    unsigned char *data = g_try_malloc(size);
    if (!data) return fail(error, error_size, "cannot allocate module snapshot");
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = pread(fd, data + offset, size - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            g_free(data);
            return fail(error, error_size, "cannot read module snapshot");
        }
        offset += count;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_nlink != after.st_nlink ||
        before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        g_free(data);
        errno = ESTALE;
        return fail(error, error_size, "module changed while reading");
    }
    int result = module_inspect_memory(data, size, info, NULL, NULL, error, error_size);
    g_free(data);
    return result;
}

int lat_aot_v2_module_inspect_file(const char *path,
                                   LatAotModuleInfoV2 *info,
                                   char *error, size_t error_size)
{
    if (!path || !info) {
        return fail(error, error_size, "invalid module inspection arguments");
    }
    GMappedFile *mapping = module_map(path, error, error_size);
    if (!mapping) {
        return -1;
    }
    int result = module_inspect_memory(
        (const void *)g_mapped_file_get_contents(mapping),
        g_mapped_file_get_length(mapping), info, NULL, NULL, error, error_size);
    g_mapped_file_unref(mapping);
    return result;
}

int lat_aot_v2_module_validate_tbset_file(const char *path,
                                          const char *tbset_path,
                                          char *error,
                                          size_t error_size)
{
    LatAotModuleInfoV2 info;
    return lat_aot_v2_module_inspect_and_validate_tbset_file(
        path, tbset_path, &info, error, error_size);
}

typedef struct ModuleTbView {
    GMappedFile *mapping;
    const unsigned char *records;
    size_t count;
} ModuleTbView;

static void module_tb_at(const ModuleTbView *view, size_t index,
                          LatAotTbV2 *tb)
{
    memcpy(tb, view->records + index * sizeof(*tb), sizeof(*tb));
}

static int module_tb_key_compare(const LatAotTbV2 *a, const LatAotTbV2 *b)
{
    if (a->guest_rva != b->guest_rva) {
        return a->guest_rva < b->guest_rva ? -1 : 1;
    }
    return a->flags < b->flags ? -1 : a->flags > b->flags;
}

/* Aggregate module coverage is not a bounded compiler request. Keep the
 * validated sorted table mapped instead of exporting every key to a TB set. */
static int module_tb_view_open(const char *path, LatAotModuleInfoV2 *info,
                               ModuleTbView *view,
                               const LatAotExpectedV2 *expected,
                               const LatAotConfigIdentityV2 *config,
                               char *error, size_t error_size)
{
    memset(view, 0, sizeof(*view));
    GMappedFile *mapping = module_map(path, error, error_size);
    if (!mapping) {
        return -1;
    }
    const unsigned char *file =
        (const void *)g_mapped_file_get_contents(mapping);
    size_t size = g_mapped_file_get_length(mapping);
    if (module_inspect_memory(file, size, info, expected, config, error, error_size)) {
        goto failed;
    }
    const Elf64_Ehdr *header = (const void *)file;
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    const Elf64_Shdr *names_section = &sections[header->e_shstrndx];
    const char *names = (const void *)(file + names_section->sh_offset);
    const Elf64_Shdr *section = find_section(file, header, names,
        names_section->sh_size, ".rodata.lat.tb");
    *view = (ModuleTbView) {
        .mapping = mapping,
        .records = file + section->sh_offset,
        .count = section->sh_size / sizeof(LatAotTbV2),
    };
    LatAotTbV2 previous = {0};
    for (size_t i = 0; i < view->count; i++) {
        LatAotTbV2 tb;
        module_tb_at(view, i, &tb);
        if (tb.flags != (LAT_AOT_TB_CODE64 | LAT_AOT_TB_PARALLEL) ||
            (i && module_tb_key_compare(&previous, &tb) >= 0)) {
            fail(error, error_size, "AOT TB key %zu is invalid or unordered", i);
            goto failed;
        }
        previous = tb;
    }
    return 0;
failed:
    g_mapped_file_unref(mapping);
    memset(view, 0, sizeof(*view));
    return -1;
}

int lat_aot_v2_module_read_tbset_file(
    const char *path, LatAotModuleInfoV2 *info, LatTbKeySet *keys,
    char *error, size_t error_size)
{
    if (!path || !info || !keys) {
        return fail(error, error_size, "invalid module key export arguments");
    }
    memset(keys, 0, sizeof(*keys));
    ModuleTbView view;
    if (module_tb_view_open(path, info, &view, NULL, NULL, error, error_size)) {
        return -1;
    }
    if (view.count > LAT_AOT_V2_TBSET_RECORD_LIMIT) {
        g_mapped_file_unref(view.mapping);
        return fail(error, error_size, "module exceeds TB key-set export limit");
    }
    size_t count = view.count;
    keys->keys = g_try_new(LatTbKey, count);
    if (count && !keys->keys) {
        g_mapped_file_unref(view.mapping);
        return fail(error, error_size, "cannot allocate module TB keys");
    }
    memcpy(keys->source_sha256, info->note.source_sha256, 32);
    for (size_t i = 0; i < count; i++) {
        LatAotTbV2 tb;
        module_tb_at(&view, i, &tb);
        keys->keys[i] = (LatTbKey) {
            .guest_rva = tb.guest_rva, .flags = tb.flags,
        };
    }
    keys->count = count;
    g_mapped_file_unref(view.mapping);
    return 0;
}

static int module_validate_replacement_file(
    const char *previous, const char *replacement,
    const LatAotExpectedV2 *expected,
    const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size)
{
    LatAotModuleInfoV2 old_info, new_info;
    ModuleTbView old = {0}, next = {0};
    int result = -1;
    if (module_tb_view_open(previous, &old_info, &old, expected, config, error, error_size) ||
        module_tb_view_open(replacement, &new_info, &next, expected, config, error, error_size)) {
        goto out;
    }
    if (memcmp(old_info.note.source_sha256, new_info.note.source_sha256, 32) ||
        memcmp(old_info.note.codegen_id, new_info.note.codegen_id, 32)) {
        fail(error, error_size,
             "replacement source or codegen identity mismatch");
        goto out;
    }
    size_t missing = 0, j = 0;
    LatAotTbV2 first = {0};
    for (size_t i = 0; i < old.count; i++) {
        LatAotTbV2 wanted, candidate;
        module_tb_at(&old, i, &wanted);
        while (j < next.count) {
            module_tb_at(&next, j, &candidate);
            if (module_tb_key_compare(&candidate, &wanted) >= 0) break;
            j++;
        }
        if (j == next.count || module_tb_key_compare(&candidate, &wanted)) {
            if (!missing++) first = wanted;
        }
    }
    if (missing) {
        fail(error, error_size,
             "replacement loses module coverage: missing=%zu "
             "first_missing_rva=0x%" PRIx64 " flags=0x%x",
             missing, first.guest_rva, first.flags);
        goto out;
    }
    result = 0;
out:
    if (old.mapping) g_mapped_file_unref(old.mapping);
    if (next.mapping) g_mapped_file_unref(next.mapping);
    return result;
}

int lat_aot_v2_module_validate_replacement_file(
    const char *previous, const char *replacement,
    char *error, size_t error_size)
{
    return module_validate_replacement_file(previous, replacement, NULL, NULL,
                                            error, error_size);
}

int lat_aot_v2_module_validate_config_replacement_file(
    const char *previous, const char *replacement,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size)
{
    if (!previous || !replacement || !expected || !config)
        return fail(error, error_size, "missing configuration replacement identity");
    return module_validate_replacement_file(previous, replacement, expected, config,
                                            error, error_size);
}

static int module_missing_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    LatTbKeySet *missing, size_t *requested_count,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size)
{
    memset(missing, 0, sizeof(*missing));
    LatTbKeySet tbset = {0};
    ModuleTbView actual;
    if (module_tb_view_open(path, info, &actual, expected, config, error, error_size)) {
        return -1;
    }
    if (lat_tb_key_set_read_file(tbset_path, info->note.source_sha256,
                                 &tbset, error, error_size)) {
        g_mapped_file_unref(actual.mapping);
        return -1;
    }
    if (requested_count) *requested_count = tbset.count;
    memcpy(missing->source_sha256, tbset.source_sha256, 32);
    missing->sequence = tbset.sequence;
    missing->keys = g_try_new(LatTbKey, tbset.count);
    if (tbset.count && !missing->keys) {
        lat_tb_key_set_destroy(&tbset);
        g_mapped_file_unref(actual.mapping);
        return fail(error, error_size, "cannot allocate missing module TB keys");
    }
    size_t j = 0;
    for (size_t i = 0; i < tbset.count; i++) {
        LatAotTbV2 wanted = {.guest_rva = tbset.keys[i].guest_rva,
                             .flags = tbset.keys[i].flags};
        LatAotTbV2 candidate;
        while (j < actual.count) {
            module_tb_at(&actual, j, &candidate);
            if (module_tb_key_compare(&candidate, &wanted) >= 0) break;
            j++;
        }
        if (j == actual.count || module_tb_key_compare(&candidate, &wanted)) {
            missing->keys[missing->count++] = tbset.keys[i];
        }
    }
    lat_tb_key_set_destroy(&tbset);
    g_mapped_file_unref(actual.mapping);
    return 0;
}

int lat_aot_v2_module_missing_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    LatTbKeySet *missing, char *error, size_t error_size)
{
    if (!path || !tbset_path || !info || !missing) {
        return fail(error, error_size,
                    "invalid missing module TB set arguments");
    }
    return module_missing_tbset_file(path, tbset_path, info, missing, NULL, NULL, NULL,
                                     error, error_size);
}

static int module_validate_tbset(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size)
{
    LatTbKeySet missing = {0};
    size_t requested = 0;
    if (module_missing_tbset_file(path, tbset_path, info, &missing,
                                  &requested, expected, config, error, error_size)) {
        return -1;
    }
    int result = 0;
    if (missing.count) {
        result = fail(error, error_size,
                      "TB set is not fully covered: covered=%zu total=%zu "
                      "first_missing_rva=0x%" PRIx64 " flags=0x%x",
                      requested - missing.count, requested,
                      missing.keys[0].guest_rva, missing.keys[0].flags);
    }
    lat_tb_key_set_destroy(&missing);
    return result;
}

int lat_aot_v2_module_inspect_and_validate_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    char *error, size_t error_size)
{
    return module_validate_tbset(path, tbset_path, info, NULL, NULL, error, error_size);
}

int lat_aot_v2_module_validate_config_tbset_file(
    const char *path, const char *tbset_path, LatAotModuleInfoV2 *info,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    char *error, size_t error_size)
{
    if (!path || !tbset_path || !info || !expected || !config)
        return fail(error, error_size, "missing configuration coverage identity");
    return module_validate_tbset(path, tbset_path, info, expected, config, error, error_size);
}
