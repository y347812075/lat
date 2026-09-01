#define _GNU_SOURCE

#include "module-inspect.h"

#include "elf-validate.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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

int lat_aot_v2_module_inspect_file(const char *path,
                                   LatAotModuleInfoV2 *info,
                                   char *error, size_t error_size)
{
    if (!path || !info) {
        return fail(error, error_size, "invalid module inspection arguments");
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return fail(error, error_size, "cannot open AOT module: %s",
                    strerror(errno));
    }
    memset(info, 0, sizeof(*info));
    if (lat_aot_v2_elf_validate_fd(fd, NULL, &info->note,
                                   error, error_size)) {
        close(fd);
        return -1;
    }
    close(fd);

    gchar *contents = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &contents, &size, NULL) ||
        size < sizeof(Elf64_Ehdr)) {
        g_free(contents);
        return fail(error, error_size, "cannot read AOT module");
    }
    const unsigned char *file = (const void *)contents;
    const Elf64_Ehdr *header = (const void *)file;
    if (header->e_shentsize != sizeof(Elf64_Shdr) || !header->e_shnum ||
        header->e_shstrndx >= header->e_shnum ||
        header->e_shoff > size ||
        header->e_shnum > (size - header->e_shoff) / sizeof(Elf64_Shdr)) {
        g_free(contents);
        return fail(error, error_size, "AOT section table is invalid");
    }
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    const Elf64_Shdr *names_section = &sections[header->e_shstrndx];
    if (names_section->sh_offset > size ||
        names_section->sh_size > size - names_section->sh_offset) {
        g_free(contents);
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
        g_free(contents);
        return fail(error, error_size, "AOT module sections are incomplete");
    }
    info->text_size = text->sh_size;
    info->tb_count = tbs->sh_size / sizeof(LatAotTbV2);
    info->pc_map_count = maps->sh_size / sizeof(LatAotPcMapV2);
    info->guest_slot_records = slots->sh_size / sizeof(LatAotGuestSlotV2);
    g_free(contents);
    return 0;
}

int lat_aot_v2_module_validate_tbset_file(const char *path,
                                          const char *tbset_path,
                                          char *error,
                                          size_t error_size)
{
    LatAotModuleInfoV2 info;
    if (lat_aot_v2_module_inspect_file(path, &info, error, error_size)) {
        return -1;
    }
    gchar *contents = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &contents, &size, NULL)) {
        return fail(error, error_size, "cannot read AOT module");
    }
    const unsigned char *file = (const void *)contents;
    const Elf64_Ehdr *header = (const void *)file;
    const Elf64_Shdr *sections = (const void *)(file + header->e_shoff);
    const Elf64_Shdr *names_section = &sections[header->e_shstrndx];
    const char *names = (const void *)(file + names_section->sh_offset);
    const Elf64_Shdr *section = find_section(file, header, names,
        names_section->sh_size, ".rodata.lat.tb");
    if (!section || section->sh_offset > size ||
        section->sh_size > size - section->sh_offset ||
        section->sh_size % sizeof(LatAotTbV2)) {
        g_free(contents);
        return fail(error, error_size, "AOT TB section is invalid");
    }
    const LatAotTbV2 *tbs = (const void *)(file + section->sh_offset);
    size_t tb_count = section->sh_size / sizeof(*tbs);
    GHashTable *keys = g_hash_table_new_full(g_str_hash, g_str_equal,
                                              g_free, NULL);
    for (size_t i = 0; i < tb_count; i++) {
        char *key = g_strdup_printf("%016" PRIx64 ":%08x",
                                    tbs[i].guest_rva, tbs[i].flags);
        g_hash_table_add(keys, key);
    }
    FILE *tbset = fopen(tbset_path, "r");
    if (!tbset) {
        g_hash_table_destroy(keys);
        g_free(contents);
        return fail(error, error_size, "cannot read compiled TB set: %s",
                    strerror(errno));
    }
    char *line = NULL;
    size_t capacity = 0;
    int result = 0;
    if (getline(&line, &capacity, tbset) < 0) {
        result = fail(error, error_size, "compiled TB set is empty");
    }
    size_t record = 0;
    size_t missing = 0;
    uint64_t first_missing_rva = 0;
    uint64_t first_missing_flags = 0;
    while (!result && getline(&line, &capacity, tbset) >= 0) {
        uint64_t rva, flags;
        char extra;
        record++;
        if (sscanf(line, "%" SCNx64 " %" SCNx64 " %c",
                   &rva, &flags, &extra) != 2) {
            result = fail(error, error_size,
                          "compiled TB set record %zu is invalid", record);
            break;
        }
        char key[48];
        snprintf(key, sizeof(key), "%016" PRIx64 ":%08" PRIx64,
                 rva, flags);
        if (!g_hash_table_contains(keys, key)) {
            if (!missing) {
                first_missing_rva = rva;
                first_missing_flags = flags;
            }
            missing++;
        }
    }
    if (!result && ferror(tbset)) {
        result = fail(error, error_size, "cannot read compiled TB set");
    }
    size_t covered = record - missing;
    if (!result && record && !covered) {
        result = fail(error, error_size,
                      "TB set has no TB in module: covered=%zu total=%zu "
                      "first_missing_rva=0x%" PRIx64 " flags=0x%" PRIx64,
                      covered, record, first_missing_rva,
                      first_missing_flags);
    }
    free(line);
    fclose(tbset);
    g_hash_table_destroy(keys);
    g_free(contents);
    return result;
}
