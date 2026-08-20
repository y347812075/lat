#include "native-image.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int invalid(char *error, size_t error_size, const char *format, ...)
{
    va_list args;

    if (error && error_size) {
        va_start(args, format);
        vsnprintf(error, error_size, format, args);
        va_end(args);
    }
    return -1;
}

static int range_valid(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

int lat_native_image_validate(const void *data, size_t size,
                              char *error, size_t error_size)
{
    const LatNativeImageHeaderV1 *header = data;
    const LatNativeTbV1 *tbs;
    const LatNativeRelocationV1 *relocations;
    uint64_t table_size;

    if (!data || size < sizeof(*header)) {
        return invalid(error, error_size, "native image is truncated");
    }
    if (memcmp(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8) != 0 ||
        header->version != LAT_NATIVE_IMAGE_VERSION ||
        header->header_size != sizeof(*header)) {
        return invalid(error, error_size, "invalid native image header");
    }
    if (!header->lat_build_id[0] ||
        header->lat_build_id[LAT_NATIVE_BUILD_ID_SIZE - 1] != '\0') {
        return invalid(error, error_size, "invalid LAT build ID");
    }
    if (!header->guest_image_size || !header->code_size || !header->tb_count ||
        header->guest_image_offset < sizeof(*header)) {
        return invalid(error, error_size, "native image has an empty section");
    }
    if (!range_valid(header->guest_image_offset, header->guest_image_size,
                     size) ||
        !range_valid(header->code_offset, header->code_size, size)) {
        return invalid(error, error_size, "native image payload is truncated");
    }
    if (header->code_offset <
        header->guest_image_offset + header->guest_image_size) {
        return invalid(error, error_size, "native image sections overlap");
    }
    if (header->tb_count > UINT64_MAX / sizeof(*tbs)) {
        return invalid(error, error_size, "native TB table is too large");
    }
    table_size = header->tb_count * sizeof(*tbs);
    if (!range_valid(header->tb_table_offset, table_size, size)) {
        return invalid(error, error_size, "native TB table is truncated");
    }
    if (header->tb_table_offset < header->code_offset + header->code_size) {
        return invalid(error, error_size, "native image sections overlap");
    }
    if (header->relocation_count > UINT64_MAX / sizeof(*relocations)) {
        return invalid(error, error_size,
                       "native relocation table is too large");
    }
    table_size = header->relocation_count * sizeof(*relocations);
    if (!range_valid(header->relocation_offset, table_size, size)) {
        return invalid(error, error_size,
                       "native relocation table is truncated");
    }
    if (header->relocation_offset <
            header->tb_table_offset +
            header->tb_count * sizeof(*tbs) ||
        header->relocation_offset + table_size != size) {
        return invalid(error, error_size,
                       "native image has invalid section boundaries");
    }

    tbs = (const void *)((const unsigned char *)data +
                         header->tb_table_offset);
    for (uint64_t i = 0; i < header->tb_count; i++) {
        if (tbs[i].code_offset >= header->code_size ||
            tbs[i].code_size > header->code_size - tbs[i].code_offset) {
            return invalid(error, error_size,
                           "native TB %llu has an invalid code range",
                           (unsigned long long)i);
        }
        if (i && (tbs[i - 1].guest_pc > tbs[i].guest_pc ||
                  (tbs[i - 1].guest_pc == tbs[i].guest_pc &&
                   tbs[i - 1].flags >= tbs[i].flags))) {
            return invalid(error, error_size,
                           "native TB table is not sorted by guest PC and flags");
        }
    }

    relocations = (const void *)((const unsigned char *)data +
                                 header->relocation_offset);
    for (uint64_t i = 0; i < header->relocation_count; i++) {
        if (relocations[i].code_offset >= header->code_size ||
            !relocations[i].slots || relocations[i].slots > 3 ||
            relocations[i].slots * 4 >
                header->code_size - relocations[i].code_offset ||
            relocations[i].kind < LAT_NATIVE_RELOC_RUNTIME_SYMBOL ||
            relocations[i].kind > LAT_NATIVE_RELOC_GUEST_ADDRESS) {
            return invalid(error, error_size,
                           "native relocation %llu is invalid",
                           (unsigned long long)i);
        }
        if (relocations[i].kind == LAT_NATIVE_RELOC_RUNTIME_SYMBOL &&
            (relocations[i].target <= LAT_NATIVE_SYMBOL_INVALID ||
             relocations[i].target >= LAT_NATIVE_SYMBOL_COUNT)) {
            return invalid(error, error_size,
                           "native relocation %llu has an invalid runtime symbol",
                           (unsigned long long)i);
        }
        if (relocations[i].kind == LAT_NATIVE_RELOC_GUEST_ADDRESS &&
            relocations[i].target != 0) {
            return invalid(error, error_size,
                           "native relocation %llu has an invalid guest target",
                           (unsigned long long)i);
        }
    }
    return 0;
}

int lat_native_image_inspect_file(const char *path,
                                  LatNativeImageHeaderV1 *header,
                                  char *error, size_t error_size)
{
    FILE *input = fopen(path, "rb");
    void *data = NULL;
    int result = -1;

    if (!input) {
        return invalid(error, error_size, "cannot open native image");
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        goto out;
    }
    long end = ftell(input);
    if (end < 0 || fseek(input, 0, SEEK_SET) != 0) {
        goto out;
    }
    size_t size = (size_t)end;
    if ((long)size != end || !(data = malloc(size ? size : 1)) ||
        (size && fread(data, size, 1, input) != 1)) {
        goto out;
    }
    if (lat_native_image_validate(data, size, error, error_size) != 0) {
        goto out;
    }
    if (header) {
        memcpy(header, data, sizeof(*header));
    }
    result = 0;
out:
    if (result && error && error_size && !error[0]) {
        snprintf(error, error_size, "cannot read native image");
    }
    free(data);
    fclose(input);
    return result;
}
