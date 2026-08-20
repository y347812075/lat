#include "dispatch.h"

#include <stdlib.h>

static const LatNativeImageHeaderV1 *dispatch_header;
static const unsigned char *dispatch_image;
static size_t dispatch_image_size;
static const unsigned char *dispatch_code;

const LatNativeTbV1 *lat_native_tb_find(const LatNativeImageHeaderV1 *header,
                                        const unsigned char *image,
                                        size_t image_size,
                                        uint64_t guest_pc, uint32_t flags)
{
    if (!header || !image || header->tb_table_offset > image_size ||
        header->tb_count > (image_size - header->tb_table_offset) /
            sizeof(LatNativeTbV1)) {
        return NULL;
    }
    const LatNativeTbV1 *tbs =
        (const void *)(image + header->tb_table_offset);
    uint64_t left = 0;
    uint64_t right = header->tb_count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        const LatNativeTbV1 *tb = &tbs[middle];
        if (tb->guest_pc < guest_pc ||
            (tb->guest_pc == guest_pc && tb->flags < flags)) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < header->tb_count && tbs[left].guest_pc == guest_pc &&
        tbs[left].flags == flags) {
        return &tbs[left];
    }
    return NULL;
}

const LatNativeTbV1 *lat_native_tb_find_unique_pc(
    const LatNativeImageHeaderV1 *header, const unsigned char *image,
    size_t image_size, uint64_t guest_pc)
{
    if (!header || !image || header->tb_table_offset > image_size ||
        header->tb_count > (image_size - header->tb_table_offset) /
            sizeof(LatNativeTbV1)) {
        return NULL;
    }
    const LatNativeTbV1 *tbs =
        (const void *)(image + header->tb_table_offset);
    uint64_t left = 0;
    uint64_t right = header->tb_count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        if (tbs[middle].guest_pc < guest_pc) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left >= header->tb_count || tbs[left].guest_pc != guest_pc) {
        return NULL;
    }
    if (left + 1 < header->tb_count && tbs[left + 1].guest_pc == guest_pc) {
        return NULL;
    }
    return &tbs[left];
}

void lat_native_x86_dispatch_configure(const LatNativeImageHeaderV1 *header,
                                       const unsigned char *image,
                                       size_t image_size,
                                       const void *code_address)
{
    dispatch_header = header;
    dispatch_image = image;
    dispatch_image_size = image_size;
    dispatch_code = code_address;
}

void *lat_native_x86_dispatch_lookup(uint64_t guest_pc)
{
    const LatNativeTbV1 *tb = lat_native_tb_find(
        dispatch_header, dispatch_image, dispatch_image_size, guest_pc, 0);
    if (!tb || !dispatch_code) abort();
    return (void *)(dispatch_code + tb->code_offset);
}
