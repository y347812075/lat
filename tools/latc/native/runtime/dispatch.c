#include "dispatch.h"

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
