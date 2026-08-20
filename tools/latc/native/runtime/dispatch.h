#ifndef LATC_NATIVE_DISPATCH_H
#define LATC_NATIVE_DISPATCH_H

#include "lat-native-image.h"

#include <stddef.h>
#include <stdint.h>

const LatNativeTbV1 *lat_native_tb_find(const LatNativeImageHeaderV1 *header,
                                        const unsigned char *image,
                                        size_t image_size,
                                        uint64_t guest_pc, uint32_t flags);
const LatNativeTbV1 *lat_native_tb_find_unique_pc(
    const LatNativeImageHeaderV1 *header, const unsigned char *image,
    size_t image_size, uint64_t guest_pc);

void lat_native_x86_dispatch_configure(const LatNativeImageHeaderV1 *header,
                                       const unsigned char *image,
                                       size_t image_size,
                                       const void *code_address);
void *lat_native_x86_dispatch_lookup(uint64_t guest_pc);

#endif
