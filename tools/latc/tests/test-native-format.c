#include "lat-fallback.h"
#include "lat-native-image.h"
#include "native-image.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(LatX86StateV1) == 560,
               "LatX86StateV1 ABI size changed");
_Static_assert(offsetof(LatX86StateV1, xmm) == 300,
               "LatX86StateV1 XMM offset changed");
_Static_assert(sizeof(LatNativeImageHeaderV1) == 208,
               "native image header size changed");
_Static_assert(sizeof(LatNativeTbV1) == 24,
               "native TB record size changed");
_Static_assert(sizeof(LatNativeRelocationV1) == 24,
               "native relocation record size changed");

int main(void)
{
    unsigned char image[512] = {0};
    LatNativeImageHeaderV1 *header = (void *)image;
    LatNativeTbV1 *tb;
    LatNativeRelocationV1 *relocation;
    char error[128] = {0};

    memcpy(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->header_size = sizeof(*header);
    header->guest_image_offset = sizeof(*header);
    header->guest_image_size = 16;
    header->code_offset = header->guest_image_offset + header->guest_image_size;
    header->code_size = 32;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 1;
    header->relocation_offset = header->tb_table_offset + sizeof(*tb);
    header->relocation_count = 1;
    strcpy(header->lat_build_id, "test-build");
    tb = (void *)(image + header->tb_table_offset);
    tb->guest_pc = 0x401000;
    tb->code_offset = 0;
    tb->code_size = 16;
    relocation = (void *)(image + header->relocation_offset);
    relocation->code_offset = 8;
    relocation->kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;

    if (lat_native_image_validate(image, sizeof(image), error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "valid image rejected: %s\n", error);
        return 1;
    }
    tb->code_size = 33;
    if (lat_native_image_validate(image, sizeof(image), error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "code range")) {
        fprintf(stderr, "bad TB range accepted: %s\n", error);
        return 1;
    }
    puts("test-native-format: PASS");
    return 0;
}
