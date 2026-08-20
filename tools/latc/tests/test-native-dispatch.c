#include "dispatch.h"

#include <stdio.h>

int main(void)
{
    unsigned char image[320] = {0};
    LatNativeImageHeaderV1 *header = (void *)image;
    header->tb_table_offset = sizeof(*header);
    header->tb_count = 3;
    LatNativeTbV1 *tbs = (void *)(image + header->tb_table_offset);
    tbs[0] = (LatNativeTbV1){ .guest_pc = 0x1000, .flags = 0 };
    tbs[1] = (LatNativeTbV1){ .guest_pc = 0x1000, .flags = 4 };
    tbs[2] = (LatNativeTbV1){ .guest_pc = 0x2000, .flags = 0 };
    if (lat_native_tb_find(header, image, sizeof(image), 0x1000, 4) !=
            &tbs[1] ||
        lat_native_tb_find(header, image, sizeof(image), 0x1000, 2) ||
        lat_native_tb_find(header, image, sizeof(image), 0x3000, 0) ||
        lat_native_tb_find_unique_pc(header, image, sizeof(image), 0x1000) ||
        lat_native_tb_find_unique_pc(header, image, sizeof(image), 0x2000) !=
            &tbs[2]) {
        fprintf(stderr, "native TB lookup failed\n");
        return 1;
    }
    puts("test-native-dispatch: PASS");
    return 0;
}
