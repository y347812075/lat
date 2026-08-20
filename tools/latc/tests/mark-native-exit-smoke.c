#include "lat-native-image.h"

#include <stdio.h>
#include <string.h>

static const unsigned char expected_guest_sha256[][32] = {
    {
        0x0b, 0xd9, 0x23, 0xe5, 0xea, 0x65, 0xb3, 0x2a,
        0xb8, 0x92, 0x3e, 0xc5, 0x6b, 0x74, 0x79, 0xbd,
        0x53, 0x5a, 0xe8, 0xba, 0xf3, 0xde, 0x0e, 0xa5,
        0x63, 0x67, 0x90, 0x30, 0xc6, 0x88, 0x91, 0xbd,
    },
    {
        0xb1, 0x00, 0x8e, 0xe8, 0x00, 0xbb, 0x0e, 0x09,
        0xf2, 0x8e, 0x10, 0xb0, 0x3d, 0x32, 0xac, 0xe8,
        0xd1, 0x60, 0xc1, 0x4e, 0xa9, 0xba, 0x37, 0x51,
        0xef, 0x7a, 0x83, 0xdf, 0x40, 0x94, 0x52, 0x80,
    },
};

static int guest_is_allowed(const unsigned char digest[32])
{
    for (size_t i = 0; i < sizeof(expected_guest_sha256) /
                            sizeof(expected_guest_sha256[0]); i++) {
        if (!memcmp(digest, expected_guest_sha256[i], 32)) return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s IMAGE\n", argv[0]);
        return 2;
    }
    FILE *image = fopen(argv[1], "r+b");
    LatNativeImageHeaderV1 header;
    if (!image || fread(&header, sizeof(header), 1, image) != 1 ||
        memcmp(header.magic, LAT_NATIVE_IMAGE_MAGIC, 8) ||
        header.version != LAT_NATIVE_IMAGE_VERSION ||
        strcmp(header.lat_build_id,
               "lat-42c042301e107b34063773e118c825dd644d476c-x64-v1") ||
        !guest_is_allowed(header.guest_sha256)) {
        fprintf(stderr, "cannot mark incompatible native image\n");
        if (image) fclose(image);
        return 1;
    }
    header.flags |= LAT_NATIVE_IMAGE_X86_EXIT_SMOKE;
    if (fseek(image, 0, SEEK_SET) ||
        fwrite(&header, sizeof(header), 1, image) != 1 || fclose(image)) {
        fprintf(stderr, "cannot update native image\n");
        return 1;
    }
    return 0;
}
