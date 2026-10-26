#include "native-image.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t fixture(unsigned char *data)
{
    memset(data, 0, 8192);
    LatNativeImageHeaderV2 *h = (void *)data;
    memcpy(h->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    h->version = LAT_NATIVE_IMAGE_VERSION;
    h->header_size = sizeof(*h);
    h->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    strcpy(h->lat_build_id, "constant-test");
    h->guest_image_offset = sizeof(*h);
    h->guest_image_size = 8;
    h->code_offset = sizeof(*h) + 8;
    h->code_size = 192;
    h->tb_table_offset = h->code_offset + h->code_size;
    h->tb_count = 1;
    h->relocation_offset = h->tb_table_offset + sizeof(LatNativeTbV1);
    h->relocation_count = 2;
    h->pc_map_offset = h->relocation_offset + 2 * sizeof(LatNativeRelocationV1);
    h->tu_table_offset = h->pc_map_offset;
    h->tu_count = 1;
    LatNativeTbV1 *tb = (void *)(data + h->tb_table_offset);
    *tb = (LatNativeTbV1){.guest_pc = 0x1000, .code_size = 24, .flags = 3};
    LatNativeTuV1 *tu = (void *)(data + h->tu_table_offset);
    *tu = (LatNativeTuV1){.code_size = 64, .search_offset = 64};
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    for (unsigned i = 0; i < 2; i++) {
        rel[i] = (LatNativeRelocationV1){.code_offset = i * 12,
            .kind = LAT_NATIVE_RELOC_IMAGE_DATA, .slots = 3,
            .addend = 144 + i * 16, .reserved = 48 - i * 16,
            .data_object_offset = 128, .data_object_size = 64,
            .data_object_alignment = 32,
            .data_object_flags = LAT_NATIVE_DATA_POINTER_FREE};
        uint32_t words[] = {0x1400000c, 0x0380018c, 0x1600000c};
        memcpy(data + h->code_offset + i * 12, words, sizeof(words));
    }
    memset(data + h->code_offset + 128, 0xa5, 64);
    return h->tu_table_offset + sizeof(*tu);
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    unsigned char data[8192];
    size_t size = fixture(data);
    char error[256] = {0};
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    LatNativeImageHeaderV2 *h = (void *)data;
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    for (unsigned test = 0; test < 10; test++) {
        LatNativeRelocationV1 saved = rel[0];
        switch (test) {
        case 0: rel[0].data_object_size = 0; break;
        case 1: rel[0].data_object_size = UINT64_MAX; break;
        case 2: rel[0].data_object_alignment = 3; break;
        case 3: rel[0].data_object_alignment = 8192; break;
        case 4: rel[0].data_object_flags = 2; break;
        case 5: rel[0].data_object_offset++; break;
        case 6: rel[0].addend = 127; break;
        case 7: rel[0].addend = 192; break;
        case 8: rel[0].reserved--; break;
        case 9: rel[0].data_object_alignment = 64; break;
        }
        assert(lat_native_image_validate(data, size, error, sizeof(error)));
        rel[0] = saved;
    }
    /* Two individually bounded objects must not partially overlap. */
    rel[1].data_object_offset = 160;
    rel[1].data_object_size = 32;
    assert(lat_native_image_validate(data, size, error, sizeof(error)));
    size = fixture(data);
    /* A valid suffix is insufficient: the unreferenced prefix overlaps a TU. */
    for (unsigned i = 0; i < 2; i++) {
        rel[i].data_object_offset = 32;
        rel[i].data_object_size = 160;
    }
    assert(lat_native_image_validate(data, size, error, sizeof(error)));
    size = fixture(data);
    rel[0].kind = LAT_NATIVE_RELOC_GUEST_ADDRESS;
    assert(lat_native_image_validate(data, size, error, sizeof(error)));
    size = fixture(data);
    h->version--;
    assert(lat_native_image_validate(data, size, error, sizeof(error)));
    h->version++;
    for (int i = 1; i < 3; i++) {
        FILE *out = fopen(argv[i], "wb");
        assert(out && fwrite(data, size, 1, out) == 1 && !fclose(out));
    }
    assert(!lat_native_image_merge_files(argv[1], argv[2], argv[3], error, sizeof(error)));
    FILE *in = fopen(argv[3], "rb");
    assert(in);
    size = fread(data, 1, sizeof(data), in);
    assert(!ferror(in) && !fclose(in));
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    rel = (void *)(data + h->relocation_offset);
    assert(h->relocation_count == 4 && h->code_size == 384);
    assert(rel[2].data_object_offset == 320 && rel[2].addend == 336);
    assert(rel[3].data_object_offset == 320 && rel[3].addend == 352);
    assert(rel[2].data_object_size == 64 && rel[2].data_object_alignment == 32);
    assert(!memcmp(data + h->code_offset + 128, data + h->code_offset + 320, 64));
    /* The delta shift must preserve alignments larger than merge's old32. */
    size = fixture(data);
    h->code_size = 256;
    h->tb_table_offset = h->code_offset + h->code_size;
    h->relocation_offset = h->tb_table_offset + sizeof(LatNativeTbV1);
    h->pc_map_offset = h->relocation_offset + 2 * sizeof(LatNativeRelocationV1);
    h->tu_table_offset = h->pc_map_offset;
    LatNativeTbV1 *tb = (void *)(data + h->tb_table_offset);
    *tb = (LatNativeTbV1){.guest_pc = 0x1000, .code_size = 24, .flags = 3};
    rel = (void *)(data + h->relocation_offset);
    for (unsigned i = 0; i < 2; i++) {
        rel[i] = (LatNativeRelocationV1){.code_offset = i * 12,
            .kind = LAT_NATIVE_RELOC_IMAGE_DATA, .slots = 3,
            .addend = 144 + i * 16, .reserved = 48 - i * 16,
            .data_object_offset = 128, .data_object_size = 64,
            .data_object_alignment = 128, .data_object_flags = LAT_NATIVE_DATA_POINTER_FREE};
    }
    *(LatNativeTuV1 *)(data + h->tu_table_offset) =
        (LatNativeTuV1){.code_size = 64, .search_offset = 64};
    size = h->tu_table_offset + sizeof(LatNativeTuV1);
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    FILE *out = fopen(argv[2], "wb");
    assert(out && fwrite(data, size, 1, out) == 1 && !fclose(out));
    assert(!lat_native_image_merge_files(argv[1], argv[2], argv[3], error, sizeof(error)));
    in = fopen(argv[3], "rb");
    assert(in);
    size = fread(data, 1, sizeof(data), in);
    assert(!ferror(in) && !fclose(in));
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    rel = (void *)(data + h->relocation_offset);
    assert(h->code_size == 512 && rel[2].data_object_offset == 384);
    assert(rel[2].data_object_alignment == 128 && rel[2].addend == 400);
    puts("test-native-constants: PASS complete-object/alias/merge/reject");
    return 0;
}
