#include "lat-native-image.h"
#include "relocate.h"

#include <stdio.h>
#include <string.h>

static int test_constant_object(void)
{
    unsigned char image[sizeof(LatNativeImageHeaderV2) + 96 +
                        sizeof(LatNativeRelocationV1)] = {0};
    LatNativeImageHeaderV2 *h = (void *)image;
    h->code_offset = sizeof(*h);
    h->code_size = 96;
    h->relocation_offset = h->code_offset + h->code_size;
    h->relocation_count = 1;
    uint32_t words[] = {0x1400000c, 0x0380018c, 0x1600000c};
    memcpy(image + h->code_offset, words, sizeof(words));
    for (unsigned i = 0; i < 32; i++) image[h->code_offset + 64 + i] = i ^ 0x5a;
    LatNativeRelocationV1 *rel = (void *)(image + h->relocation_offset);
    *rel = (LatNativeRelocationV1){.kind = LAT_NATIVE_RELOC_IMAGE_DATA,
        .slots = 3, .addend = 80, .reserved = 16,
        .data_object_offset = 64, .data_object_size = 32,
        .data_object_alignment = 32, .data_object_flags = LAT_NATIVE_DATA_POINTER_FREE};
    LatNativeCode code = {0};
    char error[256] = {0};
    if (lat_native_code_load(h, image, sizeof(image), &code, error, sizeof(error))) return 1;
    const uint32_t *loaded = code.address;
    int64_t pages = (int32_t)(((loaded[0] >> 5) & 0xfffff) << 12) >> 12;
    uintptr_t target = (((uintptr_t)loaded & ~(uintptr_t)4095) + pages * 4096) |
                       ((loaded[1] >> 10) & 4095);
    int bad = target != (uintptr_t)loaded + 80 || loaded[2] != 0x03400000 ||
        memcmp((const void *)(target - 16), image + h->code_offset + 64, 32);
    lat_native_code_unload(&code);
    if (bad) return 1;
    rel->data_object_size = 0;
    return !lat_native_code_load(h, image, sizeof(image), &code, error, sizeof(error));
}

int main(void)
{
    if (test_constant_object()) return 1;
    unsigned char image[sizeof(LatNativeImageHeaderV2) + 56 +
                        sizeof(LatNativeTbV1) +
                        6 * sizeof(LatNativeRelocationV1)] = {0};
    LatNativeImageHeaderV2 *header = (void *)image;
    uint32_t *instructions;
    LatNativeRelocationV1 *relocations;
    LatNativeCode code = {0};
    char error[128] = {0};

    header->code_offset = sizeof(*header);
    header->code_size = 56;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 1;
    header->relocation_offset = header->tb_table_offset +
                                sizeof(LatNativeTbV1);
    header->relocation_count = 6;
    header->pc_map_offset = header->relocation_offset +
                            header->relocation_count *
                            sizeof(LatNativeRelocationV1);
    instructions = (void *)(image + header->code_offset);
    instructions[0] = 0x1400000c;
    instructions[1] = 0x0380018c;
    instructions[2] = 0x1600000c;
    instructions[3] = 0x1400000c;
    instructions[4] = 0x0380018c;
    instructions[5] = 0x1e00000c;
    instructions[6] = 0x4c000184;
    instructions[7] = 0x1e00000c;
    instructions[8] = 0x4c000180;
    instructions[9] = 0x50000000;
    instructions[10] = 0x1a00000c;
    instructions[11] = 0x0380018c;
    instructions[12] = 0x00000981;
    instructions[13] = 0x000009a0;
    LatNativeTbV1 *tb = (void *)(image + header->tb_table_offset);
    tb->guest_pc = 0x402000;
    tb->code_offset = 0;
    relocations = (void *)(image + header->relocation_offset);
    relocations[0].code_offset = 0;
    relocations[0].kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;
    relocations[0].target = LAT_NATIVE_SYMBOL_RAISE_SYSCALL;
    relocations[0].slots = 3;
    relocations[1].code_offset = 12;
    relocations[1].kind = LAT_NATIVE_RELOC_GUEST_ADDRESS;
    relocations[1].addend = 0x401000;
    relocations[1].slots = 2;
    relocations[2].code_offset = 20;
    relocations[2].kind = LAT_NATIVE_RELOC_TB_TARGET;
    relocations[2].addend = 0x402000;
    relocations[2].slots = 2;
    relocations[2].reserved = LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0;
    relocations[3].code_offset = 28;
    relocations[3].kind = LAT_NATIVE_RELOC_TB_TARGET;
    relocations[3].addend = 0x403000;
    relocations[3].slots = 2;
    relocations[3].reserved = LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0;
    relocations[4].code_offset = 36;
    relocations[4].kind = LAT_NATIVE_RELOC_TB_TARGET;
    relocations[4].addend = 0x402000;
    relocations[4].slots = 1;
    relocations[5].code_offset = 40;
    relocations[5].kind = LAT_NATIVE_RELOC_JRRA_TARGET;
    relocations[5].addend = 0x402000;
    relocations[5].slots = 4;

    size_t image_size = header->pc_map_offset;
    header->flags = LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    if (!lat_native_code_load(header, image, image_size, &code,
                              error, sizeof(error)) || code.address) {
        fprintf(stderr, "unverified configuration became executable\n");
        return 1;
    }
    header->flags = 0;
    if (lat_native_code_load(header, image, image_size, &code,
                             error, sizeof(error))) {
        fprintf(stderr, "native relocation failed: %s\n", error);
        return 1;
    }
    const uint32_t *loaded = code.address;
    uint32_t jrra_high = (loaded[10] >> 5) & 0xfffff;
    int64_t jrra_page_delta = (int32_t)(jrra_high << 12) >> 12;
    uintptr_t jrra_target = (((uintptr_t)&loaded[10] >> 12) +
                             jrra_page_delta) << 12;
    jrra_target |= (loaded[11] >> 10) & 0xfff;
    if (loaded[5] != 0x18000044u ||
        (loaded[6] & 0xfc000000u) != 0x50000000u ||
        (loaded[7] == instructions[7] && loaded[8] == instructions[8]) ||
        loaded[9] == instructions[9] ||
        jrra_target != (uintptr_t)code.address ||
        loaded[12] != instructions[12] || loaded[13] != instructions[13]) {
        fprintf(stderr, "native TB target was not relocated or preserved\n");
        lat_native_code_unload(&code);
        return 1;
    }
    lat_native_code_unload(&code);
    if (code.address || code.size) {
        return 1;
    }
    header->flags = LAT_NATIVE_IMAGE_X86_STATIC_EXEC;
    error[0] = '\0';
    if (lat_native_code_load(header, image, image_size, &code,
                             error, sizeof(error)) == 0 ||
        !strstr(error, "relocation")) {
        fprintf(stderr, "missing static TB target accepted: %s\n", error);
        lat_native_code_unload(&code);
        return 1;
    }
    puts("test-native-relocate: PASS");
    return 0;
}
