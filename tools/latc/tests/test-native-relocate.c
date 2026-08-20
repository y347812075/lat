#include "lat-native-image.h"
#include "relocate.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char image[512] = {0};
    LatNativeImageHeaderV1 *header = (void *)image;
    uint32_t *instructions;
    LatNativeRelocationV1 *relocations;
    LatNativeCode code = {0};
    char error[128] = {0};

    header->code_offset = sizeof(*header);
    header->code_size = 28;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 1;
    header->relocation_offset = header->tb_table_offset +
                                sizeof(LatNativeTbV1);
    header->relocation_count = 3;
    instructions = (void *)(image + header->code_offset);
    instructions[0] = 0x1400000c;
    instructions[1] = 0x0380018c;
    instructions[2] = 0x1600000c;
    instructions[3] = 0x1400000c;
    instructions[4] = 0x0380018c;
    instructions[5] = 0x1e00000c;
    instructions[6] = 0x4c000180;
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

    size_t image_size = header->relocation_offset +
                        3 * sizeof(*relocations);
    if (lat_native_code_load(header, image, image_size, &code,
                             error, sizeof(error))) {
        fprintf(stderr, "native relocation failed: %s\n", error);
        return 1;
    }
    const uint32_t *loaded = code.address;
    if (loaded[5] == instructions[5] && loaded[6] == instructions[6]) {
        fprintf(stderr, "native TB target was not relocated\n");
        lat_native_code_unload(&code);
        return 1;
    }
    lat_native_code_unload(&code);
    if (code.address || code.size) {
        return 1;
    }
    puts("test-native-relocate: PASS");
    return 0;
}
