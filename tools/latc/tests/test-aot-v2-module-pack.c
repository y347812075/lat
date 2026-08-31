#include "lat-native-image.h"
#include "lat-aot-v2.h"
#include "module-pack.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int write_fixture(const char *path, int overlap)
{
    unsigned char image[1024] = {0};
    LatNativeImageHeaderV2 *header = (void *)image;
    memcpy(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->header_size = sizeof(*header);
    header->flags = LAT_NATIVE_IMAGE_X86_STATIC_EXEC;
    header->guest_entry = 0x401000;
    header->preferred_guest_base = 0x400000;
    header->guest_image_offset = sizeof(*header);
    header->guest_image_size = 1;
    header->code_offset = header->guest_image_offset + 8;
    header->code_size = 28;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 2;
    header->relocation_offset = header->tb_table_offset +
                                2 * sizeof(LatNativeTbV1);
    header->relocation_count = 3;
    header->pc_map_offset = header->relocation_offset +
                            3 * sizeof(LatNativeRelocationV1);
    header->pc_map_count = 2;
    strcpy(header->lat_build_id, "aot-v2-module-pack-test-v1");

    uint32_t *code = (void *)(image + header->code_offset);
    code[0] = 0x1e00000c; /* pcaddu18i $t0, 0 */
    code[1] = 0x4c000184; /* jirl $a0, $t0, 0 */
    code[2] = 0x1e00000c; /* pcaddu18i $t0, 0 */
    code[3] = 0x4c000180; /* jirl $zero, $t0, 0 */
    code[4] = 0x50000000; /* b 0 */
    code[5] = 0x03400000; /* reserved nop */
    code[6] = 0x03400000; /* target TB */

    LatNativeTbV1 *tbs = (void *)(image + header->tb_table_offset);
    tbs[0] = (LatNativeTbV1){
        .guest_pc = 0x401000, .code_offset = 0, .code_size = 24,
    };
    tbs[1] = (LatNativeTbV1){
        .guest_pc = 0x402000,
        .code_offset = overlap ? 20 : 24,
        .code_size = overlap ? 8 : 4,
    };

    LatNativeRelocationV1 *relocations =
        (void *)(image + header->relocation_offset);
    relocations[0] = (LatNativeRelocationV1){
        .code_offset = 0,
        .addend = 0x402000,
        .kind = LAT_NATIVE_RELOC_TB_TARGET,
        .slots = 2,
        .reserved = LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0,
    };
    relocations[1] = (LatNativeRelocationV1){
        .code_offset = 8,
        .addend = 0x402000,
        .kind = LAT_NATIVE_RELOC_TB_TARGET,
        .slots = 2,
        .reserved = LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0,
    };
    relocations[2] = (LatNativeRelocationV1){
        .code_offset = 16,
        .addend = 0x402000,
        .kind = LAT_NATIVE_RELOC_TB_TARGET,
        .slots = 2,
        .reserved = LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0,
    };

    LatNativePcMapV2 *maps = (void *)(image + header->pc_map_offset);
    maps[0] = (LatNativePcMapV2){
        .guest_pc = 0x401000,
        .host_offset_begin = 0,
        .host_offset_end = 24,
        .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE,
    };
    maps[1] = (LatNativePcMapV2){
        .guest_pc = 0x402000,
        .host_offset_begin = 24,
        .host_offset_end = 28,
        .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE,
    };

    size_t size = header->pc_map_offset +
                  header->pc_map_count * sizeof(LatNativePcMapV2);
    FILE *file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    int result = fwrite(image, size, 1, file) == 1 ? 0 : -1;
    if (fclose(file)) {
        result = -1;
    }
    if (result) {
        return -1;
    }
    return 0;
}

static int write_large_guest_table_fixture(const char *path,
                                           size_t address_count)
{
    const size_t code_size = address_count * 3 * sizeof(uint32_t);
    const size_t tb_offset = sizeof(LatNativeImageHeaderV2) + 8 + code_size;
    const size_t relocation_offset = tb_offset + sizeof(LatNativeTbV1);
    const size_t pc_map_offset = relocation_offset +
        address_count * sizeof(LatNativeRelocationV1);
    const size_t image_size = pc_map_offset + sizeof(LatNativePcMapV2);
    unsigned char *image = g_malloc0(image_size);
    if (!image) {
        return -1;
    }
    LatNativeImageHeaderV2 *header = (void *)image;
    memcpy(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->header_size = sizeof(*header);
    header->flags = LAT_NATIVE_IMAGE_PIE;
    header->guest_entry = 0x401000;
    header->preferred_guest_base = 0x400000;
    header->guest_image_offset = sizeof(*header);
    header->guest_image_size = 1;
    header->code_offset = sizeof(*header) + 8;
    header->code_size = code_size;
    header->tb_table_offset = tb_offset;
    header->tb_count = 1;
    header->relocation_offset = relocation_offset;
    header->relocation_count = address_count;
    header->pc_map_offset = pc_map_offset;
    header->pc_map_count = 1;
    strcpy(header->lat_build_id, "aot-v2-two-level-guest-table-test-v1");

    uint32_t *code = (void *)(image + header->code_offset);
    LatNativeRelocationV1 *relocations =
        (void *)(image + relocation_offset);
    for (size_t i = 0; i < address_count; i++) {
        code[i * 3] = 12; /* destination register */
        code[i * 3 + 1] = 0x03400000u;
        code[i * 3 + 2] = 0x03400000u;
        relocations[i] = (LatNativeRelocationV1) {
            .code_offset = i * 3 * sizeof(uint32_t),
            .addend = 0x401000 + i * 8,
            .kind = LAT_NATIVE_RELOC_GUEST_ADDRESS,
            .slots = 3,
        };
    }
    LatNativeTbV1 *tb = (void *)(image + tb_offset);
    *tb = (LatNativeTbV1) {
        .guest_pc = 0x401000, .code_offset = 0, .code_size = code_size,
    };
    LatNativePcMapV2 *map = (void *)(image + pc_map_offset);
    *map = (LatNativePcMapV2) {
        .guest_pc = 0x401000,
        .host_offset_begin = 0,
        .host_offset_end = code_size,
        .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE,
    };
    FILE *file = fopen(path, "wb");
    int result = file && fwrite(image, image_size, 1, file) == 1 ? 0 : -1;
    if (file && fclose(file)) {
        result = -1;
    }
    g_free(image);
    return result;
}

int main(void)
{
    char directory[] = "/tmp/latc-aot-v2-module-pack-XXXXXX";
    if (!g_mkdtemp(directory)) {
        perror("create test directory");
        return 1;
    }
    char *image_path = g_build_filename(directory, "fixture.latnative", NULL);
    char error[256] = {0};
    if (write_fixture(image_path, 0) ||
        lat_aot_v2_emit_module_sources(image_path, directory,
                                       error, sizeof(error))) {
        fprintf(stderr, "cannot emit test module: %s\n", error);
        g_free(image_path);
        return 1;
    }
    char *metadata_path = g_build_filename(directory, "module.c", NULL);
    char *text_path = g_build_filename(directory, "text.bin", NULL);
    gchar *text = NULL;
    gsize text_size = 0;
    if (!g_file_get_contents(text_path, &text, &text_size, NULL) ||
        text_size != 28) {
        fprintf(stderr, "cannot read emitted module text\n");
        g_free(text_path);
        g_free(image_path);
        return 1;
    }
    if (write_large_guest_table_fixture(
            image_path, LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT + 1) ||
        lat_aot_v2_emit_module_sources(image_path, directory,
                                       error, sizeof(error))) {
        fprintf(stderr, "cannot emit two-level guest table: %s\n", error);
        g_free(text);
        g_free(text_path);
        g_free(metadata_path);
        g_free(image_path);
        return 1;
    }
    gchar *metadata = NULL;
    if (!g_file_get_contents(metadata_path, &metadata, NULL, NULL) ||
        !strstr(metadata, "LAT_AOT_MODULE_TWO_LEVEL_GUEST_SLOTS") ||
        !strstr(metadata, "guest_slots,guest_slots+257") ||
        !strstr(metadata, "{0x1800,-16,0}")) {
        fprintf(stderr, "257-entry two-level guest table was not emitted\n");
        g_free(metadata);
        g_free(text);
        g_free(text_path);
        g_free(metadata_path);
        g_free(image_path);
        return 1;
    }
    g_free(metadata);
    metadata = NULL;
    if (write_large_guest_table_fixture(
            image_path, LAT_AOT_V2_GUEST_ADDRESS_LIMIT + 1) ||
        !lat_aot_v2_emit_module_sources(image_path, directory,
                                        error, sizeof(error)) ||
        !strstr(error, "no TB supported")) {
        fprintf(stderr, "guest address overflow was not rejected safely: %s\n",
                error[0] ? error : "unexpected success");
        g_free(text);
        g_free(text_path);
        g_free(metadata_path);
        g_free(image_path);
        return 1;
    }
    const uint32_t *code = (const void *)text;
    if (code[0] != 0x18000044u ||
        (code[1] & 0xfc000000u) != 0x50000000u ||
        code[2] != 0x03400000u ||
        (code[3] & 0xfc000000u) != 0x50000000u ||
        code[4] == 0x50000000u || code[5] != 0x03400000u) {
        fprintf(stderr, "AOT v2 TB target pair was not direct-linked\n");
        g_free(text);
        g_free(text_path);
        g_free(image_path);
        return 1;
    }
    memset(error, 0, sizeof(error));
    if (write_fixture(image_path, 1) ||
        !lat_aot_v2_emit_module_sources(image_path, directory,
                                        error, sizeof(error)) ||
        !strstr(error, "overlap")) {
        fprintf(stderr, "overlapping AOT v2 TBs were accepted: %s\n", error);
        g_free(text);
        g_free(text_path);
        g_free(image_path);
        return 1;
    }
    g_free(text);
    g_remove(text_path);
    char *assembly_path = g_build_filename(directory, "module.S", NULL);
    g_remove(metadata_path);
    g_remove(assembly_path);
    g_remove(image_path);
    g_rmdir(directory);
    g_free(assembly_path);
    g_free(metadata_path);
    g_free(text_path);
    g_free(image_path);
    puts("test-aot-v2-module-pack: PASS");
    return 0;
}
