#include "lat-fallback.h"
#include "lat-native-image.h"
#include "native-image.h"
#include "lat-translation-config.h"

#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(LatX86StateV1) == 560,
               "LatX86StateV1 ABI size changed");
_Static_assert(offsetof(LatX86StateV1, xmm) == 300,
               "LatX86StateV1 XMM offset changed");
_Static_assert(sizeof(LatNativeImageHeaderV2) == 280,
               "native image header size changed");
_Static_assert(sizeof(LatNativeTbV1) == 56,
               "native TB record size changed");
_Static_assert(sizeof(LatNativeRelocationV1) == 64,
               "native relocation record size changed");
_Static_assert(sizeof(LatNativePcMapV2) == 32,
               "native PC map record size changed");
_Static_assert(sizeof(LatNativeTuV1) == 48,
               "native TU record size changed");

static int write_image(const char *path, const void *image, size_t size)
{
    FILE *output = fopen(path, "wb");
    return !output || fwrite(image, size, 1, output) != 1 || fclose(output);
}

static int test_branch_target_decode(void)
{
    uint32_t words[2] = {0};
    uint64_t target = 0;

    words[0] = 0x58000400u;
    if (!lat_native_decode_local_branch_target(
            words, 1, 8, 32, &target) || target != 12) {
        return 1;
    }
    words[0] = 0x48000000u | (0xffffu << 10) | 0x1fu;
    if (!lat_native_decode_local_branch_target(
            words, 1, 8, 32, &target) || target != 4) {
        return 1;
    }
    words[0] = 0x50000000u | (0xfffeu << 10) | 0x3ffu;
    if (!lat_native_decode_local_branch_target(
            words, 1, 8, 32, &target) || target != 0) {
        return 1;
    }
    words[0] = 0x58000000u | (0xffffu << 10);
    if (!lat_native_decode_local_branch_target(
            words, 1, 8, 32, &target) || target != 4) {
        return 1;
    }
    words[0] = 0x1e00000cu;
    words[1] = 0x4c000180u;
    if (!lat_native_decode_local_branch_target(
            words, 2, 8, 32, &target) || target != 8) {
        return 1;
    }
    /* Encodings independently produced by llvm-mc, not the decoder formula. */
    static const struct {
        uint32_t word;
        uint64_t site;
        uint64_t target;
    } cases[] = {
        {0x53fffbffu, 8, 0},             /* b -8 */
        {0x54000401u, 0, 262148},        /* bl 262148 */
        {0x43fffc9fu, 8, 4},            /* beqz $a0, -4 */
        {0x44000181u, 0, 262144},        /* bnez $t0, 262144 */
        {0x48000068u, 0, 2097152},       /* bceqz $fcc3, 2097152 */
        {0x480001f8u, 2097152, 0},       /* bcnez $fcc7, -2097152 */
        {0x5bfffc85u, 8, 4},            /* beq $a0, $a1, -4 */
        {0x53fffdffu, 0, 134217724},    /* b maximum */
        {0x50000200u, 134217728, 0},    /* b minimum */
        {0x43fffc8fu, 0, 4194300},      /* beqz maximum */
        {0x40000090u, 4194304, 0},      /* beqz minimum */
        {0x59fffc85u, 0, 131068},       /* beq maximum */
        {0x5a000085u, 131072, 0},       /* beq minimum */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        words[0] = cases[i].word;
        if (!lat_native_decode_local_branch_target(words, 1, cases[i].site,
                268435456, &target) || target != cases[i].target) return 1;
    }
    words[0] = 0x1fffffecu;             /* pcaddu18i $t0, -1 */
    words[1] = 0x4c000180u;             /* jirl $zero, $t0, 0 */
    if (!lat_native_decode_local_branch_target(words, 2, 262144, 524288,
            &target) || target != 0) return 1;
    words[0] = 0x1e00002cu;
    words[1] = 0x4ffffd81u;             /* upper +1, lower -4 bytes */
    if (!lat_native_decode_local_branch_target(words, 2, 0, 524288,
            &target) || target != 262140) return 1;
    words[0] = 0x1fffffecu;
    words[1] = 0x4dfffd81u;             /* upper -1, lower +131068 bytes */
    if (!lat_native_decode_local_branch_target(words, 2, 262144, 524288,
            &target) || target != 131068) return 1;
    words[1] = 0x4c0001a0u;             /* Different JIRL source register. */
    if (lat_native_decode_local_branch_target(words, 2, 262144, 524288,
            &target)) return 1;
    words[0] = 0x1e000000u;             /* PCADDU18I to zero discards PC. */
    words[1] = 0x4c000000u;
    if (lat_native_decode_local_branch_target(words, 2, 8, 32, &target)) return 1;
    /* Negative displacement must not wrap, and a forward target must fit. */
    words[0] = 0x53fffbffu;
    if (lat_native_decode_local_branch_target(words, 1, 4, 32, &target)) return 1;
    words[0] = 0x54000401u;
    if (lat_native_decode_local_branch_target(words, 1, 0, 262144, &target)) return 1;
    words[0] = 0x480001f8u;
    if (lat_native_decode_local_branch_target(words, 1, 0, 4194304, &target)) return 1;
    words[0] = 0x1fffffecu;
    words[1] = 0x4c000180u;
    if (lat_native_decode_local_branch_target(words, 2, 0, 524288, &target)) return 1;
    words[0] = 0x50000400u;             /* b +4, uint64 boundary */
    if (!lat_native_decode_local_branch_target(words, 1, UINT64_MAX - 4,
            UINT64_MAX, &target) || target != UINT64_MAX) return 1;
    if (lat_native_decode_local_branch_target(words, 1, UINT64_MAX - 3,
            UINT64_MAX, &target)) return 1;
    return lat_native_decode_local_branch_target(
               words, 1, 8, 4, &target);
}

int main(int argc, char **argv)
{
    unsigned char image[1024] = {0};
    LatNativeImageHeaderV2 *header = (void *)image;
    LatNativeTbV1 *tb;
    LatNativeRelocationV1 *relocation;
    char error[128] = {0};
    size_t image_size;
    if (test_branch_target_decode()) return 1;

    memcpy(header->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->header_size = sizeof(*header);
    header->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    header->guest_image_offset = sizeof(*header);
    header->guest_image_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    header->code_offset = header->guest_image_offset + header->guest_image_size;
    header->code_size = 32;
    header->tb_table_offset = header->code_offset + header->code_size;
    header->tb_count = 1;
    header->relocation_offset = header->tb_table_offset + sizeof(*tb);
    header->relocation_count = 1;
    header->pc_map_offset = header->relocation_offset +
                            sizeof(LatNativeRelocationV1);
    header->tu_table_offset = header->pc_map_offset;
    header->tu_count = 1;
    strcpy(header->lat_build_id, "test-build");
    Elf64_Ehdr *elf = (void *)(image + header->guest_image_offset);
    memcpy(elf->e_ident, ELFMAG, SELFMAG);
    elf->e_ident[EI_CLASS] = ELFCLASS64;
    elf->e_ident[EI_DATA] = ELFDATA2LSB;
    elf->e_type = ET_EXEC;
    elf->e_machine = EM_X86_64;
    elf->e_entry = 0x401000;
    elf->e_phoff = sizeof(*elf);
    elf->e_ehsize = sizeof(*elf);
    elf->e_phentsize = sizeof(Elf64_Phdr);
    elf->e_phnum = 1;
    Elf64_Phdr *phdr = (void *)((unsigned char *)elf + elf->e_phoff);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_vaddr = elf->e_entry;
    phdr->p_memsz = 16;
    header->guest_entry = elf->e_entry;
    tb = (void *)(image + header->tb_table_offset);
    tb->guest_pc = 0x401000;
    tb->code_offset = 0;
    tb->code_size = 16;
    tb->tu_index = 0;
    relocation = (void *)(image + header->relocation_offset);
    relocation->code_offset = 8;
    relocation->kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;
    relocation->target = LAT_NATIVE_SYMBOL_RAISE_SYSCALL;
    relocation->slots = 3;
    relocation->physical_target_plus_one = 1;
    LatNativeTuV1 *tu = (void *)(image + header->tu_table_offset);
    tu->code_offset = 0;
    tu->code_size = header->code_size;
    tu->search_offset = header->code_size;
    image_size = header->tu_table_offset + sizeof(*tu);

    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "valid image rejected: %s\n", error);
        return 1;
    }
    tu->config_dependency_version = LAT_TRANSLATION_CONFIG_VERSION;
    tu->config_dependencies = LAT_CONFIG_ALL_BITS;
    if (lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "valid configuration dependencies rejected: %s\n", error);
        return 1;
    }
    const LatNativeTuV1 good_tu = *tu;
    for (int bad = 0; bad < 4; bad++) {
        *tu = good_tu;
        if (bad == 0) tu->config_dependency_version = 0;
        if (bad == 1) tu->config_dependency_version++;
        if (bad == 2) tu->config_dependencies |= UINT64_C(1) << 63;
        if (bad == 3) tu->config_dependency_reserved = 1;
        if (!lat_native_image_validate(image, image_size, error, sizeof(error)) ||
            !strstr(error, "configuration dependencies")) {
            fprintf(stderr, "bad configuration dependencies accepted\n");
            return 1;
        }
    }
    *tu = good_tu;
    uint32_t *code = (void *)(image + header->code_offset);
    code[0] = 0x58000400u; /* beq zero, zero, +4 */
    tb->conditional_exit_offset = 1;
    if (lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "valid conditional exit rejected: %s\n", error);
        return 1;
    }
    const uint32_t bad_offsets[] = {2, 17, UINT32_MAX};
    for (size_t i = 0; i < sizeof(bad_offsets) / sizeof(bad_offsets[0]); i++) {
        tb->conditional_exit_offset = bad_offsets[i];
        if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
            fprintf(stderr, "bad conditional offset accepted\n");
            return 1;
        }
    }
    tb->conditional_exit_offset = 1;
    const uint32_t bad_instructions[] = {
        0x03400000u, 0x58001000u, 0x5bfffc00u,
    }; /* NOP, target at TB end, negative target */
    for (size_t i = 0;
         i < sizeof(bad_instructions) / sizeof(bad_instructions[0]); i++) {
        code[0] = bad_instructions[i];
        if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
            fprintf(stderr, "bad conditional instruction accepted\n");
            return 1;
        }
    }
    code[0] = 0x58000400u;
    tb->indirect_exit_offset = 1;
    if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "invalid indirect exit accepted\n");
        return 1;
    }
    tb->indirect_exit_offset = 0;
    header->version = 5;
    if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "old native version accepted\n");
        return 1;
    }
    header->version = LAT_NATIVE_IMAGE_VERSION;
    header->translation_config_sha256[0] = 1;
    if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "unmarked native configuration accepted\n");
        return 1;
    }
    header->flags |= LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "missing native configuration snapshot accepted\n");
        return 1;
    }
    header->translation_config_sha256[0] = 0;
    if (!lat_native_image_validate(image, image_size, error, sizeof(error))) {
        fprintf(stderr, "missing native configuration digest accepted\n");
        return 1;
    }
    header->flags &= ~LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    if (argc == 4) {
        if (write_image(argv[1], image, image_size)) return 1;
        tb->guest_pc = 0x401010;
        if (write_image(argv[2], image, image_size) ||
            lat_native_image_merge_files(argv[1], argv[2], argv[3],
                                         error, sizeof(error)) ||
            lat_native_image_inspect_file(argv[3], header, error,
                                          sizeof(error)) ||
            header->tb_count != 2 || header->code_size != 64 ||
            header->relocation_count != 2 || header->tu_count != 2) {
            fprintf(stderr, "cannot merge native images: %s\n", error);
            return 1;
        }
        gchar *base_bytes = NULL, *delta_bytes = NULL, *merged_bytes = NULL;
        gsize base_bytes_size = 0, delta_bytes_size = 0;
        gsize file_merged_size = 0;
        void *memory_merged = NULL;
        size_t memory_merged_size = 0;
        if (!g_file_get_contents(argv[1], &base_bytes, &base_bytes_size, NULL) ||
            !g_file_get_contents(argv[2], &delta_bytes, &delta_bytes_size, NULL) ||
            !g_file_get_contents(argv[3], &merged_bytes, &file_merged_size, NULL) ||
            lat_native_image_merge_memory(base_bytes, base_bytes_size,
                delta_bytes, delta_bytes_size, &memory_merged,
                &memory_merged_size, error, sizeof(error)) ||
            memory_merged_size != file_merged_size ||
            memcmp(memory_merged, merged_bytes, file_merged_size)) {
            fprintf(stderr, "memory and file native merges differ\n");
            g_free(base_bytes);
            g_free(delta_bytes);
            g_free(merged_bytes);
            free(memory_merged);
            return 1;
        }
        g_free(base_bytes);
        g_free(delta_bytes);
        g_free(merged_bytes);
        free(memory_merged);
        LatNativeTbV1 merged_tbs[2];
        LatNativeTuV1 merged_tus[2];
        LatNativeRelocationV1 merged_relocations[2];
        FILE *merged_file = fopen(argv[3], "rb");
        if (!merged_file || fseek(merged_file, header->tb_table_offset, SEEK_SET) ||
            fread(merged_tbs, sizeof(merged_tbs), 1, merged_file) != 1 ||
            fseek(merged_file, header->tu_table_offset, SEEK_SET) ||
            fread(merged_tus, sizeof(merged_tus), 1, merged_file) != 1 ||
            fseek(merged_file, header->relocation_offset, SEEK_SET) ||
            fread(merged_relocations, sizeof(merged_relocations), 1,
                  merged_file) != 1 || fclose(merged_file) ||
            merged_tbs[0].conditional_exit_offset != 1 ||
            merged_tbs[1].conditional_exit_offset != 1 ||
            merged_tbs[0].tu_index != 0 || merged_tbs[1].tu_index != 1 ||
            merged_tbs[1].code_offset != 32 ||
            merged_tus[0].code_offset != 0 ||
            merged_tus[1].code_offset != 32 ||
            merged_tus[0].config_dependencies != LAT_CONFIG_ALL_BITS ||
            merged_tus[1].config_dependencies != LAT_CONFIG_ALL_BITS ||
            merged_tus[0].config_dependency_version != LAT_TRANSLATION_CONFIG_VERSION ||
            merged_tus[1].config_dependency_version != LAT_TRANSLATION_CONFIG_VERSION ||
            merged_relocations[0].physical_target_plus_one != 1 ||
            merged_relocations[1].physical_target_plus_one != 2) {
            fprintf(stderr, "merged conditional exit metadata changed\n");
            return 1;
        }
        error[0] = '\0';
        if (lat_native_image_merge_files(argv[1], argv[1], argv[3],
                                         error, sizeof(error)) ||
            lat_native_image_inspect_file(argv[3], header, error,
                                          sizeof(error)) ||
            header->tb_count != 2 || header->code_size != 64 ||
            header->relocation_count != 2 || header->tu_count != 2) {
            fprintf(stderr, "cannot merge overlapping native TBs: %s\n",
                    error);
            return 1;
        }
        FILE *aliased_file = fopen(argv[3], "rb");
        LatNativeTbV1 aliased_tbs[2];
        if (!aliased_file ||
            fseek(aliased_file, header->tb_table_offset, SEEK_SET) ||
            fread(aliased_tbs, sizeof(aliased_tbs), 1, aliased_file) != 1 ||
            fclose(aliased_file) ||
            aliased_tbs[0].guest_pc != aliased_tbs[1].guest_pc ||
            aliased_tbs[0].flags != aliased_tbs[1].flags ||
            aliased_tbs[0].code_offset != 0 ||
            aliased_tbs[1].code_offset != 32 ||
            aliased_tbs[0].tu_index != 0 ||
            aliased_tbs[1].tu_index != 1) {
            fprintf(stderr, "merged physical TB alias was not preserved\n");
            return 1;
        }
        remove(argv[1]);
        remove(argv[2]);
        remove(argv[3]);
        puts("test-native-format: PASS merge=2 overlap=physical-alias");
        return 0;
    }
    tb->conditional_exit_offset = 0;
    code[0] = 0;
    if (argc == 2) {
        if (write_image(argv[1], image, image_size)) {
            fprintf(stderr, "cannot write native image fixture\n");
            return 1;
        }
        if (lat_native_image_mark_x86_static_file(argv[1], error,
                                                  sizeof(error)) != 0 ||
            lat_native_image_inspect_file(argv[1], header, error,
                                          sizeof(error)) != 0 ||
            !(header->flags & LAT_NATIVE_IMAGE_X86_STATIC_EXEC)) {
            fprintf(stderr, "cannot mark static x86 image: %s\n", error);
            return 1;
        }

        header->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP |
                        LAT_NATIVE_IMAGE_PIE;
        elf->e_type = ET_DYN;
        elf->e_entry = 0x1000;
        phdr->p_vaddr = elf->e_entry;
        header->guest_entry = elf->e_entry;
        if (write_image(argv[1], image, image_size) ||
            lat_native_image_mark_x86_static_file(argv[1], error,
                                                  sizeof(error)) != 0 ||
            lat_native_image_inspect_file(argv[1], header, error,
                                          sizeof(error)) != 0 ||
            !(header->flags & LAT_NATIVE_IMAGE_X86_STATIC_EXEC)) {
            fprintf(stderr, "cannot mark static PIE x86 image: %s\n", error);
            return 1;
        }

        header->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
        elf->e_type = ET_EXEC;
        elf->e_entry = 0x401000;
        phdr->p_vaddr = elf->e_entry;
        header->guest_entry = elf->e_entry;
        phdr->p_type = PT_INTERP;
        if (write_image(argv[1], image, image_size)) return 1;
        error[0] = '\0';
        if (lat_native_image_mark_x86_static_file(argv[1], error,
                                                  sizeof(error)) == 0 ||
            !strstr(error, "dynamically linked")) {
            fprintf(stderr, "dynamic x86 image accepted: %s\n", error);
            return 1;
        }
        phdr->p_type = PT_LOAD;
        if (write_image(argv[1], image, image_size) ||
            lat_native_image_mark_x86_static_file(argv[1], error,
                                                  sizeof(error))) {
            fprintf(stderr, "cannot restore static x86 image: %s\n", error);
            return 1;
        }
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [OUTPUT | BASE DELTA MERGED]\n", argv[0]);
        return 2;
    }
    tb->code_size = 33;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0) {
        fprintf(stderr, "bad TB range accepted: %s\n", error);
        return 1;
    }
    tb->code_size = 16;
    relocation->code_offset = header->code_size - 4;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "relocation")) {
        fprintf(stderr, "bad relocation range accepted: %s\n", error);
        return 1;
    }
    relocation->code_offset = 8;
    LatNativePcMapV2 *pc_map = (void *)(image + header->pc_map_offset);
    LatNativeTuV1 saved_tu = *(LatNativeTuV1 *)(
        image + header->tu_table_offset);
    header->tu_table_offset += sizeof(*pc_map);
    *(LatNativeTuV1 *)(image + header->tu_table_offset) = saved_tu;
    *pc_map = (LatNativePcMapV2) {
        .guest_pc = 0x401000,
        .host_offset_begin = 0,
        .host_offset_end = 16,
        .flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE,
    };
    header->pc_map_count = 1;
    header->flags &= ~LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    image_size += sizeof(*pc_map);
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "precise PC map rejected: %s\n", error);
        return 1;
    }
    pc_map->state_record_offset = (uint32_t)(int32_t)-8;
    pc_map->flags |= LAT_NATIVE_PC_MAP_STACK_POINTER_DELTA;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "stack delta PC map rejected: %s\n", error);
        return 1;
    }
    pc_map->flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "PC map")) {
        fprintf(stderr, "unflagged stack delta accepted: %s\n", error);
        return 1;
    }
    pc_map->state_record_offset = 0;
    pc_map->flags |= LAT_NATIVE_PC_MAP_STACK_POINTER_DELTA;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "PC map")) {
        fprintf(stderr, "empty stack delta flag accepted: %s\n", error);
        return 1;
    }
    pc_map->flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE | (1u << 31);
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "PC map")) {
        fprintf(stderr, "unknown PC map flag accepted: %s\n", error);
        return 1;
    }
    pc_map->flags = LAT_NATIVE_PC_MAP_DYNAMIC_STATE;
    pc_map->host_offset_end = header->code_size + 1;
    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) == 0 ||
        !strstr(error, "PC map")) {
        fprintf(stderr, "bad PC map accepted: %s\n", error);
        return 1;
    }
    puts("test-native-format: PASS");
    return 0;
}
