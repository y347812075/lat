#include "lat-fallback.h"
#include "lat-native-image.h"
#include "native-image.h"

#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(LatX86StateV1) == 560,
               "LatX86StateV1 ABI size changed");
_Static_assert(offsetof(LatX86StateV1, xmm) == 300,
               "LatX86StateV1 XMM offset changed");
_Static_assert(sizeof(LatNativeImageHeaderV2) == 224,
               "native image header size changed");
_Static_assert(sizeof(LatNativeTbV1) == 24,
               "native TB record size changed");
_Static_assert(sizeof(LatNativeRelocationV1) == 32,
               "native relocation record size changed");
_Static_assert(sizeof(LatNativePcMapV2) == 32,
               "native PC map record size changed");

static int write_image(const char *path, const void *image, size_t size)
{
    FILE *output = fopen(path, "wb");
    return !output || fwrite(image, size, 1, output) != 1 || fclose(output);
}

int main(int argc, char **argv)
{
    unsigned char image[512] = {0};
    LatNativeImageHeaderV2 *header = (void *)image;
    LatNativeTbV1 *tb;
    LatNativeRelocationV1 *relocation;
    char error[128] = {0};
    size_t image_size;

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
    relocation = (void *)(image + header->relocation_offset);
    relocation->code_offset = 8;
    relocation->kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL;
    relocation->target = LAT_NATIVE_SYMBOL_RAISE_SYSCALL;
    relocation->slots = 3;
    image_size = header->pc_map_offset;

    if (lat_native_image_validate(image, image_size, error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "valid image rejected: %s\n", error);
        return 1;
    }
    if (argc == 4) {
        if (write_image(argv[1], image, image_size)) return 1;
        tb->guest_pc = 0x401010;
        if (write_image(argv[2], image, image_size) ||
            lat_native_image_merge_files(argv[1], argv[2], argv[3],
                                         error, sizeof(error)) ||
            lat_native_image_inspect_file(argv[3], header, error,
                                          sizeof(error)) ||
            header->tb_count != 2 || header->code_size != 64 ||
            header->relocation_count != 2) {
            fprintf(stderr, "cannot merge native images: %s\n", error);
            return 1;
        }
        error[0] = '\0';
        if (lat_native_image_merge_files(argv[1], argv[1], argv[3],
                                         error, sizeof(error)) ||
            lat_native_image_inspect_file(argv[3], header, error,
                                          sizeof(error)) ||
            header->tb_count != 1 || header->code_size != 32 ||
            header->relocation_count != 1) {
            fprintf(stderr, "cannot merge overlapping native TBs: %s\n",
                    error);
            return 1;
        }
        remove(argv[1]);
        remove(argv[2]);
        remove(argv[3]);
        puts("test-native-format: PASS merge=2 overlap=deduplicated");
        return 0;
    }
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
                                  sizeof(error)) == 0 ||
        !strstr(error, "code range")) {
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
