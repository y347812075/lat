#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "guest-elf-map.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int executable_mapping(int fd, uint64_t bias, uint64_t *start,
                              uint64_t *size, uint64_t *offset)
{
    Elf64_Ehdr elf;
    if (pread(fd, &elf, sizeof(elf), 0) != sizeof(elf)) {
        return -1;
    }
    for (uint16_t i = 0; i < elf.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  (off_t)(elf.e_phoff + i * sizeof(phdr))) != sizeof(phdr)) {
            return -1;
        }
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) &&
            phdr.p_filesz) {
            *offset = phdr.p_offset & ~UINT64_C(0xfff);
            *start = bias + (phdr.p_vaddr & ~UINT64_C(0xfff));
            *size = ((phdr.p_offset + phdr.p_filesz + 0xfff) &
                     ~UINT64_C(0xfff)) - *offset;
            return 0;
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s MAIN INTERPRETER DSO\n", argv[0]);
        return 2;
    }
    LatGuestElfTrackerV2 *tracker = lat_guest_elf_tracker_new_v2();
    if (!tracker) {
        return 1;
    }
    static const uint64_t biases[] = {
        UINT64_C(0x555500000000),
        UINT64_C(0x7f1000000000),
        UINT64_C(0x7f2000000000),
    };
    char error[256] = {0};
    for (int i = 0; i < 3; i++) {
        int fd = open(argv[i + 1], O_RDONLY);
        uint64_t start, size, offset;
        const LatGuestElfInfoV2 *info;
        int added;
        if (fd < 0 || executable_mapping(fd, biases[i], &start, &size,
                                         &offset) ||
            lat_guest_elf_tracker_note_v2(tracker, fd, start, size, offset,
                                          4096, &info, &added,
                                          error, sizeof(error)) || !added ||
            info->load_bias != biases[i] ||
            info->preferred_base > UINT64_MAX - info->load_bias ||
            info->guest_begin != info->load_bias + info->preferred_base ||
            info->guest_end <= info->guest_begin ||
            !info->exec_range_count) {
            fprintf(stderr, "cannot track ELF %s: %s\n", argv[i + 1], error);
            if (fd >= 0) close(fd);
            lat_guest_elf_tracker_free_v2(tracker);
            return 1;
        }
        if (lat_guest_elf_tracker_note_v2(tracker, fd, start, size, offset,
                                          4096, &info, &added,
                                          error, sizeof(error)) || added) {
            fprintf(stderr, "duplicate ELF mapping was registered twice\n");
            close(fd);
            lat_guest_elf_tracker_free_v2(tracker);
            return 1;
        }
        close(fd);
    }
    if (lat_guest_elf_tracker_count_v2(tracker) != 3) {
        fprintf(stderr, "wrong tracked ELF count\n");
        lat_guest_elf_tracker_free_v2(tracker);
        return 1;
    }
    const LatGuestElfInfoV2 *removed =
        lat_guest_elf_tracker_get_v2(tracker, 1);
    uint64_t removed_begin = removed->guest_begin;
    uint64_t removed_size = removed->guest_end - removed->guest_begin;
    if (lat_guest_elf_tracker_remove_range_v2(
            tracker, removed_begin, removed_size) != 1 ||
        lat_guest_elf_tracker_count_v2(tracker) != 2 ||
        lat_guest_elf_tracker_remove_range_v2(
            tracker, removed_begin, removed_size) != 0) {
        fprintf(stderr, "tracked ELF range removal failed\n");
        lat_guest_elf_tracker_free_v2(tracker);
        return 1;
    }
    lat_guest_elf_tracker_free_v2(tracker);
    puts("test-aot-v2-guest-elf-map: PASS modules=3 duplicates=0 removed=1");
    return 0;
}
