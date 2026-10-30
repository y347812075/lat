#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "source-elf.h"
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(char *error, size_t size, const char *message)
{
    if (error && size) snprintf(error, size, "%s", message);
    return -1;
}

int latcd_validate_x86_elf(int fd, uint64_t file_size, char *error, size_t error_size)
{
    Elf64_Ehdr header;
    if (file_size < sizeof(header) || pread(fd, &header, sizeof(header), 0) != sizeof(header))
        return fail(error, error_size, "source is too small for an ELF header");
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
        (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
        header.e_phoff > file_size ||
        header.e_phnum > (file_size - header.e_phoff) / sizeof(Elf64_Phdr))
        return fail(error, error_size, "source is not a supported x86-64 executable ELF");
    int executable_load = 0;
    for (uint16_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr program;
        off_t offset = header.e_phoff + (off_t)i * sizeof(program);
        if (pread(fd, &program, sizeof(program), offset) != sizeof(program) ||
            program.p_offset > file_size || program.p_filesz > file_size - program.p_offset)
            return fail(error, error_size, "source ELF program headers are invalid");
        if (program.p_type == PT_LOAD && (program.p_flags & PF_X)) executable_load = 1;
    }
    return executable_load ? 0 : fail(error, error_size, "source ELF has no executable PT_LOAD");
}
