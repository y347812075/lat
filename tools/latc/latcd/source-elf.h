#ifndef LATCD_SOURCE_ELF_H
#define LATCD_SOURCE_ELF_H
#include <stddef.h>
#include <stdint.h>
int latcd_validate_x86_elf(int fd, uint64_t file_size, char *error, size_t error_size);
#endif
