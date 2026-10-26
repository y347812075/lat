#include "elf_image.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ELF64_R_INFO
#define ELF64_R_INFO(symbol, type) (((uint64_t)(symbol) << 32) | (type))
#endif

typedef struct {
    unsigned char bytes[4096];
    ElfFile elf;
} Fixture;

static void initialize(Fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->elf = (ElfFile){.data = f->bytes, .size = sizeof(f->bytes),
        .eh = (void *)f->bytes, .sh = (void *)(f->bytes + 512)};
    *f->elf.eh = (Elf64_Ehdr){.e_type = ET_DYN, .e_phoff = 64, .e_phnum = 4,
        .e_phentsize = sizeof(Elf64_Phdr), .e_shnum = 4};
    Elf64_Phdr *p = (void *)(f->bytes + 64);
    p[0] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
        .p_vaddr = 0x1000, .p_filesz = 2048, .p_memsz = 2048};
    p[1] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_W,
        .p_vaddr = 0x3000, .p_offset = 2048, .p_filesz = 2048, .p_memsz = 2048};
    p[2] = (Elf64_Phdr){.p_type = PT_DYNAMIC, .p_vaddr = 0x3080,
        .p_offset = 2176, .p_filesz = 128, .p_memsz = 128};
    p[3] = (Elf64_Phdr){.p_type = PT_GNU_RELRO, .p_vaddr = 0x3000,
        .p_offset = 2048, .p_filesz = 2048, .p_memsz = 4096};
    Elf64_Shdr *s = f->elf.sh;
    s[1] = (Elf64_Shdr){.sh_type = SHT_PROGBITS, .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
        .sh_addr = 0x1400, .sh_offset = 1024, .sh_size = 32};
    s[2] = (Elf64_Shdr){.sh_type = SHT_PROGBITS, .sh_flags = SHF_ALLOC | SHF_WRITE,
        .sh_addr = 0x3000, .sh_offset = 2048, .sh_size = 32};
    s[3] = (Elf64_Shdr){.sh_type = SHT_RELA, .sh_flags = SHF_ALLOC,
        .sh_addr = 0x1500, .sh_offset = 1280, .sh_size = 24, .sh_entsize = 24};
    Elf64_Dyn *d = (void *)(f->bytes + 2176);
    d[0] = (Elf64_Dyn){.d_tag = DT_RELA, .d_un.d_val = 0x1500};
    d[1] = (Elf64_Dyn){.d_tag = DT_RELASZ, .d_un.d_val = 24};
    d[2] = (Elf64_Dyn){.d_tag = DT_RELAENT, .d_un.d_val = 24};
    Elf64_Rela *r = (void *)(f->bytes + 1280);
    *r = (Elf64_Rela){.r_offset = 0x3000,
        .r_info = ELF64_R_INFO(0, R_X86_64_RELATIVE), .r_addend = 0x1400};
    f->bytes[1024] = 0xc3;
}

static bool query(Fixture *f)
{
    ElfPointerIndex *index = elf_pointer_index_new(&f->elf);
    uint64_t target = 0;
    bool result = elf_read_immutable_pointer(index, 0x3000, &target);
    if (result) assert(target == 0x1400);
    elf_pointer_index_free(index);
    return result;
}

static bool byte_query(Fixture *f, uint64_t address, uint8_t expected)
{
    ElfPointerIndex *index = elf_pointer_index_new(&f->elf);
    uint8_t value = 0x5a;
    bool result = elf_read_immutable_byte(index, address, &value);
    if (result) assert(value == expected);
    else assert(value == 0x5a);
    elf_pointer_index_free(index);
    return result;
}

static void test_bytes(void)
{
    Fixture f;
    initialize(&f);
    Elf64_Phdr *p = (void *)(f.bytes + 64);
    Elf64_Dyn *d = (void *)(f.bytes + 2176);
    Elf64_Rela *r = (void *)(f.bytes + 1280);
    assert(byte_query(&f, 0x1400, 0xc3)); /* Read-only LOAD, no relocation. */
    assert(byte_query(&f, 0x301f, 0)); /* Last byte in allocated RELRO section. */
    f.bytes[2079] = 0x80;
    assert(byte_query(&f, 0x301f, 0x80));
    assert(!byte_query(&f, 0x3020, 0)); /* No allocated section owns the byte. */
    for (unsigned i = 0; i < 8; i++)
        assert(!byte_query(&f, 0x3000 + i, 0)); /* RELATIVE writes all eight bytes. */
    assert(byte_query(&f, 0x3008, 0));
    r[0].r_offset = 0x3001;
    assert(byte_query(&f, 0x3000, 0)); /* Adjacent following write is disjoint. */
    r[0].r_info = ELF64_R_INFO(0, R_X86_64_TLSDESC);
    r[0].r_offset = 0x2ff1;
    assert(!byte_query(&f, 0x3000, 0)); /* Widest write, starts 15 bytes earlier. */
    r[0].r_offset--;
    assert(byte_query(&f, 0x3000, 0));
    r[0].r_info = ELF64_R_INFO(0, R_X86_64_8);
    r[0].r_offset = 0x3000;
    assert(!byte_query(&f, 0x3000, 0));
    assert(byte_query(&f, 0x3001, 0));
    r[0].r_info = ELF64_R_INFO(0, R_X86_64_NONE);
    assert(byte_query(&f, 0x3000, 0));
    initialize(&f);
    p[3].p_type = PT_NULL;
    assert(!byte_query(&f, 0x301f, 0)); /* Writable even with raw known bytes. */
    p[1].p_flags = PF_R;
    assert(byte_query(&f, 0x301f, 0));
    p[1].p_flags = 0;
    assert(!byte_query(&f, 0x301f, 0));
    initialize(&f);
    p[3].p_memsz = 4095;
    assert(!byte_query(&f, 0x301f, 0)); /* Loader does not protect partial page. */
    initialize(&f);
    p[3].p_offset++;
    assert(!byte_query(&f, 0x301f, 0));
    initialize(&f);
    p[3] = p[1];
    assert(!byte_query(&f, 0x301f, 0)); /* Ambiguous LOAD mapping. */
    initialize(&f);
    p[1].p_filesz = 31;
    assert(!byte_query(&f, 0x301f, 0)); /* Zero-fill is not a raw file byte. */
    initialize(&f);
    f.elf.sh[2].sh_type = SHT_NOBITS;
    assert(!byte_query(&f, 0x301f, 0));
    initialize(&f);
    f.elf.sh[2].sh_offset++;
    assert(!byte_query(&f, 0x301f, 0));
    initialize(&f);
    f.elf.sh[0] = f.elf.sh[2];
    assert(!byte_query(&f, 0x301f, 0)); /* Ambiguous section ownership. */
    initialize(&f);
    f.elf.size--;
    assert(!byte_query(&f, 0x301f, 0)); /* Truncated loader segment. */
    initialize(&f);
    d[3].d_tag = DT_RELR;
    assert(!byte_query(&f, 0x301f, 0)); /* Unsupported relocation metadata. */
    initialize(&f);
    r[0].r_info = ELF64_R_INFO(0, R_X86_64_COPY);
    assert(!byte_query(&f, 0x301f, 0)); /* Unknown write extent. */
    initialize(&f);
    f.elf.sh[2].sh_size = 256;
    d[3].d_tag = DT_DEBUG;
    assert(!byte_query(&f, 0x30b8, 0)); /* Loader writes DT_DEBUG's value. */
    initialize(&f);
    d[3] = (Elf64_Dyn){.d_tag = DT_PLTGOT, .d_un.d_ptr = 0x3008};
    assert(!byte_query(&f, 0x3008, 0));
    assert(!byte_query(&f, 0x301f, 0)); /* Three reserved GOT words. */
    d[3].d_un.d_ptr--;
    assert(byte_query(&f, 0x301f, 0)); /* Adjacent byte is not reserved. */
    d[4] = d[3];
    assert(!byte_query(&f, 0x301f, 0)); /* Ambiguous loader metadata. */
    initialize(&f);
    d[3] = (Elf64_Dyn){.d_tag = DT_PLTGOT, .d_un.d_ptr = UINT64_MAX - 22};
    assert(!byte_query(&f, 0x301f, 0));
    initialize(&f);
    assert(!byte_query(&f, UINT64_MAX, 0));
    uint8_t value = 0x5a;
    assert(!elf_read_immutable_byte(NULL, 0x1400, &value));
    assert(value == 0x5a);
    ElfPointerIndex *index = elf_pointer_index_new(&f.elf);
    assert(index);
    assert(!elf_read_immutable_byte(index, 0x1400, NULL));
    elf_pointer_index_free(index);
}

int main(void)
{
    test_bytes();
    Fixture f;
    initialize(&f);
    assert(query(&f)); /* Slot bytes are zero: only RELA addend is meaningful. */
    Elf64_Phdr *p = (void *)(f.bytes + 64);
    Elf64_Dyn *d = (void *)(f.bytes + 2176);
    Elf64_Rela *r = (void *)(f.bytes + 1280);
    p[3].p_memsz += 32; /* GNU ld rounds RELRO past the LOAD's exact bytes. */
    assert(query(&f));
    p[3].p_memsz -= 32;
    p[3].p_memsz = 4095;
    assert(!query(&f)); /* A partial last page is not protected by the loader. */
    p[3].p_memsz = 4096;
    p[3].p_type = PT_NULL;
    assert(!query(&f)); /* Writable LOAD despite section naming conventions. */
    p[1].p_flags = PF_R;
    assert(query(&f));
    initialize(&f);
    p[3].p_memsz = 7;
    p[3].p_filesz = 7;
    assert(!query(&f));
    initialize(&f);
    p[3].p_offset++;
    assert(!query(&f)); /* RELRO must describe the same loader mapping. */
    initialize(&f);
    p[3] = p[1]; /* Ambiguous aliasing LOAD. */
    assert(!query(&f));
    initialize(&f);
    p[1].p_filesz = 7; /* Zero-fill tail cannot supply a pointer. */
    assert(!query(&f));
    initialize(&f);
    f.elf.sh[2].sh_type = SHT_NOBITS;
    assert(!query(&f));
    initialize(&f);
    f.elf.sh[2].sh_offset++;
    assert(!query(&f));
    initialize(&f);
    p[0].p_flags = PF_R;
    assert(!query(&f)); /* Executable section cannot override segment flags. */
    initialize(&f);
    r[0].r_info = ELF64_R_INFO(0, R_X86_64_IRELATIVE);
    assert(!query(&f)); /* Resolver address is not its returned pointer. */
    initialize(&f);
    r[0].r_info = ELF64_R_INFO(1, R_X86_64_RELATIVE);
    assert(!query(&f));
    initialize(&f);
    d[1].d_un.d_val = 48;
    f.elf.sh[3].sh_size = 48;
    r[1] = r[0];
    assert(!query(&f)); /* Duplicate even when equal. */
    r[1].r_offset = 0x2ff9;
    assert(!query(&f)); /* Overlapping write starting before the slot. */
    r[1].r_offset = 0x3007;
    assert(!query(&f));
    r[1].r_offset = 0x3010;
    assert(query(&f)); /* Disjoint write does not invalidate this slot. */
    r[1].r_info = ELF64_R_INFO(0, R_X86_64_COPY);
    assert(!query(&f)); /* Unknown write extent disables the index. */
    initialize(&f);
    d[0].d_tag = DT_DEBUG;
    assert(!query(&f)); /* A retained SHT_RELA alone is not loader evidence. */
    initialize(&f);
    d[3].d_tag = DT_RELR;
    assert(!query(&f));
    initialize(&f);
    d[3] = d[0];
    assert(!query(&f)); /* Ambiguous dynamic tag. */
    initialize(&f);
    d[3] = (Elf64_Dyn){.d_tag = DT_JMPREL, .d_un.d_val = 0x1500};
    d[4] = (Elf64_Dyn){.d_tag = DT_PLTRELSZ, .d_un.d_val = 24};
    d[5] = (Elf64_Dyn){.d_tag = DT_PLTREL, .d_un.d_val = DT_RELA};
    assert(!query(&f)); /* Overlapping loader relocation tables. */
    initialize(&f);
    d[1].d_un.d_val = 25;
    assert(!query(&f));
    initialize(&f);
    p[1].p_vaddr = UINT64_MAX - 3;
    assert(!query(&f));
    initialize(&f);
    r[0].r_offset = UINT64_MAX - 3;
    assert(!query(&f));
    puts("test-elf-pointer: PASS");
    return 0;
}
