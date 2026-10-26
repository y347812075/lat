#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "elf_image.h"

#include "common.h"

/*
 * ELF loading and address translation.
 *
 * All later modules operate on virtual addresses. This module is the only
 * place that knows how those virtual ranges map back to bytes in the file.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint8_t *read_file(const char *path, size_t *size_out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        die_errno(path);
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        die_errno("fstat");
    }
    if (st.st_size <= 0) {
        die("empty input file");
    }

    uint8_t *data = xmalloc((size_t)st.st_size);
    if (fread(data, 1, (size_t)st.st_size, fp) != (size_t)st.st_size) {
        die_errno("fread");
    }
    fclose(fp);
    *size_out = (size_t)st.st_size;
    return data;
}

/* Load and minimally validate the only ELF flavour this tool supports. */
void elf_load(const char *path, ElfFile *elf)
{
    elf->data = read_file(path, &elf->size);
    if (elf->size < sizeof(Elf64_Ehdr)) {
        die("file too small for ELF64 header");
    }

    elf->eh = (Elf64_Ehdr *)elf->data;
    if (memcmp(elf->eh->e_ident, ELFMAG, SELFMAG) != 0) {
        die("not an ELF file");
    }
    if (elf->eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf->eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        elf->eh->e_machine != EM_X86_64) {
        die("expected little-endian ELF64 x86-64 executable");
    }
    if (elf->eh->e_shentsize != sizeof(Elf64_Shdr)) {
        die("unexpected section header size");
    }
    if (!range_ok(elf->size, elf->eh->e_shoff,
                  (uint64_t)elf->eh->e_shnum * sizeof(Elf64_Shdr))) {
        die("section header table outside file");
    }

    elf->sh = (Elf64_Shdr *)(elf->data + elf->eh->e_shoff);
    if (elf->eh->e_shstrndx >= elf->eh->e_shnum) {
        die("bad shstrndx");
    }
    Elf64_Shdr *shstr = &elf->sh[elf->eh->e_shstrndx];
    if (!range_ok(elf->size, shstr->sh_offset, shstr->sh_size)) {
        die("section string table outside file");
    }
    elf->shstr = (const char *)elf->data + shstr->sh_offset;
}

/* A function symbol is usable only if it lives in executable bytes. */
bool elf_executable_section(const ElfFile *elf, unsigned idx)
{
    if (idx >= elf->eh->e_shnum) {
        return false;
    }
    return (elf->sh[idx].sh_flags & SHF_EXECINSTR) != 0;
}

/* Used to decide whether symbol discovery needs the .eh_frame fallback. */
bool elf_has_section_type(const ElfFile *elf, uint32_t type)
{
    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        if (elf->sh[i].sh_type == type) {
            return true;
        }
    }
    return false;
}

/* Section-name lookup is section-header based; stripped files still keep it. */
const Elf64_Shdr *elf_find_section_by_name(const ElfFile *elf,
                                              const char *name,
                                              unsigned *idx_out)
{
    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        const char *secname = elf->shstr + elf->sh[i].sh_name;
        if (strcmp(secname, name) == 0) {
            if (idx_out) {
                *idx_out = i;
            }
            return &elf->sh[i];
        }
    }
    return NULL;
}

/* Validate that an FDE or symbol range is fully inside one executable section. */
bool elf_find_exec_section_for_range(const ElfFile *elf, uint64_t addr,
                                        uint64_t size, unsigned *idx_out)
{
    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        Elf64_Shdr *sec = &elf->sh[i];
        if (!elf_executable_section(elf, i) || sec->sh_type == SHT_NOBITS) {
            continue;
        }
        if (addr >= sec->sh_addr && size <= sec->sh_size &&
            addr - sec->sh_addr <= sec->sh_size - size) {
            *idx_out = i;
            return true;
        }
    }
    return false;
}


void elf_free(ElfFile *elf)
{
    free(elf->data);
    memset(elf, 0, sizeof(*elf));
}

bool elf_function_file_offset(const ElfFile *elf, uint64_t addr,
                              uint64_t size, unsigned shndx,
                              uint64_t *off_out)
{
    if (shndx >= elf->eh->e_shnum) {
        return false;
    }
    Elf64_Shdr *sec = &elf->sh[shndx];
    if (addr < sec->sh_addr ||
        size > sec->sh_size ||
        addr - sec->sh_addr > sec->sh_size - size) {
        return false;
    }
    uint64_t off = sec->sh_offset + (addr - sec->sh_addr);
    if (!range_ok(elf->size, off, size)) {
        return false;
    }
    *off_out = off;
    return true;
}

/* Jump-table recovery needs every allocated byte range, not just .text. */
IjmpSection *elf_build_ijmp_sections(const ElfFile *elf, size_t *count_out)
{
    IjmpSection *sections = xmalloc((size_t)elf->eh->e_shnum * sizeof(*sections));
    size_t n = 0;

    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        Elf64_Shdr *sec = &elf->sh[i];
        if ((sec->sh_flags & SHF_ALLOC) == 0 || sec->sh_type == SHT_NOBITS ||
            sec->sh_size == 0) {
            continue;
        }
        if (!range_ok(elf->size, sec->sh_offset, sec->sh_size)) {
            continue;
        }
        bool mapped = false, executable = false;
        bool writable = (sec->sh_flags & SHF_WRITE) != 0;
        if (elf->eh->e_phentsize == sizeof(Elf64_Phdr) &&
            range_ok(elf->size, elf->eh->e_phoff,
                      (uint64_t)elf->eh->e_phnum * sizeof(Elf64_Phdr))) {
            const Elf64_Phdr *ph = (const void *)(elf->data + elf->eh->e_phoff);
            for (unsigned j = 0; j < elf->eh->e_phnum; j++) {
                if (ph[j].p_type != PT_LOAD) {
                    continue;
                }
                if (sec->sh_addr >= ph[j].p_vaddr &&
                    sec->sh_size <= ph[j].p_filesz &&
                    sec->sh_addr - ph[j].p_vaddr <=
                        ph[j].p_filesz - sec->sh_size &&
                    sec->sh_offset >= ph[j].p_offset &&
                    sec->sh_offset - ph[j].p_offset ==
                        sec->sh_addr - ph[j].p_vaddr) {
                    mapped = true;
                    executable |= (ph[j].p_flags & PF_X) != 0;
                }
                /* Any writable overlapping load defeats table immutability. */
                if ((ph[j].p_flags & PF_W) && ph[j].p_memsz &&
                    sec->sh_addr <= UINT64_MAX - (sec->sh_size - 1) &&
                    ph[j].p_vaddr <= UINT64_MAX - (ph[j].p_memsz - 1) &&
                    sec->sh_addr <= ph[j].p_vaddr + ph[j].p_memsz - 1 &&
                    ph[j].p_vaddr <= sec->sh_addr + sec->sh_size - 1) {
                    writable = true;
                }
            }
        }
        sections[n++] = (IjmpSection){
            .addr = sec->sh_addr,
            .size = sec->sh_size,
            .off = sec->sh_offset,
            .executable = mapped && executable &&
                (sec->sh_flags & SHF_EXECINSTR) != 0,
            .writable = !mapped || writable,
        };
    }

    *count_out = n;
    return sections;
}

typedef struct {
    Elf64_Rela relocation;
    unsigned width;
} PointerRelocation;

struct ElfPointerIndex {
    const ElfFile *elf;
    const Elf64_Phdr *segments;
    PointerRelocation *relocations;
    size_t count;
    uint64_t dynamic_address;
    uint64_t dynamic_size;
    uint64_t pltgot;
    bool has_pltgot;
};

static bool contains(uint64_t start, uint64_t length, uint64_t addr,
                       uint64_t size)
{
    return size && addr >= start && size <= length && addr - start <= length - size;
}

static bool overlaps(uint64_t a, uint64_t size_a, uint64_t b, uint64_t size_b)
{
    return size_a && size_b && (a <= b ? b - a < size_a : a - b < size_b);
}

/* Require one file mapping and reject even a partial competing LOAD. */
static const Elf64_Phdr *pointer_mapping(const ElfPointerIndex *index,
                                         uint64_t addr, uint64_t size,
                                         uint64_t *offset)
{
    const Elf64_Phdr *mapping = NULL;
    for (unsigned i = 0; i < index->elf->eh->e_phnum; i++) {
        const Elf64_Phdr *p = &index->segments[i];
        if (p->p_type != PT_LOAD || !overlaps(p->p_vaddr, p->p_memsz, addr, size))
            continue;
        if (mapping || !contains(p->p_vaddr, p->p_filesz, addr, size)) return NULL;
        mapping = p;
    }
    if (!mapping) return NULL;
    *offset = mapping->p_offset + addr - mapping->p_vaddr;
    return range_ok(index->elf->size, *offset, size) ? mapping : NULL;
}

static unsigned relocation_width(unsigned type)
{
    switch (type) {
    case R_X86_64_NONE: return 0;
    case R_X86_64_64: case R_X86_64_GLOB_DAT: case R_X86_64_JUMP_SLOT:
    case R_X86_64_RELATIVE: case R_X86_64_IRELATIVE:
    case R_X86_64_DTPMOD64: case R_X86_64_DTPOFF64: case R_X86_64_TPOFF64:
    case R_X86_64_PC64: case R_X86_64_SIZE64: return 8;
    case R_X86_64_PC32: case R_X86_64_32: case R_X86_64_32S:
    case R_X86_64_DTPOFF32: case R_X86_64_TPOFF32: case R_X86_64_SIZE32: return 4;
    case R_X86_64_16: case R_X86_64_PC16: return 2;
    case R_X86_64_8: case R_X86_64_PC8: return 1;
    case R_X86_64_TLSDESC: return 16;
    default: return UINT32_MAX; /* COPY and unknown writes are not bounded here. */
    }
}

static int compare_pointer_relocation(const void *a, const void *b)
{
    const PointerRelocation *x = a, *y = b;
    return (x->relocation.r_offset > y->relocation.r_offset) -
           (x->relocation.r_offset < y->relocation.r_offset);
}

static bool index_rela_table(ElfPointerIndex *index, uint64_t address,
                              uint64_t size)
{
    if (!size) return true;
    uint64_t offset;
    if (size % sizeof(Elf64_Rela) ||
        !pointer_mapping(index, address, size, &offset)) return false;
    bool section_match = false;
    const ElfFile *elf = index->elf;
    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        const Elf64_Shdr *s = &elf->sh[i];
        if (s->sh_type == SHT_RELA && (s->sh_flags & SHF_ALLOC) &&
            s->sh_addr == address && s->sh_offset == offset &&
            s->sh_size == size && s->sh_entsize == sizeof(Elf64_Rela))
            section_match = true;
    }
    if (!section_match) return false;
    for (uint64_t off = 0; off < size; off += sizeof(Elf64_Rela)) {
        Elf64_Rela rela;
        memcpy(&rela, elf->data + offset + off, sizeof(rela));
        unsigned width = relocation_width(ELF64_R_TYPE(rela.r_info));
        if (width == UINT32_MAX || (width && rela.r_offset > UINT64_MAX - (width - 1)))
            return false;
        if (width) index->relocations[index->count++] = (PointerRelocation){rela, width};
    }
    return true;
}

ElfPointerIndex *elf_pointer_index_new(const ElfFile *elf)
{
    if (!elf || (elf->eh->e_type != ET_DYN && elf->eh->e_type != ET_EXEC) ||
        elf->eh->e_phentsize != sizeof(Elf64_Phdr) ||
        !range_ok(elf->size, elf->eh->e_phoff,
                  (uint64_t)elf->eh->e_phnum * sizeof(Elf64_Phdr))) return NULL;
    ElfPointerIndex *index = xmalloc(sizeof(*index));
    *index = (ElfPointerIndex){.elf = elf,
        .segments = (const void *)(elf->data + elf->eh->e_phoff)};
    const Elf64_Phdr *dynamic = NULL;
    for (unsigned i = 0; i < elf->eh->e_phnum; i++) {
        const Elf64_Phdr *p = &index->segments[i];
        if (p->p_type == PT_LOAD || p->p_type == PT_GNU_RELRO || p->p_type == PT_DYNAMIC) {
            if (p->p_filesz > p->p_memsz ||
                p->p_memsz > UINT64_MAX - p->p_vaddr ||
                !range_ok(elf->size, p->p_offset, p->p_filesz)) goto unsupported;
        }
        if (p->p_type == PT_DYNAMIC) {
            if (dynamic) goto unsupported;
            dynamic = p;
        }
    }
    uint64_t mapped_offset;
    if (!dynamic || !dynamic->p_filesz || dynamic->p_filesz % sizeof(Elf64_Dyn) ||
        !pointer_mapping(index, dynamic->p_vaddr, dynamic->p_filesz, &mapped_offset) ||
        mapped_offset != dynamic->p_offset) goto unsupported;
    index->dynamic_address = dynamic->p_vaddr;
    index->dynamic_size = dynamic->p_memsz;
    enum {RELA, RELASZ, RELAENT, JMPREL, PLTRELSZ, PLTREL, TAGS};
    uint64_t values[TAGS] = {0};
    bool seen[TAGS] = {0}, terminated = false;
    for (uint64_t off = 0; off < dynamic->p_filesz; off += sizeof(Elf64_Dyn)) {
        Elf64_Dyn entry;
        memcpy(&entry, elf->data + dynamic->p_offset + off, sizeof(entry));
        if (entry.d_tag == DT_NULL) { terminated = true; break; }
        unsigned which;
        switch (entry.d_tag) {
        case DT_RELA: which = RELA; break;
        case DT_RELASZ: which = RELASZ; break;
        case DT_RELAENT: which = RELAENT; break;
        case DT_JMPREL: which = JMPREL; break;
        case DT_PLTRELSZ: which = PLTRELSZ; break;
        case DT_PLTREL: which = PLTREL; break;
        case DT_PLTGOT:
            if (index->has_pltgot || entry.d_un.d_ptr > UINT64_MAX - 23)
                goto unsupported;
            index->has_pltgot = true;
            index->pltgot = entry.d_un.d_ptr;
            continue;
        /* Do not claim uniqueness without decoding every dynamic write set. */
        case DT_REL: case DT_RELSZ: case DT_RELENT:
        case DT_RELR: case DT_RELRSZ: case DT_RELRENT:
        case 0x6000000f: case 0x60000010: /* Android packed REL */
        case 0x60000011: case 0x60000012: /* Android packed RELA */
        case 0x6fffe000: case 0x6fffe001: case 0x6fffe003: /* Android RELR */
            goto unsupported;
        default: continue;
        }
        if (seen[which]) goto unsupported;
        seen[which] = true;
        values[which] = entry.d_un.d_val;
    }
    if (!terminated || !seen[RELA] || !seen[RELASZ] || !seen[RELAENT] ||
        values[RELAENT] != sizeof(Elf64_Rela) ||
        (seen[JMPREL] != seen[PLTRELSZ]) ||
        (seen[JMPREL] && (!seen[PLTREL] || values[PLTREL] != DT_RELA)) ||
        values[RELASZ] > elf->size || values[PLTRELSZ] > elf->size ||
        overlaps(values[RELA], values[RELASZ], values[JMPREL], values[PLTRELSZ]))
        goto unsupported;
    size_t capacity = values[RELASZ] / sizeof(Elf64_Rela) +
                      values[PLTRELSZ] / sizeof(Elf64_Rela);
    if (capacity > SIZE_MAX / sizeof(*index->relocations)) goto unsupported;
    index->relocations = xmalloc((capacity ? capacity : 1) * sizeof(*index->relocations));
    if (!index_rela_table(index, values[RELA], values[RELASZ]) ||
        !index_rela_table(index, values[JMPREL], values[PLTRELSZ])) goto unsupported;
    qsort(index->relocations, index->count, sizeof(*index->relocations),
           compare_pointer_relocation);
    return index;
unsupported:
    elf_pointer_index_free(index);
    return NULL;
}

void elf_pointer_index_free(ElfPointerIndex *index)
{
    if (index) { free(index->relocations); free(index); }
}

static bool immutable_file_offset(const ElfPointerIndex *index, uint64_t address,
                                  uint64_t size, uint64_t *offset)
{
    if (!index || !size || address > UINT64_MAX - (size - 1)) return false;
    const ElfFile *elf = index->elf;
    const Elf64_Phdr *mapping = pointer_mapping(index, address, size, offset);
    if (!mapping || !(mapping->p_flags & PF_R)) return false;
    bool immutable = !(mapping->p_flags & PF_W);
    for (unsigned i = 0; i < elf->eh->e_phnum; i++) {
        const Elf64_Phdr *p = &index->segments[i];
        /* x86 linux-user reports 4 KiB AT_PAGESZ (target/i386/cpu-param.h).
         * The loader rounds both RELRO endpoints down, not the end upward. */
        uint64_t protected_start = p->p_vaddr & ~UINT64_C(4095);
        uint64_t protected_end = (p->p_vaddr + p->p_memsz) & ~UINT64_C(4095);
        if (p->p_type == PT_GNU_RELRO &&
            contains(mapping->p_vaddr, mapping->p_memsz, p->p_vaddr, 1) &&
            p->p_offset >= mapping->p_offset &&
            p->p_offset - mapping->p_offset == p->p_vaddr - mapping->p_vaddr &&
            contains(p->p_vaddr, p->p_memsz, address, size) &&
            protected_end >= protected_start &&
            contains(protected_start, protected_end - protected_start, address, size))
            immutable = true;
    }
    if (!immutable) return false;
    unsigned matches = 0;
    for (unsigned i = 0; i < elf->eh->e_shnum; i++) {
        const Elf64_Shdr *s = &elf->sh[i];
        if ((s->sh_flags & SHF_ALLOC) && s->sh_type != SHT_NOBITS &&
            contains(s->sh_addr, s->sh_size, address, size) &&
            range_ok(elf->size, s->sh_offset, s->sh_size) &&
            s->sh_offset + address - s->sh_addr == *offset) matches++;
    }
    return matches == 1;
}

static size_t first_possible_relocation(const ElfPointerIndex *index,
                                         uint64_t address)
{
    size_t lo = 0, hi = index->count;
    /* TLSDESC is the widest accepted write (16 bytes). */
    uint64_t first = address >= 15 ? address - 15 : 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (index->relocations[mid].relocation.r_offset < first) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

bool elf_read_immutable_byte(const void *data, uint64_t address, uint8_t *value)
{
    const ElfPointerIndex *index = data;
    uint64_t offset;
    if (!value || !immutable_file_offset(index, address, 1, &offset)) return false;
    /* The loader updates dynamic entries and the reserved x86-64 GOT words
     * independently of relocation records, before applying RELRO. */
    if (overlaps(address, 1, index->dynamic_address, index->dynamic_size) ||
        (index->has_pltgot && overlaps(address, 1, index->pltgot, 24))) return false;
    for (size_t i = first_possible_relocation(index, address); i < index->count; i++) {
        const PointerRelocation *r = &index->relocations[i];
        if (r->relocation.r_offset > address) break;
        if (overlaps(address, 1, r->relocation.r_offset, r->width)) return false;
    }
    *value = index->elf->data[offset];
    return true;
}

bool elf_read_immutable_pointer(const void *data, uint64_t slot, uint64_t *target)
{
    const ElfPointerIndex *index = data;
    uint64_t offset;
    if (!target || !immutable_file_offset(index, slot, 8, &offset)) return false;
    const ElfFile *elf = index->elf;
    const Elf64_Rela *relative = NULL;
    for (size_t i = first_possible_relocation(index, slot); i < index->count; i++) {
        const PointerRelocation *r = &index->relocations[i];
        if (r->relocation.r_offset > slot + 7) break;
        if (!overlaps(slot, 8, r->relocation.r_offset, r->width)) continue;
        if (relative || r->relocation.r_offset != slot ||
            ELF64_R_TYPE(r->relocation.r_info) != R_X86_64_RELATIVE ||
            ELF64_R_SYM(r->relocation.r_info)) return false;
        relative = &r->relocation;
    }
    if (!relative) return false;
    uint64_t address = (uint64_t)relative->r_addend;
    const Elf64_Phdr *mapping = pointer_mapping(index, address, 1, &offset);
    unsigned section;
    uint64_t section_offset;
    if (!mapping || !(mapping->p_flags & PF_X) ||
        !elf_find_exec_section_for_range(elf, address, 1, &section) ||
        !elf_function_file_offset(elf, address, 1, section, &section_offset) ||
        section_offset != offset) return false;
    *target = address;
    return true;
}


/* Keep got_plt independent from the concrete ElfFile owner type. */
GotPltElf elf_gotplt_view(const ElfFile *elf)
{
    return (GotPltElf){
        .data = elf->data,
        .size = elf->size,
        .eh = elf->eh,
        .sh = elf->sh,
        .shstr = elf->shstr,
    };
}

const char *elf_type_name(uint16_t type)
{
    switch (type) {
    case ET_EXEC:
        return "EXEC";
    case ET_DYN:
        return "DYN";
    case ET_REL:
        return "REL";
    default:
        return "OTHER";
    }
}

static bool has_program_header_type(const ElfFile *elf, uint32_t type)
{
    if (elf->eh->e_phoff == 0 || elf->eh->e_phentsize != sizeof(Elf64_Phdr) ||
        !range_ok(elf->size, elf->eh->e_phoff,
                  (uint64_t)elf->eh->e_phnum * sizeof(Elf64_Phdr))) {
        return false;
    }

    Elf64_Phdr *ph = (Elf64_Phdr *)(elf->data + elf->eh->e_phoff);
    for (unsigned i = 0; i < elf->eh->e_phnum; i++) {
        if (ph[i].p_type == type) {
            return true;
        }
    }
    return false;
}

/* PT_INTERP is the practical dynamic-linking marker for executables here. */
const char *elf_linking_kind(const ElfFile *elf)
{
    return has_program_header_type(elf, PT_INTERP) ? "dynamic" : "static";
}
