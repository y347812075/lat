#include "cfg_decoder.h"
#include "ijmp_resolve.h"
#include "elf_image.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool resolve_mode(unsigned char *code, size_t size, size_t jump,
                          unsigned char *table, size_t table_size,
                          bool writable, IjmpResult *out)
{
    uint64_t starts[128];
    IjmpInbound inbound[128];
    size_t inbound_count = 0;
    size_t count = 0;
    for (size_t off = 0; off < size;) {
        Insn in = cfg_decode_insn(code, size, 0x1000, off);
        assert(in.len && count < 128);
        starts[count++] = 0x1000 + off;
        if (in.has_target) {
            size_t i = inbound_count++;
            while (i && inbound[i - 1].target > in.target) {
                inbound[i] = inbound[i - 1];
                i--;
            }
            inbound[i] = (IjmpInbound) {.source = in.addr, .target = in.target};
        }
        off += in.len;
    }
    IjmpSection sections[] = {
        {.addr = 0x2000, .size = table_size, .writable = writable},
        {.addr = 0x3000, .size = 32, .off = 32, .executable = true},
    };
    IjmpContext ctx = {
        .file = table, .file_size = 64,
        .sections = sections, .section_count = 2,
        .insn_addrs = starts, .insn_count = count,
        .inbound = inbound, .inbound_count = inbound_count,
        .inbound_complete = true,
        .func_addr = 0x1000, .func_size = size,
    };
    return ijmp_resolve_bounded_pic(&ctx, code, size, jump, out);
}

static bool resolve(unsigned char *code, size_t size, size_t jump,
                     unsigned char *table, size_t table_size, IjmpResult *out)
{
    return resolve_mode(code, size, jump, table, table_size, false, out);
}

static void test_store(void)
{
    unsigned char code[] = {
        0x83, 0xf8, 2, 0x77, 30,
        0x89, 0xc0, 0xc7, 0x07, 1, 0, 0, 0,
        0x48, 0x8d, 0x0d, 0xec, 0x0f, 0, 0,
        0x48, 0x63, 0x14, 0x81, 0x48, 0x01, 0xca, 0xff, 0xe2, 0xc3,
    };
    unsigned char table[64] = {0};
    int32_t entries[] = {0x1000, 0x1004, 0x1008};
    memcpy(table, entries, sizeof(entries));
    IjmpResult result;
    assert(resolve(code, sizeof(code), 27, table, 12, &result));
    code[7] = 0x83; /* add [rdi],1 changes flags but not bounded registers. */
    assert(!resolve(code, sizeof(code), 27, table, 12, &result));
}

static void test_guard_gap_and_alias(void)
{
    unsigned char code[] = {
        0x44, 0x89, 0xe3, 0x41, 0x83, 0xfc, 2,
        0x4c, 0x8b, 0x6d, 0x98, 0x77, 30,
        0x48, 0x8d, 0x05, 0xec, 0x0f, 0, 0,
        0x48, 0x63, 0x0c, 0x98, 0x48, 0x01, 0xc1, 0xff, 0xe1, 0xc3,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    unsigned char table[64] = {0};
    int32_t entries[] = {0x1000, 0x1004, 0x1008};
    memcpy(table, entries, sizeof(entries));
    IjmpResult result;
    assert(resolve(code, sizeof(code), 27, table, 12, &result));
    code[7] = 0x48;
    code[9] = 0x5d; /* Gap load overwrites EBX's alias. */
    assert(!resolve(code, sizeof(code), 27, table, 12, &result));
    memcpy(code, original, sizeof(code));
    code[1] = 0x01; /* ADD is not a copy; old alias is no longer valid. */
    assert(!resolve(code, sizeof(code), 27, table, 12, &result));
    memcpy(code, original, sizeof(code));
    code[8] = 0x03; /* ADD changes guard flags before JA. */
    assert(!resolve(code, sizeof(code), 27, table, 12, &result));
    memcpy(code, original, sizeof(code));
    unsigned char bypass[sizeof(code) + 2];
    bypass[0] = 0xeb;
    bypass[1] = 3; /* Enter CMP without executing the EBX copy. */
    memcpy(bypass + 2, code, sizeof(code));
    bypass[18] -= 2;
    assert(!resolve(bypass, sizeof(bypass), 29, table, 12, &result));
}

static void test_inbound(void)
{
    unsigned char code[] = {
        0x41, 0x83, 0xfc, 2, 0x77, 29,
        0x44, 0x89, 0xe0, 0xbb, 7, 0, 0, 0,
        0x48, 0x8d, 0x0d, 0xeb, 0x0f, 0, 0,
        0x48, 0x63, 0x14, 0x81, 0x48, 0x01, 0xca, 0xff, 0xe2, 0xc3,
    };
    unsigned char table[64] = {0};
    int32_t entries[] = {0x1000, 0x1004, 0x1008};
    memcpy(table, entries, sizeof(entries));
    IjmpSection sections[] = {
        {.addr = 0x2000, .size = 12},
        {.addr = 0x3000, .size = 32, .off = 32, .executable = true},
    };
    IjmpInbound inbound = {.source = 0x9000};
    IjmpContext ctx = {
        .file = table, .file_size = sizeof(table),
        .sections = sections, .section_count = 2,
        .func_addr = 0x1000, .inbound = &inbound,
    };
    IjmpResult out;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    ctx.inbound_complete = true;
    assert(ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    size_t protected[] = {4, 6, 14, 21, 25, 28};
    ctx.inbound_count = 1;
    for (size_t i = 0; i < sizeof(protected) / sizeof(protected[0]); i++) {
        inbound.target = 0x1000 + protected[i];
        assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
        assert(!out.count);
    }
    ctx.inbound_count = 0;
    unsigned char bypass[sizeof(code) + 2];
    bypass[0] = 0xeb;
    bypass[1] = 4; /* Skip CMP and enter JA using stale flags. */
    memcpy(bypass + 2, code, sizeof(code));
    bypass[19] -= 2;
    assert(!resolve(bypass, sizeof(bypass), 30, table, 12, &out));
}

static void test_load_permissions(void)
{
    unsigned char file[1024] = {0};
    Elf64_Ehdr header = {
        .e_shnum = 1, .e_phnum = 2, .e_phentsize = sizeof(Elf64_Phdr),
        .e_phoff = 128,
    };
    Elf64_Shdr section = {
        .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
        .sh_addr = 0x2000, .sh_size = 32, .sh_offset = 512,
    };
    Elf64_Phdr loads[] = {
        {.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
         .p_vaddr = 0x2000, .p_offset = 512, .p_filesz = 32, .p_memsz = 32},
        {.p_type = PT_NULL},
    };
    ElfFile elf = {.data = file, .size = sizeof(file),
        .eh = &header, .sh = &section};
    for (unsigned mode = 0; mode < 5; mode++) {
        loads[0].p_flags = PF_R | PF_X;
        loads[0].p_offset = 512;
        loads[1].p_type = PT_NULL;
        if (mode == 1) loads[0].p_flags |= PF_W;
        if (mode == 2) loads[0].p_flags = PF_R;
        if (mode == 3) loads[0].p_offset++;
        if (mode == 4) {
            loads[1] = loads[0];
            loads[1].p_flags = PF_R | PF_W;
        }
        memcpy(file + header.e_phoff, loads, sizeof(loads));
        size_t count;
        IjmpSection *sections = elf_build_ijmp_sections(&elf, &count);
        assert(count == 1);
        assert(sections[0].executable == (mode != 2 && mode != 3));
        assert(sections[0].writable == (mode == 1 || mode == 3 || mode == 4));
        free(sections);
    }
}

static void test_masked_relational_pic(void)
{
    unsigned char code[] = {
        0x83, 0xe0, 3, 0x83, 0xe1, 3, 0x39, 0xc1,
        0x74, 27, 0x77, 1, 0x91,
        0x48, 0x8d, 0x50, 3, 0x48, 0x29, 0xca,
        0x4c, 0x8d, 0x1d, 0xe5, 0x0f, 0, 0,
        0x49, 0x63, 0x0c, 0x93, 0x49, 0x8d, 0x0c, 0x0b,
        0xff, 0xe1, 0xc3,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    unsigned char file[64] = {0};
    int32_t entries[] = {0x1000, 0x1004, 0x1008, 0x100c};
    memcpy(file, entries, sizeof(entries));
    IjmpSection sections[] = {
        {.addr = 0x2000, .size = 12},
        {.addr = 0x3000, .size = 32, .off = 32, .executable = true},
    };
    IjmpInbound inbound = {.source = 0x9000};
    IjmpContext ctx = {
        .file = file, .file_size = sizeof(file),
        .sections = sections, .section_count = 2,
        .inbound = &inbound, .inbound_complete = true,
        .func_addr = 0x1000,
    };
    IjmpResult out;
    assert(ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    assert(out.count == 3 && out.table_addr == 0x2000);
    assert(out.targets[0] == 0x3008 && out.targets[2] == 0x3000);
    for (size_t size = 0; size < 37; size++) {
        assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, size, &out));
        assert(!out.count);
    }
    sections[0].writable = true;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    sections[0].writable = false;
    sections[0].size = 11;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    sections[0].size = 12;
    sections[1].executable = false;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    sections[1].executable = true;
    ctx.inbound_count = 1;
    const size_t bypass[] = {3, 6, 10, 13, 20, 27, 35};
    for (size_t i = 0; i < sizeof(bypass) / sizeof(bypass[0]); i++) {
        inbound.target = ctx.func_addr + bypass[i];
        assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    }
    ctx.inbound_count = 0;
    /* Removing the swap allows unsigned index underflow on half the paths. */
    code[12] = 0x90;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[10] = 0x7f; /* Signed guard not supported by this unsigned proof. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[10] = 0xe2; /* LOOP is not a flags-based unsigned condition. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[11] = 0xff; /* Backward edge cannot be silently bounded. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[8] = 0x90; /* Clobbers the equality bypass and instruction boundaries. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[23]++; /* Wrong table base, outside the complete read-only table. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[19] = 0xd2; /* SUB rdx,rdx rewrites the index, all paths target case 0. */
    assert(ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    assert(out.count == 1 && out.targets[0] == 0x3000);
    memcpy(code, original, sizeof(code));
    code[5] = 63; /* Different masks exceed the supplied table's domain. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    code[2] = 127; /* Explicit analysis resource bound, never truncate. */
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
    memcpy(code, original, sizeof(code));
    ctx.inbound_complete = false;
    assert(!ijmp_resolve_bounded_pic_entry(&ctx, code, sizeof(code), &out));
}

int main(void)
{
    /* cmp r12d,2; ja default; mov eax,r12d; mov ebx,7;
     * lea rcx,table; movsxd rdx,[rcx+rax*4]; add rdx,rcx; jmp rdx. */
    unsigned char code[] = {
        0x41, 0x83, 0xfc, 2, 0x77, 29,
        0x44, 0x89, 0xe0, 0xbb, 7, 0, 0, 0,
        0x48, 0x8d, 0x0d, 0xeb, 0x0f, 0, 0,
        0x48, 0x63, 0x14, 0x81, 0x48, 0x01, 0xca, 0xff, 0xe2,
        0xc3,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    unsigned char table[64] = {0};
    int32_t entries[] = {0x1000, 0x1004, 0x1008, 0x100c};
    memcpy(table, entries, sizeof(entries));
    IjmpResult out;
    assert(resolve(code, sizeof(code), 28, table, 16, &out));
    assert(out.count == 3 && out.targets[0] == 0x3000 &&
           out.targets[2] == 0x3008);
    /* Adjacent valid-looking fourth entry is not part of the proven table. */
    assert(out.targets[2] != 0x300c);
    assert(!resolve_mode(code, sizeof(code), 28, table, 16, true, &out));
    for (size_t size = 0; size < 30; size++) {
        assert(!resolve(code, size, 28, table, 16, &out));
    }
    code[10] = 0x90;
    assert(resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    code[9] = 0xb8; /* Unrelated write becomes an index overwrite. */
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    test_store();
    test_guard_gap_and_alias();
    test_inbound();
    test_load_permissions();
    test_masked_relational_pic();
    memcpy(code, original, sizeof(code));
    code[6] = 0x4c; /* A 64-bit copy does not zero-extend a 32-bit guard. */
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    code[0] = 0x49; /* 64-bit unsigned comparison proves full-width bound. */
    assert(resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    code[4] = 0x7f; /* Signed guard cannot establish a nonnegative index. */
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    code[5] = 8; /* Out-of-range path enters the dispatch. */
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    code[24] = 0x83; /* Wrong index/base combination. */
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    for (unsigned reg = 0; reg < 16; reg++) {
        code[0] = 0x40 | (reg >= 8);
        code[2] = 0xf8 | (reg & 7);
        code[6] = 0x40 | (reg >= 8 ? 4 : 0);
        code[8] = 0xc0 | ((reg & 7) << 3);
        assert(resolve(code, sizeof(code), 28, table, 16, &out));
    }
    memcpy(code, original, sizeof(code));
    code[9] = 0xeb; /* Another edge bypasses the register-copy proof. */
    code[10] = 10;
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    memcpy(code, original, sizeof(code));
    unsigned char taken[sizeof(code) + 1];
    memcpy(taken, code, 6);
    taken[4] = 0x76;
    taken[5] = 1;
    taken[6] = 0xc3;
    memcpy(taken + 7, code + 6, sizeof(code) - 6);
    taken[18]--;
    assert(resolve(taken, sizeof(taken), 29, table, 16, &out));
    taken[6] = 0x90; /* Out-of-range fallthrough also enters dispatch. */
    assert(!resolve(taken, sizeof(taken), 29, table, 16, &out));
    memcpy(code, original, sizeof(code));
    for (size_t size = 0; size < 12; size++) {
        assert(!resolve(code, sizeof(code), 28, table, size, &out));
    }
    entries[1] = 0x2000; /* A target outside the executable range. */
    memcpy(table, entries, sizeof(entries));
    assert(!resolve(code, sizeof(code), 28, table, 16, &out));
    puts("test-bounded-pic: PASS");
    return 0;
}
