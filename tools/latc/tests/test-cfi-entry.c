#include "ijmp_resolve.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t slots[3];
    uint64_t targets[3];
    unsigned count;
    unsigned calls;
    bool fail_second;
    bool fail_byte;
} Pointers;

static void test_split(IjmpContext *ctx, Pointers *pointers)
{
    uint8_t code[] = {
        0xb9, 3, 0, 0, 0, 0x44, 0x0f, 0xb6, 0xf9,
        0xb1, 64, 0x44, 0x28, 0xf9, 0x44, 0x0f, 0xb6, 0xe1,
        0x48, 0x89, 0xc2, /* proof_start=18; copy rax->rdx */
        0x48, 0x8d, 0x0d, 0xe4, 0x0f, 0, 0, /* base=2000 */
        0x48, 0x29, 0xca, 0x48, 0x89, 0xd6,
        0x44, 0x89, 0xf9, 0x48, 0xd3, 0xee,
        0x44, 0x89, 0xe1, 0x48, 0xd3, 0xe2,
        0x48, 0x09, 0xf2, 0x48, 0x83, 0xfa, 1, 0x77, 0x40,
        0xff, 0x50, 0x28,
    };
    uint8_t original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    pointers->count = 2;
    pointers->slots[0] = 0x2028;
    pointers->slots[1] = 0x2030;
    IjmpResult result;
    assert(ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    assert(result.count == 2 && result.table_addr == 0x2000);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_split_cfi_entry(ctx, code, size, 18, &result));
        assert(!result.count);
    }
    for (size_t byte = 19; byte < sizeof(code); byte++) {
        IjmpInbound edge = {.source = 0x9000, .target = 0x1000 + byte};
        ctx->inbound = &edge;
        ctx->inbound_count = 1;
        assert(!ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18,
                                            &result));
    }
    IjmpInbound backedge = {.source = 0x9000, .target = 0x1012};
    ctx->inbound = &backedge;
    ctx->inbound_count = 1;
    assert(!ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    ctx->inbound_count = 0;
    ctx->inbound = NULL;
    const unsigned offsets[] = {10, 36, 39, 45, 48, 53, 56};
    const uint8_t values[] = {63, 0xf1, 0xfe, 0xe6, 0xd2, 0x7f, 0x51};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        code[offsets[i]] = values[i];
        assert(!ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18,
                                            &result));
        assert(!result.count);
        memcpy(code, original, sizeof(code));
    }
    pointers->fail_second = true;
    assert(!ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    assert(!result.count);
    pointers->fail_second = false;
    /* Counts are masked to six bits, including the identity rotation. */
    code[1] = 0;
    pointers->slots[1] = 0x2029;
    assert(ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    code[1] = 63;
    pointers->slots[1] = UINT64_C(0x8000000000002028);
    assert(ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    code[1] = 67;
    pointers->slots[1] = 0x2030;
    assert(ijmp_resolve_split_cfi_entry(ctx, code, sizeof(code), 18, &result));
    memcpy(code, original, sizeof(code));
    /* A CALL before initialization is harmless; after it kills the facts. */
    uint8_t call[sizeof(code) + 5];
    memcpy(call, code, 18);
    call[18] = 0xe8;
    memset(call + 19, 0, 4);
    memcpy(call + 23, code + 18, sizeof(code) - 18);
    assert(!ijmp_resolve_split_cfi_entry(ctx, call, sizeof(call), 23, &result));
    pointers->slots[1] = 0x2068;
}

static bool read_byte(const void *data, uint64_t address, uint8_t *value)
{
    const Pointers *p = data;
    if (address < 0x4000 || address > 0x41e1 || p->fail_byte) return false;
    *value = address == 0x4000 || address == 0x41e1 ? 0x80 : 0;
    return true;
}

static bool read_pointer(const void *data, uint64_t slot, uint64_t *target)
{
    Pointers *pointers = (Pointers *)data;
    pointers->calls++;
    for (unsigned i = 0; i < pointers->count; i++) {
        if (slot == pointers->slots[i] && !(i && pointers->fail_second)) {
            *target = pointers->targets[i];
            return true;
        }
    }
    return false;
}

static void test_register_dispatch(IjmpContext *ctx, Pointers *pointers)
{
    unsigned char code[] = {
        0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0,
        0x48, 0x89, 0xc2, 0x48, 0x29, 0xca,
        0x48, 0xc1, 0xca, 6, 0x48, 0x83, 0xfa, 1,
        0x77, 0x6b,
        0x48, 0x8b, 0x40, 0x28, /* mov rax,[rax+40] */
        0x48, 0x89, 0xdf,       /* mov rdi,rbx */
        0x31, 0xf6,             /* xor esi,esi */
        0x48, 0x83, 0xc4, 8,   /* add rsp,8 */
        0x5b, 0x41, 0x5e, 0x5d,
        0xff, 0xe0,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    pointers->count = 2;
    pointers->slots[0] = 0x2028;
    pointers->slots[1] = 0x2068;
    IjmpResult result;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(result.count == 2);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_cfi_entry(ctx, code, size, &result));
        assert(!result.count);
    }
    for (size_t byte = 1; byte < sizeof(code); byte++) {
        IjmpInbound inbound = {.source = 0x9000, .target = 0x1000 + byte};
        ctx->inbound = &inbound;
        ctx->inbound_count = 1;
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    }
    ctx->inbound = NULL;
    ctx->inbound_count = 0;
    const unsigned offsets[] = {23, 25, 29, 31, 35, 36, 41};
    const unsigned char values[] = {0x40, 0x60, 0xd8, 0xc0, 0x80, 0x58, 0xe1};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        code[offsets[i]] = values[i];
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
        assert(!result.count);
        memcpy(code, original, sizeof(code));
    }
    code[41] = 0xd0; /* Register CALL is also a proven control transfer. */
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[22] = sizeof(code) - 23 - 1; /* Reject enters last opcode byte. */
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    pointers->fail_second = true;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->fail_second = false;
    /* Target can be a high register distinct from the constrained pointer. */
    code[23] = 0x4c;
    code[39] = 0x41;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
}

static void test_bit_filter(IjmpContext *ctx, Pointers *pointers)
{
    unsigned char code[] = {
        0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0,
        0x48, 0x89, 0xc2, 0x48, 0x29, 0xca,
        0x48, 0xc1, 0xca, 6, 0x48, 0x83, 0xfa, 2,
        0x77, 0x6b,
        0x49, 0xbf, 5, 0, 0, 0, 0, 0, 0, 0, /* movabs r15,5 */
        0x49, 0x0f, 0xa3, 0xd7, /* bt r15,rdx */
        0x73, 0x5b,
        0x48, 0x8b, 0x75, 0xd0, 0xff, 0x50, 0x28,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    pointers->count = 2;
    pointers->slots[0] = 0x2028;
    pointers->slots[1] = 0x20a8;
    pointers->calls = 0;
    IjmpResult result;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(result.count == 2 && pointers->calls == 2);
    assert(result.targets[0] == 0x3000 && result.targets[1] == 0x3010);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_cfi_entry(ctx, code, size, &result));
        assert(!result.count);
    }
    for (size_t byte = 1; byte < sizeof(code); byte++) {
        IjmpInbound inbound = {.source = 0x9000, .target = 0x1000 + byte};
        ctx->inbound = &inbound;
        ctx->inbound_count = 1;
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    }
    ctx->inbound = NULL;
    ctx->inbound_count = 0;
    const unsigned offsets[] = {23, 33, 35, 36, 37, 38};
    const unsigned char invalid[] = {0x41, 0x41, 0xab, 0xf7, 0x72, 0};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        code[offsets[i]] = invalid[i];
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
        assert(!result.count);
        memcpy(code, original, sizeof(code));
    }
    code[24] = 0xba; /* Constant overwrites the constrained index RDX. */
    code[23] = 0x48;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[24] = 0xb8; /* Constant overwrites the source pointer RAX. */
    code[23] = 0x48;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[25] = 0; /* Empty domain must not return a successful proof. */
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    memcpy(code, original, sizeof(code));
    pointers->fail_second = true;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->fail_second = false;
    /* BT wraps the bit index, but the pointer inverse must not wrap at 64. */
    code[20] = 64;
    code[25] = 1;
    pointers->slots[1] = 0x3028;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(result.count == 2);
    memcpy(code, original, sizeof(code));
    pointers->slots[1] = 0x20a8;
    unsigned char near_jump[sizeof(code) + 4];
    memcpy(near_jump, code, 37);
    near_jump[37] = 0x0f;
    near_jump[38] = 0x83;
    near_jump[39] = 0x5b;
    memset(near_jump + 40, 0, 3);
    memcpy(near_jump + 43, code + 39, sizeof(code) - 39);
    assert(ijmp_resolve_cfi_entry(ctx, near_jump, sizeof(near_jump), &result));
    /* The constant can reuse the no-longer-live base register RCX. */
    code[23] = 0x48;
    code[24] = 0xb9;
    code[33] = 0x48;
    code[36] = 0xd1;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
}

static void test_byte_filter(IjmpContext *ctx, Pointers *pointers)
{
    unsigned char code[] = {
        0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0,
        0x48, 0x89, 0xc2, 0x48, 0x29, 0xca,
        0x48, 0xc1, 0xca, 3,
        0x48, 0x81, 0xfa, 0xe1, 1, 0, 0, /* cmp rdx,481 */
        0x77, 0x60,
        0x48, 0x8d, 0x0d, 0xdf, 0x2f, 0, 0, /* lea rcx,4000 */
        0xf6, 0x04, 0x11, 0x80, /* test byte [rcx+rdx],80 */
        0x74, 0x50,
        0xff, 0x50, 0x28,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    pointers->count = 2;
    pointers->slots[0] = 0x2028;
    pointers->slots[1] = 0x2f30;
    ctx->read_immutable_byte = read_byte;
    IjmpResult result;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(result.count == 2);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_cfi_entry(ctx, code, size, &result));
        assert(!result.count);
    }
    for (size_t byte = 1; byte < sizeof(code); byte++) {
        IjmpInbound inbound = {.source = 0x9000, .target = 0x1000 + byte};
        ctx->inbound = &inbound;
        ctx->inbound_count = 1;
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
        assert(!result.count);
    }
    ctx->inbound = NULL;
    ctx->inbound_count = 0;
    const unsigned offsets[] = {21, 24, 26, 29, 30, 33, 34, 35, 36, 37};
    const unsigned char values[] = {2, 0x76, 0x4c, 0xde, 0xff, 0xf7,
                                   0x0c, 0x51, 0, 0x75};
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
        code[offsets[i]] = values[i];
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
        assert(!result.count);
        memcpy(code, original, sizeof(code));
    }
    pointers->fail_byte = true;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->fail_byte = false;
    pointers->fail_second = true;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->fail_second = false;
    ctx->read_immutable_byte = NULL;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->slots[1] = 0x2068;
}

static void test_narrow_bit_filter(IjmpContext *ctx, Pointers *pointers)
{
    unsigned char code[] = {
        0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0,
        0x48, 0x89, 0xc2, 0x48, 0x29, 0xca,
        0x48, 0xc1, 0xca, 6, 0x48, 0x83, 0xfa, 32,
        0x77, 0x6b,
        0xbe, 1, 0, 0, 0, /* mov esi,1 */
        0x0f, 0xa3, 0xd6, /* bt esi,edx: indices0 and32 accepted */
        0x73, 0x5b,
        0x41, 0x0f, 0xb6, 0x77, 8, /* movzx esi,byte [r15+8] */
        0xff, 0x50, 0x28,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    pointers->count = 2;
    pointers->slots[0] = 0x2028;
    pointers->slots[1] = 0x2828;
    pointers->calls = 0;
    IjmpResult result;
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(result.count == 2 && pointers->calls == 2);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_cfi_entry(ctx, code, size, &result));
        assert(!result.count);
    }
    for (size_t byte = 1; byte < sizeof(code); byte++) {
        IjmpInbound inbound = {.source = 0x9000, .target = 0x1000+byte};
        ctx->inbound = &inbound;
        ctx->inbound_count = 1;
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    }
    ctx->inbound = NULL;
    ctx->inbound_count = 0;
    const unsigned offsets[] = {23, 28, 30, 31, 33, 35, 36};
    const unsigned char values[] = {0xba, 0xab, 0xc6, 0x72, 0x66, 0xbe, 0x47};
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
        code[offsets[i]] = values[i];
        assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
        assert(!result.count);
        memcpy(code, original, sizeof(code));
    }
    pointers->fail_second = true;
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    assert(!result.count);
    pointers->fail_second = false;
    code[35] = 0xb7; /* Word source is also a read-only zero extension. */
    assert(ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[36] = 0xc0; /* Destination EAX destroys constrained pointer. */
    assert(!ijmp_resolve_cfi_entry(ctx, code, sizeof(code), &result));
    pointers->slots[1] = 0x2068;
}

int main(void)
{
    unsigned char code[] = {
        0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0,
        0x48, 0x89, 0xc2, 0x48, 0x29, 0xca,
        0x48, 0xc1, 0xca, 6, 0x48, 0x83, 0xfa, 1,
        0x77, 0x6b, 0x48, 0x8b, 0x75, 0xd0, 0xff, 0x50, 0x28,
    };
    unsigned char original[sizeof(code)];
    memcpy(original, code, sizeof(code));
    IjmpSection executable = {.addr = 0x3000, .size = 32, .executable = true};
    unsigned char file[32] = {0};
    Pointers pointers = {.slots = {0x2028, 0x2068}, .targets = {0x3000, 0x3010},
                         .count = 2};
    IjmpContext ctx = {
        .file = file, .file_size = sizeof(file),
        .sections = &executable, .section_count = 1,
        .inbound_complete = true, .func_addr = 0x1000,
        .read_immutable_pointer = read_pointer, .pointer_data = &pointers,
    };
    IjmpResult result;
    test_byte_filter(&ctx, &pointers);
    test_narrow_bit_filter(&ctx, &pointers);
    test_register_dispatch(&ctx, &pointers);
    test_split(&ctx, &pointers);
    assert(ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    assert(result.count == 2 && result.targets[0] == 0x3000 &&
           result.targets[1] == 0x3010 && result.table_addr == 0x2000);
    for (size_t size = 0; size < sizeof(code); size++) {
        assert(!ijmp_resolve_cfi_entry(&ctx, code, size, &result));
        assert(!result.count);
    }
    for (size_t byte = 1; byte < sizeof(code); byte++) {
        IjmpInbound inbound = {.source = 0x9000, .target = 0x1000 + byte};
        ctx.inbound = &inbound;
        ctx.inbound_count = 1;
        assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    }
    ctx.inbound = NULL;
    ctx.inbound_count = 0;
    ctx.inbound_complete = false;
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    ctx.inbound_complete = true;
    const unsigned offsets[] = {0, 7, 10, 13, 17};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        code[offsets[i]] = 0x40; /* A 32-bit operation loses pointer semantics. */
        assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
        memcpy(code, original, sizeof(code));
    }
    code[21] = 0x7f; /* Signed guard. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[22] = 2; /* Rejected path enters dispatch. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[25] = 0x45; /* Gap load overwrites pointer RAX. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[20] = 0x80; /* Sign-extended negative bound is not a small set. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[28] = 0x51; /* Wrong pointer register. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    pointers.fail_second = true;
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    assert(!result.count); /* No partial result when any exact slot fails. */
    pointers.fail_second = false;
    pointers.targets[1] = 0x4000;
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    pointers.targets[1] = 0x3010;
    code[16] = 63;
    pointers.slots[1] = UINT64_C(0x8000000000002028);
    assert(ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    code[16] = 0;
    pointers.slots[1] = 0x2029;
    assert(ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    code[16] = 63;
    code[20] = 2;
    pointers.count = 3;
    pointers.slots[1] = UINT64_C(0x8000000000002028);
    pointers.slots[2] = 0x2029; /* ROL64(2,63)==1, not (2<<63)==0. */
    pointers.targets[2] = 0x3008;
    assert(ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    assert(result.count == 3);
    memcpy(code, original, sizeof(code));
    pointers.count = 2;
    pointers.slots[1] = 0x2068;
    unsigned char near_jump[sizeof(code) + 4];
    memcpy(near_jump, code, 21);
    near_jump[21] = 0x0f;
    near_jump[22] = 0x87;
    near_jump[23] = 0x6b;
    memset(near_jump + 24, 0, 3);
    memcpy(near_jump + 27, code + 23, sizeof(code) - 23);
    assert(ijmp_resolve_cfi_entry(&ctx, near_jump, sizeof(near_jump), &result));
    code[27] = 0x41; /* REX.B: call [r8+disp] but original pointer is RAX. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[2] = 0x15; /* Base RDX aliases scratch RDX. */
    assert(!ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    memcpy(code, original, sizeof(code));
    code[20] = 0;
    pointers.calls = 0;
    assert(ijmp_resolve_cfi_entry(&ctx, code, sizeof(code), &result));
    assert(result.count == 1 && pointers.calls == 1);
    test_bit_filter(&ctx, &pointers);
    puts("test-cfi-entry: PASS");
    return 0;
}
