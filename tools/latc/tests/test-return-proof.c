#include "cfg_return_proof.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { const uint8_t *code; size_t size; } Image;
static bool read_code(const void *data, uint64_t pc, uint8_t bytes[15], size_t *size)
{
    const Image *image = data;
    if (pc < 0x1000 || pc - 0x1000 >= image->size) return false;
    *size = image->size - (pc - 0x1000);
    if (*size > 15) *size = 15;
    memcpy(bytes, image->code + pc - 0x1000, *size);
    return true;
}
static void check(const uint8_t *code, size_t size, uint16_t demanded,
                   bool expected, CfgReturnReason reason)
{
    Image image = {code, size};
    CfgReturnContext context = {read_code, &image, 10000, 8};
    CfgReturnProof proof;
    bool ok = cfg_prove_return_preservation(&context, 0x1000, demanded, &proof);
    if (ok != expected || proof.reason != reason)
        fprintf(stderr, "expected=%d/%s actual=%d/%s frontier=%#lx\n", expected,
            cfg_return_reason_name(reason), ok, cfg_return_reason_name(proof.reason),
            (unsigned long)proof.frontier);
    assert(ok == expected && proof.reason == reason);
    if (!ok) assert(!proof.preserved);
    else assert((proof.preserved & demanded) == demanded);
}
#define CHECK(demand, expected, reason, ...) do { \
    const uint8_t code[] = {__VA_ARGS__}; \
    check(code, sizeof(code), demand, expected, reason); \
} while (0)

static void check_context(void)
{
    /* A child writes an explicitly passed caller-local object. The saved R15,
     * caller return slot and child return slot remain separately protected. */
    uint8_t local[] = {
        0x41, 0x57, 0x48, 0x83, 0xec, 32,
        0x48, 0x8d, 0x7c, 0x24, 8,
        0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 7, 0, 0, 0,
        0x48, 0x83, 0xc4, 32, 0x41, 0x5f, 0xc3,
        0x48, 0x89, 0x07, 0xc3,
    };
    check(local, sizeof(local), 0x8000, true, CFG_RETURN_PROVED);
    local[10] = 32;
    check(local, sizeof(local), 0x8000, false, CFG_RETURN_CLOBBER);
    local[10] = 40;
    check(local, sizeof(local), 0x8000, false, CFG_RETURN_STACK);
    local[10] = 0xf8;
    check(local, sizeof(local), 0x8000, false, CFG_RETURN_STACK);
    /* A different activation's valid return token is not this child's token. */
    const uint8_t wrong_return[] = {
        0x48, 0x89, 0xe7, 0xe8, 1, 0, 0, 0, 0xc3,
        0x48, 0x8b, 0x07, 0x48, 0x89, 0x04, 0x24, 0xc3,
    };
    check(wrong_return, sizeof(wrong_return), 0, false, CFG_RETURN_STACK);
    /* The child publishes a known token into a caller slot. */
    const uint8_t output[] = {
        0x48, 0x83, 0xec, 8, 0x48, 0x89, 0xe7,
        0x4c, 0x89, 0xfe, 0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 9, 0, 0, 0,
        0x4c, 0x8b, 0x3c, 0x24, 0x48, 0x83, 0xc4, 8, 0xc3,
        0x48, 0x89, 0x37, 0xc3,
    };
    check(output, sizeof(output), 0x8000, true, CFG_RETURN_PROVED);
    /* A child-returned stack alias remains usable after RET. */
    const uint8_t alias[] = {
        0x41, 0x57, 0x48, 0x89, 0xe7, 0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 8, 0, 0, 0, 0x4c, 0x8b, 0x38,
        0x48, 0x83, 0xc4, 8, 0xc3,
        0x48, 0x89, 0xf8, 0xc3,
    };
    check(alias, sizeof(alias), 0x8000, true, CFG_RETURN_PROVED);
    /* Join every child return: one path invalidates the caller's saved slot. */
    const uint8_t branches[] = {
        0x41, 0x57, 0x48, 0x89, 0xe7, 0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
        0x74, 1, 0xc3, 0xc6, 0x07, 0, 0xc3,
    };
    check(branches, sizeof(branches), 0x8000, false, CFG_RETURN_CLOBBER);
    /* Revisiting a previously processed RET must weaken its summary. */
    const uint8_t weaken[] = {
        0x90, 0x74, 1, 0xc3, 0x41, 0xbf, 3, 0, 0, 0, 0xeb, 0xf4,
    };
    check(weaken, sizeof(weaken), 0x8000, false, CFG_RETURN_CLOBBER);
    /* Unknown writes still destroy caller saves even if a child explicitly
     * restores both return tokens and can return normally. */
    const uint8_t unknown_store[] = {
        0x41, 0x57, 0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
        0x4c, 0x8b, 0x14, 0x24, 0x4c, 0x8b, 0x5c, 0x24, 16,
        0x48, 0x89, 0x07, 0x4c, 0x89, 0x14, 0x24,
        0x4c, 0x89, 0x5c, 0x24, 16, 0xc3,
    };
    check(unknown_store, sizeof(unknown_store), 0x8000, false, CFG_RETURN_CLOBBER);
    /* A second visit to the CALL has lost its known stack argument. */
    const uint8_t call_loop[] = {
        0x41, 0x57, 0x48, 0x89, 0xe7, 0x41, 0xbf, 3, 0, 0, 0,
        0xe8, 13, 0, 0, 0, 0x4c, 0x8b, 0x38,
        0x74, 4, 0x31, 0xff, 0xeb, 0xf2,
        0x48, 0x83, 0xc4, 8, 0xc3,
        0x48, 0x89, 0xf8, 0xc3,
    };
    check(call_loop, sizeof(call_loop), 0x8000, false, CFG_RETURN_CLOBBER);
    /* A previous sibling's return token cannot satisfy another CALL. */
    const uint8_t sibling[] = {
        0x48, 0x83, 0xec, 8, 0x48, 0x89, 0xe7,
        0xe8, 10, 0, 0, 0, 0xe8, 13, 0, 0, 0,
        0x48, 0x83, 0xc4, 8, 0xc3,
        0x48, 0x8b, 0x04, 0x24, 0x48, 0x89, 0x07, 0xc3,
        0x48, 0x8b, 0x07, 0x48, 0x89, 0x04, 0x24, 0xc3,
    };
    check(sibling, sizeof(sibling), 0, false, CFG_RETURN_STACK);
}
int main(void)
{
    check_context();
    CHECK(0x9000, true, CFG_RETURN_PROVED, 0x40, 0x0f, 0x9c, 0xc6, 0xc3);
    CHECK(0x8000, false, CFG_RETURN_CLOBBER, 0x41, 0x0f, 0x95, 0xc7, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x40, 0x0f, 0x94, 0xc4, 0xc3);
    CHECK(1, false, CFG_RETURN_CLOBBER, 0x0f, 0x94, 0xc4, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0x48, 0x83, 0xec, 8, 0x0f, 0x94, 0x04, 0x24,
          0x48, 0x83, 0xc4, 8, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x0f, 0x94, 0x04, 0x24, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x0f, 0x94, 0x07, 0xc3);
    CHECK(0x8000, false, CFG_RETURN_CLOBBER,
          0x41, 0x57, 0x0f, 0x94, 0x44, 0x24, 7, 0x41, 0x5f, 0xc3);
    /* SETO memory access is READ in bundled metadata; still a byte write. */
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x0f, 0x90, 0x04, 0x24, 0xc3);
    CHECK(0x8000, false, CFG_RETURN_CLOBBER,
          0x41, 0x57, 0x0f, 0x90, 0x44, 0x24, 7, 0x41, 0x5f, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0x41, 0x57, 0x41, 0xbf, 3, 0, 0, 0, 0x41, 0x5f, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_CLOBBER, 0x41, 0xb7, 3, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x41, 0x57, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK,
          0x41, 0x57, 0x48, 0x89, 0x07, 0x41, 0x5f, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_CLOBBER,
          0x41, 0x57, 0xc6, 0x04, 0x24, 0, 0x41, 0x5f, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0x55, 0x48, 0x89, 0xe5, 0x41, 0x57,
          0x48, 0x83, 0xec, 8, 0x41, 0xbf, 3, 0, 0, 0,
          0x48, 0x83, 0xc4, 8, 0x41, 0x5f, 0x5d, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 3, 0, 0, 0, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_CLOBBER,
          0xe8, 1, 0, 0, 0, 0xc3, 0x41, 0xbf, 3, 0, 0, 0, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0xeb, 0, 0x90, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0x90, 0x75, 0xfd, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_NO_RETURN, 0xeb, 0xfe);
    CHECK(0x9000, false, CFG_RETURN_RECURSION, 0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_INDIRECT, 0xff, 0xe0);
    CHECK(0x9000, false, CFG_RETURN_UNSUPPORTED, 0xcc, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_UNSUPPORTED, 0x0f, 0x0b);
    CHECK(0x9000, false, CFG_RETURN_UNSUPPORTED, 0x74, 1, 0x41, 0x57, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_UNSUPPORTED, 0x0f, 0xb1, 0xcb, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_UNMAPPED, 0xeb, 0x7f);
    /* Saved tokens below caller SP cannot survive a child's return slot. */
    CHECK(0x9000, false, CFG_RETURN_CLOBBER,
          0x4c, 0x89, 0x7c, 0x24, 0xf8, 0xe8, 6, 0, 0, 0,
          0x4c, 0x8b, 0x7c, 0x24, 0xf8, 0xc3, 0xc3);
    /* Copying a stack address does not hide a partial overlapping store. */
    CHECK(0x9000, false, CFG_RETURN_CLOBBER,
          0x41, 0x57, 0x48, 0x89, 0xe0, 0xc6, 0x00, 0,
          0x41, 0x5f, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED,
          0x48, 0x83, 0xec, 8, 0x4c, 0x89, 0x3c, 0x24,
          0x41, 0xbf, 3, 0, 0, 0, 0x4c, 0x8b, 0x3c, 0x24,
          0x48, 0x83, 0xc4, 8, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_UNSUPPORTED,
          0x67, 0x48, 0x8d, 0x04, 0x24, 0xc3);
    CHECK(0x9000, true, CFG_RETURN_PROVED, 0x58, 0x50, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0xc6, 0x04, 0x24, 0, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK, 0x58, 0x57, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_CLOBBER,
          0x74, 1, 0xc3, 0x41, 0xbf, 3, 0, 0, 0, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_RECURSION,
          0xe8, 1, 0, 0, 0, 0xc3, 0xe8, 0xf5, 0xff, 0xff, 0xff, 0xc3);
    CHECK(0x9000, false, CFG_RETURN_STACK,
          0xe8, 1, 0, 0, 0, 0xc3, 0x48, 0x89, 0x07, 0xc3);
    const uint8_t ret[] = {0xc3};
    Image image = {ret, sizeof(ret)};
    CfgReturnContext context = {read_code, &image, 1, 1};
    CfgReturnProof proof;
    assert(cfg_prove_return_preservation(&context, 0x1000, 0x9000, &proof));
    context.instruction_budget = 0;
    assert(!cfg_prove_return_preservation(&context, 0x1000, 0x9000, &proof));
    assert(proof.reason == CFG_RETURN_BAD_INPUT && !proof.preserved);
    const uint8_t two[] = {0x90, 0xc3};
    image.code = two;
    image.size = sizeof(two);
    context.instruction_budget = 1;
    assert(!cfg_prove_return_preservation(&context, 0x1000, 0x9000, &proof));
    assert(proof.reason == CFG_RETURN_LIMIT && !proof.preserved);
    const uint8_t nested[] = {0xe8, 1, 0, 0, 0, 0xc3, 0xc3};
    image.code = nested;
    image.size = sizeof(nested);
    context.instruction_budget = 100;
    assert(!cfg_prove_return_preservation(&context, 0x1000, 0x9000, &proof));
    assert(proof.reason == CFG_RETURN_LIMIT && !proof.preserved);
    const uint8_t branches[] = {
        0x74, 7, 0x41, 0xbc, 3, 0, 0, 0, 0xc3,
        0x41, 0xbf, 3, 0, 0, 0, 0xc3,
    };
    image.code = branches;
    image.size = sizeof(branches);
    assert(cfg_prove_return_preservation(&context, 0x1000, 0, &proof));
    assert(proof.preserved == (uint16_t)~0x9000);
    puts("Return preservation: PASS");
    return 0;
}
