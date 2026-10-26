#include "cfg_decoder.h"

#include <assert.h>
#include <glib.h>
#include <stdio.h>

#define B(n) (UINT16_C(1) << (n))

static void check(const uint8_t *code, size_t size, uint16_t expected)
{
    uint16_t mask = 0x5a5a;
    bool decoded = cfg_insn_gpr_writes(code, size, &mask);
    if (!decoded) {
        fprintf(stderr, "rejected:");
        for (size_t i = 0; i < size; i++) fprintf(stderr, " %02x", code[i]);
        fprintf(stderr, "\n");
    }
    assert(decoded);
    assert(mask == expected);
    for (size_t truncated = 0; truncated < size; truncated++) {
        mask = 0x5a5a;
        if (!cfg_insn_gpr_writes(code, truncated, &mask))
            assert(mask == 0x5a5a);
    }
}

#define CHECK(mask, ...) do { \
    const uint8_t code[] = {__VA_ARGS__}; \
    check(code, sizeof(code), (mask)); \
} while (0)

static gpointer exercise(gpointer unused)
{
    (void)unused;
    CHECK(B(12), 0x41, 0xbc, 3, 0, 0, 0); /* mov r12d,3 */
    CHECK(B(12), 0x66, 0x41, 0xbc, 3, 0);
    CHECK(B(12), 0x41, 0xb4, 3);
    CHECK(B(0), 0xb4, 3); /* AH, not SPL */
    CHECK(B(4), 0x40, 0xb4, 3);
    CHECK(B(15), 0x44, 0x0f, 0xb6, 0xf9);
    CHECK(B(12), 0x4d, 0x8d, 0x64, 0x24, 8);
    CHECK(0, 0x4d, 0x39, 0xfc);
    CHECK(0, 0x4d, 0x89, 0x3c, 0x24); /* memory base is read only */
    CHECK(B(12), 0x4d, 0x0f, 0x45, 0xe7);
    CHECK(B(12) | B(15), 0x4d, 0x87, 0xfc);
    CHECK(B(0) | B(2), 0x49, 0xf7, 0xe4); /* implicit MUL outputs */
    CHECK(B(0) | B(1) | B(2) | B(3), 0x0f, 0xa2);
    CHECK(B(0) | B(2), 0x0f, 0x31);
    CHECK(B(1) | B(6) | B(7), 0xf3, 0xa4);
    CHECK(B(4), 0x41, 0x57);
    CHECK(B(4) | B(15), 0x41, 0x5f);
    CHECK(UINT16_MAX, 0xe8, 0, 0, 0, 0);
    CHECK(UINT16_MAX, 0x41, 0xff, 0xd4);
    for (unsigned condition = 0; condition < 16; condition++) {
        uint8_t low[] = {0x0f, 0x90 + condition, 0xc1};
        uint8_t high[] = {0x0f, 0x90 + condition, 0xc4};
        uint8_t rex[] = {0x40, 0x0f, 0x90 + condition, 0xc4};
        uint8_t r15[] = {0x41, 0x0f, 0x90 + condition, 0xc7};
        uint8_t mem[] = {0x43, 0x0f, 0x90 + condition, 0x44, 0xbc, 8};
        check(low, sizeof(low), B(1));
        check(high, sizeof(high), B(0));
        check(rex, sizeof(rex), B(4));
        check(r15, sizeof(r15), B(15));
        check(mem, sizeof(mem), 0);
        uint8_t memory_writes = 0xff;
        assert(cfg_insn_memory_writes(mem, sizeof(mem), &memory_writes));
        assert(memory_writes == 1);
        assert(cfg_insn_memory_writes(r15, sizeof(r15), &memory_writes));
        assert(memory_writes == 0);
    }
    return NULL;
}

int main(void)
{
    exercise(NULL);
    GThread *threads[4];
    for (unsigned i = 0; i < G_N_ELEMENTS(threads); i++)
        threads[i] = g_thread_new("gpr-writes", exercise, NULL);
    for (unsigned i = 0; i < G_N_ELEMENTS(threads); i++)
        g_thread_join(threads[i]);
    const uint8_t rejected[][5] = {
        {0x0f, 0x05}, {0x0f, 0x0b}, {0xcd, 0x80}, {0x0f, 0x07},
        {0x48, 0x8b}, {0x0f}, {0xe2, 0xfe}, {0xe1, 0xfe}, {0xe0, 0xfe},
        {0x0f, 0xb0, 0xcb}, {0x66, 0x0f, 0xb1, 0xcb},
        {0x0f, 0xb1, 0xcb}, {0x48, 0x0f, 0xb1, 0xcb},
        {0x48, 0x0f, 0xb1, 0x0b}, {0x0f, 0x01, 0xee}, {0xd7},
    };
    const size_t lengths[] = {2, 2, 2, 2, 2, 1, 2, 2, 2,
                              3, 4, 3, 4, 4, 3, 1};
    for (unsigned i = 0; i < G_N_ELEMENTS(rejected); i++) {
        uint16_t mask = 0x5a5a;
        assert(!cfg_insn_gpr_writes(rejected[i], lengths[i], &mask));
        assert(mask == 0x5a5a);
    }
    uint16_t mask = 0x5a5a;
    uint8_t oversized[16] = {0x90};
    assert(!cfg_insn_gpr_writes(NULL, 1, &mask));
    assert(!cfg_insn_gpr_writes(oversized, sizeof(oversized), &mask));
    assert(!cfg_insn_gpr_writes(oversized, 1, NULL));
    assert(mask == 0x5a5a);
    uint8_t mem_sentinel = 0xa5;
    assert(!cfg_insn_memory_writes(NULL, 1, &mem_sentinel));
    assert(!cfg_insn_memory_writes(oversized, 1, NULL));
    assert(mem_sentinel == 0xa5);
    puts("GPR write summaries: PASS");
    return 0;
}
