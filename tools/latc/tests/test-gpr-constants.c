#include "ijmp_resolve.h"

#include <assert.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

static bool leaf_code(const void *data, uint64_t pc, uint8_t bytes[15], size_t *size)
{
    if (pc != 0x107b) return false;
    bytes[0] = data ? 0xcc : 0xc3;
    *size = 1;
    return true;
}

static CfgGprConstants analyze(const uint8_t *code, size_t size, size_t query,
                                const IjmpInbound *inbound, size_t count)
{
    IjmpContext ctx = {.func_addr = 0x1000, .inbound_complete = true,
                       .inbound = inbound, .inbound_count = count};
    CfgGprConstants state;
    assert(ijmp_gpr_constants(&ctx, code, size, query, &state));
    return state;
}

static void known(CfgGprConstants state, unsigned reg, uint64_t value)
{
    assert(state.known[reg] == UINT64_MAX);
    assert(state.value[reg] == value);
}

int main(void)
{
    /* The actual producer shape, not application addresses or bytes. */
    const uint8_t init[] = {
        0xb9, 3, 0, 0, 0, 0x44, 0x0f, 0xb6, 0xf9,
        0xb1, 64, 0x44, 0x28, 0xf9, 0x44, 0x0f, 0xb6, 0xe1, 0x90,
    };
    CfgGprConstants state = analyze(init, sizeof(init), 18, NULL, 0);
    known(state, 15, 3);
    known(state, 12, 61);
    known(state, 1, 61);
    IjmpInbound independent = {.source = UINT64_MAX, .target = 0x1009};
    state = analyze(init, sizeof(init), 18, &independent, 1);
    assert(!state.known[15] && !state.known[12]);

    uint8_t loop[] = {
        0x41, 0xbc, 3, 0, 0, 0, /* r12d=3 */
        0x90, 0x75, 0xfd, 0xc3,
    };
    known(analyze(loop, sizeof(loop), 6, NULL, 0), 12, 3);
    uint8_t clobber[] = {
        0x41, 0xbc, 3, 0, 0, 0,
        0x90, 0x41, 0xb4, 4, 0x75, 0xfa, 0xc3,
    };
    state = analyze(clobber, sizeof(clobber), 6, NULL, 0);
    assert((state.known[12] & 7) != 7);
    uint8_t call[] = {
        0x41, 0xbc, 3, 0, 0, 0,
        0xe8, 0x70, 0, 0, 0, 0x90,
    };
    state = analyze(call, sizeof(call), 11, NULL, 0);
    assert(!state.known[12]);
    CfgReturnContext returns = {leaf_code, NULL, 64, 4};
    IjmpContext proved_ctx = {.func_addr = 0x1000, .inbound_complete = true,
                              .return_context = &returns};
    assert(ijmp_gpr_constants(&proved_ctx, call, sizeof(call), 11, &state));
    known(state, 12, 3);
    returns.data = &returns;
    assert(ijmp_gpr_constants(&proved_ctx, call, sizeof(call), 11, &state));
    assert(!state.known[12]);
    /* Even a local RET is not an ABI preservation certificate. */
    const uint8_t local_call[] = {
        0x41, 0xbc, 3, 0, 0, 0,
        0xe8, 1, 0, 0, 0, 0x90, 0xc3,
    };
    state = analyze(local_call, sizeof(local_call), 11, NULL, 0);
    assert(!state.known[12]);
    const uint8_t call_loop[] = {
        0x41, 0xbc, 3, 0, 0, 0, 0x90,
        0xe8, 0x70, 0, 0, 0, 0x75, 0xf8, 0xc3,
    };
    state = analyze(call_loop, sizeof(call_loop), 6, NULL, 0);
    assert(!state.known[12]);
    /* Conflicting definitions must meet, even if the first path was known. */
    uint8_t join[] = {
        0x74, 8, 0x41, 0xbc, 3, 0, 0, 0, 0xeb, 6,
        0x41, 0xbc, 3, 0, 0, 0, 0x90,
    };
    known(analyze(join, sizeof(join), 16, NULL, 0), 12, 3);
    join[12] = 4;
    state = analyze(join, sizeof(join), 16, NULL, 0);
    assert((state.known[12] & 7) != 7);
    /* High-byte writes update AH, not AL, and retain proved other bits. */
    const uint8_t high[] = {0xb8, 3, 0, 0, 0, 0xb4, 7, 0x90};
    known(analyze(high, sizeof(high), 7, NULL, 0), 0, 0x703);
    const uint8_t copy[] = {0xb8, 3, 0, 0, 0, 0x49, 0x89, 0xc4, 0x90};
    known(analyze(copy, sizeof(copy), 8, NULL, 0), 12, 3);
    const uint8_t memory[] = {0xb8, 3, 0, 0, 0, 0x4c, 0x8b, 0x20, 0x90};
    assert(!analyze(memory, sizeof(memory), 8, NULL, 0).known[12]);
    const uint8_t set_other[] = {
        0x41, 0xbf, 3, 0, 0, 0, 0x40, 0x0f, 0x9c, 0xc6, 0x90,
    };
    known(analyze(set_other, sizeof(set_other), 10, NULL, 0), 15, 3);
    const uint8_t set_count[] = {
        0x41, 0xbf, 3, 0, 0, 0, 0x41, 0x0f, 0x95, 0xc7, 0x90,
    };
    assert(!analyze(set_count, sizeof(set_count), 10, NULL, 0).known[15]);
    const uint8_t cmpxchg[] = {
        0xb8, 3, 0, 0, 0, 0xbb, 4, 0, 0, 0, 0xb9, 5, 0, 0, 0,
        0x0f, 0xb1, 0xcb, 0x41, 0x89, 0xc7, 0x90,
    };
    IjmpContext rejected_ctx = {.func_addr = 0x1000, .inbound_complete = true};
    assert(!ijmp_gpr_constants(&rejected_ctx, cmpxchg, sizeof(cmpxchg), 21,
                               &state));
    /* Irrelevant inbound entries do not alter facts or require a full scan. */
    IjmpInbound *many = g_new0(IjmpInbound, 100000);
    for (unsigned i = 0; i < 100000; i++) {
        many[i].source = UINT64_MAX;
        many[i].target = 0x10000 + i;
    }
    for (unsigned i = 0; i < 100; i++)
        known(analyze(init, sizeof(init), 18, many, 100000), 12, 61);
    g_free(many);
    IjmpContext ctx = {.func_addr = 0x1000, .inbound_complete = true};
    CfgGprConstants sentinel, output;
    memset(&sentinel, 0xa5, sizeof(sentinel));
    output = sentinel;
    assert(!ijmp_gpr_constants(&ctx, init, sizeof(init), 1, &output));
    assert(!memcmp(&output, &sentinel, sizeof(output)));
    IjmpInbound mid = {.source = UINT64_MAX, .target = 0x1001};
    ctx.inbound = &mid;
    ctx.inbound_count = 1;
    assert(!ijmp_gpr_constants(&ctx, init, sizeof(init), 18, &output));
    assert(!memcmp(&output, &sentinel, sizeof(output)));
    const uint8_t mid_branch[] = {0xeb, 1, 0x41, 0xbc, 3, 0, 0, 0, 0x90};
    ctx.inbound_count = 0;
    assert(!ijmp_gpr_constants(&ctx, mid_branch, sizeof(mid_branch), 8, &output));
    const uint8_t indirect[] = {0xff, 0xe0, 0x90};
    assert(!ijmp_gpr_constants(&ctx, indirect, sizeof(indirect), 2, &output));
    ctx.inbound_complete = false;
    assert(!ijmp_gpr_constants(&ctx, init, sizeof(init), 18, &output));
    assert(!memcmp(&output, &sentinel, sizeof(output)));
    puts("All-path GPR constants: PASS");
    return 0;
}
