#ifndef CFG_RETURN_PROOF_H
#define CFG_RETURN_PROOF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool (*read_code)(const void *data, uint64_t pc, uint8_t bytes[15],
                       size_t *size);
    const void *data;
    size_t instruction_budget;
    unsigned call_depth;
} CfgReturnContext;

typedef enum {
    CFG_RETURN_PROVED,
    CFG_RETURN_BAD_INPUT,
    CFG_RETURN_UNMAPPED,
    CFG_RETURN_UNSUPPORTED,
    CFG_RETURN_INDIRECT,
    CFG_RETURN_STACK,
    CFG_RETURN_CLOBBER,
    CFG_RETURN_LIMIT,
    CFG_RETURN_RECURSION,
    CFG_RETURN_NO_RETURN,
} CfgReturnReason;

typedef struct {
    uint16_t preserved;
    bool writes_memory;
    size_t instructions;
    size_t returns;
    uint64_t frontier;
    CfgReturnReason reason;
} CfgReturnProof;

/* Conditional on normal synchronous execution from entry. No ABI assumption,
 * symbol boundary or prologue inference. Every reachable edge must be decoded;
 * unsupported instructions, traps, indirect transfers and recursion fail.
 * Unknown stores invalidate all saved slots, including the return address.
 * Direct children share caller stack coordinates and saved values; each CALL
 * has a distinct return token. Known stores invalidate overlapping slots only.
 * This does not model arbitrary signal-context modification/nonlocal reentry.
 * A successful result proves demanded GPR values and the caller stack pointer
 * on every modeled return, and requires at least one structural return. */
bool cfg_prove_return_preservation(const CfgReturnContext *context,
                                    uint64_t entry, uint16_t demanded,
                                    CfgReturnProof *proof);
const char *cfg_return_reason_name(CfgReturnReason reason);

#endif
