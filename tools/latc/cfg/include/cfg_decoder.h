#ifndef CFG_DECODER_H
#define CFG_DECODER_H

/*
 * Lightweight x86-64 instruction decoder for CFG construction.
 *
 * The decoder is intentionally length-oriented. It recognizes control-flow
 * terminators and direct branch targets, and otherwise returns enough
 * instruction length information to keep block boundaries aligned.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    INSN_NORMAL,
    INSN_CALL,
    INSN_ICALL,
    INSN_JCC,
    INSN_JMP,
    INSN_IJMP,
    INSN_RET,
    INSN_SYSCALL,
    INSN_STOP,
} InsnKind;

typedef struct {
    /* Virtual address and offset within the function byte buffer. */
    uint64_t addr;
    size_t off;

    /* Decoded byte length. A caller may clamp zero-length malformed input. */
    size_t len;
    InsnKind kind;

    /* Present for direct jcc/jmp targets only. */
    bool has_target;
    uint64_t target;
} Insn;

Insn cfg_decode_insn(const uint8_t *buf, size_t size, uint64_t base,
                     size_t off);
const char *cfg_insn_kind_name(InsnKind kind);
bool cfg_is_legacy_prefix(uint8_t b);
bool cfg_insn_requires_avx512(const uint8_t *buf, size_t size);

/* Architectural encoding order: AX,CX,DX,BX,SP,BP,SI,DI,R8..R15. All
 * subregister writes kill the corresponding full-register value. Calls are
 * barriers with all GPRs killed, without assuming a callee-saved ABI. False
 * leaves *writes unchanged; unaudited instruction families are rejected.
 * This is not a stack/alias or return-value proof. */
bool cfg_insn_gpr_writes(const uint8_t *buf, size_t size, uint16_t *writes);

/* Bitmap of explicit memory destinations by decoded operand index. Shares
 * the audited instruction subset above, including SETcc metadata correction.
 * Does not include implicit string/stack writes. False leaves output intact. */
bool cfg_insn_memory_writes(const uint8_t *buf, size_t size, uint8_t *operands);

typedef struct {
    uint64_t known[16];
    uint64_t value[16];
} CfgGprConstants;

/* Unknown instructions kill all facts. Memory loads never create constants;
 * only decoded immediate/register MOV, MOVZX, SUB and self-XOR do so. */
void cfg_insn_transfer_constants(const uint8_t *buf, size_t size,
                                  CfgGprConstants *state);

#endif
