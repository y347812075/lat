#include "cfg_decoder.h"

#include "common.h"
#include "latc-translation-capabilities.h"

#include <capstone/capstone.h>
#include <glib.h>

/*
 * Length-oriented x86-64 decoder.
 *
 * This is not intended to replace Capstone. It recognizes CFG terminators and
 * computes instruction lengths for the subset of encodings seen in SPEC and
 * common system binaries. The optional Capstone shadow pass validates that the
 * resulting boundaries stay aligned.
 */

typedef struct {
    const uint8_t *buf;
    size_t size;

    /* Prefix state that changes immediate/address sizes. */
    bool op66;
    bool addr67;
    bool rex_w;
} DecodeCtx;

bool cfg_is_legacy_prefix(uint8_t b)
{
    switch (b) {
    case 0xf0:
    case 0xf2:
    case 0xf3:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return false;
    }
}

static size_t imm_osz(const DecodeCtx *ctx)
{
    return ctx->op66 ? 2 : 4;
}

static size_t moffs_size(const DecodeCtx *ctx)
{
    return ctx->addr67 ? 4 : 8;
}

static size_t modrm_tail_len(const DecodeCtx *ctx, size_t off)
{
    if (off >= ctx->size) {
        return 0;
    }

    uint8_t modrm = ctx->buf[off];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    size_t len = 1;

    /*
     * Account for SIB and displacement bytes. This is the core piece needed to
     * avoid drifting into the middle of the next instruction after FF /4, FF /5,
     * vector ops, and ordinary memory operands.
     */
    if (!ctx->addr67 && mod != 3 && rm == 4) {
        if (off + len >= ctx->size) {
            return len + 1;
        }
        uint8_t sib = ctx->buf[off + len];
        uint8_t base = sib & 7;
        len++;
        if (mod == 0 && base == 5) {
            len += 4;
        }
    } else if (ctx->addr67 && mod != 3 && rm == 4) {
        if (off + len >= ctx->size) {
            return len + 1;
        }
        uint8_t sib = ctx->buf[off + len];
        uint8_t base = sib & 7;
        len++;
        if (mod == 0 && base == 5) {
            len += 4;
        }
    }

    if (mod == 1) {
        len += 1;
    } else if (mod == 2) {
        len += 4;
    } else if (mod == 0 && rm == 5) {
        len += 4;
    }

    return len;
}

static uint8_t modrm_reg(const DecodeCtx *ctx, size_t off)
{
    if (off >= ctx->size) {
        return 0;
    }
    return (ctx->buf[off] >> 3) & 7;
}

static bool one_byte_has_modrm(uint8_t op)
{
    /*
     * Compact opcode table for the instructions this tool must step over.
     * Unknown one-byte opcodes are treated as no-ModRM with zero immediate so
     * the decoder advances conservatively by one byte.
     */
    if (op <= 0x3f) {
        return (op & 7) <= 3;
    }
    if (op >= 0x84 && op <= 0x8f) {
        return true;
    }
    if (op >= 0xd0 && op <= 0xdf) {
        return true;
    }
    switch (op) {
    case 0x62:
    case 0x63:
    case 0x69:
    case 0x6b:
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0xc0:
    case 0xc1:
    case 0xc4:
    case 0xc5:
    case 0xc6:
    case 0xc7:
    case 0xf6:
    case 0xf7:
    case 0xfe:
    case 0xff:
        return true;
    default:
        return false;
    }
}

static bool op0f_no_modrm(uint8_t op)
{
    switch (op) {
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0b:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x37:
    case 0x77:
    case 0xa0:
    case 0xa1:
    case 0xa2:
    case 0xa8:
    case 0xa9:
        return true;
    default:
        return op >= 0xc8 && op <= 0xcf;
    }
}

static size_t decode_0f_map(const DecodeCtx *ctx, size_t op_off, bool map_0f38,
                            bool map_0f3a)
{
    if (op_off >= ctx->size) {
        return ctx->size ? 1 : 0;
    }

    uint8_t op = ctx->buf[op_off];
    size_t len = op_off + 1;
    bool has_modrm = true;
    size_t imm = 0;
    /*
     * 0F 38 and 0F 3A are separate opcode maps. Most entries in both maps have
     * ModRM; 0F 3A also carries an imm8. Do not apply the normal 0F no-ModRM
     * table here: opcodes like VEX.0F38.A9 are FMA instructions with ModRM,
     * while legacy 0F A9 is POP GS without ModRM.
     */
    if (map_0f38) {
        has_modrm = true;
    } else if (map_0f3a) {
        has_modrm = true;
        imm = 1;
    } else {
        if (op0f_no_modrm(op) || (op >= 0x80 && op <= 0x8f)) {
            has_modrm = false;
        }
        switch (op) {
        case 0x0f:
        case 0x70:
        case 0x71:
        case 0x72:
        case 0x73:
        case 0xa4:
        case 0xac:
        case 0xba:
        case 0xc2:
        case 0xc4:
        case 0xc5:
        case 0xc6:
            imm = 1;
            break;
        default:
            break;
        }
    }

    if (has_modrm) {
        len += modrm_tail_len(ctx, len);
    }
    len += imm;
    return len;
}

static size_t decode_vex_len(const DecodeCtx *ctx, size_t off, uint8_t op)
{
    size_t prefix_len = op == 0xc5 ? 2 : 3;
    if (off + prefix_len >= ctx->size) {
        return ctx->size - off;
    }

    uint8_t map = 1;
    if (op == 0xc4) {
        map = ctx->buf[off + 1] & 0x1f;
    }

    size_t op_off = off + prefix_len;
    if (map == 2) {
        return decode_0f_map(ctx, op_off, true, false) - op_off + prefix_len;
    }
    if (map == 3) {
        return decode_0f_map(ctx, op_off, false, true) - op_off + prefix_len;
    }
    return decode_0f_map(ctx, op_off, false, false) - op_off + prefix_len;
}

static size_t decode_evex_len(const DecodeCtx *ctx, size_t off)
{
    if (off + 4 >= ctx->size) {
        return ctx->size - off;
    }

    uint8_t map = ctx->buf[off + 1] & 3;
    size_t op_off = off + 4;
    if (map == 2) {
        return decode_0f_map(ctx, op_off, true, false) - op_off + 4;
    }
    if (map == 3) {
        return decode_0f_map(ctx, op_off, false, true) - op_off + 4;
    }
    return decode_0f_map(ctx, op_off, false, false) - op_off + 4;
}

typedef struct {
    csh handle;
    cs_insn *insn;
} CapabilityDecoder;

static void capability_decoder_free(void *opaque)
{
    CapabilityDecoder *decoder = opaque;
    cs_free(decoder->insn, 1);
    cs_close(&decoder->handle);
    g_free(decoder);
}

static GPrivate capability_decoder = G_PRIVATE_INIT(capability_decoder_free);

static CapabilityDecoder *get_capability_decoder(void)
{
    CapabilityDecoder *decoder = g_private_get(&capability_decoder);
    if (!decoder) {
        decoder = g_new0(CapabilityDecoder, 1);
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &decoder->handle) != CS_ERR_OK ||
            cs_option(decoder->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK ||
            !(decoder->insn = cs_malloc(decoder->handle))) {
            g_error("cannot initialize static capability decoder");
        }
        g_private_set(&capability_decoder, decoder);
    }
    return decoder;
}

static int gpr_location(unsigned reg, unsigned *shift, unsigned *width)
{
    static const unsigned aliases[16][5] = {
        {X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AL, X86_REG_AH},
        {X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CL, X86_REG_CH},
        {X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL, X86_REG_DH},
        {X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BL, X86_REG_BH},
        {X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL},
        {X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL},
        {X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL},
        {X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL},
        {X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B},
        {X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B},
        {X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B},
        {X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B},
        {X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B},
        {X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B},
        {X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B},
        {X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B},
    };
    for (unsigned i = 0; i < G_N_ELEMENTS(aliases); i++) {
        for (unsigned j = 0; j < G_N_ELEMENTS(aliases[i]); j++) {
            if (reg && aliases[i][j] == reg) {
                *shift = j == 4 ? 8 : 0;
                *width = j == 0 ? 64 : j == 1 ? 32 : j == 2 ? 16 : 8;
                return i;
            }
        }
    }
    return -1;
}

static uint16_t gpr_bit(unsigned reg)
{
    unsigned shift, width;
    int index = gpr_location(reg, &shift, &width);
    return index < 0 ? 0 : UINT16_C(1) << index;
}

static bool is_setcc(unsigned id)
{
    switch (id) {
    case X86_INS_SETA: case X86_INS_SETAE: case X86_INS_SETB:
    case X86_INS_SETBE: case X86_INS_SETE: case X86_INS_SETNE:
    case X86_INS_SETG: case X86_INS_SETGE: case X86_INS_SETL:
    case X86_INS_SETLE: case X86_INS_SETO: case X86_INS_SETNO:
    case X86_INS_SETP: case X86_INS_SETNP: case X86_INS_SETS:
    case X86_INS_SETNS:
        return true;
    default:
        return false;
    }
}

bool cfg_insn_gpr_writes(const uint8_t *buf, size_t size, uint16_t *writes)
{
    if (!buf || !size || size > 15 || !writes) return false;
    CapabilityDecoder *decoder = get_capability_decoder();
    const uint8_t *code = buf;
    size_t available = size;
    uint64_t address = 0;
    if (!cs_disasm_iter(decoder->handle, &code, &available, &address,
                        decoder->insn) || decoder->insn->size != size ||
        !decoder->insn->detail) return false;
    Insn in = cfg_decode_insn(buf, size, 0, 0);
    if (in.len != size || in.kind == INSN_SYSCALL || in.kind == INSN_STOP)
        return false;
    if (in.kind == INSN_CALL || in.kind == INSN_ICALL) {
        *writes = UINT16_MAX;
        return true;
    }
    const cs_detail *detail = decoder->insn->detail;
    /* This bundled Capstone omits LOOP's implicit RCX write. Until the proof
     * transfer models that family explicitly, it is not a preservation fact. */
    if (decoder->insn->id == X86_INS_ENCLU ||
        decoder->insn->id == X86_INS_ENCLS ||
        decoder->insn->id == X86_INS_LOOP ||
        decoder->insn->id == X86_INS_LOOPE ||
        decoder->insn->id == X86_INS_LOOPNE) return false;
    for (unsigned i = 0; i < detail->groups_count; i++) {
        unsigned group = detail->groups[i];
        if (group == X86_GRP_PRIVILEGE || group == X86_GRP_IRET ||
            group == X86_GRP_INT || group == X86_GRP_VM ||
            group == X86_GRP_RTM) return false;
        if ((group == X86_GRP_JUMP && in.kind != INSN_JCC &&
             in.kind != INSN_JMP && in.kind != INSN_IJMP) ||
            (group == X86_GRP_RET && in.kind != INSN_RET)) return false;
    }
    /* SETcc has one byte destination and no implicit GPR definitions. Audit
     * that operand directly rather than extending trust in implicit metadata. */
    if (is_setcc(decoder->insn->id)) {
        const cs_x86 *x86 = &detail->x86;
        if (in.kind != INSN_NORMAL || x86->op_count != 1 ||
            x86->operands[0].size != 1) return false;
        const cs_x86_op *op = &x86->operands[0];
        if (op->type == X86_OP_REG) {
            unsigned shift, width;
            int reg = gpr_location(op->reg, &shift, &width);
            if (reg < 0 || width != 8) return false;
            *writes = UINT16_C(1) << reg;
        } else if (op->type == X86_OP_MEM) {
            *writes = 0;
        } else return false;
        return true;
    }
    /* Register-access metadata is incomplete for some implicit definitions
     * (e.g. CMPXCHG and RDPKRU). Only audited families can preserve facts;
     * newly decoded instructions do not silently extend the proof domain. */
    if (in.kind == INSN_NORMAL) {
        switch (decoder->insn->id) {
        case X86_INS_MOV: case X86_INS_MOVABS: case X86_INS_MOVZX:
        case X86_INS_MOVSX: case X86_INS_MOVSXD: case X86_INS_LEA:
        case X86_INS_ADD: case X86_INS_SUB: case X86_INS_ADC:
        case X86_INS_SBB: case X86_INS_AND: case X86_INS_OR:
        case X86_INS_XOR: case X86_INS_NOT: case X86_INS_NEG:
        case X86_INS_INC: case X86_INS_DEC: case X86_INS_CMP:
        case X86_INS_TEST: case X86_INS_SHL: case X86_INS_SHR:
        case X86_INS_SAR: case X86_INS_ROL: case X86_INS_ROR:
        case X86_INS_XCHG: case X86_INS_PUSH: case X86_INS_POP:
        case X86_INS_MUL: case X86_INS_IMUL: case X86_INS_DIV:
        case X86_INS_IDIV: case X86_INS_CPUID: case X86_INS_RDTSC:
        case X86_INS_MOVSB: case X86_INS_NOP:
        case X86_INS_CMOVA: case X86_INS_CMOVAE: case X86_INS_CMOVB:
        case X86_INS_CMOVBE: case X86_INS_CMOVE: case X86_INS_CMOVNE:
        case X86_INS_CMOVG: case X86_INS_CMOVGE: case X86_INS_CMOVL:
        case X86_INS_CMOVLE: case X86_INS_CMOVO: case X86_INS_CMOVNO:
        case X86_INS_CMOVP: case X86_INS_CMOVNP: case X86_INS_CMOVS:
        case X86_INS_CMOVNS:
            break;
        default:
            return false;
        }
    }
    cs_regs reads, modified;
    uint8_t read_count, modified_count;
    if (cs_regs_access(decoder->handle, decoder->insn, reads, &read_count,
                        modified, &modified_count) != CS_ERR_OK) return false;
    uint16_t mask = 0;
    for (unsigned i = 0; i < modified_count; i++) mask |= gpr_bit(modified[i]);
    const cs_x86 *x86 = &detail->x86;
    for (unsigned i = 0; i < x86->op_count; i++) {
        const cs_x86_op *op = &x86->operands[i];
        if (op->type == X86_OP_REG && gpr_bit(op->reg) && !op->access)
            return false;
    }
    *writes = mask;
    return true;
}

bool cfg_insn_memory_writes(const uint8_t *buf, size_t size, uint8_t *operands)
{
    uint16_t gprs;
    if (!operands || !cfg_insn_gpr_writes(buf, size, &gprs)) return false;
    const cs_insn *insn = get_capability_decoder()->insn;
    const cs_x86 *x86 = &insn->detail->x86;
    uint8_t mask = 0;
    for (unsigned i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM &&
            ((x86->operands[i].access & CS_AC_WRITE) || is_setcc(insn->id)))
            mask |= UINT8_C(1) << i;
    }
    *operands = mask;
    return true;
}

static uint64_t width_mask(unsigned width)
{
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
}

static bool constant_operand(const CfgGprConstants *state,
                               const cs_x86_op *op, uint64_t *value)
{
    if (op->type == X86_OP_IMM) {
        *value = op->imm;
        return true;
    }
    unsigned shift, width;
    int reg = op->type == X86_OP_REG ?
        gpr_location(op->reg, &shift, &width) : -1;
    if (reg < 0) return false;
    uint64_t mask = width_mask(width);
    if (((state->known[reg] >> shift) & mask) != mask) return false;
    *value = (state->value[reg] >> shift) & mask;
    return true;
}

void cfg_insn_transfer_constants(const uint8_t *buf, size_t size,
                                  CfgGprConstants *state)
{
    uint16_t writes;
    CfgGprConstants before = *state;
    if (!cfg_insn_gpr_writes(buf, size, &writes)) {
        memset(state, 0, sizeof(*state));
        return;
    }
    for (unsigned i = 0; i < 16; i++) {
        if (writes & (UINT16_C(1) << i)) {
            state->known[i] = 0;
            state->value[i] = 0;
        }
    }
    const cs_insn *in = get_capability_decoder()->insn;
    const cs_x86 *x86 = &in->detail->x86;
    if (x86->op_count != 2 || x86->operands[0].type != X86_OP_REG)
        return;
    unsigned shift, width;
    int reg = gpr_location(x86->operands[0].reg, &shift, &width);
    if (reg < 0 || writes != (UINT16_C(1) << reg)) return;
    uint64_t result, left, right;
    bool known = false;
    if (in->id == X86_INS_MOV || in->id == X86_INS_MOVABS ||
        in->id == X86_INS_MOVZX) {
        known = constant_operand(&before, &x86->operands[1], &result);
    } else if (in->id == X86_INS_SUB) {
        known = constant_operand(&before, &x86->operands[0], &left) &&
                constant_operand(&before, &x86->operands[1], &right);
        if (known) result = left - right;
    } else if (in->id == X86_INS_XOR &&
               x86->operands[1].type == X86_OP_REG &&
               x86->operands[0].reg == x86->operands[1].reg) {
        result = 0;
        known = true;
    }
    if (!known) return;
    uint64_t mask = width_mask(width) << shift;
    state->known[reg] = before.known[reg] | mask;
    state->value[reg] = (before.value[reg] & ~mask) |
                        ((result << shift) & mask);
    if (width == 32) {
        state->known[reg] = UINT64_MAX;
        state->value[reg] &= UINT32_MAX;
    }
}

/* No current LAT build implements AVX-512. Only positively decoded forms are
 * excluded; an unknown encoding remains a translation/validation error. */
bool cfg_insn_requires_avx512(const uint8_t *buf, size_t size)
{
    if (LATC_TRANSLATOR_AVX512_SUPPORTED) {
        return false;
    }
    size_t p = 0;
    while (p < size && cfg_is_legacy_prefix(buf[p])) {
        p++;
    }
    if (p >= size || (buf[p] != 0x62 && buf[p] != 0xc4 && buf[p] != 0xc5)) {
        return false;
    }
    CapabilityDecoder *decoder = get_capability_decoder();
    const uint8_t *code = buf;
    size_t available = size;
    uint64_t address = 0;
    if (!cs_disasm_iter(decoder->handle, &code, &available, &address,
                        decoder->insn) || decoder->insn->size != size) {
        return false;
    }
    if (latc_decoded_uses_evex(buf, size)) {
        return true;
    }
    const cs_x86 *x86 = &decoder->insn->detail->x86;
    for (unsigned i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_REG &&
            x86->operands[i].reg >= X86_REG_K0 &&
            x86->operands[i].reg <= X86_REG_K7) {
            return true;
        }
    }
    return false;
}

Insn cfg_decode_insn(const uint8_t *buf, size_t size, uint64_t base,
                     size_t off)
{
    DecodeCtx ctx = {
        .buf = buf,
        .size = size,
    };
    Insn insn = {
        .addr = base + off,
        .off = off,
        .len = 1,
        .kind = INSN_NORMAL,
    };

    /* Consume legacy and REX prefixes before classifying the opcode. */
    size_t p = off;
    while (p < size) {
        uint8_t b = buf[p];
        if (cfg_is_legacy_prefix(b)) {
            if (b == 0x66) {
                ctx.op66 = true;
            } else if (b == 0x67) {
                ctx.addr67 = true;
            }
            p++;
            continue;
        }
        if (b >= 0x40 && b <= 0x4f) {
            ctx.rex_w = (b & 8) != 0;
            p++;
            continue;
        }
        break;
    }

    if (p >= size) {
        insn.len = size - off;
        return insn;
    }

    uint8_t op = buf[p];
    size_t len = p + 1;

    /* First handle the control-flow opcodes that define CFG boundaries. */
    if (op >= 0x70 && op <= 0x7f) {
        if (p + 1 < size) {
            insn.kind = INSN_JCC;
            insn.has_target = true;
            insn.target = insn.addr + (len - off) + 1 + (int8_t)buf[p + 1];
        }
        len += 1;
    } else if (op == 0x0f) {
        if (p + 1 >= size) {
            len = size;
        } else {
            uint8_t op2 = buf[p + 1];
            if (op2 >= 0x80 && op2 <= 0x8f) {
                if (p + 5 < size) {
                    insn.kind = INSN_JCC;
                    insn.has_target = true;
                    insn.target = insn.addr + (p + 6 - off) +
                                  rd_i32(buf + p + 2);
                }
                len = p + 6;
            } else if (op2 == 0x0b || op2 == 0xb9 || op2 == 0xff) {
                len = op2 == 0x0b ? p + 2 :
                      p + 2 + modrm_tail_len(&ctx, p + 2);
                if (len <= size && (op2 == 0x0b || p + 2 < size)) {
                    insn.kind = INSN_STOP;
                }
            } else if (op2 == 0x05 || op2 == 0x34) {
                /* syscall/sysenter return to the following guest address. */
                insn.kind = INSN_SYSCALL;
                len = p + 2;
            } else {
                if (op2 == 0x38 && p + 2 < size) {
                    len = decode_0f_map(&ctx, p + 2, true, false);
                } else if (op2 == 0x3a && p + 2 < size) {
                    len = decode_0f_map(&ctx, p + 2, false, true);
                } else {
                    len = decode_0f_map(&ctx, p + 1, false, false);
                }
            }
        }
    } else if (op == 0xe8) {
        if (p + 4 < size) {
            insn.kind = INSN_CALL;
            insn.has_target = true;
            insn.target = insn.addr + (p + 5 - off) + rd_i32(buf + p + 1);
        }
        len += 4;
    } else if (op >= 0xe0 && op <= 0xe3) {
        /* loopne/loope/loop/jrcxz are conditional control transfers. */
        if (p + 1 < size) {
            insn.kind = INSN_JCC;
            insn.has_target = true;
            insn.target = insn.addr + (len - off) + 1 + (int8_t)buf[p + 1];
        }
        len += 1;
    } else if (op == 0xeb) {
        if (p + 1 < size) {
            insn.kind = INSN_JMP;
            insn.has_target = true;
            insn.target = insn.addr + (len - off) + 1 + (int8_t)buf[p + 1];
        }
        len += 1;
    } else if (op == 0xe9) {
        if (p + 4 < size) {
            insn.kind = INSN_JMP;
            insn.has_target = true;
            insn.target = insn.addr + (p + 5 - off) + rd_i32(buf + p + 1);
        }
        len += 4;
    } else if (op == 0xc2 || op == 0xca) {
        insn.kind = INSN_RET;
        len += 2;
    } else if (op == 0xc3 || op == 0xcb) {
        insn.kind = INSN_RET;
    } else if (op == 0xcc || op == 0xce || op == 0xcf || op == 0xf4) {
        insn.kind = INSN_STOP;
    } else if (op == 0xcd) {
        insn.kind = INSN_STOP;
        len += 1;
    } else if (op == 0xc5 && p + 1 < size) {
        /* In 64-bit mode C5/C4 are VEX prefixes, not LDS/LES. */
        len = p + decode_vex_len(&ctx, p, op);
    } else if (op == 0xc4 && p + 2 < size) {
        len = p + decode_vex_len(&ctx, p, op);
    } else if (op == 0x62 && p + 3 < size) {
        /* EVEX prefix; required for AVX-512-heavy libc routines. */
        len = p + decode_evex_len(&ctx, p);
    } else {
        bool has_modrm = one_byte_has_modrm(op);
        size_t imm = 0;

        /* Generic length path for non-control-flow instructions. */
        if ((op & 0xf8) == 0xb8) {
            imm = ctx.rex_w ? 8 : imm_osz(&ctx);
        } else if ((op & 0xf8) == 0xb0) {
            imm = 1;
        } else if ((op & 0xc7) == 0x04 || (op >= 0x6a && op <= 0x6b) ||
                   op == 0xa8 || op == 0xc0 || op == 0xc1) {
            imm = 1;
        } else if ((op & 0xc7) == 0x05 || op == 0x68 || op == 0xa9) {
            imm = imm_osz(&ctx);
        } else if (op == 0xe8) {
            imm = 4;
        } else if (op == 0xc8) {
            imm = 3;
        } else if (op >= 0xa0 && op <= 0xa3) {
            imm = moffs_size(&ctx);
        } else if (op >= 0xe0 && op <= 0xe7) {
            imm = 1;
        } else if (op == 0x9a || op == 0xea) {
            imm = ctx.op66 ? 6 : 10;
        }

        if (has_modrm) {
            size_t modrm_off = len;
            uint8_t reg = modrm_reg(&ctx, modrm_off);
            len += modrm_tail_len(&ctx, modrm_off);

            switch (op) {
            case 0x69:
            case 0x81:
            case 0xc7:
                imm = imm_osz(&ctx);
                break;
            case 0x6b:
            case 0x80:
            case 0x82:
            case 0x83:
            case 0xc0:
            case 0xc1:
            case 0xc6:
                imm = 1;
                break;
            case 0xf6:
                imm = (reg == 0 || reg == 1) ? 1 : 0;
                break;
            case 0xf7:
                imm = (reg == 0 || reg == 1) ? imm_osz(&ctx) : 0;
                break;
            case 0xff:
                if (reg == 2 || reg == 3) {
                    /* FF /2 and FF /3 are indirect call exits. */
                    insn.kind = INSN_ICALL;
                } else if (reg == 4 || reg == 5) {
                    /* FF /4 and FF /5 are indirect jump exits. */
                    insn.kind = INSN_IJMP;
                }
                break;
            default:
                break;
            }
        }

        len += imm;
    }

    if (len <= off) {
        len = off + 1;
    }
    if (len > size) {
        len = size;
    }
    insn.len = len - off;
    return insn;
}

const char *cfg_insn_kind_name(InsnKind kind)
{
    switch (kind) {
    case INSN_CALL:
        return "call";
    case INSN_ICALL:
        return "icall";
    case INSN_JCC:
        return "jcc";
    case INSN_JMP:
        return "jmp";
    case INSN_IJMP:
        return "ijmp";
    case INSN_RET:
        return "ret";
    case INSN_SYSCALL:
        return "syscall";
    case INSN_STOP:
        return "stop";
    default:
        return "normal";
    }
}
