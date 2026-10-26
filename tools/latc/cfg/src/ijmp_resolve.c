#include "ijmp_resolve.h"

#include "common.h"
#include "cfg_decoder.h"

/*
 * Pattern-based indirect jump resolver.
 *
 * Supported table forms:
 *   - qword table with a register base or absolute disp32, direct or loaded
 *   - GCC PIC offset table: movsxd table[index*4], add/lea offset base, jmp reg
 *
 * Candidate targets must match decoded instruction boundaries or known
 * cross-function targets.
 */

#include <string.h>
#include <glib.h>

#define IJMP_LOOKBACK_BYTES 4096

typedef struct {
    Insn insn;
    CfgGprConstants input;
    bool reachable;
    bool pending;
} ConstantNode;

static size_t constant_node_at(const ConstantNode *nodes, size_t count,
                                size_t offset)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (nodes[mid].insn.off < offset) lo = mid + 1;
        else hi = mid;
    }
    return lo < count && nodes[lo].insn.off == offset ? lo : count;
}

static bool constant_merge(ConstantNode *node, const CfgGprConstants *value)
{
    bool changed = !node->reachable;
    if (!node->reachable) {
        node->input = *value;
        node->reachable = true;
    } else {
        for (unsigned i = 0; i < 16; i++) {
            uint64_t known = node->input.known[i] & value->known[i] &
                            ~(node->input.value[i] ^ value->value[i]);
            changed |= known != node->input.known[i];
            node->input.known[i] = known;
            node->input.value[i] &= known;
        }
    }
    node->pending |= changed;
    return changed;
}

static size_t constant_inbound_lower(const IjmpContext *ctx, uint64_t target)
{
    size_t lo = 0, hi = ctx->inbound_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->inbound[mid].target < target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static bool gpr_constants_pair(const IjmpContext *ctx, const uint8_t *code,
                                size_t size, size_t query, size_t query2,
                                CfgGprConstants *out, CfgGprConstants *out2)
{
    if (!ctx || !code || !out || !ctx->inbound_complete || !size ||
        size > IJMP_LOOKBACK_BYTES || query >= size || query2 >= size ||
        size > UINT64_MAX - ctx->func_addr ||
        (ctx->inbound_count && !ctx->inbound)) return false;
    ConstantNode *nodes = g_new0(ConstantNode, size);
    size_t count = 0;
    bool ok = false;
    for (size_t off = 0; off < size;) {
        Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
        uint16_t writes;
        if (!in.len || in.len > size - off || count >= 1024 ||
            in.kind == INSN_IJMP || in.kind == INSN_SYSCALL ||
            (in.kind != INSN_STOP &&
             !cfg_insn_gpr_writes(code + off, in.len, &writes))) goto done;
        nodes[count++].insn = in;
        off += in.len;
    }
    size_t queried = constant_node_at(nodes, count, query);
    size_t queried2 = constant_node_at(nodes, count, query2);
    if (queried == count || queried2 == count) goto done;
    /* Every in-window direct edge must land on a decoded boundary, including
     * currently unreachable edges: reachability is not a decoding oracle. */
    uint64_t end = ctx->func_addr + size;
    for (size_t i = 0; i < count; i++) {
        Insn in = nodes[i].insn;
        if (in.has_target && in.target >= ctx->func_addr && in.target < end &&
            constant_node_at(nodes, count, in.target - ctx->func_addr) == count)
            goto done;
    }
    CfgGprConstants unknown = {0};
    constant_merge(&nodes[0], &unknown);
    for (size_t i = constant_inbound_lower(ctx, ctx->func_addr);
         i < ctx->inbound_count && ctx->inbound[i].target < end; i++) {
        IjmpInbound edge = ctx->inbound[i];
        if (edge.target < ctx->func_addr || edge.target >= end) continue;
        size_t target = constant_node_at(nodes, count,
                                          edge.target - ctx->func_addr);
        if (target == count) goto done;
        if (edge.source >= ctx->func_addr && edge.source < end) {
            size_t source = constant_node_at(nodes, count,
                                              edge.source - ctx->func_addr);
            if (source == count || !nodes[source].insn.has_target ||
                nodes[source].insn.target != edge.target) goto done;
        } else {
            constant_merge(&nodes[target], &unknown);
        }
    }
    /* Monotone bit intersection terminates even with loops. Resource limits
     * fail the entire proof rather than returning a pre-fixpoint result. */
    size_t budget = count * 1026;
    bool pending;
    do {
        pending = false;
        for (size_t i = 0; i < count; i++) {
            ConstantNode *node = &nodes[i];
            if (!node->pending) continue;
            if (!budget--) goto done;
            node->pending = false;
            Insn in = node->insn;
            CfgGprConstants next = node->input;
            cfg_insn_transfer_constants(code + in.off, in.len, &next);
            if (in.kind == INSN_CALL && ctx->return_context) {
                CfgReturnProof proof;
                if (cfg_prove_return_preservation(ctx->return_context,
                        in.target, 0, &proof)) {
                    for (unsigned reg = 0; reg < 16; reg++) {
                        if (proof.preserved & (UINT16_C(1) << reg)) {
                            next.known[reg] = node->input.known[reg];
                            next.value[reg] = node->input.value[reg];
                        }
                    }
                }
            }
            if (in.has_target && in.target >= ctx->func_addr && in.target < end) {
                size_t target = constant_node_at(nodes, count,
                                                  in.target - ctx->func_addr);
                const CfgGprConstants *input = in.kind == INSN_CALL ?
                                               &unknown : &next;
                constant_merge(&nodes[target], input);
            }
            if (i + 1 < count && in.kind != INSN_JMP &&
                in.kind != INSN_RET && in.kind != INSN_STOP)
                constant_merge(&nodes[i + 1], &next);
        }
        for (size_t i = 0; i < count; i++) pending |= nodes[i].pending;
    } while (pending);
    if (nodes[queried].reachable && nodes[queried2].reachable) {
        *out = nodes[queried].input;
        *out2 = nodes[queried2].input;
        ok = true;
    }
done:
    g_free(nodes);
    return ok;
}

bool ijmp_gpr_constants(const IjmpContext *ctx, const uint8_t *code,
                         size_t size, size_t query, CfgGprConstants *out)
{
    CfgGprConstants second;
    return gpr_constants_pair(ctx, code, size, query, query, out, &second);
}

typedef struct {
    /* Decoded legacy/REX prefix state and offset of the real opcode. */
    int rex_w;
    int rex_r;
    int rex_x;
    int rex_b;
    bool nonflat_address;
    size_t op;
} Prefix;

typedef struct {
    /* add r/m64, r64 with register destination/source. */
    int dst;
    int src;
    size_t len;
} AddReg;

typedef struct {
    /* movsxd r64, dword ptr [base + index * 4] */
    int dst;
    int base;
    int index;
    int scale;
    size_t len;
} MovsxdMem;

typedef struct {
    /* lea reg, [rip + disp32] */
    int dst;
    uint64_t target;
    size_t len;
} LeaRip;

typedef struct {
    /* lea reg, [base + index * scale] */
    int dst;
    int base;
    int index;
    int scale;
    size_t len;
} LeaReg;

typedef struct {
    /* mov r64, r64 */
    int dst;
    int src;
    size_t len;
} MovReg;

typedef struct {
    /* mov r64, qword ptr [rip + disp32] */
    int dst;
    uint64_t address;
    size_t len;
} MovRip;

typedef struct {
    /* mov r64, qword ptr [base + index * scale + disp] */
    int dst;
    int base;
    int index;
    int scale;
    int32_t disp;
    size_t len;
} MovMem;

typedef struct {
    /* jmp qword ptr [base + index * scale], or [disp32 + index * scale]. */
    int base;
    int index;
    int scale;
    uint64_t table_addr;
    size_t len;
} JmpMem;

typedef struct {
    int dst;
    uint32_t value;
    size_t len;
} RegImm;

static bool in_func(const IjmpContext *ctx, uint64_t addr)
{
    return addr >= ctx->func_addr && addr < ctx->func_addr + ctx->func_size;
}

static bool is_insn_addr(const IjmpContext *ctx, uint64_t addr)
{
    if (ctx->insn_bitmap && addr >= ctx->func_addr) {
        uint64_t offset = addr - ctx->func_addr;
        return offset < ctx->insn_bitmap_size && ctx->insn_bitmap[offset];
    }
    size_t lo = 0;
    size_t hi = ctx->insn_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->insn_addrs[mid] < addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < ctx->insn_count && ctx->insn_addrs[lo] == addr;
}

static size_t insn_lower_bound_off(const IjmpContext *ctx, size_t off)
{
    uint64_t addr = ctx->func_addr + off;
    size_t lo = 0, hi = ctx->insn_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->insn_addrs[mid] < addr) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static bool is_func_entry(const IjmpContext *ctx, uint64_t addr)
{
    return ctx->is_func_entry &&
           ctx->is_func_entry(ctx->func_entry_data, addr);
}

static bool is_program_insn(const IjmpContext *ctx, uint64_t addr)
{
    size_t lo = 0;
    size_t hi = ctx->program_insn_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->program_insn_addrs[mid] < addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < ctx->program_insn_count &&
           ctx->program_insn_addrs[lo] == addr;
}

static bool is_direct_target(const IjmpContext *ctx, uint64_t addr)
{
    size_t lo = 0;
    size_t hi = ctx->direct_target_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->direct_targets[mid] < addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < ctx->direct_target_count &&
           ctx->direct_targets[lo] == addr;
}

static bool is_valid_target(const IjmpContext *ctx, uint64_t target)
{
    if (in_func(ctx, target)) {
        return is_insn_addr(ctx, target);
    }
    return is_func_entry(ctx, target) || is_program_insn(ctx, target) ||
           is_direct_target(ctx, target);
}

static const uint8_t *va_ptr(const IjmpContext *ctx, uint64_t addr, size_t len)
{
    /* Translate a virtual table address back to a file pointer. */
    for (size_t i = 0; i < ctx->section_count; i++) {
        const IjmpSection *s = &ctx->sections[i];
        if (addr >= s->addr && len <= s->size &&
            addr - s->addr <= s->size - len) {
            uint64_t off = s->off + (addr - s->addr);
            if (off <= ctx->file_size && len <= ctx->file_size - off) {
                return ctx->file + off;
            }
        }
    }
    return NULL;
}

static Prefix parse_prefix(const uint8_t *buf, size_t size, size_t off)
{
    Prefix p = {0};
    p.op = off;

    while (p.op < size) {
        uint8_t b = buf[p.op];
        if (b == 0x3e || b == 0x66 || b == 0x67 || b == 0xf2 ||
            b == 0xf3 || b == 0xf0 || b == 0x2e || b == 0x36 ||
            b == 0x26 || b == 0x64 || b == 0x65) {
            p.nonflat_address |= b == 0x67 || b == 0x64 || b == 0x65;
            p.op++;
            continue;
        }
        if (b >= 0x40 && b <= 0x4f) {
            p.rex_w = (b >> 3) & 1;
            p.rex_r = (b >> 2) & 1;
            p.rex_x = (b >> 1) & 1;
            p.rex_b = b & 1;
            p.op++;
            continue;
        }
        break;
    }
    return p;
}

static bool parse_indirect_reg(const uint8_t *buf, size_t size, size_t off,
                               int *reg_out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 1 >= size || buf[p.op] != 0xff) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;
    if (mod != 3 || (reg != 2 && reg != 4)) {
        return false;
    }

    *reg_out = rm + p.rex_b * 8;
    return true;
}

static bool parse_mov_rip(const uint8_t *buf, size_t size,
                          uint64_t func_addr, size_t off, MovRip *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 5 >= size || buf[p.op] != 0x8b) {
        return false;
    }
    uint8_t modrm = buf[p.op + 1];
    if ((modrm >> 6) != 0 || (modrm & 7) != 5) {
        return false;
    }
    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->len = p.op + 6 - off;
    out->address = func_addr + off + out->len + rd_i32(buf + p.op + 2);
    return true;
}

static bool parse_jmp_mem_scaled(const uint8_t *buf, size_t size, size_t off,
                                 JmpMem *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || buf[p.op] != 0xff) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;
    if (mod != 0 || reg != 4 || rm != 4) {
        return false;
    }

    uint8_t sib = buf[p.op + 2];
    uint8_t scale_bits = sib >> 6;
    uint8_t index = (sib >> 3) & 7;
    uint8_t base = sib & 7;
    if (index == 4 && !p.rex_x) {
        return false;
    }

    out->table_addr = 0;
    if (base == 5) {
        if (size - p.op < 7 || p.nonflat_address) {
            return false;
        }
        /* A no-base SIB uses a sign-extended disp32, even with REX.B. */
        out->table_addr = (uint64_t)(int64_t)rd_i32(buf + p.op + 3);
    }
    out->base = base == 5 ? -1 : base + p.rex_b * 8;
    out->index = index + p.rex_x * 8;
    out->scale = 1 << scale_bits;
    out->len = p.op + 3 + (base == 5 ? 4 : 0) - off;
    return true;
}

static bool parse_add_reg(const uint8_t *buf, size_t size, size_t off,
                          AddReg *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 1 >= size || buf[p.op] != 0x01) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    if ((modrm >> 6) != 3) {
        return false;
    }

    out->src = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->dst = (modrm & 7) + p.rex_b * 8;
    out->len = p.op + 2 - off;
    return true;
}

static bool parse_and_imm(const uint8_t *buf, size_t size, size_t off,
                          RegImm *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || (buf[p.op] != 0x83 && buf[p.op] != 0x81)) {
        return false;
    }
    uint8_t modrm = buf[p.op + 1];
    if ((modrm >> 6) != 3 || ((modrm >> 3) & 7) != 4) {
        return false;
    }
    out->dst = (modrm & 7) + p.rex_b * 8;
    if (buf[p.op] == 0x83) {
        out->value = (uint8_t)buf[p.op + 2];
        out->len = p.op + 3 - off;
    } else {
        if (p.op + 5 >= size) return false;
        out->value = (uint32_t)rd_i32(buf + p.op + 2);
        out->len = p.op + 6 - off;
    }
    return true;
}

static bool parse_shl_imm(const uint8_t *buf, size_t size, size_t off,
                          RegImm *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || buf[p.op] != 0xc1) return false;
    uint8_t modrm = buf[p.op + 1];
    if ((modrm >> 6) != 3 || ((modrm >> 3) & 7) != 4) return false;
    out->dst = (modrm & 7) + p.rex_b * 8;
    out->value = buf[p.op + 2];
    out->len = p.op + 3 - off;
    return true;
}

static bool parse_movsxd_mem(const uint8_t *buf, size_t size, size_t off,
                             MovsxdMem *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || buf[p.op] != 0x63) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    if (mod == 3 || rm != 4) {
        return false;
    }

    uint8_t sib = buf[p.op + 2];
    uint8_t scale_bits = sib >> 6;
    uint8_t index = (sib >> 3) & 7;
    uint8_t base = sib & 7;
    if ((index == 4 && !p.rex_x) || (mod == 0 && base == 5) ||
        scale_bits != 2) {
        return false;
    }

    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->base = base + p.rex_b * 8;
    out->index = index + p.rex_x * 8;
    out->scale = 1 << scale_bits;
    out->len = p.op + 3 - off;
    if (mod == 1) {
        out->len += 1;
    } else if (mod == 2) {
        out->len += 4;
    }
    return true;
}

static bool parse_lea_rip(const uint8_t *buf, size_t size, uint64_t func_addr,
                          size_t off, LeaRip *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 5 >= size || buf[p.op] != 0x8d) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    if (mod != 0 || rm != 5) {
        return false;
    }

    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->len = p.op + 6 - off;
    out->target = func_addr + off + out->len + rd_i32(buf + p.op + 2);
    return true;
}

static bool parse_lea_reg(const uint8_t *buf, size_t size, size_t off,
                          LeaReg *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || buf[p.op] != 0x8d) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    if (mod != 0 || rm != 4) {
        return false;
    }

    uint8_t sib = buf[p.op + 2];
    uint8_t scale_bits = sib >> 6;
    uint8_t index = (sib >> 3) & 7;
    uint8_t base = sib & 7;
    if ((index == 4 && !p.rex_x) || base == 5) {
        return false;
    }

    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->base = base + p.rex_b * 8;
    out->index = index + p.rex_x * 8;
    out->scale = 1 << scale_bits;
    out->len = p.op + 3 - off;
    return true;
}

static bool parse_mov_reg(const uint8_t *buf, size_t size, size_t off,
                          MovReg *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 1 >= size || (buf[p.op] != 0x89 && buf[p.op] != 0x8b)) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    if ((modrm >> 6) != 3) {
        return false;
    }

    int reg = ((modrm >> 3) & 7) + p.rex_r * 8;
    int rm = (modrm & 7) + p.rex_b * 8;
    if (buf[p.op] == 0x89) {
        out->src = reg;
        out->dst = rm;
    } else {
        out->src = rm;
        out->dst = reg;
    }
    out->len = p.op + 2 - off;
    return true;
}

static bool parse_mov_mem_scaled(const uint8_t *buf, size_t size, size_t off,
                                 MovMem *out)
{
    Prefix p = parse_prefix(buf, size, off);
    if (p.op + 2 >= size || buf[p.op] != 0x8b) {
        return false;
    }

    uint8_t modrm = buf[p.op + 1];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    if (mod == 3 || rm != 4) {
        return false;
    }

    uint8_t sib = buf[p.op + 2];
    uint8_t scale_bits = sib >> 6;
    uint8_t index = (sib >> 3) & 7;
    uint8_t base = sib & 7;
    if (index == 4 && !p.rex_x) {
        return false;
    }
    bool absolute = mod == 0 && base == 5;
    if (absolute && (!p.rex_w || p.nonflat_address)) {
        return false;
    }

    size_t len = p.op + 3 - off;
    int32_t disp = 0;
    if (mod == 1) {
        if (p.op + 3 >= size) {
            return false;
        }
        disp = (int8_t)buf[p.op + 3];
        len += 1;
    } else if (mod == 2 || absolute) {
        if (p.op + 6 >= size) {
            return false;
        }
        disp = rd_i32(buf + p.op + 3);
        len += 4;
    }

    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->base = absolute ? -1 : base + p.rex_b * 8;
    out->index = index + p.rex_x * 8;
    out->scale = 1 << scale_bits;
    out->disp = disp;
    out->len = len;
    return true;
}

static bool add_target(IjmpResult *out, uint64_t target)
{
    /* Tables may contain duplicate case targets; keep each edge once. */
    for (size_t i = 0; i < out->count; i++) {
        if (out->targets[i] == target) {
            return true;
        }
    }
    if (out->count == IJMP_MAX_TARGETS) {
        return false;
    }
    out->targets[out->count++] = target;
    return true;
}

static bool resolve_qword_table(const IjmpContext *ctx, const uint8_t *func,
                                size_t func_size, size_t ijmp_off,
                                IjmpResult *out)
{
    /*
     * Absolute qword table pattern:
     *   lea base, [rip + table]
     *   jmp qword ptr [base + index * 8]
     * or jmp qword ptr [disp32 + index * 8].
     */
    JmpMem jmp;
    if (!parse_jmp_mem_scaled(func, func_size, ijmp_off, &jmp) ||
        jmp.scale != 8) {
        return false;
    }

    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
                   ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    LeaRip lea = { .target = jmp.table_addr };
    bool have_lea = jmp.base < 0;
    for (size_t ii = insn_lower_bound_off(ctx, start);
         jmp.base >= 0 && ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + ijmp_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        LeaRip cur;
        if (parse_lea_rip(func, ijmp_off, ctx->func_addr, off, &cur) &&
            cur.dst == jmp.base) {
            lea = cur;
            have_lea = true;
        }
    }
    if (!have_lea) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->table_addr = lea.target;
    size_t entries = 0;
    bool has_cross_target = false;
    for (size_t i = 0; i < IJMP_MAX_TARGETS; i++) {
        if (i > (UINT64_MAX - lea.target) / 8) {
            break;
        }
        const uint8_t *p = va_ptr(ctx, lea.target + i * 8, 8);
        if (!p) {
            break;
        }

        uint64_t target = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                          ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
                          ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
                          ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
        if (!is_valid_target(ctx, target)) {
            break;
        }
        entries++;
        if (!in_func(ctx, target)) {
            has_cross_target = true;
        }
        if (!add_target(out, target)) {
            break;
        }
    }

    return out->count > 0 && (!has_cross_target || entries >= 2);
}

static bool resolve_reg_qword_table(const IjmpContext *ctx,
                                    const uint8_t *func,
                                    size_t ijmp_off,
                                    int jmp_reg, IjmpResult *out)
{
    /*
     * Function-pointer table loaded through a register:
     *   lea base, [rip + table]
     *   mov target, qword ptr [base + index * 8 + disp]
     *   jmp target
     */
    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
                   ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    MovMem mov = {0};
    size_t mov_off = 0;
    bool have_mov = false;

    for (size_t ii = insn_lower_bound_off(ctx, start);
         ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + ijmp_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        MovMem cur;
        if (parse_mov_mem_scaled(func, ijmp_off, off, &cur) &&
            cur.dst == jmp_reg && cur.scale == 8) {
            if (cur.base < 0 && cur.len != ijmp_off - off) {
                continue;
            }
            mov = cur;
            mov_off = off;
            have_mov = true;
        }
    }
    if (!have_mov) {
        return false;
    }

    LeaRip lea = {0};
    bool have_lea = mov.base < 0;
    for (size_t ii = insn_lower_bound_off(ctx, start);
         mov.base >= 0 && ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + mov_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        LeaRip cur;
        if (parse_lea_rip(func, mov_off, ctx->func_addr, off, &cur) &&
            cur.dst == mov.base) {
            lea = cur;
            have_lea = true;
        }
    }
    if (!have_lea) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->table_addr = lea.target + (uint64_t)(int64_t)mov.disp;
    size_t entries = 0;
    bool has_cross_target = false;
    for (size_t i = 0; i < IJMP_MAX_TARGETS; i++) {
        if (i > (UINT64_MAX - out->table_addr) / 8) {
            break;
        }
        const uint8_t *p = va_ptr(ctx, out->table_addr + i * 8, 8);
        if (!p) {
            break;
        }

        uint64_t target = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                          ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
                          ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
                          ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
        if (!is_valid_target(ctx, target)) {
            break;
        }
        entries++;
        if (!in_func(ctx, target)) {
            has_cross_target = true;
        }
        if (!add_target(out, target)) {
            break;
        }
    }

    return out->count > 0 && (!has_cross_target || entries >= 2);
}

static bool resolve_const_reg_target(const IjmpContext *ctx,
                                     const uint8_t *func,
                                     size_t func_size, size_t ijmp_off,
                                     int jmp_reg, IjmpResult *out)
{
    /*
     * Some optimized loops use a register as a local branch target without a
     * table, e.g.:
     *   lea rcx, [rip + label]
     *   ...
     *   jmp rcx
     * Allow a short backwards alias chain through mov reg,reg, but stop when
     * the wanted register is otherwise modified. That keeps callback/vtable
     * jumps classified as unresolved.
     */
    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
                   ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    int wanted = jmp_reg;

    for (size_t ii = insn_lower_bound_off(ctx, ijmp_off); ii > 0;) {
        size_t off = (size_t)(ctx->insn_addrs[--ii] - ctx->func_addr);
        if (off < start) break;

        LeaRip lea;
        if (parse_lea_rip(func, func_size, ctx->func_addr, off, &lea) &&
            lea.dst == wanted) {
            if (!is_valid_target(ctx, lea.target)) {
                return false;
            }
            memset(out, 0, sizeof(*out));
            out->table_addr = 0;
            return add_target(out, lea.target);
        }

        MovRip mov_rip;
        if (parse_mov_rip(func, func_size, ctx->func_addr, off, &mov_rip) &&
            mov_rip.dst == wanted) {
            const uint8_t *p = va_ptr(ctx, mov_rip.address, 8);
            if (!p) return false;
            uint64_t target = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                              ((uint64_t)p[2] << 16) |
                              ((uint64_t)p[3] << 24) |
                              ((uint64_t)p[4] << 32) |
                              ((uint64_t)p[5] << 40) |
                              ((uint64_t)p[6] << 48) |
                              ((uint64_t)p[7] << 56);
            if (!is_valid_target(ctx, target)) return false;
            memset(out, 0, sizeof(*out));
            out->table_addr = mov_rip.address;
            return add_target(out, target);
        }

        MovReg mov;
        if (parse_mov_reg(func, func_size, off, &mov)) {
            if (mov.dst == wanted) {
                wanted = mov.src;
            }
            continue;
        }

        AddReg add;
        if (parse_add_reg(func, func_size, off, &add) && add.dst == wanted) {
            return false;
        }

        MovsxdMem movsxd;
        if (parse_movsxd_mem(func, func_size, off, &movsxd) &&
            movsxd.dst == wanted) {
            return false;
        }

        LeaReg lea_reg;
        if (parse_lea_reg(func, func_size, off, &lea_reg) &&
            lea_reg.dst == wanted) {
            return false;
        }
    }

    return false;
}

static bool resolve_computed_stride(const IjmpContext *ctx,
                                    const uint8_t *func, size_t func_size,
                                    size_t start, size_t combine_off,
                                    int offset_reg, int base_reg,
                                    IjmpResult *out)
{
    /* Optimized libc routines use code itself as a table:
     *   lea base, [rip + first_case]
     *   and index, case_count - 1
     *   shl index, log2(case_stride)
     *   add index, base
     *   jmp index
     * Every fixed-stride case is a valid indirect entry point. */
    LeaRip base = {0};
    RegImm mask = {0};
    RegImm shift = {0};
    bool have_base = false, have_mask = false, have_shift = false;
    for (size_t ii = insn_lower_bound_off(ctx, start);
         ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + combine_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        LeaRip cur_base;
        if (parse_lea_rip(func, func_size, ctx->func_addr, off, &cur_base) &&
            cur_base.dst == base_reg) {
            base = cur_base;
            have_base = true;
        }
        RegImm cur;
        if (parse_and_imm(func, func_size, off, &cur) &&
            cur.dst == offset_reg) {
            mask = cur;
            have_mask = true;
        }
        if (parse_shl_imm(func, func_size, off, &cur) &&
            cur.dst == offset_reg) {
            shift = cur;
            have_shift = true;
        }
    }
    uint64_t count = (uint64_t)mask.value + 1;
    if (!have_base || !have_mask || !have_shift || shift.value >= 63 ||
        !count || count > IJMP_MAX_TARGETS || (count & (count - 1))) {
        return false;
    }
    uint64_t stride = UINT64_C(1) << shift.value;
    memset(out, 0, sizeof(*out));
    out->table_addr = base.target;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t target = base.target + i * stride;
        if (target < base.target || !is_valid_target(ctx, target) ||
            !add_target(out, target)) {
            memset(out, 0, sizeof(*out));
            return false;
        }
    }
    return out->count >= 2;
}

typedef struct {
    uint64_t address;
    uint32_t bound;
    int kind;
    bool wide;
} PicValue;

enum { PIC_UNKNOWN, PIC_INDEX, PIC_ADDRESS, PIC_OFFSET, PIC_TARGET };

typedef struct {
    unsigned low;
    unsigned full;
    bool zero_extended;
} PicAlias;

static bool pic_plain_prefix(const uint8_t *buf, size_t off, Prefix p)
{
    for (size_t i = off; i < p.op; i++) {
        if (buf[i] < 0x40 || buf[i] > 0x4f) {
            return false;
        }
    }
    return true;
}

static bool pic_executable(const IjmpContext *ctx, uint64_t target)
{
    for (size_t i = 0; i < ctx->section_count; i++) {
        const IjmpSection *s = &ctx->sections[i];
        if (s->executable && target >= s->addr &&
            target - s->addr < s->size && va_ptr(ctx, target, 1)) {
            return true;
        }
    }
    return false;
}

static bool pic_readonly_table(const IjmpContext *ctx, uint64_t table,
                                size_t bytes)
{
    for (size_t i = 0; i < ctx->section_count; i++) {
        const IjmpSection *s = &ctx->sections[i];
        if (!s->writable && table >= s->addr && bytes <= s->size &&
            table - s->addr <= s->size - bytes) {
            return true;
        }
    }
    return false;
}

/* Only flag-preserving integer instructions enter the guard/branch gap. */
static bool pic_preserves_flags(const uint8_t *buf, size_t size, size_t off,
                                 Insn in, int *written, bool *zero_extended)
{
    Prefix p = parse_prefix(buf, size, off);
    *written = -1;
    *zero_extended = !p.rex_w;
    if (!pic_plain_prefix(buf, off, p) || p.op >= size ||
        !in.len || in.len > size - off || in.kind != INSN_NORMAL) {
        return false;
    }
    uint8_t op = buf[p.op];
    MovReg move;
    if (parse_mov_reg(buf, size, off, &move) && move.len == in.len) {
        *written = move.dst;
        return true;
    }
    if (op >= 0xb8 && op <= 0xbf) {
        *written = (op & 7) + p.rex_b * 8;
        return true;
    }
    if (op == 0x90 && in.len == 1 && !p.rex_b) {
        return true;
    }
    if (p.op + 1 >= size) {
        return false;
    }
    uint8_t modrm = buf[p.op + 1];
    if (op == 0x8b || (op == 0x8d && (modrm >> 6) != 3)) {
        *written = ((modrm >> 3) & 7) + p.rex_r * 8;
        return true;
    }
    return (modrm >> 6) != 3 &&
        (op == 0x88 || op == 0x89 ||
         ((op == 0xc6 || op == 0xc7) && !(modrm & 0x38)));
}

static size_t pic_inbound_lower(const IjmpContext *ctx, uint64_t target)
{
    size_t lo = 0, hi = ctx->inbound_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ctx->inbound[mid].target < target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static bool pic_entry_at(const IjmpContext *ctx, uint64_t address)
{
    size_t at = pic_inbound_lower(ctx, address);
    return (at < ctx->inbound_count && ctx->inbound[at].target == address) ||
        is_direct_target(ctx, address) || is_func_entry(ctx, address);
}

static bool cfi_plain_wide(const uint8_t *code, size_t size, size_t off,
                            Prefix *prefix)
{
    *prefix = parse_prefix(code, size, off);
    return pic_plain_prefix(code, off, *prefix) && prefix->rex_w &&
        prefix->op < size;
}

static bool cfi_slot_operand(const uint8_t *code, size_t size, size_t off,
                             Insn in, int pointer, int32_t *displacement,
                             int *loaded)
{
    Prefix p = parse_prefix(code, size, off);
    if (!pic_plain_prefix(code, off, p) || p.op + 1 >= size) return false;
    unsigned modrm = code[p.op + 1], mod = modrm >> 6;
    unsigned group = (modrm >> 3) & 7, rm = modrm & 7;
    if (code[p.op] == 0xff &&
        (in.kind == INSN_ICALL || in.kind == INSN_IJMP) &&
        (group == 2 || group == 4) && !p.rex_r) {
        *loaded = -1;
    } else if (code[p.op] == 0x8b && p.rex_w &&
               in.kind == INSN_NORMAL) {
        *loaded = group + 8 * p.rex_r;
        if (*loaded == 4) return false;
    } else {
        return false;
    }
    if (mod == 3) return false;
    size_t cursor = p.op + 2;
    int base = rm + 8 * p.rex_b;
    if (rm == 4) {
        if (cursor >= size || (code[cursor] & 0x38) != 0x20 || p.rex_x)
            return false;
        base = (code[cursor++] & 7) + 8 * p.rex_b;
    }
    if ((!mod && (base & 7) == 5) || base != pointer) return false;
    *displacement = 0;
    if (mod == 1) {
        if (cursor >= size) return false;
        *displacement = (int8_t)code[cursor++];
    } else if (mod == 2) {
        if (size - cursor < 4) return false;
        *displacement = rd_i32(code + cursor);
        cursor += 4;
    }
    return cursor - off == in.len;
}

/* MOVZX only reads its operand and writes the complete 32/64-bit destination. */
static bool cfi_zero_extend_load(const uint8_t *code, size_t size, size_t off,
                                 Insn in, int *written)
{
    Prefix p = parse_prefix(code, size, off);
    if (!pic_plain_prefix(code, off, p) || in.kind != INSN_NORMAL ||
        !in.len || in.len > size - off || size - p.op < 3 ||
        code[p.op] != 0x0f ||
        (code[p.op + 1] != 0xb6 && code[p.op + 1] != 0xb7)) return false;
    *written = ((code[p.op + 2] >> 3) & 7) + 8 * p.rex_r;
    return true;
}

/* After the immutable slot read, only the loaded value must remain live. */
static bool cfi_register_dispatch(const IjmpContext *ctx, const uint8_t *code,
                                  size_t size, size_t *offset, int target)
{
    size_t off = *offset;
    for (unsigned steps = 0; steps < 16 && off < size; steps++) {
        Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
        Prefix p = parse_prefix(code, size, off);
        if (!in.len || in.len > size - off ||
            !pic_plain_prefix(code, off, p) || p.op >= size) return false;
        int reg;
        if ((in.kind == INSN_ICALL || in.kind == INSN_IJMP) &&
            parse_indirect_reg(code, size, off, &reg) && reg == target) {
            *offset = off + in.len;
            return true;
        }
        unsigned op = code[p.op];
        bool accepted = false;
        if (op >= 0x58 && op <= 0x5f && !p.rex_r && !p.rex_x &&
            in.len == p.op + 1 - off) {
            reg = (op & 7) + 8 * p.rex_b;
            accepted = reg != target && reg != 4;
        } else if (p.op + 1 < size && (op == 0x31 || op == 0x33) &&
                   (code[p.op + 1] >> 6) == 3) {
            unsigned modrm = code[p.op + 1];
            reg = op == 0x31 ? (modrm & 7) + 8 * p.rex_b :
                              ((modrm >> 3) & 7) + 8 * p.rex_r;
            accepted = reg != target && reg != 4;
        } else if (p.rex_w && !p.rex_r && !p.rex_x && !p.rex_b &&
                   (op == 0x83 || op == 0x81) && p.op + 1 < size &&
                   code[p.op + 1] == 0xc4) {
            size_t bytes = op == 0x83 ? 1 : 4;
            if (size - p.op >= 2 + bytes && in.len == p.op + 2 + bytes - off) {
                int64_t adjustment = bytes == 1 ? (int8_t)code[p.op + 2] :
                                                 rd_i32(code + p.op + 2);
                accepted = adjustment >= 0;
            }
        } else {
            bool zero;
            accepted = (((op == 0x90 || op == 0x8b || op == 0x8d ||
                (op >= 0xb8 && op <= 0xbf) ||
                (op == 0x89 && p.op + 1 < size &&
                 (code[p.op + 1] >> 6) == 3)) &&
                pic_preserves_flags(code, size, off, in, &reg, &zero)) ||
                cfi_zero_extend_load(code, size, off, in, &reg)) &&
                reg != target && reg != 4;
        }
        if (!accepted || in.kind != INSN_NORMAL) return false;
        off += in.len;
    }
    return false;
}

static bool cfi_bit_filter(const IjmpContext *ctx, const uint8_t *code,
                           size_t size, size_t *offset, int index, int pointer,
                           uint64_t *mask, uint64_t *rejected)
{
    size_t off = *offset;
    Prefix p = parse_prefix(code, size, off);
    if (!pic_plain_prefix(code, off, p) || p.rex_r || p.rex_x ||
        p.op >= size || code[p.op] < 0xb8 || code[p.op] > 0xbf)
        return false;
    bool wide = p.rex_w;
    size_t immediate = wide ? 8 : 4;
    if (size - p.op < 1 + immediate) return false;
    int bits = code[p.op] - 0xb8 + 8 * p.rex_b;
    if (bits == index || bits == pointer) return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 1 + immediate - off) return false;
    uint64_t value = wide ? rd64(code + p.op + 1) :
                           (uint32_t)rd_i32(code + p.op + 1);
    off += in.len;
    p = parse_prefix(code, size, off);
    if (!pic_plain_prefix(code, off, p) || p.rex_w != wide ||
        p.op > size || size - p.op < 3 ||
        code[p.op] != 0x0f || code[p.op + 1] != 0xa3 || p.rex_x)
        return false;
    unsigned modrm = code[p.op + 2];
    if ((modrm >> 6) != 3 ||
        (int)(modrm & 7) + 8 * p.rex_b != bits ||
        (int)((modrm >> 3) & 7) + 8 * p.rex_r != index) return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 3 - off) return false;
    off += in.len;
    if (off >= size || (code[off] != 0x73 &&
        !(size - off >= 2 && code[off] == 0x0f && code[off + 1] == 0x83)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (!in.has_target || in.len > size - off) return false;
    *offset = off + in.len;
    /* Register BT masks its index by operand width, not pointer width. */
    if (!wide) value |= value << 32;
    *mask = value;
    *rejected = in.target;
    return true;
}

static bool cfi_byte_filter(const IjmpContext *ctx, const uint8_t *code,
                            size_t size, size_t *offset, int index, int pointer,
                            uint64_t *table, uint8_t *mask, uint64_t *rejected)
{
    size_t off = *offset;
    LeaRip base;
    Prefix p;
    if (!ctx->read_immutable_byte ||
        !cfi_plain_wide(code, size, off, &p) ||
        !parse_lea_rip(code, size, ctx->func_addr, off, &base) ||
        base.dst == index || base.dst == pointer || base.dst == 4) return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != base.len) return false;
    off += in.len;
    p = parse_prefix(code, size, off);
    if (!pic_plain_prefix(code, off, p) || p.rex_w || p.rex_r ||
        p.op >= size || size - p.op < 4 || code[p.op] != 0xf6 ||
        code[p.op + 1] != 0x04) return false;
    unsigned sib = code[p.op + 2];
    if ((sib >> 6) != 0 || (sib & 7) == 5 ||
        ((sib >> 3) & 7) + 8 * p.rex_x != (unsigned)index ||
        (sib & 7) + 8 * p.rex_b != (unsigned)base.dst ||
        (!p.rex_x && ((sib >> 3) & 7) == 4)) return false;
    uint8_t value = code[p.op + 3];
    if (!value) return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.kind != INSN_NORMAL || in.len != p.op + 4 - off) return false;
    off += in.len;
    if (off >= size || (code[off] != 0x74 &&
        !(size - off >= 2 && code[off] == 0x0f && code[off + 1] == 0x84)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (!in.has_target || in.len > size - off) return false;
    *offset = off + in.len;
    *table = base.target;
    *mask = value;
    *rejected = in.target;
    return true;
}

static bool cfi_finish(const IjmpContext *ctx, const uint8_t *code,
                        size_t size, size_t off, size_t proof_start,
                        int pointer, int index, uint64_t base,
                        unsigned rotation, IjmpResult *out)
{
    Prefix p;
    if (!cfi_plain_wide(code, size, off, &p) || p.op + 2 >= size ||
        (code[p.op] != 0x83 && code[p.op] != 0x81) ||
        (code[p.op + 1] & 0xf8) != 0xf8 || p.rex_r ||
        (code[p.op + 1] & 7) + 8 * p.rex_b != index) return false;
    /* A small unsigned bound is a resource policy, never a truncated result. */
    size_t immediate = code[p.op] == 0x83 ? 1 : 4;
    if (size - p.op < 2 + immediate) return false;
    int64_t limit = immediate == 1 ? (int8_t)code[p.op + 2] :
                                    rd_i32(code + p.op + 2);
    if (limit < 0 || limit >= IJMP_MAX_TARGETS) return false;
    unsigned bound = (unsigned)limit;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 2 + immediate - off) return false;
    off += in.len;
    if (off >= size || (code[off] != 0x77 &&
        !(size - off >= 2 && code[off] == 0x0f && code[off + 1] == 0x87)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (!in.has_target || in.len > size - off) return false;
    uint64_t rejected = in.target;
    off += in.len;
    uint64_t mask = UINT64_MAX, bit_rejected = 0;
    bool filtered = cfi_bit_filter(ctx, code, size, &off, index, pointer,
                                   &mask, &bit_rejected);
    uint64_t byte_table = 0;
    uint8_t byte_mask = 0;
    bool byte_filtered = !filtered &&
        cfi_byte_filter(ctx, code, size, &off, index, pointer,
                         &byte_table, &byte_mask, &bit_rejected);
    int32_t displacement = 0;
    bool found = false;
    for (unsigned steps = 0; steps < 16 && off < size; steps++) {
        in = cfg_decode_insn(code, size, ctx->func_addr, off);
        if (!in.len || in.len > size - off) return false;
        int loaded;
        if (cfi_slot_operand(code, size, off, in, pointer, &displacement,
                             &loaded)) {
            off += in.len;
            if (loaded >= 0 &&
                !cfi_register_dispatch(ctx, code, size, &off, loaded))
                return false;
            found = true;
            break;
        }
        int written;
        bool zero;
        Prefix gap = parse_prefix(code, size, off);
        bool zero_load = cfi_zero_extend_load(code, size, off, in, &written);
        if (!zero_load && (gap.op >= size ||
            /* Unknown memory aliases must not mutate a protected slot. */
            (code[gap.op] != 0x90 && code[gap.op] != 0x8b &&
             code[gap.op] != 0x8d &&
             !(code[gap.op] >= 0xb8 && code[gap.op] <= 0xbf) &&
             !((code[gap.op] == 0x89) && gap.op + 1 < size &&
               (code[gap.op + 1] >> 6) == 3)) ||
            !pic_preserves_flags(code, size, off, in, &written, &zero)))
            return false;
        if (written == pointer || written == 4) return false;
        off += in.len;
    }
    if (!found || rejected < ctx->func_addr + off ||
        ((filtered || byte_filtered) && bit_rejected < ctx->func_addr + off)) return false;
    /* No known entry, even inside an instruction, may bypass the proof. */
    size_t inbound = pic_inbound_lower(ctx, ctx->func_addr + proof_start + 1);
    if (inbound < ctx->inbound_count &&
        ctx->inbound[inbound].target < ctx->func_addr + off) return false;
    IjmpResult result = {.table_addr = base};
    for (unsigned i = 0; i <= bound; i++) {
        /* Register BT uses the low six index bits for a 64-bit operand. */
        if (!(mask & (UINT64_C(1) << (i & 63)))) continue;
        if (byte_filtered) {
            uint8_t value;
            if (byte_table > UINT64_MAX - i ||
                !ctx->read_immutable_byte(ctx->pointer_data, byte_table + i,
                                          &value)) return false;
            if (!(value & byte_mask)) continue;
        }
        uint64_t value = i;
        uint64_t delta = rotation ?
            (value << rotation) | (value >> (64 - rotation)) : value;
        uint64_t slot = base + delta + (uint64_t)(int64_t)displacement;
        uint64_t target;
        if (!ctx->read_immutable_pointer(ctx->pointer_data, slot, &target) ||
            !pic_executable(ctx, target) || !add_target(&result, target))
            return false;
    }
    if (!result.count) return false;
    *out = result;
    return true;
}

bool ijmp_resolve_cfi_entry(const IjmpContext *ctx, const uint8_t *code,
                            size_t size, IjmpResult *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!ctx || !code || !ctx->inbound_complete ||
        !ctx->read_immutable_pointer || size > UINT64_MAX - ctx->func_addr)
        return false;
    Prefix p;
    LeaRip base;
    MovReg copy;
    size_t off = 0;
    if (!cfi_plain_wide(code, size, off, &p) ||
        !parse_lea_rip(code, size, ctx->func_addr, off, &base)) return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (base.len != in.len) return false;
    off += in.len;
    if (!cfi_plain_wide(code, size, off, &p) ||
        !parse_mov_reg(code, size, off, &copy)) return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (copy.len != in.len || copy.dst == copy.src || copy.dst == base.dst ||
        copy.src == base.dst) return false;
    off += in.len;
    if (!cfi_plain_wide(code, size, off, &p) || p.op + 1 >= size)
        return false;
    unsigned modrm = code[p.op + 1];
    int reg = ((modrm >> 3) & 7) + 8 * p.rex_r;
    int rm = (modrm & 7) + 8 * p.rex_b;
    if ((modrm >> 6) != 3 ||
        !((code[p.op] == 0x29 && rm == copy.dst && reg == base.dst) ||
          (code[p.op] == 0x2b && reg == copy.dst && rm == base.dst)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 2 - off) return false;
    off += in.len;
    if (!cfi_plain_wide(code, size, off, &p) || p.op + 2 >= size ||
        code[p.op] != 0xc1 || (code[p.op + 1] & 0xf8) != 0xc8 || p.rex_r ||
        (code[p.op + 1] & 7) + 8 * p.rex_b != copy.dst) return false;
    unsigned rotation = code[p.op + 2] & 63;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 3 - off) return false;
    return cfi_finish(ctx, code, size, off + in.len, 0, copy.src, copy.dst,
                       base.target, rotation, out);
}

static bool cfi_take_move(const IjmpContext *ctx, const uint8_t *code,
                           size_t size, size_t *off, MovReg *move, bool wide)
{
    Prefix p = parse_prefix(code, size, *off);
    if (!pic_plain_prefix(code, *off, p) || p.rex_w != wide ||
        !parse_mov_reg(code, size, *off, move)) return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, *off);
    if (in.len != move->len || !in.len) return false;
    *off += in.len;
    return true;
}

static bool cfi_take_shift(const IjmpContext *ctx, const uint8_t *code,
                            size_t size, size_t *off, int reg, unsigned group)
{
    Prefix p;
    if (!cfi_plain_wide(code, size, *off, &p) || size - p.op < 2 ||
        p.rex_r || code[p.op] != 0xd3 ||
        (code[p.op + 1] & 0xf8) != (0xc0 | (group << 3)) ||
        (code[p.op + 1] & 7) + 8 * p.rex_b != reg) return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, *off);
    if (in.len != p.op + 2 - *off) return false;
    *off += in.len;
    return true;
}

bool ijmp_resolve_split_cfi_entry(const IjmpContext *ctx, const uint8_t *code,
                                  size_t size, size_t proof_start,
                                  IjmpResult *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!ctx || !code || proof_start >= size ||
        !ctx->inbound_complete || !ctx->read_immutable_pointer ||
        size > UINT64_MAX - ctx->func_addr) return false;
    size_t off = proof_start;
    MovReg copy, low, count_right, count_left;
    if (!cfi_take_move(ctx, code, size, &off, &copy, true) ||
        copy.src == copy.dst || copy.src == 4 || copy.dst == 4 ||
        copy.src == 1 || copy.dst == 1) return false;
    LeaRip base;
    Prefix p;
    if (!cfi_plain_wide(code, size, off, &p) ||
        !parse_lea_rip(code, size, ctx->func_addr, off, &base) ||
        base.dst == copy.src || base.dst == copy.dst || base.dst == 4)
        return false;
    Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != base.len) return false;
    off += in.len;
    if (!cfi_plain_wide(code, size, off, &p) || size - p.op < 2)
        return false;
    unsigned m = code[p.op + 1];
    int reg = ((m >> 3) & 7) + 8 * p.rex_r;
    int rm = (m & 7) + 8 * p.rex_b;
    if ((m >> 6) != 3 ||
        !((code[p.op] == 0x29 && rm == copy.dst && reg == base.dst) ||
          (code[p.op] == 0x2b && reg == copy.dst && rm == base.dst)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 2 - off) return false;
    off += in.len;
    if (!cfi_take_move(ctx, code, size, &off, &low, true) ||
        low.src != copy.dst || low.dst == copy.src || low.dst == copy.dst ||
        low.dst == 1 || low.dst == 4) return false;
    if (!cfi_take_move(ctx, code, size, &off, &count_right, false) ||
        count_right.dst != 1) return false;
    size_t right_shift = off;
    if (!cfi_take_shift(ctx, code, size, &off, low.dst, 5) ||
        !cfi_take_move(ctx, code, size, &off, &count_left, false) ||
        count_left.dst != 1) return false;
    size_t left_shift = off;
    if (!cfi_take_shift(ctx, code, size, &off, copy.dst, 4) ||
        !cfi_plain_wide(code, size, off, &p) || size - p.op < 2)
        return false;
    m = code[p.op + 1];
    reg = ((m >> 3) & 7) + 8 * p.rex_r;
    rm = (m & 7) + 8 * p.rex_b;
    if ((m >> 6) != 3 ||
        !((code[p.op] == 0x09 && rm == copy.dst && reg == low.dst) ||
          (code[p.op] == 0x0b && reg == copy.dst && rm == low.dst)))
        return false;
    in = cfg_decode_insn(code, size, ctx->func_addr, off);
    if (in.len != p.op + 2 - off) return false;
    off += in.len;
    CfgGprConstants right, left;
    if (!gpr_constants_pair(ctx, code, off, right_shift, left_shift,
                             &right, &left) ||
        (right.known[1] & 63) != 63 || (left.known[1] & 63) != 63)
        return false;
    unsigned rotation = right.value[1] & 63;
    /* Both zero shifts OR the unshifted input. Otherwise require a genuine
     * complementary 64-bit rotation; arbitrary counts have a huge inverse. */
    if (((rotation + (left.value[1] & 63)) & 63) != 0) return false;
    return cfi_finish(ctx, code, size, off, proof_start, copy.src, copy.dst,
                       base.target, rotation, out);
}

static void pic_alias_seed(const IjmpContext *ctx, const uint8_t *buf,
                            size_t size, size_t guard, int index,
                            uint32_t bound, bool wide, PicValue regs[16])
{
    PicAlias aliases[16];
    unsigned version = 16;
    for (unsigned i = 0; i < 16; i++) {
        aliases[i] = (PicAlias) {.low = i, .full = i};
    }
    size_t begin = insn_lower_bound_off(ctx,
        guard > IJMP_LOOKBACK_BYTES ? guard - IJMP_LOOKBACK_BYTES : 0);
    for (size_t i = begin; i < ctx->insn_count; i++) {
        size_t off = ctx->insn_addrs[i] - ctx->func_addr;
        if (off >= guard) {
            break;
        }
        Insn in = cfg_decode_insn(buf, size, ctx->func_addr, off);
        Prefix p = parse_prefix(buf, size, off);
        MovReg move;
        int written;
        bool zero;
        if (pic_entry_at(ctx, ctx->func_addr + off)) {
            for (unsigned j = 0; j < 16; j++) {
                version++;
                aliases[j] = (PicAlias) {.low = version, .full = version};
            }
        }
        if (pic_plain_prefix(buf, off, p) &&
            parse_mov_reg(buf, size, off, &move) && move.len == in.len) {
            aliases[move.dst] = aliases[move.src];
            if (!p.rex_w) {
                aliases[move.dst].zero_extended = true;
                aliases[move.dst].full = ++version;
            }
        } else if (pic_preserves_flags(buf, size, off, in, &written, &zero)) {
            if (written >= 0) {
                version++;
                aliases[written] = (PicAlias) {
                    .low = version, .full = version,
                    .zero_extended = zero,
                };
            }
        } else if (pic_plain_prefix(buf, off, p) && p.op + 1 < size &&
                   buf[p.op] == 0xff && (buf[p.op + 1] >> 6) == 3 &&
                   (buf[p.op + 1] & 0x38) <= 8) {
            written = (buf[p.op + 1] & 7) + p.rex_b * 8;
            version++;
            aliases[written] = (PicAlias) {
                .low = version, .full = version, .zero_extended = !p.rex_w,
            };
        } else {
            /* Unknown effects and control transfers invalidate all aliases. */
            for (unsigned j = 0; j < 16; j++) {
                version++;
                aliases[j] = (PicAlias) {.low = version, .full = version};
            }
        }
    }
    if (pic_entry_at(ctx, ctx->func_addr + guard)) {
        for (unsigned j = 0; j < 16; j++) {
            version++;
            aliases[j] = (PicAlias) {.low = version, .full = version};
        }
    }
    for (unsigned i = 0; i < 16; i++) {
        if (aliases[i].low == aliases[index].low) {
            regs[i] = (PicValue) {.kind = PIC_INDEX, .bound = bound,
                .wide = aliases[i].zero_extended ||
                    (wide && aliases[i].full == aliases[index].full)};
        }
    }
}

static bool pic_guard(const uint8_t *buf, size_t size, size_t off,
                       int *reg, uint32_t *bound, bool *wide, size_t *next)
{
    Prefix p = parse_prefix(buf, size, off);
    if (!pic_plain_prefix(buf, off, p) || p.op >= size) {
        return false;
    }
    size_t imm;
    unsigned bytes;
    if (buf[p.op] == 0x3d) {
        *reg = 0;
        imm = p.op + 1;
        bytes = 4;
    } else if ((buf[p.op] == 0x81 || buf[p.op] == 0x83) &&
               p.op + 1 < size && (buf[p.op + 1] & 0xf8) == 0xf8 &&
               !p.rex_r) {
        *reg = (buf[p.op + 1] & 7) + p.rex_b * 8;
        imm = p.op + 2;
        bytes = buf[p.op] == 0x83 ? 1 : 4;
    } else {
        return false;
    }
    if (imm > size || bytes > size - imm) {
        return false;
    }
    int64_t value = bytes == 1 ? (int8_t)buf[imm] : rd_i32(buf + imm);
    if (value < 0 || value >= IJMP_MAX_TARGETS) {
        return false;
    }
    *bound = value;
    *wide = p.rex_w;
    *next = imm + bytes;
    return true;
}

static bool pic_dispatch(const IjmpContext *ctx, const uint8_t *buf,
                          size_t size, size_t start, size_t jump,
                          size_t guard, size_t guard_branch,
                          int index, uint32_t bound, bool wide,
                          IjmpResult *out)
{
    PicValue regs[16] = {0};
    pic_alias_seed(ctx, buf, size, guard, index, bound, wide, regs);
    for (size_t off = guard; off < guard_branch;) {
        Insn in = cfg_decode_insn(buf, size, ctx->func_addr, off);
        if (!in.len || in.len > guard_branch - off) {
            return false;
        }
        if (off != guard && off != guard_branch) {
            int written;
            bool zero;
            if (!pic_preserves_flags(buf, size, off, in, &written, &zero)) {
                return false;
            }
            if (written >= 0) {
                regs[written].kind = PIC_UNKNOWN;
            }
        }
        off += in.len;
    }
    uint64_t table = 0;
    uint32_t count = 0;
    uint64_t protected_start = ctx->func_addr + guard + 1;
    uint64_t protected_end = ctx->func_addr + jump;
    uint64_t branch_pc = ctx->func_addr + guard_branch;
    for (size_t i = pic_inbound_lower(ctx, protected_start);
         i < ctx->inbound_count && ctx->inbound[i].target <= protected_end;
         i++) {
        if (ctx->inbound[i].source != branch_pc) {
            return false;
        }
    }
    /* Target-only callers cannot establish which edge is the guarded one. */
    for (size_t i = 0; i < ctx->direct_target_count; i++) {
        if (ctx->direct_targets[i] >= protected_start &&
            ctx->direct_targets[i] <= protected_end && !ctx->inbound_complete) {
            return false;
        }
    }
    /* A separate direct edge into this path could bypass the range check. */
    for (size_t i = 0; i < ctx->insn_count; i++) {
        size_t off = ctx->insn_addrs[i] - ctx->func_addr;
        Insn in = cfg_decode_insn(buf, size, ctx->func_addr, off);
        if (off != guard_branch && in.has_target &&
            in.target > ctx->func_addr + guard &&
            in.target <= ctx->func_addr + jump) {
            return false;
        }
    }
    for (size_t off = start; off <= jump;) {
        Insn in = cfg_decode_insn(buf, size, ctx->func_addr, off);
        if (!in.len || in.len > size - off ||
            (off < jump && in.len > jump - off)) {
            return false;
        }
        Prefix p = parse_prefix(buf, size, off);
        if (!pic_plain_prefix(buf, off, p) || p.op >= size) {
            return false;
        }
        if (off == jump) {
            int target;
            if (!parse_indirect_reg(buf, size, off, &target) ||
                regs[target].kind != PIC_TARGET || !count) {
                return false;
            }
            memset(out, 0, sizeof(*out));
            out->table_addr = table;
            const uint8_t *entries = va_ptr(ctx, table, (size_t)count * 4);
            if (!entries ||
                !pic_readonly_table(ctx, table, (size_t)count * 4)) {
                return false;
            }
            for (uint32_t i = 0; i < count; i++) {
                int64_t delta = rd_i32(entries + i * 4);
                uint64_t base = regs[target].address;
                if ((delta < 0 && base < (uint64_t)-delta) ||
                    (delta >= 0 && base > UINT64_MAX - (uint64_t)delta)) {
                    return false;
                }
                uint64_t address = base + delta;
                if (!pic_executable(ctx, address) ||
                    !add_target(out, address)) {
                    memset(out, 0, sizeof(*out));
                    return false;
                }
            }
            return out->count != 0;
        }
        if (in.kind != INSN_NORMAL) {
            return false;
        }
        MovReg move;
        LeaRip lea;
        MovsxdMem load;
        AddReg add;
        if (parse_mov_reg(buf, size, off, &move) && move.len == in.len) {
            PicValue value = regs[move.src];
            if (!p.rex_w) {
                if (value.kind != PIC_INDEX) {
                    value.kind = PIC_UNKNOWN;
                }
                value.wide = true;
            }
            regs[move.dst] = value;
        } else if (p.rex_w && parse_lea_rip(buf, size, ctx->func_addr,
                                           off, &lea) && lea.len == in.len) {
            regs[lea.dst] = (PicValue) {
                .kind = PIC_ADDRESS, .address = lea.target,
            };
        } else if (p.rex_w && parse_movsxd_mem(buf, size, off, &load) &&
                   load.len == in.len && (buf[p.op + 1] >> 6) == 0 &&
                   !count &&
                   regs[load.base].kind == PIC_ADDRESS &&
                   regs[load.index].kind == PIC_INDEX &&
                   regs[load.index].wide) {
            table = regs[load.base].address;
            count = regs[load.index].bound + 1;
            regs[load.dst] = (PicValue) {.kind = PIC_OFFSET};
        } else if (p.rex_w && parse_add_reg(buf, size, off, &add) &&
                   add.len == in.len && regs[add.dst].kind == PIC_OFFSET &&
                   regs[add.src].kind == PIC_ADDRESS) {
            regs[add.dst] = (PicValue) {
                .kind = PIC_TARGET, .address = regs[add.src].address,
            };
        } else if (buf[p.op] == 0x90 && in.len == 1 && !p.rex_b) {
            /* NOP does not affect the proof state. */
        } else if (buf[p.op] >= 0xb8 && buf[p.op] <= 0xbf) {
            regs[(buf[p.op] & 7) + p.rex_b * 8].kind = PIC_UNKNOWN;
        } else if (p.op + 1 < size && (buf[p.op + 1] >> 6) != 3 &&
                   (buf[p.op] == 0x88 || buf[p.op] == 0x89 ||
                    ((buf[p.op] == 0xc6 || buf[p.op] == 0xc7) &&
                     (buf[p.op + 1] & 0x38) == 0))) {
            /* Plain stores change no register. The table must be read-only. */
        } else {
            int written;
            bool zero;
            if (!pic_preserves_flags(buf, size, off, in, &written, &zero)) {
                return false;
            }
            if (written >= 0) {
                regs[written].kind = PIC_UNKNOWN;
            }
        }
        off += in.len;
    }
    return false;
}

bool ijmp_resolve_bounded_pic(const IjmpContext *ctx, const uint8_t *func,
                              size_t func_size, size_t ijmp_off,
                              IjmpResult *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctx->inbound_complete || ijmp_off >= func_size) {
        return false;
    }
    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
        ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    for (size_t i = insn_lower_bound_off(ctx, start);
         i < ctx->insn_count; i++) {
        size_t off = ctx->insn_addrs[i] - ctx->func_addr;
        if (off >= ijmp_off) {
            break;
        }
        int reg;
        uint32_t bound;
        bool wide;
        size_t branch;
        if (!pic_guard(func, func_size, off, &reg, &bound, &wide, &branch)) {
            continue;
        }
        Insn cmp = cfg_decode_insn(func, func_size, ctx->func_addr, off);
        Insn jcc = cfg_decode_insn(func, func_size, ctx->func_addr, branch);
        size_t gap_end = branch;
        while (gap_end < ijmp_off && jcc.kind == INSN_NORMAL) {
            int written;
            bool zero;
            if (!pic_preserves_flags(func, func_size, gap_end, jcc,
                                      &written, &zero) || written == reg) {
                break;
            }
            gap_end += jcc.len;
            jcc = cfg_decode_insn(func, func_size, ctx->func_addr, gap_end);
        }
        if (cmp.len != branch - off || jcc.kind != INSN_JCC ||
            !jcc.has_target || !jcc.len || jcc.len > func_size - gap_end) {
            continue;
        }
        branch = gap_end;
        size_t path = branch + jcc.len;
        uint8_t condition = func[branch] == 0x0f ?
            func[branch + 1] : func[branch];
        if (condition == 0x76 || condition == 0x86) {
            if (jcc.target < ctx->func_addr ||
                jcc.target - ctx->func_addr < path ||
                jcc.target - ctx->func_addr > ijmp_off) {
                continue;
            }
            path = jcc.target - ctx->func_addr;
            size_t previous = insn_lower_bound_off(ctx, path);
            if (!previous) {
                continue;
            }
            size_t prior_off = ctx->insn_addrs[previous - 1] - ctx->func_addr;
            Insn prior = cfg_decode_insn(func, func_size,
                                         ctx->func_addr, prior_off);
            if (prior_off + prior.len != path ||
                (prior.kind != INSN_RET && prior.kind != INSN_STOP &&
                 prior.kind != INSN_JMP)) {
                continue;
            }
        } else if (condition != 0x77 && condition != 0x87) {
            continue;
        } else if (jcc.target >= ctx->func_addr + path &&
                   jcc.target <= ctx->func_addr + ijmp_off) {
            continue;
        }
        if (pic_dispatch(ctx, func, func_size, path, ijmp_off,
                          off, branch,
                          reg, bound, wide, out)) {
            return true;
        }
    }
    memset(out, 0, sizeof(*out));
    return false;
}

typedef struct {
    uint64_t value;
    int kind;
} PicConcrete;

static bool pic_mask_seed(const uint8_t *code, size_t size, size_t off,
                           RegImm *mask)
{
    Prefix p = parse_prefix(code, size, off);
    Insn in = cfg_decode_insn(code, size, 0, off);
    return pic_plain_prefix(code, off, p) &&
        parse_and_imm(code, size, off, mask) && mask->len == in.len &&
        mask->value > 0 && mask->value <= 63;
}

/* Enumerate a small masked domain without guessing a table's terminal entry. */
static bool pic_masked_path(const IjmpContext *ctx, const uint8_t *code,
                             size_t size, size_t start, size_t jump,
                             PicConcrete regs[16], IjmpResult *out)
{
    bool comparison = false;
    uint64_t left = 0, right = 0;
    for (size_t off = start, steps = 0; steps < 128; steps++) {
        if (off > jump) {
            return true;
        }
        Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
        Prefix p = parse_prefix(code, size, off);
        if (!in.len || in.len > size - off ||
            !pic_plain_prefix(code, off, p) || p.op >= size) {
            return false;
        }
        if (off == jump) {
            int reg;
            return in.kind == INSN_IJMP &&
                parse_indirect_reg(code, size, off, &reg) &&
                regs[reg].kind == PIC_TARGET &&
                pic_executable(ctx, regs[reg].value) &&
                add_target(out, regs[reg].value);
        }
        if (in.len > jump - off) {
            return false;
        }
        if (in.kind == INSN_JCC || in.kind == INSN_JMP) {
            if (!in.has_target) {
                return false;
            }
            bool take = true;
            if (in.kind == INSN_JCC) {
                if (!comparison ||
                    !((code[p.op] >= 0x70 && code[p.op] <= 0x7f) ||
                      (code[p.op] == 0x0f && p.op + 1 < size &&
                       code[p.op + 1] >= 0x80 && code[p.op + 1] <= 0x8f))) {
                    return false;
                }
                unsigned cc = code[p.op] == 0x0f ?
                    code[p.op + 1] & 15 : code[p.op] & 15;
                switch (cc) {
                case 2: take = left < right; break;
                case 3: take = left >= right; break;
                case 4: take = left == right; break;
                case 5: take = left != right; break;
                case 6: take = left <= right; break;
                case 7: take = left > right; break;
                default: return false;
                }
            }
            if (take) {
                if (in.target < ctx->func_addr ||
                    in.target > ctx->func_addr + jump) {
                    return true;
                }
                size_t next = in.target - ctx->func_addr;
                if (next <= off || !is_insn_addr(ctx, in.target)) {
                    return false;
                }
                off = next;
            } else {
                off += in.len;
            }
            continue;
        }
        if (in.kind != INSN_NORMAL) {
            return false;
        }
        uint8_t op = code[p.op];
        uint8_t modrm = p.op + 1 < size ? code[p.op + 1] : 0;
        int rm = (modrm & 7) + p.rex_b * 8;
        int reg = ((modrm >> 3) & 7) + p.rex_r * 8;
        MovReg move;
        LeaRip rip;
        LeaReg lea;
        MovsxdMem load;
        AddReg add;
        if ((op == 0x39 || op == 0x3b) && (modrm >> 6) == 3 &&
            in.len == p.op + 2 - off) {
            if (regs[rm].kind != PIC_INDEX || regs[reg].kind != PIC_INDEX) {
                return false;
            }
            left = regs[op == 0x39 ? rm : reg].value;
            right = regs[op == 0x39 ? reg : rm].value;
            if (!p.rex_w) {
                left = (uint32_t)left;
                right = (uint32_t)right;
            }
            comparison = true;
        } else if ((op == 0x87 && (modrm >> 6) == 3 &&
                    in.len == p.op + 2 - off) ||
                   (op >= 0x91 && op <= 0x97 && in.len == p.op + 1 - off)) {
            if (op != 0x87) {
                rm = (op & 7) + p.rex_b * 8;
                reg = 0;
            }
            PicConcrete tmp = regs[rm];
            regs[rm] = regs[reg];
            regs[reg] = tmp;
            if (!p.rex_w) {
                regs[rm].value = (uint32_t)regs[rm].value;
                regs[reg].value = (uint32_t)regs[reg].value;
                if (regs[rm].kind != PIC_INDEX) regs[rm].kind = PIC_UNKNOWN;
                if (regs[reg].kind != PIC_INDEX) regs[reg].kind = PIC_UNKNOWN;
            }
        } else if (parse_mov_reg(code, size, off, &move) && move.len == in.len) {
            regs[move.dst] = regs[move.src];
            if (!p.rex_w) {
                regs[move.dst].value = (uint32_t)regs[move.dst].value;
                if (regs[move.dst].kind != PIC_INDEX) {
                    regs[move.dst].kind = PIC_UNKNOWN;
                }
            }
        } else if (p.rex_w && parse_lea_rip(code, size, ctx->func_addr,
                                            off, &rip) && rip.len == in.len) {
            regs[rip.dst] = (PicConcrete) {rip.target, PIC_ADDRESS};
        } else if (p.rex_w && op == 0x8d && (modrm >> 6) == 1 &&
                   (modrm & 7) != 4 && in.len == p.op + 3 - off &&
                   regs[rm].kind == PIC_INDEX) {
            regs[reg] = (PicConcrete) {
                regs[rm].value + (int8_t)code[p.op + 2], PIC_INDEX,
            };
        } else if (p.rex_w && op == 0x29 && (modrm >> 6) == 3 &&
                   in.len == p.op + 2 - off &&
                   regs[rm].kind == PIC_INDEX && regs[reg].kind == PIC_INDEX) {
            regs[rm].value -= regs[reg].value;
            comparison = false;
        } else if (p.rex_w && parse_movsxd_mem(code, size, off, &load) &&
                   load.len == in.len && (modrm >> 6) == 0 &&
                   regs[load.base].kind == PIC_ADDRESS &&
                   regs[load.index].kind == PIC_INDEX) {
            uint64_t table = regs[load.base].value;
            uint64_t index = regs[load.index].value;
            if (index >= IJMP_MAX_TARGETS ||
                table > UINT64_MAX - index * 4 ||
                !pic_readonly_table(ctx, table, (size_t)(index + 1) * 4)) {
                return false;
            }
            const uint8_t *entry = va_ptr(ctx, table + index * 4, 4);
            if (!entry || (out->count && out->table_addr != table)) {
                return false;
            }
            out->table_addr = table;
            regs[load.dst] = (PicConcrete) {(uint64_t)(int64_t)rd_i32(entry),
                                           PIC_OFFSET};
        } else if (p.rex_w && parse_lea_reg(code, size, off, &lea) &&
                   lea.len == in.len && lea.scale == 1 &&
                   regs[lea.base].kind == PIC_ADDRESS &&
                   regs[lea.index].kind == PIC_OFFSET) {
            uint64_t base = regs[lea.base].value;
            int64_t delta = (int64_t)regs[lea.index].value;
            if ((delta < 0 && base < (uint64_t)-delta) ||
                (delta >= 0 && base > UINT64_MAX - (uint64_t)delta)) {
                return false;
            }
            regs[lea.dst] = (PicConcrete) {
                base + delta, PIC_TARGET,
            };
        } else if (p.rex_w && parse_add_reg(code, size, off, &add) &&
                   add.len == in.len && regs[add.dst].kind == PIC_OFFSET &&
                   regs[add.src].kind == PIC_ADDRESS) {
            uint64_t base = regs[add.src].value;
            int64_t delta = (int64_t)regs[add.dst].value;
            if ((delta < 0 && base < (uint64_t)-delta) ||
                (delta >= 0 && base > UINT64_MAX - (uint64_t)delta)) {
                return false;
            }
            regs[add.dst] = (PicConcrete) {
                base + delta, PIC_TARGET,
            };
            comparison = false;
        } else {
            int written;
            bool zero;
            if (!pic_preserves_flags(code, size, off, in, &written, &zero)) {
                return false;
            }
            if (written >= 0) regs[written].kind = PIC_UNKNOWN;
        }
        off += in.len;
    }
    return false;
}

static bool pic_masked_entry(const IjmpContext *ctx, const uint8_t *code,
                              size_t size, IjmpResult *out)
{
    RegImm first, second;
    if (!pic_mask_seed(code, size, 0, &first) ||
        !pic_mask_seed(code, size, first.len, &second) ||
        first.dst == second.dst) {
        return false;
    }
    uint64_t starts[128];
    size_t count = 0, jump = 0;
    for (size_t off = 0; off < size && count < 128;) {
        Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
        if (!in.len || in.len > size - off) return false;
        starts[count++] = in.addr;
        if (in.kind == INSN_IJMP) {
            jump = off;
            break;
        }
        off += in.len;
    }
    if (!jump) return false;
    uint64_t end = ctx->func_addr + jump;
    for (size_t i = pic_inbound_lower(ctx, ctx->func_addr + 1);
         i < ctx->inbound_count && ctx->inbound[i].target <= end; i++) {
        if (ctx->inbound[i].source < ctx->func_addr ||
            ctx->inbound[i].source >= end) {
            return false;
        }
    }
    IjmpContext local = *ctx;
    local.insn_addrs = starts;
    local.insn_count = count;
    local.insn_bitmap = NULL;
    local.insn_bitmap_size = 0;
    for (uint32_t a = 0; a <= first.value; a++) {
        for (uint32_t b = 0; b <= second.value; b++) {
            PicConcrete regs[16] = {0};
            regs[first.dst] = (PicConcrete) {a, PIC_INDEX};
            regs[second.dst] = (PicConcrete) {b, PIC_INDEX};
            if (!pic_masked_path(&local, code, size, first.len + second.len,
                                 jump, regs, out)) {
                memset(out, 0, sizeof(*out));
                return false;
            }
        }
    }
    return out->count != 0;
}

bool ijmp_resolve_bounded_pic_entry(const IjmpContext *ctx,
                                    const uint8_t *code, size_t size,
                                    IjmpResult *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctx->inbound_complete) {
        return false;
    }
    if (pic_masked_entry(ctx, code, size, out)) {
        return true;
    }
    memset(out, 0, sizeof(*out));
    int reg;
    uint32_t bound;
    bool wide;
    size_t branch;
    if (!pic_guard(code, size, 0, &reg, &bound, &wide, &branch)) {
        MovReg move;
        Prefix p = parse_prefix(code, size, 0);
        bool inc_dec = pic_plain_prefix(code, 0, p) && p.op + 1 < size &&
            code[p.op] == 0xff && (code[p.op + 1] >> 6) == 3 &&
            (code[p.op + 1] & 0x38) <= 8;
        if (!inc_dec && !parse_mov_reg(code, size, 0, &move)) {
            return false;
        }
    }
    uint64_t starts[128];
    size_t count = 0;
    for (size_t off = 0; off < size && count < 128;) {
        Insn in = cfg_decode_insn(code, size, ctx->func_addr, off);
        if (!in.len || in.len > size - off) {
            break;
        }
        starts[count++] = in.addr;
        if (in.kind == INSN_IJMP) {
            IjmpContext local = *ctx;
            local.insn_addrs = starts;
            local.insn_count = count;
            local.func_size = size;
            return ijmp_resolve_bounded_pic(&local, code, size, off, out);
        }
        off += in.len;
    }
    return false;
}

bool ijmp_resolve_jump_table(const IjmpContext *ctx, const uint8_t *func,
                             size_t func_size, size_t ijmp_off,
                             IjmpResult *out)
{
    memset(out, 0, sizeof(*out));

    if (ijmp_resolve_bounded_pic(ctx, func, func_size, ijmp_off, out)) {
        return true;
    }

    int jmp_reg = -1;
    if (!parse_indirect_reg(func, func_size, ijmp_off, &jmp_reg)) {
        return resolve_qword_table(ctx, func, func_size, ijmp_off, out);
    }

    /* An adjacent absolute table load defines the jump register directly. */
    size_t jump_index = insn_lower_bound_off(ctx, ijmp_off);
    if (jump_index) {
        size_t off = ctx->insn_addrs[jump_index - 1] - ctx->func_addr;
        MovMem mov;
        if (parse_mov_mem_scaled(func, ijmp_off, off, &mov) &&
            mov.base < 0 && mov.dst == jmp_reg && mov.scale == 8 &&
            mov.len == ijmp_off - off) {
            return resolve_reg_qword_table(ctx, func, ijmp_off, jmp_reg, out);
        }
    }

    /*
     * GCC PIC table pattern:
     *   lea table_base, [rip + table]
     *   lea base, [rip + offset_base]  (may be the same as table_base)
     *   movsxd off, dword ptr [table_base + index * 4]
     *   add/lea jmp_reg, base + off
     *   jmp jmp_reg
     *
     * The scan is deliberately local: look back only a small window and only at
     * known instruction starts to avoid matching immediates or data bytes.
     */
    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
                   ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    int offset_reg = -1;
    int base_reg = -1;
    size_t combine_off = 0;
    bool have_combine = false;

    for (size_t ii = insn_lower_bound_off(ctx, start);
         ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + ijmp_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        AddReg cur;
        if (parse_add_reg(func, ijmp_off, off, &cur) && cur.dst == jmp_reg) {
            offset_reg = jmp_reg;
            base_reg = cur.src;
            combine_off = off;
            have_combine = true;
        }

        LeaReg lea_reg;
        if (parse_lea_reg(func, ijmp_off, off, &lea_reg) &&
            lea_reg.dst == jmp_reg && lea_reg.scale == 1) {
            offset_reg = lea_reg.index;
            base_reg = lea_reg.base;
            combine_off = off;
            have_combine = true;
        }
    }
    if (!have_combine) {
        if (resolve_reg_qword_table(ctx, func, ijmp_off, jmp_reg, out)) {
            return true;
        }
        return resolve_const_reg_target(ctx, func, func_size, ijmp_off,
                                        jmp_reg, out);
    }


    if (resolve_computed_stride(ctx, func, func_size, start, combine_off,
                                offset_reg, base_reg, out)) {
        return true;
    }

    MovsxdMem mov = {0};
    size_t mov_off = 0;
    bool have_mov = false;
    for (size_t ii = insn_lower_bound_off(ctx, start);
         ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + combine_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        MovsxdMem cur;
        if (parse_movsxd_mem(func, combine_off, off, &cur) &&
            cur.dst == offset_reg) {
            mov = cur;
            mov_off = off;
            have_mov = true;
        }
    }
    if (!have_mov) {
        return false;
    }

    LeaRip lea = {0};
    LeaRip target_base = {0};
    bool have_lea = false;
    bool have_target_base = false;
    for (size_t ii = insn_lower_bound_off(ctx, start);
         ii < ctx->insn_count &&
         ctx->insn_addrs[ii] < ctx->func_addr + mov_off; ii++) {
        size_t off = (size_t)(ctx->insn_addrs[ii] - ctx->func_addr);
        LeaRip cur;
        if (parse_lea_rip(func, combine_off, ctx->func_addr, off, &cur)) {
            if (cur.dst == mov.base) {
                lea = cur;
                have_lea = true;
            }
            if (cur.dst == base_reg) {
                target_base = cur;
                have_target_base = true;
            }
        }
    }
    if (!have_lea || !have_target_base) {
        return false;
    }

    out->table_addr = lea.target;
    for (size_t i = 0; i < IJMP_MAX_TARGETS; i++) {
        const uint8_t *p = va_ptr(ctx, lea.target + i * 4, 4);
        if (!p) {
            break;
        }

        uint64_t target = target_base.target + (uint64_t)rd_i32(p);
        if (!is_valid_target(ctx, target)) {
            break;
        }
        if (!add_target(out, target)) {
            break;
        }
    }

    return out->count > 0;
}
