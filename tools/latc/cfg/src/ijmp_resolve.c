#include "ijmp_resolve.h"

#include "common.h"

/*
 * Pattern-based indirect jump resolver.
 *
 * Supported table forms:
 *   - absolute qword table: jmp qword ptr [base + index * 8]
 *   - GCC PIC offset table: movsxd table[index*4], add/lea base, jmp reg
 *
 * Candidate targets are accepted only if they stay in the current function and
 * land exactly on a decoded instruction boundary.
 */

#include <string.h>

#define IJMP_LOOKBACK_BYTES 4096

typedef struct {
    /* Decoded legacy/REX prefix state and offset of the real opcode. */
    int rex_w;
    int rex_r;
    int rex_x;
    int rex_b;
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
    /* jmp qword ptr [base + index * scale] */
    int base;
    int index;
    int scale;
    size_t len;
} JmpMem;

static bool in_func(const IjmpContext *ctx, uint64_t addr)
{
    return addr >= ctx->func_addr && addr < ctx->func_addr + ctx->func_size;
}

static bool is_insn_addr(const IjmpContext *ctx, uint64_t addr)
{
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

static bool is_insn_off(const IjmpContext *ctx, size_t off)
{
    return is_insn_addr(ctx, ctx->func_addr + off);
}

static bool is_func_entry(const IjmpContext *ctx, uint64_t addr)
{
    return ctx->is_func_entry &&
           ctx->is_func_entry(ctx->func_entry_data, addr);
}

static bool is_valid_target(const IjmpContext *ctx, uint64_t target)
{
    if (in_func(ctx, target)) {
        return is_insn_addr(ctx, target);
    }
    return is_func_entry(ctx, target);
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
    if ((index == 4 && !p.rex_x) || base == 5) {
        return false;
    }

    out->base = base + p.rex_b * 8;
    out->index = index + p.rex_x * 8;
    out->scale = 1 << scale_bits;
    out->len = p.op + 3 - off;
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
    if ((index == 4 && !p.rex_x) || (mod == 0 && base == 5)) {
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
    } else if (mod == 2) {
        if (p.op + 6 >= size) {
            return false;
        }
        disp = rd_i32(buf + p.op + 3);
        len += 4;
    }

    out->dst = ((modrm >> 3) & 7) + p.rex_r * 8;
    out->base = base + p.rex_b * 8;
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
     */
    JmpMem jmp;
    if (!parse_jmp_mem_scaled(func, func_size, ijmp_off, &jmp) ||
        jmp.scale != 8) {
        return false;
    }

    size_t start = ijmp_off > IJMP_LOOKBACK_BYTES ?
                   ijmp_off - IJMP_LOOKBACK_BYTES : 0;
    LeaRip lea = {0};
    bool have_lea = false;
    for (size_t off = start; off < ijmp_off; off++) {
        LeaRip cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
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

    for (size_t off = start; off < ijmp_off; off++) {
        MovMem cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
        if (parse_mov_mem_scaled(func, ijmp_off, off, &cur) &&
            cur.dst == jmp_reg && cur.scale == 8) {
            mov = cur;
            mov_off = off;
            have_mov = true;
        }
    }
    if (!have_mov) {
        return false;
    }

    LeaRip lea = {0};
    bool have_lea = false;
    for (size_t off = start; off < mov_off; off++) {
        LeaRip cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
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

    for (size_t off = ijmp_off; off-- > start;) {
        if (!is_insn_off(ctx, off)) {
            continue;
        }

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

bool ijmp_resolve_jump_table(const IjmpContext *ctx, const uint8_t *func,
                             size_t func_size, size_t ijmp_off,
                             IjmpResult *out)
{
    memset(out, 0, sizeof(*out));

    int jmp_reg = -1;
    if (!parse_indirect_reg(func, func_size, ijmp_off, &jmp_reg)) {
        return resolve_qword_table(ctx, func, func_size, ijmp_off, out);
    }

    /*
     * GCC PIC table pattern:
     *   lea base, [rip + table]
     *   movsxd off, dword ptr [base + index * 4]
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

    for (size_t off = start; off < ijmp_off; off++) {
        AddReg cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
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

    MovsxdMem mov = {0};
    size_t mov_off = 0;
    bool have_mov = false;
    for (size_t off = start; off < combine_off; off++) {
        MovsxdMem cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
        if (parse_movsxd_mem(func, combine_off, off, &cur) &&
            cur.dst == offset_reg && cur.base == base_reg) {
            mov = cur;
            mov_off = off;
            have_mov = true;
        }
    }
    if (!have_mov) {
        return false;
    }

    LeaRip lea = {0};
    bool have_lea = false;
    for (size_t off = start; off < mov_off; off++) {
        LeaRip cur;
        if (!is_insn_off(ctx, off)) {
            continue;
        }
        if (parse_lea_rip(func, combine_off, ctx->func_addr, off, &cur) &&
            cur.dst == mov.base) {
            lea = cur;
            have_lea = true;
        }
    }
    if (!have_lea) {
        return false;
    }

    out->table_addr = lea.target;
    for (size_t i = 0; i < IJMP_MAX_TARGETS; i++) {
        const uint8_t *p = va_ptr(ctx, lea.target + i * 4, 4);
        if (!p) {
            break;
        }

        uint64_t target = lea.target + (uint64_t)rd_i32(p);
        if (!is_valid_target(ctx, target)) {
            break;
        }
        if (!add_target(out, target)) {
            break;
        }
    }

    return out->count > 0;
}
