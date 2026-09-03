#define _GNU_SOURCE

#include "cfg_program.h"

#include "cfg_decoder.h"
#include "elf_image.h"
#include "function_symbols.h"
#include "ijmp_resolve.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct { Insn *v; size_t n; size_t cap; } InsnVec;
typedef struct { uint64_t *v; size_t n; size_t cap; } AddrVec;

static bool grow(void **ptr, size_t *cap, size_t count, size_t elem)
{
    if (count < *cap) {
        return true;
    }
    size_t next = *cap ? *cap * 2 : 64;
    void *p = realloc(*ptr, next * elem);
    if (!p) {
        return false;
    }
    *ptr = p;
    *cap = next;
    return true;
}

static bool insn_push(InsnVec *v, Insn value)
{
    if (!grow((void **)&v->v, &v->cap, v->n, sizeof(*v->v))) {
        return false;
    }
    v->v[v->n++] = value;
    return true;
}

static bool addr_push(AddrVec *v, uint64_t value)
{
    if (!grow((void **)&v->v, &v->cap, v->n, sizeof(*v->v))) {
        return false;
    }
    v->v[v->n++] = value;
    return true;
}

static int cmp_addr(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static size_t addr_lower_bound(const AddrVec *v, uint64_t addr)
{
    size_t lo = 0, hi = v->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v->v[mid] < addr) lo = mid + 1; else hi = mid;
    }
    return lo;
}

static void sort_unique(AddrVec *v)
{
    if (!v->n) {
        return;
    }
    qsort(v->v, v->n, sizeof(*v->v), cmp_addr);
    size_t out = 1;
    for (size_t i = 1; i < v->n; i++) {
        if (v->v[i] != v->v[out - 1]) {
            v->v[out++] = v->v[i];
        }
    }
    v->n = out;
}

static ssize_t find_insn(const InsnVec *v, uint64_t addr)
{
    size_t lo = 0, hi = v->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v->v[mid].addr < addr) lo = mid + 1; else hi = mid;
    }
    return lo < v->n && v->v[lo].addr == addr ? (ssize_t)lo : -1;
}

static bool prefix_entry(const InsnVec *v, const uint8_t *buf, uint64_t addr)
{
    for (size_t i = 0; i < v->n; i++) {
        const Insn *in = &v->v[i];
        if (addr <= in->addr || addr >= in->addr + in->len) continue;
        size_t skipped = (size_t)(addr - in->addr);
        for (size_t j = 0; j < skipped; j++) {
            if (!cfg_is_legacy_prefix(buf[in->off + j])) return false;
        }
        return true;
    }
    return false;
}

static bool has_leader(const AddrVec *leaders, uint64_t addr)
{
    return bsearch(&addr, leaders->v, leaders->n, sizeof(addr), cmp_addr) != NULL;
}

static bool addr_in_function(uint64_t addr, const FuncSym *fn)
{
    return addr >= fn->addr && addr < fn->addr + fn->size;
}

static bool is_function_entry(const void *opaque, uint64_t addr)
{
    return funcs_find_by_entry((const FuncVec *)opaque, addr) != NULL;
}

static bool push_function(CfgProgram *p, size_t *cap, CfgProgramFunction value)
{
    if (!grow((void **)&p->functions, cap, p->function_count,
              sizeof(*p->functions))) return false;
    p->functions[p->function_count++] = value;
    return true;
}

static bool push_tb(CfgProgram *p, size_t *cap, CfgTb value)
{
    if (!grow((void **)&p->tbs, cap, p->tb_count, sizeof(*p->tbs))) return false;
    p->tbs[p->tb_count++] = value;
    return true;
}

static bool push_edge(CfgProgram *p, size_t *cap, CfgProgramEdge value)
{
    if (!grow((void **)&p->edges, cap, p->edge_count, sizeof(*p->edges))) return false;
    p->edges[p->edge_count++] = value;
    return true;
}

static CfgTbTerm term_from_insn(InsnKind kind)
{
    switch (kind) {
    case INSN_CALL: return CFG_TB_CALL;
    case INSN_ICALL: return CFG_TB_INDIRECT_CALL;
    case INSN_JCC: return CFG_TB_CONDITIONAL;
    case INSN_JMP: return CFG_TB_JUMP;
    case INSN_IJMP: return CFG_TB_INDIRECT_JUMP;
    case INSN_RET: return CFG_TB_RETURN;
    case INSN_SYSCALL: return CFG_TB_SYSCALL;
    case INSN_STOP: return CFG_TB_STOP;
    default: return CFG_TB_FALLTHROUGH;
    }
}

static int collect_program_insns_and_direct_targets(const ElfFile *elf,
                                                    const FuncVec *funcs,
                                                    AddrVec *insn_addrs,
                                                    AddrVec *targets)
{
    for (size_t i = 0; i < funcs->n; i++) {
        const FuncSym *fn = &funcs->v[i];
        uint64_t file_off;
        if (!fn->size || !elf_function_file_offset(
                elf, fn->addr, fn->size, fn->shndx, &file_off)) {
            continue;
        }
        const uint8_t *buf = elf->data + file_off;
        size_t size = (size_t)fn->size;
        for (size_t off = 0; off < size;) {
            Insn in = cfg_decode_insn(buf, size, fn->addr, off);
            if (!in.len) in.len = 1;
            if (!addr_push(insn_addrs, in.addr)) {
                return -1;
            }
            if (in.has_target &&
                (in.kind == INSN_CALL || in.kind == INSN_JCC ||
                 in.kind == INSN_JMP) &&
                !addr_push(targets, in.target)) {
                return -1;
            }
            off += in.len;
        }
    }
    sort_unique(insn_addrs);
    sort_unique(targets);
    return 0;
}

static bool insn_can_fall_through(InsnKind kind)
{
    return kind == INSN_CALL || kind == INSN_ICALL || kind == INSN_JCC ||
           kind == INSN_SYSCALL;
}

/*
 * Some glibc assembly functions end in a conditional branch and deliberately
 * fall through alignment NOPs into the next symbol. Include only these proven
 * fallthrough gaps; arbitrary executable-section gaps may contain data.
 */
static void extend_symbol_fallthroughs(const ElfFile *elf, FuncVec *funcs)
{
    for (size_t i = 0; i + 1 < funcs->n; i++) {
        FuncSym *fn = &funcs->v[i];
        const FuncSym *next = &funcs->v[i + 1];
        uint64_t file_off;
        if (!fn->size || fn->shndx != next->shndx ||
            fn->addr + fn->size >= next->addr ||
            !elf_function_file_offset(elf, fn->addr, fn->size, fn->shndx,
                                      &file_off)) {
            continue;
        }

        const uint8_t *buf = elf->data + file_off;
        size_t size = (size_t)fn->size;
        Insn last = {0};
        for (size_t off = 0; off < size;) {
            last = cfg_decode_insn(buf, size, fn->addr, off);
            if (!last.len) {
                last.len = 1;
            }
            off += last.len;
        }
        if (last.addr + last.len == fn->addr + fn->size &&
            insn_can_fall_through(last.kind)) {
            fn->size = next->addr - fn->addr;
        }
    }
}

static int analyze_function(const ElfFile *elf, const FuncVec *funcs,
                            const IjmpSection *sections, size_t section_count,
                            const AddrVec *program_insns,
                            const AddrVec *direct_targets,
                            const AddrVec *extra_leaders, const FuncSym *fn,
                            const CfgAnalyzeOptions *options, CfgProgram *out,
                            size_t *tb_cap, size_t *edge_cap,
                            CfgProgramFunction *result)
{
    uint64_t file_off;
    if (!fn->size || !elf_function_file_offset(elf, fn->addr, fn->size,
                                                fn->shndx, &file_off)) {
        return 1;
    }
    const uint8_t *buf = elf->data + file_off;
    size_t size = (size_t)fn->size;
    InsnVec insns = {0};
    AddrVec leaders = {0}, insn_addrs = {0};
    int rc = -1;

    for (size_t off = 0; off < size;) {
        Insn in = cfg_decode_insn(buf, size, fn->addr, off);
        if (!in.len) in.len = 1;
        if (!insn_push(&insns, in) || !addr_push(&insn_addrs, in.addr)) goto done;
        off += in.len;
    }

    IjmpContext ijmp = {
        .file = elf->data, .file_size = elf->size,
        .sections = sections, .section_count = section_count,
        .insn_addrs = insn_addrs.v, .insn_count = insn_addrs.n,
        .program_insn_addrs = program_insns->v,
        .program_insn_count = program_insns->n,
        .direct_targets = direct_targets->v,
        .direct_target_count = direct_targets->n,
        .is_func_entry = is_function_entry, .func_entry_data = funcs,
        .func_addr = fn->addr, .func_size = fn->size,
    };

    if (!addr_push(&leaders, fn->addr)) goto done;
    if (extra_leaders) {
        size_t i = addr_lower_bound(extra_leaders, fn->addr);
        for (; i < extra_leaders->n &&
               addr_in_function(extra_leaders->v[i], fn); i++) {
            if (!addr_push(&leaders, extra_leaders->v[i])) {
                goto done;
            }
        }
    }
    for (size_t i = 0; i < direct_targets->n; i++) {
        if (addr_in_function(direct_targets->v[i], fn) &&
            !addr_push(&leaders, direct_targets->v[i])) {
            goto done;
        }
    }
    for (size_t i = 0; i < insns.n; i++) {
        Insn *in = &insns.v[i];
        uint64_t next = in->addr + in->len;
        if (in->has_target && addr_in_function(in->target, fn) &&
            !addr_push(&leaders, in->target)) goto done;
        if (in->kind != INSN_NORMAL && next < fn->addr + fn->size &&
            !addr_push(&leaders, next)) goto done;
        if ((!options || options->resolve_jump_tables) &&
            (in->kind == INSN_IJMP ||
                           in->kind == INSN_ICALL)) {
            IjmpResult jt;
            if (ijmp_resolve_jump_table(&ijmp, buf, size, in->off, &jt)) {
                for (size_t j = 0; j < jt.count; j++) {
                    if (addr_in_function(jt.targets[j], fn) &&
                        !addr_push(&leaders, jt.targets[j])) goto done;
                }
            }
        }
    }
    sort_unique(&leaders);

    result->first_tb = out->tb_count;
    result->status = CFG_FUNCTION_OK;
    for (size_t li = 0; li < leaders.n; li++) {
        uint64_t start = leaders.v[li];
        ssize_t si = find_insn(&insns, start);
        if (si < 0) {
            result->status = prefix_entry(&insns, buf, start) ?
                CFG_FUNCTION_OPEN : CFG_FUNCTION_ERROR;
            continue;
        }
        size_t ei = (size_t)si;
        while (ei < insns.n) {
            if (ei != (size_t)si && has_leader(&leaders, insns.v[ei].addr)) break;
            InsnKind kind = insns.v[ei].kind;
            ei++;
            if (kind != INSN_NORMAL) break;
        }
        if (ei == (size_t)si) continue;
        Insn *last = &insns.v[ei - 1];
        CfgTb tb = {
            .start = start,
            .end = last->addr + last->len,
            .terminator_pc = last->addr,
            .semantic_flags = CFG_TB_CODE64,
            .terminator = term_from_insn(last->kind),
            .first_edge = out->edge_count,
        };
        uint64_t next = last->addr + last->len;
#define EDGE(K, T, R) do { \
            if (!push_edge(out, edge_cap, (CfgProgramEdge){ \
                    .from = start, .to = (T), .kind = (K), .resolution = (R) })) \
                goto done; \
        } while (0)
        switch (last->kind) {
        case INSN_CALL:
            if (last->has_target) EDGE(CFG_EDGE_CALL, last->target, CFG_EDGE_STATIC);
            if (next < fn->addr + fn->size)
                EDGE(CFG_EDGE_CALL_RETURN, next, CFG_EDGE_STATIC);
            break;
        case INSN_ICALL:
        {
            IjmpResult jt;
            bool found = (!options || options->resolve_jump_tables) &&
                ijmp_resolve_jump_table(&ijmp, buf, size, last->off, &jt);
            if (found) {
                for (size_t j = 0; j < jt.count; j++) {
                    EDGE(CFG_EDGE_CALL, jt.targets[j], CFG_EDGE_STATIC);
                }
            } else {
                EDGE(CFG_EDGE_RUNTIME, 0, CFG_EDGE_RUNTIME_RESOLVED);
                if (result->status != CFG_FUNCTION_ERROR)
                    result->status = CFG_FUNCTION_OPEN;
            }
            if (next < fn->addr + fn->size)
                EDGE(CFG_EDGE_CALL_RETURN, next, CFG_EDGE_STATIC);
            break;
        }
        case INSN_JCC:
            if (last->has_target) EDGE(CFG_EDGE_TRUE, last->target, CFG_EDGE_STATIC);
            if (next < fn->addr + fn->size) EDGE(CFG_EDGE_FALSE, next, CFG_EDGE_STATIC);
            break;
        case INSN_JMP:
            if (last->has_target) EDGE(CFG_EDGE_JUMP, last->target, CFG_EDGE_STATIC);
            break;
        case INSN_IJMP: {
            IjmpResult jt;
            bool found = (!options || options->resolve_jump_tables) &&
                ijmp_resolve_jump_table(&ijmp, buf, size, last->off, &jt);
            if (found) {
                out->resolved_jump_tables++;
                out->resolved_jump_table_targets += jt.count;
                for (size_t j = 0; j < jt.count; j++)
                    EDGE(CFG_EDGE_CASE, jt.targets[j], CFG_EDGE_STATIC);
            } else {
                EDGE(CFG_EDGE_RUNTIME, 0, CFG_EDGE_RUNTIME_RESOLVED);
                if (result->status != CFG_FUNCTION_ERROR)
                    result->status = CFG_FUNCTION_OPEN;
            }
            break;
        }
        case INSN_RET:
            EDGE(CFG_EDGE_RUNTIME, 0, CFG_EDGE_RUNTIME_RESOLVED);
            break;
        case INSN_SYSCALL:
            EDGE(CFG_EDGE_RUNTIME, 0, CFG_EDGE_RUNTIME_RESOLVED);
            if (next < fn->addr + fn->size) EDGE(CFG_EDGE_FALLTHROUGH, next, CFG_EDGE_STATIC);
            break;
        case INSN_NORMAL:
            if (next < fn->addr + fn->size) EDGE(CFG_EDGE_FALLTHROUGH, next, CFG_EDGE_STATIC);
            break;
        case INSN_STOP:
            break;
        }
#undef EDGE
        tb.edge_count = out->edge_count - tb.first_edge;
        if (!push_tb(out, tb_cap, tb)) goto done;
    }
    result->tb_count = out->tb_count - result->first_tb;
    rc = 0;
done:
    free(insns.v); free(leaders.v); free(insn_addrs.v);
    return rc;
}

int cfg_analyze_elf(const char *path, const CfgAnalyzeOptions *options,
                    CfgProgram *program, char *error, size_t error_size)
{
    if (!path || !program) return -1;
    memset(program, 0, sizeof(*program));
    ElfFile elf = {0};
    FuncVec funcs = {0};
    AddrVec program_insns = {0}, direct_targets = {0}, extra_leaders = {0};
    IjmpSection *sections = NULL;
    const char *source = NULL;
    size_t function_cap = 0, tb_cap = 0, edge_cap = 0;
    int rc = -1;

    /* The imported ELF reader reports malformed input fatally. Validated callers
     * use this API today; converting parser failures to diagnostics is tracked
     * before exposing latc to untrusted files. */
    elf_load(path, &elf);
    funcs_load_all(&elf, &funcs, &source);
    (void)source;
    extend_symbol_fallthroughs(&elf, &funcs);
    if (options) {
        for (size_t i = 0; i < options->extra_leader_count; i++) {
            if (!addr_push(&extra_leaders, options->extra_leaders[i])) {
                goto out;
            }
        }
        sort_unique(&extra_leaders);
    }
    if (collect_program_insns_and_direct_targets(
            &elf, &funcs, &program_insns, &direct_targets)) goto out;
    size_t section_count = 0;
    sections = elf_build_ijmp_sections(&elf, &section_count);
    program->exec_ranges = calloc(elf.eh->e_shnum,
                                  sizeof(*program->exec_ranges));
    if (!program->exec_ranges) goto out;
    for (unsigned i = 0; i < elf.eh->e_shnum; i++) {
        const Elf64_Shdr *section = &elf.sh[i];
        if (!elf_executable_section(&elf, i) || !section->sh_size ||
            section->sh_type == SHT_NOBITS) continue;
        program->exec_ranges[program->exec_range_count++] = (CfgExecRange){
            .start = section->sh_addr,
            .size = section->sh_size,
        };
    }

    for (size_t i = 0; i < funcs.n; i++) {
        CfgProgramFunction fn = {
            .name = strdup(funcs.v[i].name),
            .start = funcs.v[i].addr,
            .size = funcs.v[i].size,
        };
        if (!fn.name) goto out;
        int ar = analyze_function(&elf, &funcs, sections, section_count,
                                  &program_insns, &direct_targets,
                                  &extra_leaders, &funcs.v[i],
                                  options,
                                  program, &tb_cap, &edge_cap, &fn);
        if (ar < 0) { free(fn.name); goto out; }
        if (ar > 0) { free(fn.name); continue; }
        if (fn.status == CFG_FUNCTION_OPEN) program->open_function_count++;
        if (fn.status == CFG_FUNCTION_ERROR) program->error_function_count++;
        if (!push_function(program, &function_cap, fn)) { free(fn.name); goto out; }
    }
    rc = 0;
out:
    free(program_insns.v);
    free(direct_targets.v);
    free(extra_leaders.v);
    free(sections);
    funcs_free(&funcs);
    elf_free(&elf);
    if (rc && error && error_size) {
        snprintf(error, error_size, "CFG analysis failed: %s", strerror(errno));
        cfg_program_destroy(program);
    }
    return rc;
}

void cfg_program_destroy(CfgProgram *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->function_count; i++) free(p->functions[i].name);
    free(p->functions); free(p->tbs); free(p->edges); free(p->exec_ranges);
    memset(p, 0, sizeof(*p));
}

bool cfg_program_address_is_executable(const CfgProgram *p, uint64_t address)
{
    for (size_t i = 0; i < p->exec_range_count; i++) {
        const CfgExecRange *range = &p->exec_ranges[i];
        if (address >= range->start && address - range->start < range->size)
            return true;
    }
    return false;
}

const char *cfg_tb_term_name(CfgTbTerm t)
{
    static const char *names[] = {"fallthrough", "call", "icall", "jcc", "jmp",
        "ijmp", "ret", "syscall", "stop"};
    return (unsigned)t < sizeof(names) / sizeof(names[0]) ? names[t] : "unknown";
}

const char *cfg_program_edge_kind_name(CfgProgramEdgeKind k)
{
    static const char *names[] = {"fall", "true", "false", "jmp", "call",
        "return", "case", "runtime"};
    return (unsigned)k < sizeof(names) / sizeof(names[0]) ? names[k] : "unknown";
}

const char *cfg_function_status_name(CfgFunctionStatus s)
{
    static const char *names[] = {"ok", "open", "error"};
    return (unsigned)s < sizeof(names) / sizeof(names[0]) ? names[s] : "unknown";
}
