#include "cfg_return_proof.h"
#include "cfg_decoder.h"

#include <capstone/capstone.h>
#include <glib.h>
#include <limits.h>
#include <string.h>

#define MAX_SLOTS 64
#define MAX_DEPTH 16
#define MAX_NODES 4096

typedef enum { UNKNOWN, ORIGINAL, STACK_ADDRESS, RETURN_ADDRESS } ValueKind;
typedef struct {
    ValueKind kind;
    int64_t number;
} Value;
typedef struct {
    int64_t offset;
    Value value;
} Slot;
typedef struct {
    Value regs[16];
    Slot slots[MAX_SLOTS];
    unsigned count;
} State;
typedef struct {
    uint64_t pc;
    size_t length;
    State state;
    bool pending;
} Node;
typedef struct {
    const CfgReturnContext *context;
    CfgReturnProof *proof;
    csh handle;
    cs_insn *insn;
    size_t remaining;
    uint64_t active[MAX_DEPTH];
    unsigned depth;
    int64_t activation;
} Engine;

static int full_reg(unsigned reg)
{
    static const unsigned regs[] = {
        X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
        X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
        X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
        X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    };
    for (unsigned i = 0; i < G_N_ELEMENTS(regs); i++)
        if (reg == regs[i]) return i;
    return -1;
}

static bool equal(Value a, Value b)
{
    return a.kind == b.kind && (a.kind == UNKNOWN || a.number == b.number);
}

static bool add_offset(int64_t left, int64_t right, int64_t *out)
{
    return !__builtin_add_overflow(left, right, out);
}

static Value load_slot(const State *s, int64_t offset)
{
    for (unsigned i = 0; i < s->count; i++)
        if (s->slots[i].offset == offset) return s->slots[i].value;
    return (Value){0};
}

static bool store_slot(State *s, int64_t offset, unsigned size, Value value)
{
    int64_t end;
    if (!size || !add_offset(offset, size, &end)) return false;
    for (unsigned i = 0; i < s->count;) {
        int64_t old_end;
        if (!add_offset(s->slots[i].offset, 8, &old_end)) return false;
        if (offset < old_end && s->slots[i].offset < end)
            s->slots[i] = s->slots[--s->count];
        else i++;
    }
    if (size == 8 && value.kind != UNKNOWN) {
        if (s->count == MAX_SLOTS) return false;
        s->slots[s->count++] = (Slot){offset, value};
    }
    return true;
}

static bool memory_offset(const State *s, const cs_x86_op *op, int64_t *offset)
{
    int base = full_reg(op->mem.base);
    return op->type == X86_OP_MEM && !op->mem.segment &&
        !op->mem.index && base >= 0 && s->regs[base].kind == STACK_ADDRESS &&
        add_offset(s->regs[base].number, op->mem.disp, offset);
}

static Value operand_value(const State *s, const cs_x86_op *op)
{
    if (op->size != 8) return (Value){0};
    int reg = op->type == X86_OP_REG ? full_reg(op->reg) : -1;
    if (reg >= 0) return s->regs[reg];
    int64_t offset;
    if (op->type == X86_OP_MEM && memory_offset(s, op, &offset))
        return load_slot(s, offset);
    return (Value){0};
}

static bool fail(Engine *e, uint64_t pc, CfgReturnReason reason)
{
    e->proof->frontier = pc;
    e->proof->reason = reason;
    return false;
}

static bool merge_state(State *to, const State *from)
{
    bool changed = false;
    for (unsigned i = 0; i < 16; i++) {
        if (to->regs[i].kind != UNKNOWN && !equal(to->regs[i], from->regs[i])) {
            to->regs[i] = (Value){0};
            changed = true;
        }
    }
    for (unsigned i = 0; i < to->count;) {
        if (!equal(to->slots[i].value, load_slot(from, to->slots[i].offset))) {
            to->slots[i] = to->slots[--to->count];
            changed = true;
        } else i++;
    }
    return changed;
}

static bool enqueue(Engine *e, GArray *nodes, uint64_t pc, const State *state)
{
    for (unsigned i = 0; i < nodes->len; i++) {
        Node *node = &g_array_index(nodes, Node, i);
        if (node->pc == pc) {
            node->pending |= merge_state(&node->state, state);
            return true;
        }
    }
    if (nodes->len >= MAX_NODES) return fail(e, pc, CFG_RETURN_LIMIT);
    Node node = {.pc = pc, .state = *state, .pending = true};
    g_array_append_val(nodes, node);
    return true;
}

static bool analyze(Engine *e, uint64_t entry, const State *initial,
                      State *returned, bool *writes_memory);

static void discard_below(State *state, int64_t sp)
{
    for (unsigned i = 0; i < state->count;) {
        if (state->slots[i].offset < sp)
            state->slots[i] = state->slots[--state->count];
        else i++;
    }
}

static bool transfer(Engine *e, uint64_t pc, const uint8_t *bytes, size_t size,
                       Insn in, State *s, bool *writes_memory)
{
    uint16_t writes;
    uint8_t memory_writes;
    if (!cfg_insn_gpr_writes(bytes, size, &writes) ||
        !cfg_insn_memory_writes(bytes, size, &memory_writes))
        return fail(e, pc, CFG_RETURN_UNSUPPORTED);
    const uint8_t *code = bytes;
    size_t available = size;
    uint64_t address = pc;
    if (!cs_disasm_iter(e->handle, &code, &available, &address, e->insn) ||
        e->insn->size != size || !e->insn->detail)
        return fail(e, pc, CFG_RETURN_UNSUPPORTED);
    unsigned id = e->insn->id;
    cs_x86 x86 = e->insn->detail->x86;
    if (x86.addr_size != 8) return fail(e, pc, CFG_RETURN_UNSUPPORTED);
    State before = *s;
    if (in.kind == INSN_CALL) {
        bool stores = false;
        if (s->regs[4].kind != STACK_ADDRESS)
            return fail(e, pc, CFG_RETURN_STACK);
        /* CALL's return slot and the child's private stack overwrite any
         * caller red-zone facts even when the child restores all GPRs. */
        int64_t caller_sp = s->regs[4].number, child_sp;
        if (!add_offset(caller_sp, -8, &child_sp) || e->activation == INT64_MAX)
            return fail(e, pc, CFG_RETURN_STACK);
        discard_below(s, caller_sp);
        s->regs[4] = (Value){STACK_ADDRESS, child_sp};
        if (!store_slot(s, child_sp, 8,
                        (Value){RETURN_ADDRESS, ++e->activation}))
            return fail(e, pc, CFG_RETURN_STACK);
        State returned;
        if (!analyze(e, in.target, s, &returned, &stores)) return false;
        *s = returned;
        s->regs[4] = (Value){STACK_ADDRESS, caller_sp};
        discard_below(s, caller_sp);
        *writes_memory |= stores;
        return true;
    }
    if (in.kind == INSN_ICALL || in.kind == INSN_IJMP)
        return fail(e, pc, CFG_RETURN_INDIRECT);
    for (unsigned i = 0; i < 16; i++)
        if (writes & (UINT16_C(1) << i)) s->regs[i] = (Value){0};
    if (id == X86_INS_PUSH || id == X86_INS_POP) {
        if (x86.op_count != 1 || before.regs[4].kind != STACK_ADDRESS ||
            x86.operands[0].size != 8)
            return fail(e, pc, CFG_RETURN_STACK);
        int64_t offset = before.regs[4].number;
        if (id == X86_INS_PUSH) {
            if (!add_offset(offset, -8, &offset) ||
                !store_slot(s, offset, 8, operand_value(&before, &x86.operands[0])))
                return fail(e, pc, CFG_RETURN_STACK);
            if (offset >= 0) *writes_memory = true;
        } else {
            int reg = x86.operands[0].type == X86_OP_REG ?
                       full_reg(x86.operands[0].reg) : -1;
            if (reg < 0 || reg == 4) return fail(e, pc, CFG_RETURN_STACK);
            s->regs[reg] = load_slot(&before, offset);
            if (!store_slot(s, offset, 8, (Value){0}) ||
                !add_offset(offset, 8, &offset))
                return fail(e, pc, CFG_RETURN_STACK);
        }
        s->regs[4] = (Value){STACK_ADDRESS, offset};
        return true;
    }
    /* Implicit string stores have no reliable explicit operand destination. */
    if (id == X86_INS_MOVSB) {
        s->count = 0;
        *writes_memory = true;
    }
    for (unsigned i = 0; i < x86.op_count; i++) {
        const cs_x86_op *op = &x86.operands[i];
        if (memory_writes & (UINT8_C(1) << i)) {
            int64_t offset;
            if (memory_offset(&before, op, &offset)) {
                Value value = id == X86_INS_MOV && x86.op_count == 2 ?
                               operand_value(&before, &x86.operands[1]) : (Value){0};
                if (!store_slot(s, offset, op->size, value))
                    return fail(e, pc, CFG_RETURN_STACK);
            } else s->count = 0;
            *writes_memory = true;
        }
    }
    if (x86.op_count == 2 && x86.operands[0].type == X86_OP_REG) {
        int dst = full_reg(x86.operands[0].reg);
        if (dst >= 0 && x86.operands[0].size == 8) {
            if (id == X86_INS_MOV) {
                s->regs[dst] = operand_value(&before, &x86.operands[1]);
            } else if (id == X86_INS_LEA) {
                int64_t offset;
                if (memory_offset(&before, &x86.operands[1], &offset))
                    s->regs[dst] = (Value){STACK_ADDRESS, offset};
            } else if ((id == X86_INS_ADD || id == X86_INS_SUB) &&
                       x86.operands[1].type == X86_OP_IMM &&
                       before.regs[dst].kind == STACK_ADDRESS) {
                int64_t change = x86.operands[1].imm, offset;
                if (id == X86_INS_SUB && __builtin_sub_overflow((int64_t)0,
                                                               change, &change))
                    return fail(e, pc, CFG_RETURN_STACK);
                if (!add_offset(before.regs[dst].number, change, &offset))
                    return fail(e, pc, CFG_RETURN_STACK);
                s->regs[dst] = (Value){STACK_ADDRESS, offset};
            }
        }
    }
    return true;
}

static bool analyze(Engine *e, uint64_t entry, const State *initial,
                      State *returned, bool *writes_memory)
{
    if (e->depth >= e->context->call_depth || e->depth == MAX_DEPTH)
        return fail(e, entry, CFG_RETURN_LIMIT);
    for (unsigned i = 0; i < e->depth; i++)
        if (e->active[i] == entry) return fail(e, entry, CFG_RETURN_RECURSION);
    e->active[e->depth++] = entry;
    Value expected_sp = initial->regs[4];
    Value expected_return = load_slot(initial, expected_sp.number);
    GArray *nodes = g_array_new(false, false, sizeof(Node));
    enqueue(e, nodes, entry, initial);
    bool ok = false, pending;
    size_t returns = 0;
    do {
        pending = false;
        for (unsigned i = 0; i < nodes->len; i++) {
            Node *node = &g_array_index(nodes, Node, i);
            if (!node->pending) continue;
            node->pending = false;
            uint64_t pc = node->pc;
            State state = node->state;
            if (!e->remaining) { fail(e, pc, CFG_RETURN_LIMIT); goto done; }
            e->remaining--;
            e->proof->instructions++;
            uint8_t bytes[15];
            size_t size = 0;
            if (!e->context->read_code(e->context->data, pc, bytes, &size) ||
                !size || size > 15) { fail(e, pc, CFG_RETURN_UNMAPPED); goto done; }
            Insn in = cfg_decode_insn(bytes, size, pc, 0);
            if (!in.len || in.len > size || pc > UINT64_MAX - in.len) {
                fail(e, pc, CFG_RETURN_UNSUPPORTED); goto done;
            }
            for (unsigned j = 0; j < nodes->len; j++) {
                const Node *other = &g_array_index(nodes, Node, j);
                if (j != i && ((other->pc > pc && other->pc < pc + in.len) ||
                    (other->length && pc > other->pc &&
                     pc - other->pc < other->length))) {
                    fail(e, pc, CFG_RETURN_UNSUPPORTED); goto done;
                }
            }
            g_array_index(nodes, Node, i).length = in.len;
            if (in.kind == INSN_RET) {
                /* Plain near RET only: no far/interrupt/ret-imm contracts. */
                if (in.len != 1 || bytes[0] != 0xc3 ||
                    !equal(state.regs[4], expected_sp) ||
                    !equal(load_slot(&state, expected_sp.number), expected_return)) {
                    fail(e, pc, CFG_RETURN_STACK); goto done;
                }
                if (!returns) *returned = state;
                else merge_state(returned, &state);
                returns++;
                continue;
            }
            if (!transfer(e, pc, bytes, in.len, in, &state, writes_memory))
                goto done;
            if (in.kind == INSN_JMP || in.kind == INSN_JCC) {
                if (!in.has_target || !enqueue(e, nodes, in.target, &state)) goto done;
            }
            if (in.kind != INSN_JMP && !enqueue(e, nodes, pc + in.len, &state))
                goto done;
        }
        for (unsigned i = 0; i < nodes->len; i++)
            pending |= g_array_index(nodes, Node, i).pending;
    } while (pending);
    if (!returns) { fail(e, entry, CFG_RETURN_NO_RETURN); goto done; }
    e->proof->returns += returns;
    ok = true;
done:
    e->depth--;
    g_array_free(nodes, true);
    return ok;
}

bool cfg_prove_return_preservation(const CfgReturnContext *context,
                                    uint64_t entry, uint16_t demanded,
                                    CfgReturnProof *proof)
{
    if (!proof) return false;
    memset(proof, 0, sizeof(*proof));
    proof->reason = CFG_RETURN_BAD_INPUT;
    if (!context || !context->read_code || !context->instruction_budget ||
        !context->call_depth || context->call_depth > MAX_DEPTH) return false;
    Engine engine = {.context = context, .proof = proof,
                     .remaining = context->instruction_budget};
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &engine.handle) != CS_ERR_OK)
        return false;
    if (cs_option(engine.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK ||
        !(engine.insn = cs_malloc(engine.handle))) {
        cs_close(&engine.handle);
        return false;
    }
    State initial = {0}, returned;
    for (unsigned i = 0; i < 16; i++) initial.regs[i] = (Value){ORIGINAL, i};
    initial.regs[4] = (Value){STACK_ADDRESS, 0};
    store_slot(&initial, 0, 8, (Value){RETURN_ADDRESS, 0});
    bool ok = analyze(&engine, entry, &initial, &returned, &proof->writes_memory);
    if (ok) {
        for (unsigned i = 0; i < 16; i++)
            if (equal(initial.regs[i], returned.regs[i]))
                proof->preserved |= UINT16_C(1) << i;
        if ((proof->preserved & demanded) != demanded)
            ok = fail(&engine, entry, CFG_RETURN_CLOBBER);
    }
    if (ok) proof->reason = CFG_RETURN_PROVED;
    else proof->preserved = 0;
    cs_free(engine.insn, 1);
    cs_close(&engine.handle);
    return ok;
}

const char *cfg_return_reason_name(CfgReturnReason reason)
{
    static const char *names[] = {"proved", "bad-input", "unmapped", "unsupported",
        "indirect", "stack", "clobber", "limit", "recursion", "no-return"};
    return (unsigned)reason < G_N_ELEMENTS(names) ? names[reason] : "invalid";
}
