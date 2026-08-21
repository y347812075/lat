#include "cfg_decoder.h"
#include "cfg_program.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_decoder(void)
{
    const unsigned char direct_call[] = {0xe8, 1, 0, 0, 0};
    Insn in = cfg_decode_insn(direct_call, sizeof(direct_call), 0x1000, 0);
    assert(in.kind == INSN_CALL && in.len == 5 && in.target == 0x1006);

    const unsigned char indirect_call[] = {0xff, 0xd0};
    in = cfg_decode_insn(indirect_call, sizeof(indirect_call), 0x2000, 0);
    assert(in.kind == INSN_ICALL && in.len == 2);

    const unsigned char syscall[] = {0x0f, 0x05};
    in = cfg_decode_insn(syscall, sizeof(syscall), 0x3000, 0);
    assert(in.kind == INSN_SYSCALL && in.len == 2);

    const unsigned char loop[] = {0xe2, 0xfe};
    in = cfg_decode_insn(loop, sizeof(loop), 0x4000, 0);
    assert(in.kind == INSN_JCC && in.target == 0x4000);
}

static void test_program(const char *path)
{
    CfgProgram p;
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    char error[256] = {0};
    assert(cfg_analyze_elf(path, &options, &p, error, sizeof(error)) == 0);
    const CfgProgramFunction *start = NULL;
    const CfgProgramFunction *jump_source = NULL;
    const CfgProgramFunction *jump_container = NULL;
    const CfgProgramFunction *jump_table_source = NULL;
    const CfgProgramFunction *jump_plt_source = NULL;
    const CfgProgramFunction *plt = NULL;
    const CfgProgramFunction *fallthrough_check = NULL;
    const CfgProgramFunction *fallthrough_next = NULL;
    const CfgProgramFunction *zero_sized = NULL;
    for (size_t i = 0; i < p.function_count; i++) {
        if (strcmp(p.functions[i].name, "_start") == 0) start = &p.functions[i];
        if (strcmp(p.functions[i].name, "jump_source") == 0)
            jump_source = &p.functions[i];
        if (strcmp(p.functions[i].name, "jump_container") == 0)
            jump_container = &p.functions[i];
        if (strcmp(p.functions[i].name, "jump_table_source") == 0)
            jump_table_source = &p.functions[i];
        if (strcmp(p.functions[i].name, "jump_plt_source") == 0)
            jump_plt_source = &p.functions[i];
        if (strcmp(p.functions[i].name, "_plt") == 0)
            plt = &p.functions[i];
        if (strcmp(p.functions[i].name, "fallthrough_check") == 0)
            fallthrough_check = &p.functions[i];
        if (strcmp(p.functions[i].name, "fallthrough_next") == 0)
            fallthrough_next = &p.functions[i];
        if (strcmp(p.functions[i].name, "zero_sized") == 0)
            zero_sized = &p.functions[i];
    }
    assert(start && start->tb_count >= 4);
    int call = 0, jcc = 0, icall = 0, syscall = 0;
    for (size_t i = start->first_tb; i < start->first_tb + start->tb_count; i++) {
        call += p.tbs[i].terminator == CFG_TB_CALL;
        jcc += p.tbs[i].terminator == CFG_TB_CONDITIONAL;
        icall += p.tbs[i].terminator == CFG_TB_INDIRECT_CALL;
        syscall += p.tbs[i].terminator == CFG_TB_SYSCALL;
    }
    assert(call == 1 && jcc == 1 && icall == 1 && syscall == 1);
    assert(start->status == CFG_FUNCTION_OPEN);
    assert(jump_source && jump_source->tb_count == 1 && jump_container);
    const CfgTb *source_tb = &p.tbs[jump_source->first_tb];
    assert(source_tb->terminator == CFG_TB_JUMP && source_tb->edge_count == 1);
    uint64_t cross_target = p.edges[source_tb->first_edge].to;
    assert(cross_target > jump_container->start &&
           cross_target < jump_container->start + jump_container->size);
    int target_is_leader = 0;
    for (size_t i = jump_container->first_tb;
         i < jump_container->first_tb + jump_container->tb_count; i++) {
        target_is_leader |= p.tbs[i].start == cross_target;
    }
    assert(target_is_leader);

    assert(jump_table_source);
    int case_edges = 0;
    int local_case_edges = 0;
    for (size_t i = jump_table_source->first_tb;
         i < jump_table_source->first_tb + jump_table_source->tb_count; i++) {
        const CfgTb *tb = &p.tbs[i];
        for (size_t j = tb->first_edge; j < tb->first_edge + tb->edge_count;
             j++) {
            const CfgProgramEdge *edge = &p.edges[j];
            if (edge->kind != CFG_EDGE_CASE) continue;
            case_edges++;
            if (edge->to > jump_table_source->start &&
                edge->to < jump_table_source->start + jump_table_source->size) {
                local_case_edges++;
            }
        }
    }
    assert(case_edges == 3 && local_case_edges == 2);

    assert(jump_plt_source && jump_plt_source->tb_count == 1 && plt);
    source_tb = &p.tbs[jump_plt_source->first_tb];
    assert(source_tb->terminator == CFG_TB_JUMP && source_tb->edge_count == 1);
    cross_target = p.edges[source_tb->first_edge].to;
    assert(cross_target > plt->start && cross_target < plt->start + plt->size);
    target_is_leader = 0;
    for (size_t i = plt->first_tb; i < plt->first_tb + plt->tb_count; i++) {
        target_is_leader |= p.tbs[i].start == cross_target;
    }
    assert(target_is_leader);

    assert(fallthrough_check && fallthrough_next);
    int found_cross_symbol_fallthrough = 0;
    for (size_t i = fallthrough_check->first_tb;
         i < fallthrough_check->first_tb + fallthrough_check->tb_count; i++) {
        const CfgTb *tb = &p.tbs[i];
        if (tb->terminator != CFG_TB_CONDITIONAL) continue;
        for (size_t j = tb->first_edge; j < tb->first_edge + tb->edge_count;
             j++) {
            const CfgProgramEdge *edge = &p.edges[j];
            if (edge->kind == CFG_EDGE_FALSE &&
                edge->to < fallthrough_next->start) {
                found_cross_symbol_fallthrough = 1;
            }
        }
    }
    assert(found_cross_symbol_fallthrough);
    assert(zero_sized && zero_sized->size > 0 && zero_sized->tb_count == 1);
    cfg_program_destroy(&p);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    test_decoder();
    test_program(argv[1]);
    puts("test-cfg: PASS");
    return 0;
}
