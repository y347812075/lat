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
    for (size_t i = 0; i < p.function_count; i++) {
        if (strcmp(p.functions[i].name, "_start") == 0) start = &p.functions[i];
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
