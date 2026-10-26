#include "bundle.h"
#include "cfg_program.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    CfgProgram program;
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    char error[256] = {0};
    if (cfg_analyze_elf(argv[1], &options, &program, error, sizeof(error))) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    /* Test fixture: exercise the existing unbounded shared-TU producer path. */
    for (size_t i = 0; i < program.tb_count; i++) {
        program.tbs[i].selected = true;
        program.tbs[i].semantic_flags = CFG_TB_CODE64 | CFG_TB_PARALLEL;
    }
    int result = latc_bundle_write(argv[2], argv[1], argv[3], NULL, &program,
                                   NULL, error, sizeof(error));
    cfg_program_destroy(&program);
    if (result) fprintf(stderr, "%s\n", error);
    return result ? 1 : 0;
}
