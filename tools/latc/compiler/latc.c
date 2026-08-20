#include "cfg_program.h"
#include "bundle.h"
#include "profile.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void usage(const char *name)
{
    fprintf(stderr, "usage:\n"
            "  %s analyze [--json] X86_ELF\n"
            "  %s compile X86_ELF -o OUTPUT --runner RUNNER [--profile FILE]"
            " [--profile-ignore-outside-exec] [--aot FILE]\n"
            "  %s inspect [--json] BUNDLE\n", name, name, name);
}

static int compile_bundle(const char *input, const char *output,
                          const char *runner, const char *profile,
                          int profile_ignore_outside_exec, const char *aot)
{
    CfgProgram program;
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    char error[256] = {0};
    if (cfg_analyze_elf(input, &options, &program, error, sizeof(error)) != 0) {
        fprintf(stderr, "latc: %s\n", error); return 1;
    }
    if (profile) {
        size_t matched = 0, unmatched = 0, ignored = 0;
        if (latc_profile_apply(profile, &program, profile_ignore_outside_exec,
                               &matched, &unmatched, &ignored,
                               error, sizeof(error)) != 0) {
            fprintf(stderr, "latc: %s\n", error);
            cfg_program_destroy(&program);
            return 1;
        }
        fprintf(stderr, "latc: profile matched=%zu added=%zu ignored=%zu\n",
                matched, unmatched, ignored);
    }
    int rc = latc_bundle_write(runner, input, output, aot, &program,
                               error, sizeof(error));
    cfg_program_destroy(&program);
    if (rc) { fprintf(stderr, "latc: %s\n", error); return 1; }
    printf("output=%s\n", output);
    return 0;
}

static int inspect_bundle(const char *path, int json)
{
    LatcBundleInfo info;
    char error[256] = {0};
    if (latc_bundle_inspect(path, &info, 1, error, sizeof(error)) != 0) {
        fprintf(stderr, "latc: %s\n", error); return 1;
    }
    if (json) {
        printf("{\"bundle\":\"%s\",\"execution_model\":\"%s\""
               ",\"runner_size\":%" PRIu64
               ",\"guest_size\":%" PRIu64 ",\"cfg_size\":%" PRIu64
               ",\"functions\":%" PRIu64 ",\"tbs\":%" PRIu64
               ",\"edges\":%" PRIu64 ",\"profiled_tbs\":%" PRIu64
               ",\"aot_size\":%" PRIu64 ",\"aot_name\":\"%s\""
               ",\"guest_sha256\":\"%s\"}\n",
               path, LATC_EXECUTION_MODEL, info.runner_size, info.guest_size,
               info.cfg_size,
               info.function_count, info.tb_count, info.edge_count,
               info.profiled_tb_count,
               info.aot_size, info.aot_name,
               info.guest_sha256);
    } else {
        printf("bundle=%s\nexecution_model=%s\nrunner_size=%" PRIu64
               "\nguest_size=%" PRIu64
               "\ncfg_size=%" PRIu64 "\nfunctions=%" PRIu64
               "\ntbs=%" PRIu64 "\nedges=%" PRIu64 "\nprofiled_tbs=%" PRIu64
               "\naot_size=%" PRIu64 "\naot_name=%s"
               "\nguest_sha256=%s\n", path, LATC_EXECUTION_MODEL,
               info.runner_size,
               info.guest_size, info.cfg_size, info.function_count,
               info.tb_count, info.edge_count, info.profiled_tb_count,
               info.aot_size, info.aot_name,
               info.guest_sha256);
    }
    return 0;
}

static int analyze(const char *path, int json)
{
    CfgProgram program;
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    char error[256] = {0};
    if (cfg_analyze_elf(path, &options, &program, error, sizeof(error)) != 0) {
        fprintf(stderr, "latc: %s\n", error[0] ? error : "analysis failed");
        return 1;
    }
    if (json) {
        printf("{\"input\":\"%s\",\"functions\":%zu,\"tbs\":%zu,"
               "\"edges\":%zu,\"open_functions\":%zu,"
               "\"error_functions\":%zu,\"jump_tables\":%zu,"
               "\"jump_table_targets\":%zu}\n",
               path, program.function_count, program.tb_count,
               program.edge_count, program.open_function_count,
               program.error_function_count, program.resolved_jump_tables,
               program.resolved_jump_table_targets);
    } else {
        printf("input=%s\nfunctions=%zu\ntbs=%zu\nedges=%zu\n",
               path, program.function_count, program.tb_count,
               program.edge_count);
        printf("open_functions=%zu\nerror_functions=%zu\n",
               program.open_function_count, program.error_function_count);
        printf("resolved_jump_tables=%zu\nresolved_jump_table_targets=%zu\n",
               program.resolved_jump_tables,
               program.resolved_jump_table_targets);
        for (size_t i = 0; i < program.function_count; i++) {
            if (program.functions[i].status == CFG_FUNCTION_ERROR)
                printf("error_function=%s@0x%" PRIx64 "\n",
                       program.functions[i].name, program.functions[i].start);
        }
    }
    cfg_program_destroy(&program);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "compile") == 0) {
        const char *input = argv[2], *output = NULL, *runner = NULL;
        const char *profile = NULL;
        const char *aot = NULL;
        int profile_ignore_outside_exec = 0;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) output = argv[++i];
            else if (strcmp(argv[i], "--runner") == 0 && i + 1 < argc) runner = argv[++i];
            else if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) profile = argv[++i];
            else if (strcmp(argv[i], "--profile-ignore-outside-exec") == 0)
                profile_ignore_outside_exec = 1;
            else if (strcmp(argv[i], "--aot") == 0 && i + 1 < argc) aot = argv[++i];
            else { usage(argv[0]); return 2; }
        }
        if (!output || !runner) { usage(argv[0]); return 2; }
        return compile_bundle(input, output, runner, profile,
                              profile_ignore_outside_exec, aot);
    }
    if (strcmp(argv[1], "inspect") == 0) {
        int json = 0; const char *path = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0) json = 1;
            else if (!path) path = argv[i]; else { usage(argv[0]); return 2; }
        }
        if (!path) { usage(argv[0]); return 2; }
        return inspect_bundle(path, json);
    }
    if (strcmp(argv[1], "analyze") != 0) { usage(argv[0]); return 2; }
    int json = 0;
    const char *path = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) json = 1;
        else if (!path) path = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (!path) { usage(argv[0]); return 2; }
    return analyze(path, json);
}
