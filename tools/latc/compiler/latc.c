#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cfg_program.h"
#include "bundle.h"
#include "tbset.h"
#include "tbplan.h"
#include "native-image.h"
#include "native-tu-plan.h"
#include "native-tu-audit.h"
#include "module-pack.h"
#include "module-inspect.h"
#include "latc-build-id.h"
#include "lat-translation-config.h"

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *name)
{
    fprintf(stderr, "usage:\n"
            "  %s analyze [--json] X86_ELF\n"
            "  %s emit-static-tbset X86_ELF -o FILE\n"
            "  %s compile X86_ELF -o OUTPUT --runner RUNNER [--tbset FILE]"
            " [--tbset-ignore-outside-exec] [--aot FILE]\n"
            "  %s inspect [--json] BUNDLE\n", name, name, name, name);
    fprintf(stderr, "  %s inspect-native [--json] IMAGE\n", name);
    fprintf(stderr, "  %s validate-replay-native IMAGE CONFIG\n", name);
    fprintf(stderr, "  %s mark-native-x86 IMAGE\n", name);
    fprintf(stderr, "  %s merge-native BASE DELTA -o OUTPUT\n", name);
    fprintf(stderr, "  %s plan-native-tus IMAGE SEED_TBSET -o OUTPUT_TBSET\n", name);
    fprintf(stderr, "  %s plan-native-config IMAGE CONFIG -o OUTPUT_TBSET\n", name);
    fprintf(stderr, "  %s extract-native-tus IMAGE REMOVE_TBSET -o OUTPUT_NATIVE\n", name);
    fprintf(stderr, "  %s audit-native-tu-references IMAGE\n", name);
    fprintf(stderr, "  %s audit-native-tu-execution IMAGE\n", name);
    fprintf(stderr, "  %s emit-aot-v2 NATIVE_IMAGE OUTPUT_DIRECTORY"
                    " [X86_ELF [TBSET]]\n",
            name);
    fprintf(stderr,
            "  %s compile-module X86_ELF -o MODULE --runner RUNNER"
            " --runtime-dir DIRECTORY [--tbset FILE [--static-tbset]]\n",
            name);
    fprintf(stderr, "  %s inspect-module [--json] MODULE\n", name);
    fprintf(stderr, "  %s emit-module-tbset MODULE -o TBSET\n", name);
    fprintf(stderr, "  %s missing-module-tbset MODULE TBSET -o DELTA\n", name);
    fprintf(stderr, "  %s validate-native-base MODULE NATIVE_IMAGE\n", name);
    fprintf(stderr, "  %s split-tbset TBSET LEFT RIGHT\n", name);
    fprintf(stderr, "  %s plan-tbset X86_ELF TBSET DIRECTORY"
                    " [--static] [--batch-size N] [--work-budget N]\n", name);
    fprintf(stderr, "  %s list-tbplan X86_ELF DIRECTORY\n", name);
    fprintf(stderr, "  %s validate-tbplan-module X86_ELF DIRECTORY MODULE\n", name);
    fprintf(stderr, "  %s validate-module-replacement OLD_MODULE NEW_MODULE\n",
            name);
    fprintf(stderr, "  %s build-id\n", name);
}

static int inspect_native(const char *path, int json)
{
    LatNativeImageHeaderV2 header;
    char error[256] = {0};
    if (lat_native_image_inspect_file(path, &header, error, sizeof(error))) {
        fprintf(stderr, "latc: %s\n", error);
        return 1;
    }
    if (json) {
        char config_digest[65];
        for (size_t i = 0; i < 32; i++) {
            snprintf(config_digest + 2 * i, 3, "%02x",
                     header.translation_config_sha256[i]);
        }
        printf("{\"image\":\"%s\",\"execution_model\":\"lat-native-image\""
               ",\"flags\":%u,\"guest_entry\":%" PRIu64
               ",\"preferred_guest_base\":%" PRIu64
               ",\"guest_size\":%" PRIu64
               ",\"code_size\":%" PRIu64 ",\"tbs\":%" PRIu64
               ",\"relocations\":%" PRIu64 ",\"pc_maps\":%" PRIu64
               ",\"lat_build_id\":\"%s\",\"translation_config_sha256\":\"%s\"}\n",
               path, header.flags, header.guest_entry,
               header.preferred_guest_base, header.guest_image_size,
               header.code_size, header.tb_count, header.relocation_count,
               header.pc_map_count, header.lat_build_id, config_digest);
    } else {
        printf("image=%s\nexecution_model=lat-native-image\n"
               "flags=0x%x\nguest_entry=0x%" PRIx64
               "\npreferred_guest_base=0x%" PRIx64
               "\nguest_size=%" PRIu64
               "\ncode_size=%" PRIu64 "\ntbs=%" PRIu64
               "\nrelocations=%" PRIu64 "\npc_maps=%" PRIu64
               "\nlat_build_id=%s\n",
               path, header.flags, header.guest_entry,
               header.preferred_guest_base, header.guest_image_size,
               header.code_size, header.tb_count, header.relocation_count,
               header.pc_map_count, header.lat_build_id);
    }
    return 0;
}

static void digest_hex(const uint8_t digest[32], char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = '\0';
}

static int file_digest(const char *path, uint8_t digest[32],
                       char *error, size_t error_size)
{
    gchar *contents = NULL;
    gsize size = 0;
    GError *gerror = NULL;
    if (!g_file_get_contents(path, &contents, &size, &gerror)) {
        g_snprintf(error, error_size, "cannot read %s: %s", path,
                   gerror ? gerror->message : "unknown error");
        g_clear_error(&gerror);
        return -1;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)contents, size);
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    g_checksum_free(checksum);
    g_free(contents);
    return digest_size == 32 ? 0 : -1;
}

static int split_tbset(const char *input, const char *left, const char *right)
{
    LatTbKeySet keys = {0};
    char error[256] = {0};
    const char *paths[] = {left, right};
    bool created[2] = {false, false};
    int result = lat_tb_key_set_read_file(input, NULL, &keys,
                                          error, sizeof(error));
    if (!result && keys.count < 2) {
        snprintf(error, sizeof(error), "TB set cannot be split further");
        result = -1;
    }
    for (unsigned i = 0; !result && i < 2; i++) {
        size_t middle = keys.count / 2;
        LatTbKeySet part = keys;
        part.keys += i ? middle : 0;
        part.count = i ? keys.count - middle : middle;
        int fd = open(paths[i], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            snprintf(error, sizeof(error), "cannot create split TB set: %s",
                     strerror(errno));
            result = -1;
            break;
        }
        created[i] = true;
        result = lat_tb_key_set_write_fd(fd, &part, error, sizeof(error));
        if (close(fd) && !result) {
            snprintf(error, sizeof(error), "cannot close split TB set: %s",
                     strerror(errno));
            result = -1;
        }
    }
    lat_tb_key_set_destroy(&keys);
    if (result) {
        for (unsigned i = 0; i < 2; i++) {
            if (created[i]) {
                unlink(paths[i]);
            }
        }
        fprintf(stderr, "latc: %s\n", error);
    }
    return result ? 1 : 0;
}

static int inspect_module(const char *path, int json)
{
    LatAotModuleInfoV2 info;
    char error[256] = {0};
    if (lat_aot_v2_module_inspect_file(path, &info, error, sizeof(error))) {
        fprintf(stderr, "latc: %s\n", error);
        return 1;
    }
    char source[65];
    char codegen[65];
    digest_hex(info.note.source_sha256, source);
    digest_hex(info.note.codegen_id, codegen);
    int precise = !!(info.note.module_flags & LAT_AOT_MODULE_PRECISE_PC_MAP);
    int test_only = !!(info.note.module_flags & LAT_AOT_MODULE_M1_TEST_ONLY);
    if (json) {
        printf("{\"module\":\"%s\",\"execution_model\":\"lat-aot-v2\""
               ",\"abi_version\":%u,\"module_flags\":%" PRIu64
               ",\"required_features\":%" PRIu64
               ",\"text_size\":%" PRIu64 ",\"tbs\":%" PRIu64
               ",\"pc_maps\":%" PRIu64
               ",\"precise_pc_map\":%s,\"test_only\":%s"
               ",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\"}\n",
               path, info.note.abi_version, info.note.module_flags,
               info.note.required_features, info.text_size, info.tb_count,
               info.pc_map_count, precise ? "true" : "false",
               test_only ? "true" : "false", source, codegen);
    } else {
        printf("module=%s\nexecution_model=lat-aot-v2\nabi_version=%u"
               "\nmodule_flags=0x%" PRIx64
               "\nrequired_features=0x%" PRIx64
               "\ntext_size=%" PRIu64 "\ntbs=%" PRIu64
               "\npc_maps=%" PRIu64 "\nprecise_pc_map=%s\ntest_only=%s"
               "\nsource_sha256=%s\ncodegen_id=%s\n",
               path, info.note.abi_version, info.note.module_flags,
               info.note.required_features, info.text_size, info.tb_count,
               info.pc_map_count, precise ? "true" : "false",
               test_only ? "true" : "false", source, codegen);
    }
    return 0;
}

static int missing_module_tbset(const char *module, const char *input,
                                 const char *output)
{
    char error[256] = {0};
    LatAotModuleInfoV2 info;
    LatTbKeySet missing = {0};
    int result = lat_aot_v2_module_missing_tbset_file(
        module, input, &info, &missing, error, sizeof(error));
    if (!result) {
        uint8_t expected[32];
        lat_aot_v2_codegen_digest(LATC_BUILD_ID, expected);
        if (memcmp(info.note.codegen_id, expected, sizeof(expected))) {
            snprintf(error, sizeof(error), "module codegen identity mismatch");
            result = -1;
        }
    }
    int fd = -1;
    if (!result) {
        fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            snprintf(error, sizeof(error), "cannot create delta TB set: %s",
                     strerror(errno));
            result = -1;
        } else {
            result = lat_tb_key_set_write_fd(fd, &missing, error, sizeof(error));
            if (close(fd) && !result) {
                snprintf(error, sizeof(error), "cannot close delta TB set: %s",
                         strerror(errno));
                result = -1;
            }
        }
    }
    if (result) {
        if (fd >= 0) unlink(output);
        fprintf(stderr, "latc: %s\n", error);
    } else {
        printf("missing_tb_keys=%zu\n", missing.count);
    }
    lat_tb_key_set_destroy(&missing);
    return result ? 1 : 0;
}

static int plan_native_tus(const char *image, const char *input,
                            const char *output, bool from_config, bool extract)
{
    g_autofree char *data = NULL;
    gsize size;
    GError *gerror = NULL;
    char error[256] = {0};
    LatTbKeySet seeds = {0}, plan = {0};
    g_autofree void *extracted = NULL;
    size_t extracted_size = 0;
    int fd = -1, result = -1;
    uint64_t changed = 0;
    if (!g_file_get_contents(image, &data, &size, &gerror)) {
        fprintf(stderr, "latc: %s\n", gerror->message);
        g_clear_error(&gerror);
        return 1;
    }
    if (lat_native_image_validate(data, size, error, sizeof(error))) goto out;
    const LatNativeImageHeaderV2 *h = (const void *)data;
    if (strcmp(h->lat_build_id, LATC_BUILD_ID)) {
        snprintf(error, sizeof(error), "native TU plan codegen identity mismatch");
        goto out;
    }
    if (from_config) {
        uint8_t target[LAT_NATIVE_CONFIG_CAPACITY];
        struct stat status;
        int config_fd = open(input, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (config_fd < 0 || fstat(config_fd, &status) ||
            !S_ISREG(status.st_mode) ||
            status.st_size < LAT_TRANSLATION_CONFIG_HEADER_SIZE ||
            status.st_size > (off_t)sizeof(target) ||
            pread(config_fd, target, status.st_size, 0) != status.st_size) {
            snprintf(error, sizeof(error), "cannot read bounded target configuration");
            if (config_fd >= 0) close(config_fd);
            goto out;
        }
        close(config_fd);
        if (lat_native_tu_config_plan(data, size, target, status.st_size, &plan,
                &changed, error, sizeof(error))) goto out;
    } else if (lat_tb_key_set_read_file(input, h->guest_sha256, &seeds,
                   error, sizeof(error)) ||
               lat_native_tu_plan(data, size, &seeds, &plan, error,
                   sizeof(error))) goto out;
    if (extract && lat_native_tu_extract(data, size, &seeds, &extracted,
            &extracted_size, error, sizeof(error))) goto out;
    fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(error, sizeof(error), "cannot create TU plan: %s", strerror(errno));
        goto out;
    }
    if (extract) {
        size_t written = 0;
        result = 0;
        while (written < extracted_size) {
            ssize_t count = write(fd, (const uint8_t *)extracted + written,
                                  extracted_size - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { result = -1; break; }
            written += count;
        }
        if (!result && fsync(fd)) result = -1;
        if (result) snprintf(error, sizeof(error), "cannot write extracted native: %s", strerror(errno));
    } else {
        result = lat_tb_key_set_write_fd(fd, &plan, error, sizeof(error));
    }
    if (close(fd) && !result) {
        snprintf(error, sizeof(error), "cannot close TU plan: %s", strerror(errno));
        result = -1;
    }
out:
    if (result) {
        if (fd >= 0) unlink(output);
        fprintf(stderr, "latc: %s\n", error);
    } else {
        printf("affected_tb_keys=%zu\n", plan.count);
        if (from_config) printf("changed_config_fields=0x%" PRIx64 "\n", changed);
    }
    lat_tb_key_set_destroy(&plan);
    lat_tb_key_set_destroy(&seeds);
    return result ? 1 : 0;
}

static int compile_module(const char *input, const char *output,
                          const char *runner,
                          const char *runtime_dir, const char *tbset,
                          bool static_tbset)
{
    GError *gerror = NULL;
    gchar *executable = g_file_read_link("/proc/self/exe", &gerror);
    if (!executable) {
        fprintf(stderr, "latc: cannot locate compiler executable: %s\n",
                gerror ? gerror->message : "unknown error");
        g_clear_error(&gerror);
        return 1;
    }
#ifdef LATC_INSTALLED_SCRIPT_DIR
    gchar *script = g_build_filename(LATC_INSTALLED_SCRIPT_DIR,
                                     "compile-aot-v2-module.sh", NULL);
#else
    gchar *build_dir = g_path_get_dirname(executable);
    gchar *tool_dir = g_path_get_dirname(build_dir);
    gchar *script = g_build_filename(tool_dir, "scripts",
                                     "compile-aot-v2-module.sh", NULL);
#endif
    pid_t child = fork();
    if (child == 0) {
        if (tbset && static_tbset) {
            execl(script, script, "--static-tbset", executable, runner,
                  input, runtime_dir, output, tbset, (char *)NULL);
        } else if (tbset) {
            execl(script, script, executable, runner, input, runtime_dir, output,
                  tbset, (char *)NULL);
        } else {
            execl(script, script, executable, runner, input, runtime_dir, output,
                  (char *)NULL);
        }
        fprintf(stderr, "latc: cannot execute %s: %s\n", script,
                strerror(errno));
        _exit(127);
    }
    g_free(script);
#ifndef LATC_INSTALLED_SCRIPT_DIR
    g_free(tool_dir);
    g_free(build_dir);
#endif
    g_free(executable);
    if (child < 0) {
        fprintf(stderr, "latc: cannot start module compiler: %s\n",
                strerror(errno));
        return 1;
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "latc: cannot wait for module compiler: %s\n",
                    strerror(errno));
            return 1;
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int compile_bundle(const char *input, const char *output,
                          const char *runner, const char *tbset,
                          int tbset_ignore_outside_exec, const char *aot)
{
    CfgProgram program;
    uint8_t guest_digest[32];
    const uint8_t *known_guest_digest = NULL;
    char error[256] = {0};
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    const char *selection = getenv("LATC_TBSET_SELECTION");
    bool exact = tbset && selection &&
        (!strcmp(selection, "exact") || !strcmp(selection, "exact-static"));
    /* Exact batches have already completed discovery.  Only their executable
     * ranges and explicit keys are needed by the bundle's translation worker. */
    int analyze_result = exact ?
        cfg_load_exec_ranges(input, &program, error, sizeof(error)) :
        cfg_analyze_elf(input, &options, &program, error, sizeof(error));
    if (analyze_result != 0) {
        fprintf(stderr, "latc: %s\n", error); return 1;
    }
    if (tbset) {
        size_t matched = 0, unmatched = 0, ignored = 0;
        if (latc_tbset_apply(tbset, input, &program,
                            tbset_ignore_outside_exec,
                            &matched, &unmatched, &ignored, guest_digest,
                            error, sizeof(error)) != 0) {
            fprintf(stderr, "latc: %s\n", error);
            cfg_program_destroy(&program);
            return 1;
        }
        fprintf(stderr, "latc: TB set matched=%zu added=%zu ignored=%zu\n",
                matched, unmatched, ignored);
        known_guest_digest = guest_digest;
    }
    int rc = latc_bundle_write(runner, input, output, aot, &program,
                               known_guest_digest,
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
               ",\"edges\":%" PRIu64 ",\"selected_tbs\":%" PRIu64
               ",\"aot_size\":%" PRIu64 ",\"aot_name\":\"%s\""
               ",\"guest_sha256\":\"%s\"}\n",
               path, LATC_EXECUTION_MODEL, info.runner_size, info.guest_size,
               info.cfg_size,
               info.function_count, info.tb_count, info.edge_count,
               info.selected_tb_count,
               info.aot_size, info.aot_name,
               info.guest_sha256);
    } else {
        printf("bundle=%s\nexecution_model=%s\nrunner_size=%" PRIu64
               "\nguest_size=%" PRIu64
               "\ncfg_size=%" PRIu64 "\nfunctions=%" PRIu64
               "\ntbs=%" PRIu64 "\nedges=%" PRIu64 "\nselected_tbs=%" PRIu64
               "\naot_size=%" PRIu64 "\naot_name=%s"
               "\nguest_sha256=%s\n", path, LATC_EXECUTION_MODEL,
               info.runner_size,
               info.guest_size, info.cfg_size, info.function_count,
               info.tb_count, info.edge_count, info.selected_tb_count,
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

static int emit_static_tbset(const char *input, const char *output)
{
    CfgProgram program;
    CfgAnalyzeOptions options = { .resolve_jump_tables = true };
    char error[256] = {0};
    if (cfg_analyze_elf(input, &options, &program, error, sizeof(error))) {
        fprintf(stderr, "latc: %s\n", error[0] ? error : "analysis failed");
        return 1;
    }
    size_t written = 0;
    int result = latc_tbset_write_static(output, input, &program,
                                         &written,
                                         error, sizeof(error));
    cfg_program_destroy(&program);
    if (result) {
        fprintf(stderr, "latc: %s\n", error);
        return 1;
    }
    printf("output=%s\nstatic_tb_keys=%zu\n", output, written);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "build-id") == 0) {
        puts(LATC_BUILD_ID);
        return 0;
    }
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "plan-tbset")) {
        if (argc < 5) { usage(argv[0]); return 2; }
        bool static_input = false;
        size_t batch = 65536, work = 20000;
        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "--static")) static_input = true;
            else if ((!strcmp(argv[i], "--batch-size") ||
                      !strcmp(argv[i], "--work-budget")) && i + 1 < argc) {
                bool is_batch = !strcmp(argv[i], "--batch-size");
                char *end;
                errno = 0;
                const char *text = argv[++i];
                unsigned long long value = strtoull(text, &end, 10);
                if (errno || !*text || *end || *text == '-' || !value || value > SIZE_MAX) return 2;
                if (is_batch) batch = value;
                else work = value;
            } else { usage(argv[0]); return 2; }
        }
        char error[256] = {0};
        if (latc_tbplan_write(argv[2], argv[3], argv[4], static_input, batch, work,
                              error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (!strcmp(argv[1], "list-tbplan")) {
        if (argc != 4) { usage(argv[0]); return 2; }
        char error[256] = {0};
        if (latc_tbplan_list(argv[2], argv[3], error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (!strcmp(argv[1], "validate-tbplan-module")) {
        if (argc != 5) { usage(argv[0]); return 2; }
        char error[256] = {0};
        if (latc_tbplan_validate_module(argv[2], argv[3], argv[4], error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "emit-static-tbset") == 0) {
        const char *input = argv[2];
        const char *output = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                output = argv[++i];
            } else {
                usage(argv[0]);
                return 2;
            }
        }
        if (!output) {
            usage(argv[0]);
            return 2;
        }
        return emit_static_tbset(input, output);
    }
    if (strcmp(argv[1], "compile") == 0) {
        const char *input = argv[2], *output = NULL, *runner = NULL;
        const char *tbset = NULL;
        const char *aot = NULL;
        int tbset_ignore_outside_exec = 0;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) output = argv[++i];
            else if (strcmp(argv[i], "--runner") == 0 && i + 1 < argc) runner = argv[++i];
            else if (strcmp(argv[i], "--tbset") == 0 && i + 1 < argc) tbset = argv[++i];
            else if (strcmp(argv[i], "--tbset-ignore-outside-exec") == 0)
                tbset_ignore_outside_exec = 1;
            else if (strcmp(argv[i], "--aot") == 0 && i + 1 < argc) aot = argv[++i];
            else { usage(argv[0]); return 2; }
        }
        if (!output || !runner) { usage(argv[0]); return 2; }
        return compile_bundle(input, output, runner, tbset,
                              tbset_ignore_outside_exec, aot);
    }
    if (strcmp(argv[1], "compile-module") == 0) {
        const char *input = argv[2];
        const char *output = NULL;
        const char *runner = getenv("LATC_AOT_RUNNER");
        const char *runtime_dir = getenv("LATC_AOT_RUNTIME_DIR");
        const char *tbset = NULL;
        bool static_tbset = false;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                output = argv[++i];
            } else if (strcmp(argv[i], "--runner") == 0 && i + 1 < argc) {
                runner = argv[++i];
            } else if (strcmp(argv[i], "--runtime-dir") == 0 &&
                       i + 1 < argc) {
                runtime_dir = argv[++i];
            } else if (strcmp(argv[i], "--tbset") == 0 && i + 1 < argc) {
                tbset = argv[++i];
            } else if (strcmp(argv[i], "--static-tbset") == 0) {
                static_tbset = true;
            } else {
                usage(argv[0]);
                return 2;
            }
        }
        if (!output || !runner || !*runner || !runtime_dir || !*runtime_dir ||
            (static_tbset && !tbset)) {
            usage(argv[0]);
            return 2;
        }
        return compile_module(input, output, runner, runtime_dir, tbset,
                              static_tbset);
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
    if (strcmp(argv[1], "inspect-native") == 0) {
        int json = 0;
        const char *path = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0) json = 1;
            else if (!path) path = argv[i];
            else { usage(argv[0]); return 2; }
        }
        if (!path) { usage(argv[0]); return 2; }
        return inspect_native(path, json);
    }
    if (strcmp(argv[1], "validate-replay-native") == 0) {
        gchar *image = NULL, *config = NULL;
        gsize image_size = 0, config_size = 0;
        char error[256] = {0};
        if (argc != 4) { usage(argv[0]); return 2; }
        bool valid = g_file_get_contents(argv[2], &image, &image_size, NULL) &&
            g_file_get_contents(argv[3], &config, &config_size, NULL) &&
            !lat_native_image_validate(image, image_size, error, sizeof(error));
        if (valid) {
            const LatNativeImageHeaderV2 *header = (const void *)image;
            valid = (header->flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED) &&
                header->translation_config_size == config_size &&
                config_size <= image_size &&
                !memcmp(image + image_size - config_size, config, config_size);
        }
        g_free(image);
        g_free(config);
        if (!valid) {
            fprintf(stderr, "latc: invalid or mismatched replay native%s%s\n",
                    error[0] ? ": " : "", error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "inspect-module") == 0) {
        int json = 0;
        const char *path = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0) {
                json = 1;
            } else if (!path) {
                path = argv[i];
            } else {
                usage(argv[0]);
                return 2;
            }
        }
        if (!path) {
            usage(argv[0]);
            return 2;
        }
        return inspect_module(path, json);
    }
    if (strcmp(argv[1], "validate-module-replacement") == 0) {
        char error[256] = {0};
        if (argc != 4) {
            usage(argv[0]);
            return 2;
        }
        if (lat_aot_v2_module_validate_replacement_file(
                argv[2], argv[3], error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "emit-module-tbset") == 0) {
        char error[256] = {0};
        LatAotModuleInfoV2 info;
        LatTbKeySet keys = {0};
        if (argc != 5 || strcmp(argv[3], "-o")) {
            usage(argv[0]);
            return 2;
        }
        if (lat_aot_v2_module_read_tbset_file(
                argv[2], &info, &keys, error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        int fd = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        int result = fd < 0 ? -1 : lat_tb_key_set_write_fd(
            fd, &keys, error, sizeof(error));
        if (fd < 0) {
            snprintf(error, sizeof(error), "cannot create TB set: %s",
                     strerror(errno));
        }
        if (fd >= 0 && close(fd) && !result) {
            snprintf(error, sizeof(error), "cannot close TB set: %s",
                     strerror(errno));
            result = -1;
        }
        lat_tb_key_set_destroy(&keys);
        if (result) {
            if (fd >= 0) {
                unlink(argv[4]);
            }
            fprintf(stderr, "latc: %s\n", error);
        }
        return result ? 1 : 0;
    }
    if (strcmp(argv[1], "missing-module-tbset") == 0) {
        if (argc != 6 || strcmp(argv[4], "-o")) {
            usage(argv[0]);
            return 2;
        }
        return missing_module_tbset(argv[2], argv[3], argv[5]);
    }
    if (!strcmp(argv[1], "validate-native-base")) {
        if (argc != 4) { usage(argv[0]); return 2; }
        char error[256] = {0};
        LatAotModuleInfoV2 info;
        LatNativeImageHeaderV2 header;
        uint8_t codegen[32];
        lat_aot_v2_codegen_digest(LATC_BUILD_ID, codegen);
        if (lat_aot_v2_module_inspect_file(argv[2], &info, error, sizeof(error)) ||
            lat_native_image_inspect_file(argv[3], &header, error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        if (memcmp(info.note.source_sha256, header.guest_sha256, 32) ||
            memcmp(info.note.codegen_id, codegen, 32) ||
            strcmp(header.lat_build_id, LATC_BUILD_ID)) {
            fprintf(stderr, "latc: native base source or codegen mismatch\n");
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "mark-native-x86") == 0) {
        char error[256] = {0};
        if (argc != 3) { usage(argv[0]); return 2; }
        if (lat_native_image_mark_x86_static_file(argv[2], error,
                                                  sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "plan-native-tus") == 0) {
        if (argc != 6 || strcmp(argv[4], "-o")) { usage(argv[0]); return 2; }
        return plan_native_tus(argv[2], argv[3], argv[5], false, false);
    }
    if (strcmp(argv[1], "plan-native-config") == 0) {
        if (argc != 6 || strcmp(argv[4], "-o")) { usage(argv[0]); return 2; }
        return plan_native_tus(argv[2], argv[3], argv[5], true, false);
    }
    if (strcmp(argv[1], "extract-native-tus") == 0) {
        if (argc != 6 || strcmp(argv[4], "-o")) { usage(argv[0]); return 2; }
        return plan_native_tus(argv[2], argv[3], argv[5], false, true);
    }
    if (!strcmp(argv[1], "audit-native-tu-references") ||
        !strcmp(argv[1], "audit-native-tu-execution")) {
        if (argc != 3) { usage(argv[0]); return 2; }
        g_autofree char *data = NULL;
        gsize size;
        GError *gerror = NULL;
        char error[256] = {0};
        LatNativeTuReferenceAudit audit;
        LatNativeTuExecutionAudit execution;
        if (!g_file_get_contents(argv[2], &data, &size, &gerror)) {
            fprintf(stderr, "latc: %s\n", gerror->message);
            g_clear_error(&gerror);
            return 1;
        }
        if (!strcmp(argv[1], "audit-native-tu-execution")) {
            if (lat_native_tu_audit_execution(data, size, &execution, error, sizeof(error))) {
                fprintf(stderr, "latc: %s\n", error);
                return 1;
            }
            printf("entries=%" PRIu64 "\nreachable_words=%" PRIu64
                   "\nrecorded_transfers=%" PRIu64 "\nlocal_transfers=%" PRIu64
                   "\nhelper_calls=%" PRIu64 "\ndispatch_windows=%" PRIu64
                   "\nmovement_certified=false\n", execution.entries,
                   execution.reachable_words, execution.recorded_transfers,
                   execution.local_transfers, execution.helper_calls,
                   execution.dispatch_windows);
            return 0;
        }
        if (lat_native_tu_audit_references(data, size, &audit, error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        printf("instructions=%" PRIu64 "\npatch_windows=%" PRIu64
               "\nlocal_branches=%" PRIu64 "\nlocal_addresses=%" PRIu64
               "\nmovement_certified=false\n", audit.instructions,
               audit.patch_windows, audit.local_branches, audit.local_addresses);
        return 0;
    }
    if (strcmp(argv[1], "merge-native") == 0) {
        const char *output = NULL;
        char error[256] = {0};
        if (argc == 6 && !strcmp(argv[4], "-o")) output = argv[5];
        if (!output) { usage(argv[0]); return 2; }
        if (lat_native_image_merge_files(argv[2], argv[3], output,
                                         error, sizeof(error))) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "split-tbset") == 0) {
        if (argc != 5) {
            usage(argv[0]);
            return 2;
        }
        return split_tbset(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "emit-aot-v2") == 0) {
        char error[256] = {0};
        if (argc < 4 || argc > 6) {
            usage(argv[0]);
            return 2;
        }
        int result;
        if (argc == 4) {
            result = lat_aot_v2_emit_module_sources(
                argv[2], argv[3], error, sizeof(error));
        } else {
            CfgProgram program;
            CfgAnalyzeOptions options = {.resolve_jump_tables = true};
            uint8_t digest[32];
            if (cfg_analyze_elf(argv[4], &options, &program,
                                error, sizeof(error)) ||
                (argc == 5 && file_digest(argv[4], digest,
                                          error, sizeof(error)))) {
                fprintf(stderr, "latc: %s\n", error);
                return 1;
            }
            if (argc == 6) {
                size_t matched, unmatched, ignored;
                if (latc_tbset_apply(argv[5], argv[4], &program, true,
                                     &matched, &unmatched, &ignored, digest,
                                     error, sizeof(error))) {
                    fprintf(stderr, "latc: %s\n", error);
                    cfg_program_destroy(&program);
                    return 1;
                }
            }
            result = lat_aot_v2_emit_module_sources_with_cfg(
                argv[2], argv[3], &program, digest, error, sizeof(error));
            cfg_program_destroy(&program);
        }
        if (result) {
            fprintf(stderr, "latc: %s\n", error);
            return 1;
        }
        printf("output_directory=%s\n", argv[3]);
        return 0;
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
