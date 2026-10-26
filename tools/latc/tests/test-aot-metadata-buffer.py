#!/usr/bin/env python3
"""Exercise real CFG bounds, metadata sizing and region exhaustion code."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def extract(path, start, end):
    text = path.read_text()
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def main():
    root = Path(__file__).resolve().parents[3]
    functions = extract(root / "linux-user/latc-bundle-loader.c",
                        "uint64_t latc_bundle_tb_count(void)",
                        "void latc_bundle_pretranslate(")
    functions += extract(root / "accel/tcg/translate-all.c",
                         "static size_t aot_tb_metadata_size(",
                         "/* Must be called before using the QEMU cpus.")
    functions += extract(root / "tcg/tcg.c",
                         "static bool tcg_region_alloc(TCGContext *s)",
                         "bool tcg_region_alloc_aot(")
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "latc-bundle-format.h"
#define CONFIG_USER_ONLY 1
#define CONFIG_LATX_TU 1
#define MAX_TB_IN_CACHE 510
#define TCG_HIGHWATER 1024
#define QEMU_ALIGN_UP(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define error_report(...) fprintf(stderr, __VA_ARGS__)
typedef struct { char data[248]; } TranslationBlock;
struct separated_data { char data[160]; };
typedef struct { size_t code_gen_buffer_size; } TCGContext;
static struct { int lock; size_t agg_size_full; } region;
static bool exhausted;
static void qemu_mutex_lock(int *p) { (void)p; }
static void qemu_mutex_unlock(int *p) { (void)p; }
static bool tcg_region_alloc__locked(TCGContext *s)
{ (void)s; return exhausted; }
static unsigned int threads = 8;
static unsigned int tcg_aot_thread_count(void) { return threads; }
static size_t qemu_icache_linesize = 64;
static int bundle_self_fd = 1;
static LatcDiskFooter bundle_footer;
static LatcDiskCfgHeader header;
static int read_cfg(void *p, size_t size, uint64_t offset)
{ assert(!offset && size == sizeof(header)); memcpy(p, &header, size); return 0; }
'''
    checks = r'''
static void expect_failure(unsigned which)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        switch (which) {
        case 0: header.tb_count = UINT64_MAX; latc_bundle_tb_count(); break;
        case 1: header.function_count = UINT64_MAX; latc_bundle_tb_count(); break;
        case 2: bundle_footer.cfg_size--; latc_bundle_tb_count(); break;
        case 3: header.version++; latc_bundle_tb_count(); break;
        case 4: {
            TCGContext ctx = {4096};
            exhausted = true;
            tcg_region_alloc(&ctx);
            break;
        }
        case 5:
            /* A valid synthetic count can still overflow allocation math. */
            header.tb_count = (UINT64_MAX - sizeof(header)) / sizeof(LatcDiskTb);
            header.function_count = header.exec_range_count = header.edge_count = 0;
            header.string_size = 0;
            bundle_footer.cfg_size = sizeof(header) + header.tb_count * sizeof(LatcDiskTb);
            aot_tb_metadata_size(4096);
            break;
        }
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == (which == 4 ?
           LATC_EXIT_CODE_BUFFER_EXHAUSTED : EXIT_FAILURE));
}
int main(void)
{
    memcpy(header.magic, LATC_CFG_MAGIC, 8);
    header.version = LATC_CFG_VERSION;
    header.record_size = sizeof(header);
    header.tb_count = 1575385;
    bundle_footer.cfg_size = sizeof(header) + header.tb_count * sizeof(LatcDiskTb);
    assert(latc_bundle_tb_count() == header.tb_count);
    unsetenv("LATC_EMIT_AOT");
    assert(aot_tb_metadata_size(4096) == 4096);
    TCGContext ctx = {4096};
    exhausted = true;
    assert(tcg_region_alloc(&ctx));
    setenv("LATC_EMIT_AOT", "1", 1);
    for (threads = 1; threads <= 32; threads++) {
        size_t size = aot_tb_metadata_size(4096);
        assert(size / (2 * threads) / 448 >=
               (header.tb_count + threads - 1) / threads + 2 * MAX_TB_IN_CACHE);
    }
    threads = 8;
    exhausted = false;
    assert(!tcg_region_alloc(&ctx));
    assert(region.agg_size_full == 4096 - TCG_HIGHWATER);
    for (unsigned i = 0; i < 6; i++) expect_failure(i);
    bundle_self_fd = -1;
    assert(latc_bundle_tb_count() == 0);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="latc-metadata-") as temp:
        path = Path(temp)
        (path / "test.c").write_text(harness + functions + checks)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu99", "-Wall", "-Wextra", "-Werror",
            "-I", str(root / "include"), str(path / "test.c"),
            "-o", str(path / "test"),
        ], check=True)
        subprocess.run([str(path / "test")], check=True)
    print("test-aot-metadata-buffer: PASS")


if __name__ == "__main__":
    main()
