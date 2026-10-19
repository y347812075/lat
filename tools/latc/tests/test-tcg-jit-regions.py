#!/usr/bin/env python3
"""Check JIT and exporter region policy using the canonical C functions."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[3]
    source = (root / "tcg/tcg.c").read_text()
    begin = source.index("unsigned int tcg_aot_thread_count(void)")
    end = source.index("\n#else", source.index("static size_t tcg_n_regions(void)", begin))
    functions = source[begin:end]
    harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
static unsigned int max_tcg_ctxs;
'''
    checks = r'''
int main(void)
{
    const char *counts[] = {"1", "2", "8", "32", "64", "0"};
    const unsigned int contexts[] = {1, 2, 8, 32, 32, 1};
    unsetenv("LATC_EMIT_AOT");
    unsetenv("LATC_AOT_THREADS");
    assert(tcg_n_regions() == 1 && max_tcg_ctxs == 1);
    for (unsigned int i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        setenv("LATC_AOT_THREADS", counts[i], 1);
        assert(tcg_n_regions() == 1 && max_tcg_ctxs == 1);
        setenv("LATC_EMIT_AOT", "1", 1);
        assert(tcg_n_regions() == contexts[i] * 2);
        assert(max_tcg_ctxs == contexts[i]);
        unsetenv("LATC_EMIT_AOT");
    }
    setenv("LATC_EMIT_AOT", "1", 1);
    unsetenv("LATC_AOT_THREADS");
    assert(tcg_n_regions() == max_tcg_ctxs * 2);
    assert(max_tcg_ctxs >= 1 && max_tcg_ctxs <= 8);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="latc-jit-regions-") as temp:
        path = Path(temp)
        (path / "test.c").write_text(harness + functions + checks)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu99", "-Wall", "-Wextra", "-Werror", str(path / "test.c"),
            "-o", str(path / "test"),
        ], check=True)
        subprocess.run([str(path / "test")], check=True)
    print("test-tcg-jit-regions: PASS")


if __name__ == "__main__":
    main()
