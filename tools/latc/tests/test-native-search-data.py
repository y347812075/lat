#!/usr/bin/env python3
"""Execute native TU search-data stripping against synthetic AOT records."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[3]
    source = (root / "target/i386/latx/sbt/latc_native_export.c").read_text()
    begin = source.index("typedef struct NativeTuRange {")
    end = source.index("static gint compare_native_tu_range", begin)
    strip_begin = source.index("static int strip_process_local_search_data(")
    strip_end = source.index("\nint latc_native_export(", strip_begin)
    lookup_begin = source.index("static int native_tu_index_for_offset(")
    lookup_end = source.index("\nstatic int extract_native_pc_maps(", lookup_begin)
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#define CONFIG_LATX_TU 1
#define IS_TU_TB 1
typedef struct {
    unsigned is_first_tb, offset_in_tu, bool_flags;
    uint64_t tb_cache_offset, tb_cache_size, tu_size, tu_search_addr_offset;
} aot_tb;
typedef struct { uint64_t code_offset, code_size; } LatNativeTuV1;
'''
    checks = r'''
int main(void)
{
    uint8_t code[32];
    aot_tb tbs[] = {
        { .is_first_tb = 1, .tb_cache_offset = 64, .tb_cache_size = 16,
          .tu_size = 16 },
        { .is_first_tb = 1, .bool_flags = IS_TU_TB,
          .tb_cache_offset = 80, .tb_cache_size = 16, .tu_size = 16,
          .tu_search_addr_offset = 8 },
    };
    memset(code, 0xa5, sizeof(code));
    assert(!strip_process_local_search_data(code, sizeof(code), tbs, 2, 64));
    for (unsigned i = 0; i < 24; i++) assert(code[i] == 0xa5);
    for (unsigned i = 24; i < 32; i++) assert(code[i] == 0);
    tbs[0].tu_search_addr_offset = 17;
    assert(strip_process_local_search_data(code, sizeof(code), tbs, 2, 64));
    GArray *tus = g_array_new(FALSE, FALSE, sizeof(LatNativeTuV1));
    assert(native_tu_index_for_offset(tus, 0) == -1);
    const LatNativeTuV1 entries[] = {{4, 8}, {16, 4}, {24, 8}};
    g_array_append_vals(tus, entries, G_N_ELEMENTS(entries));
    for (unsigned offset = 0; offset <= 32; offset++) {
        int expected = -1;
        for (unsigned i = 0; i < G_N_ELEMENTS(entries); i++) {
            if (offset >= entries[i].code_offset &&
                offset - entries[i].code_offset < entries[i].code_size)
                expected = i;
        }
        assert(native_tu_index_for_offset(tus, offset) == expected);
    }
    assert(native_tu_index_for_offset(tus, UINT64_MAX) == -1);
    g_array_free(tus, TRUE);
    return 0;
}
'''
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True))
    with tempfile.TemporaryDirectory(prefix="latc-native-search-") as temp:
        path = Path(temp)
        (path / "test.c").write_text(
            harness + source[begin:end] + source[strip_begin:strip_end] +
            source[lookup_begin:lookup_end] + checks)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu99", "-Wall", "-Wextra", "-Werror", str(path / "test.c"),
            "-o", str(path / "test"), *flags,
        ], check=True)
        subprocess.run([str(path / "test")], check=True)
    print("test-native-search-data: PASS")


if __name__ == "__main__":
    main()
