#!/usr/bin/env python3
"""Keep ordinary reset offsets out of the native TU relocation table."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "target/i386/latx/sbt/latc_native_export.c").read_text()
begin = source.index("static void append_tu_relocations(")
end = source.index("static void append_jrra_relocation(", begin)
harness = r'''
#include <assert.h>
#include <stdint.h>
#include <glib.h>
#include "lat-native-image.h"
#define CONFIG_LATX_TU 1
#define IS_TU_JMP 0x40
typedef struct {
    uint16_t bool_flags;
    union { uint16_t jmp_reset_offset[2]; uint16_t tu_jmp[2]; };
    uint64_t lazypc[2];
    uint32_t cflags;
} aot_tb;
typedef struct { unsigned unused; } RelocationOffsetSet;
static int relocation_offset_contains(RelocationOffsetSet *set, uint64_t offset)
{ (void)set; (void)offset; return 0; }
static uint32_t native_semantic_flags(uint32_t flags)
{ (void)flags; return 3; }
static void append_native_relocation(GArray *output, RelocationOffsetSet *set,
                                     LatNativeRelocationV1 relocation)
{ (void)set; g_array_append_val(output, relocation); }
'''
checks = r'''
int main(void)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(LatNativeRelocationV1));
    RelocationOffsetSet offsets = {0};
    aot_tb tb = {.jmp_reset_offset = {18, UINT16_MAX}, .lazypc = {8, 0}};
    append_tu_relocations(out, &offsets, &tb, 64, 0x1000);
    assert(out->len == 0);
    tb.bool_flags = IS_TU_JMP;
    tb.tu_jmp[0] = 20;
    append_tu_relocations(out, &offsets, &tb, 64, 0x1000);
    assert(out->len == 1);
    const LatNativeRelocationV1 *rel = &g_array_index(out, LatNativeRelocationV1, 0);
    assert(rel->code_offset == 84 && rel->addend == 0x1008);
    assert(rel->kind == LAT_NATIVE_RELOC_TB_TARGET && rel->slots == 1);
    tb.tu_jmp[0] = UINT16_MAX;
    append_tu_relocations(out, &offsets, &tb, 64, 0x1000);
    assert(out->len == 1);
    g_array_free(out, TRUE);
    return 0;
}
'''
flags = shlex.split(subprocess.check_output(
    ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True))
with tempfile.TemporaryDirectory(prefix="latc-native-tu-") as temp:
    path = Path(temp)
    (path / "test.c").write_text(harness + source[begin:end] + checks)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu99", "-Wall", "-Wextra", "-Werror",
        "-I", str(root / "tools/latc/native/include"), str(path / "test.c"),
        "-o", str(path / "test"), *flags], check=True)
    subprocess.run([str(path / "test")], check=True)
print("test-native-tu-relocations: PASS")
