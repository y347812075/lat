#!/usr/bin/env python3
"""Exercise the real exporter function with interior references and sharing."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / 'target/i386/latx/sbt/latc_native_export.c').read_text()
function = source[source.index('static int append_relocation('):
                  source.index('static void append_tu_relocations(')]
harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "lat-native-image.h"
typedef struct { int tc_offset, rel_slots_num, kind; int64_t extra_addend; } aot_rel;
typedef struct { uint32_t offset_in_segment, cflags; } aot_tb;
typedef struct { struct { uint64_t seg_begin; } details; } aot_segment;
typedef struct { int unused; } RelocationOffsetSet;
enum { LOAD_CALL_TARGET = 2 };
static uint8_t table[64];
static uint64_t align_up(uint64_t n, uint64_t a) { return (n + a - 1) & ~(a - 1); }
static const void *native_constant_table(int kind, size_t *size)
{ (void)kind; *size = sizeof(table); return table; }
static bool direct_tb_target(const aot_tb *t, const aot_segment *s, int k, uint64_t *p)
{ (void)t; (void)s; (void)k; (void)p; return false; }
static int runtime_symbol(int k) { (void)k; return LAT_NATIVE_SYMBOL_INVALID; }
static uint32_t native_semantic_flags(uint32_t f) { (void)f; return 3; }
static void append_native_relocation(GArray *out, RelocationOffsetSet *set, LatNativeRelocationV1 r)
{ (void)set; g_array_append_val(out, r); }
'''
checks = r'''
int main(void) {
    for (unsigned i=0; i<sizeof(table); i++) table[i] = i ^ 0xa5;
    GArray *out = g_array_new(FALSE, FALSE, sizeof(LatNativeRelocationV1));
    GByteArray *data = g_byte_array_new();
    GHashTable *offsets = g_hash_table_new(g_direct_hash, g_direct_equal);
    RelocationOffsetSet sites = {0};
    aot_tb tb = {0}; aot_segment seg = {0};
    aot_rel rel = {.kind=1, .rel_slots_num=3, .extra_addend=16};
    assert(!append_relocation(out, &sites, data, offsets, 128, &rel, &tb, 0, &seg, 0));
    rel.tc_offset=12; rel.extra_addend=48;
    assert(!append_relocation(out, &sites, data, offsets, 128, &rel, &tb, 0, &seg, 0));
    assert(out->len==2 && data->len==64 && !memcmp(data->data, table, 64));
    for (unsigned i=0; i<2; i++) {
        const LatNativeRelocationV1 *r=&g_array_index(out, LatNativeRelocationV1, i);
        assert(r->data_object_offset==128 && r->data_object_size==64);
        assert(r->data_object_alignment==32 && r->data_object_flags==LAT_NATIVE_DATA_POINTER_FREE);
        assert(r->addend==144+i*32 && r->reserved==48-i*32);
        assert(lat_native_data_object_valid(r, 192));
    }
    rel.extra_addend=64;
    assert(append_relocation(out, &sites, data, offsets, 128, &rel, &tb, 0, &seg, 0));
    rel.extra_addend=-1;
    assert(append_relocation(out, &sites, data, offsets, 128, &rel, &tb, 0, &seg, 0));
    assert(out->len==2 && data->len==64);
    g_hash_table_destroy(offsets); g_byte_array_unref(data); g_array_unref(out);
    return 0;
}
'''
flags = shlex.split(subprocess.check_output(
    ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True))
with tempfile.TemporaryDirectory(prefix='latc-constant-export-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(harness + function + checks)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-I',
        str(root / 'tools/latc/native/include'), str(path / 'test.c'),
        '-o', str(path / 'test'), *flags], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('test-native-constant-export: PASS interior/share/reject')
