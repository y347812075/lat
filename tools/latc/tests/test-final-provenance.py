#!/usr/bin/env python3
"""Exercise the actual stub remapper and final native provenance checker."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
translator = (root / 'target/i386/latx/translator/translate.c').read_text()
remap = translator[translator.index('void tr_provenance_move_stub('):
                   translator.index('\nvoid tr_init(')]
exporter = (root / 'target/i386/latx/sbt/latc_native_export.c').read_text()
final = exporter[exporter.index('static void trace_final_numeric_words('):
                 exporter.index('\nint latc_native_export(')]
harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
typedef struct { uint32_t offset, word; } TrNumericWord;
typedef struct { GArray *numeric_provenance_words; } TranslationBlock;
typedef struct { int unused; } aot_header;
typedef struct { struct { uint64_t seg_begin; } details; } aot_segment;
typedef struct { uint64_t tb_cache_offset, offset_in_segment; } aot_tb;
typedef struct { uint64_t code_offset, search_offset; } LatNativeTuV1;
typedef struct { uint64_t code_offset; uint32_t slots; } LatNativeRelocationV1;
static const aot_segment *find_tb_segment(const aot_header *h,
    const aot_segment *s, const aot_tb *t) { (void)h; (void)t; return s; }
static int native_tu_index_for_offset(const GArray *tus, uint64_t off)
{
    for (guint i=0; i<tus->len; i++) {
        const LatNativeTuV1 *tu=&g_array_index(tus, LatNativeTuV1, i);
        if (off>=tu->code_offset && off<tu->search_offset) return i;
    }
    return -1;
}
'''
checks = r'''
int main(void)
{
    TranslationBlock tb={0};
    tr_provenance_move_stub(&tb, 8, 24);
    tb.numeric_provenance_words=g_array_new(FALSE,FALSE,sizeof(TrNumericWord));
    TrNumericWord records[]={{4,0x11111111},{8,0x22222222},{12,0x33333333}};
    g_array_append_vals(tb.numeric_provenance_words,records,3);
    tr_provenance_move_stub(&tb,8,24);
    assert(g_array_index(tb.numeric_provenance_words,TrNumericWord,0).offset==4);
    assert(g_array_index(tb.numeric_provenance_words,TrNumericWord,1).offset==24);
    assert(g_array_index(tb.numeric_provenance_words,TrNumericWord,2).offset==28);
    const GArray *owners[]={tb.numeric_provenance_words,NULL};
    aot_header h={0}; aot_segment segment={{0x5500000000}};
    aot_tb tbs[]={{64,0x1000},{80,0x1010}};
    uint32_t words[10]={0};
    words[1]=records[0].word; words[6]=records[1].word; words[7]=records[2].word;
    GArray *tus=g_array_new(FALSE,FALSE,sizeof(LatNativeTuV1));
    GArray *rels=g_array_new(FALSE,FALSE,sizeof(LatNativeRelocationV1));
    LatNativeTuV1 tu={0,32}; g_array_append_val(tus,tu);
    unsetenv("LATC_TRACE_PROVENANCE");
    trace_final_numeric_words(&h,&segment,tbs,2,owners,tus,rels,(void *)words,40,64);
    setenv("LATC_TRACE_PROVENANCE","invalid",1);
    trace_final_numeric_words(&h,&segment,tbs,2,owners,tus,rels,(void *)words,40,64);
    setenv("LATC_TRACE_PROVENANCE","1",1);
    trace_final_numeric_words(&h,&segment,tbs,2,NULL,tus,rels,(void *)words,40,64);
    trace_final_numeric_words(&h,&segment,tbs,2,owners,tus,rels,(void *)words,40,64);
    words[6]++;
    LatNativeRelocationV1 rel={24,2}; g_array_append_val(rels,rel);
    trace_final_numeric_words(&h,&segment,tbs,2,owners,tus,rels,(void *)words,40,64);
    g_array_index(tb.numeric_provenance_words,TrNumericWord,0).offset=UINT32_MAX;
    trace_final_numeric_words(&h,&segment,tbs,2,owners,tus,rels,(void *)words,40,64);
    tr_provenance_move_stub(&tb,0,4);
    assert(!tb.numeric_provenance_words);
    g_array_unref(tus); g_array_unref(rels);
    return 0;
}
'''
flags = shlex.split(subprocess.check_output(
    ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True))
with tempfile.TemporaryDirectory(prefix='latc-final-provenance-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(harness + remap + final + checks)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(path / 'test.c'),
        '-o', str(path / 'test'), *flags], check=True)
    output = subprocess.run([str(path / 'test')], check=True, capture_output=True,
                            text=True)
    rows = output.stderr.splitlines()
    assert len(rows) == 9, rows
    assert all('provenance-stage=native-final' in r and 'certified=0' in r for r in rows)
    assert all('origin=numeric-bits' in r for r in rows[:3])
    assert 'offset=24 code_offset=24' in rows[1]
    assert 'offset=28 code_offset=28' in rows[2]
    assert ['origin=unknown' in r for r in rows[3:]] == [False, True, True, True, True, True]
print('test-final-provenance: PASS stub-remap/overflow/final-word/patch/default-unknown')
