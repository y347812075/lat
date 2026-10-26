#!/usr/bin/env python3
"""Exercise actual opt-in IR provenance snapshots, not a pointer-range scan."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / 'target/i386/latx/ir2/ir2.c').read_text()
functions = source[source.index('typedef struct Ir2NumericSnapshot {'):
                   source.index('/********************************************',
                                source.index('IR2_INST *ir2_allocate(void)'))]
harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
typedef int16_t int16;
typedef struct { int _type; uint32_t _val; } IR2_OPND;
typedef struct { int16 _opcode, _id; int op_count; IR2_OPND _opnd[4]; } IR2_INST;
typedef struct { GHashTable *numeric_provenance; IR2_INST *ir2_inst_array;
                 int ir2_inst_num_current, ir2_inst_num_max;
                 IR2_INST *first_ir2, *last_ir2; } TRANSLATION_DATA;
typedef uintptr_t ADDR;
static TRANSLATION_DATA state;
static struct { TRANSLATION_DATA *tr_data; } env = {&state}, *lsenv = &env;
#define lsassert assert
static int ir2_get_id(const IR2_INST *p) { return p->_id; }
static void ir2_set_id(IR2_INST *p, int id) { p->_id = id; }
static __attribute__((noinline)) void *mm_realloc(void *p, size_t n)
{ void *r=realloc(p,n); assert(r); return r; }
static void tr_init(void *tb) { (void)tb; abort(); }
'''
checks = r'''
int main(void) {
    IR2_INST code[3] = {
        { ._opcode=10, ._id=0, .op_count=2, ._opnd={{81,12},{86,0}} },
        { ._opcode=11, ._id=1, .op_count=3, ._opnd={{81,12},{81,12},{86,42}} },
        { ._opcode=12, ._id=2, .op_count=1, ._opnd={{81,12}} }
    };
    state.ir2_inst_array=code; state.ir2_inst_num_current=2;
    assert(!ir2_has_numeric_provenance(&code[0]));
    ir2_record_numeric_range(0);
    assert(!ir2_has_numeric_provenance(&code[0]));
    state.numeric_provenance=g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,g_free);
    ir2_record_numeric_range(0);
    assert(ir2_has_numeric_provenance(&code[0]));
    assert(ir2_has_numeric_provenance(&code[1]));
    assert(!ir2_has_numeric_provenance(&code[2]));
    code[1]._opnd[2]._val++;
    assert(!ir2_has_numeric_provenance(&code[1]));
    code[1]._opnd[2]._val--; code[1]._opnd[2]._type++;
    assert(!ir2_has_numeric_provenance(&code[1]));
    code[1]._opnd[2]._type--; code[1]._opcode++;
    assert(!ir2_has_numeric_provenance(&code[1]));
    code[1]._opcode--; code[1].op_count--;
    assert(!ir2_has_numeric_provenance(&code[1]));
    code[1].op_count++;
    IR2_INST moved[3];
    for (int i=0; i<3; i++) moved[i]=code[i];
    state.ir2_inst_array=moved;
    assert(ir2_has_numeric_provenance(&moved[1]));
    g_hash_table_remove_all(state.numeric_provenance);
    assert(!ir2_has_numeric_provenance(&moved[1]));
    state.ir2_inst_array=malloc(2*sizeof(IR2_INST));
    assert(state.ir2_inst_array);
    state.ir2_inst_array[0]=code[0]; state.ir2_inst_array[1]=code[1];
    state.ir2_inst_num_current=2; state.ir2_inst_num_max=2;
    state.first_ir2=&state.ir2_inst_array[0];
    state.last_ir2=&state.ir2_inst_array[1];
    ir2_record_numeric_range(0);
    IR2_INST *allocated=ir2_allocate();
    assert(allocated==&state.ir2_inst_array[2] && allocated->_id==2);
    assert(state.ir2_inst_num_max==4 && state.ir2_inst_num_current==3);
    assert(state.first_ir2==&state.ir2_inst_array[0]);
    assert(state.last_ir2==&state.ir2_inst_array[1]);
    assert(ir2_has_numeric_provenance(&state.ir2_inst_array[1]));
    state.ir2_inst_num_current=1;
    allocated=ir2_allocate();
    assert(allocated->_id==1 && !ir2_has_numeric_provenance(allocated));
    assert(ir2_has_numeric_provenance(&state.ir2_inst_array[0]));
    free(state.ir2_inst_array);
    g_hash_table_destroy(state.numeric_provenance);
    return 0;
}
'''
flags = shlex.split(subprocess.check_output(
    ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True))
with tempfile.TemporaryDirectory(prefix='latc-ir2-provenance-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(harness + functions + checks)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(path / 'test.c'),
        '-o', str(path / 'test'), *flags], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('test-ir2-provenance: PASS opt-in/unknown/snapshot/rewrite/reallocation/reset')
