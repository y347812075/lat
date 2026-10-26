#!/usr/bin/env python3
"""Check the real WAIT constant emitter against memory loads on LoongArch."""

import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / 'target/i386/latx/translator/tr-fctrl.c').read_text()
function = source[source.index('static void load_wait_float('):
                  source.index('bool translate_wait(')]
harness = r'''
#include <assert.h>
#include <float.h>
#include <stdint.h>
#include <string.h>
typedef unsigned IR2_OPND;
static uint32_t emitted;
static uint64_t result;
static void li_numeric_wu(IR2_OPND reg, uint32_t value) { (void)reg; emitted = value; }
static void la_movgr2fr_w(IR2_OPND dest, IR2_OPND src) {
    (void)dest; (void)src;
    uint64_t dirty = UINT64_C(0x123456789abcdef0);
    __asm__ volatile("movgr2fr.d $f0, %1\n\tmovgr2fr.w $f0, %2\n\tmovfr2gr.d %0, $f0"
                     : "=r"(result) : "r"(dirty), "r"(emitted) : "$f0");
}
'''
checks = r'''
static void operation(const float *a, const float *b, int divide, unsigned rounding) {
    uint32_t av, bv;
    uint64_t old, actual, old_flags, actual_flags, saved, restored;
    uint64_t control = rounding << 8;
    memcpy(&av, a, 4); memcpy(&bv, b, 4);
    __asm__ volatile("movfcsr2gr %0, $fcsr0" : "=r"(saved));
    __asm__ volatile("movgr2fcsr $fcsr0, %2\n\tfld.s $f0, %0, 0\n\tfld.s $f1, %1, 0"
                     : : "r"(a), "r"(b), "r"(control) : "$f0", "$f1", "memory");
    if (divide) __asm__ volatile("fdiv.s $f2, $f0, $f1" : : : "$f2");
    else __asm__ volatile("fadd.s $f2, $f0, $f1" : : : "$f2");
    __asm__ volatile("movfr2gr.s %0, $f2\n\tmovfcsr2gr %1, $fcsr0"
                     : "=r"(old), "=r"(old_flags));
    __asm__ volatile("movgr2fcsr $fcsr0, %2\n\tmovgr2fr.w $f0, %0\n\tmovgr2fr.w $f1, %1"
                     : : "r"(av), "r"(bv), "r"(control) : "$f0", "$f1", "memory");
    if (divide) __asm__ volatile("fdiv.s $f2, $f0, $f1" : : : "$f2");
    else __asm__ volatile("fadd.s $f2, $f0, $f1" : : : "$f2");
    __asm__ volatile("movfr2gr.s %0, $f2\n\tmovfcsr2gr %1, $fcsr0"
                     : "=r"(actual), "=r"(actual_flags));
    __asm__ volatile("movgr2fcsr $fcsr0, %0" : : "r"(saved) : "memory");
    __asm__ volatile("movfcsr2gr %0, $fcsr0" : "=r"(restored));
    assert(restored == saved);
    assert((uint32_t)old == (uint32_t)actual && old_flags == actual_flags);
}
int main(void) {
    const float values[] = {FLT_MAX, 1.0e32f, FLT_MIN, 3.0f, 2.0f};
    const uint32_t bits[] = {0x7f7fffff, 0x749dc5ae, 0x00800000, 0x40400000, 0x40000000};
    for (unsigned i = 0; i < sizeof(values) / sizeof(*values); i++) {
        uint64_t old;
        load_wait_float(0, 0, values[i]);
        assert(emitted == bits[i]);
        __asm__ volatile("fld.s $f0, %1, 0\n\tmovfr2gr.d %0, $f0"
                         : "=r"(old) : "r"(&values[i]) : "$f0");
        assert((uint32_t)result == (uint32_t)old);
    }
    for (unsigned rounding = 0; rounding < 4; rounding++) {
        operation(&values[0], &values[1], 0, rounding);
        operation(&values[2], &values[3], 1, rounding);
        operation(&values[4], &values[3], 1, rounding);
    }
    return 0;
}
'''
if platform.machine() != 'loongarch64':
    print('test-fwait-constant-emitter: SKIP requires LoongArch64')
else:
    with tempfile.TemporaryDirectory(prefix='fwait-constant-emitter-') as temp:
        path = Path(temp)
        (path / 'test.c').write_text(harness + function + checks)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            str(path / 'test.c'), '-o', str(path / 'test')], check=True)
        subprocess.run([str(path / 'test')], check=True)
    print('test-fwait-constant-emitter: PASS bit-exact/single-precision-load-equivalent')
