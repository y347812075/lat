#!/usr/bin/env python3
"""Exercise the real IR1 terminal predicate, including the KZT exception."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[3]
    text = (root / 'target/i386/latx/ir1/ir1.c').read_text()
    begin = text.index('bool ir1_is_terminal_trap(')
    end = text.index('\nbool ir1_is_tb_ending(', begin)
    source = text[begin:end]
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
enum { dt_X86_INS_INT3, dt_X86_INS_UD0, dt_X86_INS_UD1,
       dt_X86_INS_UD2, dt_X86_INS_INT, dt_X86_INS_CALL, dt_X86_INS_NOP };
typedef struct { int opcode; uintptr_t address; } IR1_INST;
#define ir1_opcode(i) ((i)->opcode)
#define ir1_addr(i) ((i)->address)
#ifdef CONFIG_LATX_KZT
static bool CODEIS64 = true, enabled, registered;
static bool latx_kzt_runtime_enabled(void) { return enabled; }
static bool kzt_is_registered_onebridge(uintptr_t p)
{ return registered && p == 123; }
#endif
'''
    checks = r'''
int main(void)
{
    IR1_INST insn = {.address = 123};
    for (int op = dt_X86_INS_INT3; op <= dt_X86_INS_NOP; op++) {
        insn.opcode = op;
        assert(ir1_is_terminal_trap(&insn) == (op <= dt_X86_INS_UD2));
    }
#ifdef CONFIG_LATX_KZT
    enabled = registered = true;
    insn.opcode = dt_X86_INS_INT3;
    assert(!ir1_is_terminal_trap(&insn));
    CODEIS64 = false;
    assert(ir1_is_terminal_trap(&insn));
    CODEIS64 = true;
    insn.address++;
    assert(ir1_is_terminal_trap(&insn));
    for (int op = dt_X86_INS_UD0; op <= dt_X86_INS_UD2; op++) {
        insn.opcode = op;
        assert(ir1_is_terminal_trap(&insn));
    }
#endif
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='latc-terminal-trap-') as temp:
        path = Path(temp)
        (path / 'test.c').write_text(harness + source + checks)
        for defines in ([], ['-DCONFIG_LATX_KZT=1']):
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
                '-std=gnu99', '-Wall', '-Wextra', '-Werror', *defines,
                str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)
    print('test-terminal-trap: PASS')


if __name__ == '__main__':
    main()
