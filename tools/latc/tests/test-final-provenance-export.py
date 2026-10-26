#!/usr/bin/env python3
"""Verify final numeric source positions in a real shared-TU native export."""

import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from tb_key_set import read_key_set


def main():
    prefix, guest, keys, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAT', 'SAVE_XMM'))}
    env.update(HOME=str(work), TMPDIR=str(work), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATX_AOT_V2='0', LATX_SOFTFPU='0', LATC_AOT_THREADS='1',
               LATC_TBSET_SELECTION='exact')
    records = []
    _, _, requested = read_key_set(keys)

    def run(args, extra=None):
        args = list(map(str, args))
        result = subprocess.run(args, env=env | (extra or {}), capture_output=True,
                                text=True, timeout=180)
        i = len(records)
        (work / f'{i}.stdout').write_text(result.stdout)
        (work / f'{i}.stderr').write_text(result.stderr)
        records.append(dict(command=args, environment=extra or {}, rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert result.returncode == 0, records[-1] | dict(stderr=result.stderr)
        return result

    assembly = re.compile(r'provenance-stage=tb-assembly pc=(0x[0-9a-f]+) '
                          r'offset=(\d+) word=(0x[0-9a-f]+) origin=(\S+) certified=0')
    final = re.compile(r'provenance-stage=native-final pc=(0x[0-9a-f]+) '
                       r'offset=(\d+) code_offset=(\d+) word=(0x[0-9a-f]+) '
                       r'origin=(\S+) certified=0')
    jit = run([prefix / 'bin/latx-x86_64', guest], {'LATC_TRACE_PROVENANCE': '1'})
    assert not final.findall(jit.stderr)
    bundle = work / 'cfg-bundle'
    builder = Path(sys.argv[5]).resolve()
    run([builder, guest, prefix / 'bin/latx-x86_64', bundle])
    normalized = []
    summaries = []
    for trace in ('0', '1', 'invalid'):
        native = work / f'{trace}.native'
        result = run([bundle],
                     {'LATC_NATIVE_IMAGE_OUT': str(native), 'LATC_TRACE_PROVENANCE': trace,
                      'LATC_EMIT_AOT': '1', 'LATX_AOT': '1',
                      'LATC_NAMED_GUEST': str(work / 'named-guest')})
        run([prefix / 'bin/latc', 'audit-native-tu-execution', native])
        data = native.read_bytes()
        code, size, tb, count, rel, nrel, _, _, tu, ntu = struct.unpack_from('<10Q', data, 56)
        tbs = list(struct.iter_unpack('<QQIII2HI2HIII4x', data[tb:tb+count*56]))
        assert {(t[0], t[3]) for t in tbs} == set(requested)
        tus = list(struct.iter_unpack('<QQQIIQII', data[tu:tu+ntu*48]))
        shared = [i for i in range(ntu) if sum(t[-1] == i for t in tbs) > 1]
        assert count >= 3 and shared, (count, ntu, tbs)
        rows = final.findall(result.stderr)
        early = assembly.findall(result.stderr)
        if trace != '1':
            assert not rows and not early
        else:
            moves = re.findall(r'provenance-stage=tu-stub-layout pc=0x[0-9a-f]+ '
                               r'old_offset=(\d+) new_offset=(\d+) certified=0', result.stderr)
            assert moves and any(old != new for old, new in moves), moves
            expected = [(int(pc, 16), int(word, 16)) for pc, off, word, origin in early
                        if origin == 'numeric-bits']
            assert len(rows) >= 6 and len(rows) == len(expected), (rows, expected)
            assert all(origin == 'numeric-bits' for *_, origin in rows), rows
            assert [(int(pc, 16), int(word, 16)) for pc, off, site, word, origin in rows] == expected
            # ET_DYN is translated at a synthetic guest bias; match the unique
            # numeric-bearing TB by RVA using the fixture's ELF symbol.
            symbols = subprocess.check_output(['nm', '-n', str(guest)], text=True)
            wait_pc = int(next(line.split()[0] for line in symbols.splitlines()
                               if line.split()[-1] == 'provenance_wait'), 16)
            wait = next(t for t in tbs if t[0] == wait_pc)
            assert wait[-1] in shared
            for pc, off, site, word, origin in rows:
                off, site, word = int(off), int(site), int(word, 16)
                assert site == wait[1] + off
                assert struct.unpack_from('<I', data, code+site)[0] == word
                unit = tus[wait[-1]]
                assert unit[0] <= site and site+4 <= unit[2]
                for i in range(nrel):
                    patch, _, _, _, slots = struct.unpack_from('<QqIII', data, rel+i*64)
                    assert not patch <= site < patch+slots*4
            summaries.append(dict(tb_count=count, tu_count=ntu, shared_tus=shared,
                                  moved_stubs=len(moves), final_numeric_words=len(rows),
                                  certified=False))
        clean = bytearray(data[code:code+size])
        for i in range(nrel):
            site, _, _, _, slots = struct.unpack_from('<QqIII', data, rel+i*64)
            clean[site:site+slots*4] = bytes(slots*4)
        normalized.append(clean)
    assert normalized[0] == normalized[1] == normalized[2]
    (work / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    print('test-final-provenance-export: PASS shared-TU/final-positions/words/trace-neutral')


if __name__ == '__main__':
    main()
