#!/usr/bin/env python3
"""Verify native WAIT embeds float values, not exporter-process pointers."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def main():
    prefix, guest, keys, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAT', 'SAVE_XMM'))}
    env.update(HOME=str(work), TMPDIR=str(work), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATX_AOT_V2='0', LATX_SOFTFPU='0', LATC_AOT_THREADS='1',
               LATC_TBSET_SELECTION='exact')
    records = []

    def run(args, extra=None):
        result = subprocess.run(list(map(str, args)), env=env | (extra or {}),
                                capture_output=True, timeout=120)
        i = len(records)
        (work / f'{i}.stdout').write_bytes(result.stdout)
        (work / f'{i}.stderr').write_bytes(result.stderr)
        records.append(dict(command=list(map(str, args)), environment=extra or {},
                            rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert result.returncode == 0, records[-1] | dict(stderr=result.stderr.decode())
        return result

    run([prefix / 'bin/latx-x86_64', guest])
    expected = [0x7f7fffff, struct.unpack('<I', struct.pack('<f', 1.0e32))[0],
                0x00800000, 0x40400000, 0x40000000, 0x40400000]
    normalized = []
    for attempt in range(2):
        native = work / f'{attempt}.native'
        run([prefix / 'libexec/latc/scripts/compile-aot.sh', prefix / 'bin/latc',
             prefix / 'bin/latx-x86_64', guest, work / 'unused', keys],
            {'LATC_NATIVE_IMAGE_OUT': str(native)})
        run([prefix / 'bin/latc', 'audit-native-tu-execution', native])
        data = native.read_bytes()
        code, size, tb, ntb, reloc, nr = struct.unpack_from('<6Q', data, 56)
        assert ntb == 1
        words = list(struct.unpack_from(f'<{size // 4}I', data, code))
        # The original implementation's FLD.S instructions dereference absolute
        # addresses; each replacement MOVGR2FR.W consumes a numeric constant.
        loads = [w for w in words if w & 0xffc00000 == 0x2b000000]
        assert not loads, f'WAIT retains {len(loads)} host-memory float loads'
        values = []
        registers = {}
        for word in words:
            rd, rj = word & 31, word >> 5 & 31
            if word & 0xfe000000 == 0x14000000:  # LU12I.W
                registers[rd] = (word >> 5 & 0xfffff) << 12
            elif word & 0xffc00000 == 0x03800000:  # ORI
                registers[rd] = registers.get(rj, 0) | (word >> 10 & 0xfff)
            elif word & 0xfffffc00 == 0x0114a400:  # MOVGR2FR.W
                values.append(registers[rj] & 0xffffffff)
        assert values == expected, (values, expected)
        clean = bytearray(data[code:code + size])
        for i in range(nr):
            site, _, _, _, slots = struct.unpack_from('<QqIII', data, reloc + i * 64)
            clean[site:site + slots * 4] = bytes(slots * 4)
        normalized.append(clean)
    assert normalized[0] == normalized[1], 'WAIT still depends on exporter process'
    print('test-fwait-constants: PASS numeric values/no host FLD.S/repeated export/JIT')


if __name__ == '__main__':
    main()
