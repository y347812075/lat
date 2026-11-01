#!/usr/bin/env python3
"""Check real exported TU dependencies under both values of CVT_OPT."""

import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys


def main():
    prefix, guest, keys, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    root = Path(__file__).resolve().parents[3]
    schema = (root / 'tools/latc/aot-v2/include/lat-translation-config.h').read_text()
    fields = re.findall(r'\bX\([A-Z0-9_]+, ([a-z0-9_]+)\)', schema)
    cvt = 1 << fields.index('cvt_opt')
    all_bits = (1 << (len(fields) + 1)) - 1
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAT', 'SAVE_XMM'))}
    env.update(HOME=str(work), TMPDIR=str(work), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATC_AOT_THREADS='1', LATC_TBSET_SELECTION='exact')
    records = []

    def run(args, extra=None):
        args = list(map(str, args))
        result = subprocess.run(args, env=env | (extra or {}), capture_output=True,
                                text=True, timeout=180)
        index = len(records)
        (work / f'{index}.stdout').write_text(result.stdout)
        (work / f'{index}.stderr').write_text(result.stderr)
        records.append(dict(command=args, environment=extra or {}, rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert result.returncode == 0, records[-1] | dict(stderr=result.stderr)

    def masks(path):
        data = path.read_bytes()
        assert struct.unpack_from('<II', data, 8) == (11, 280)
        offset, count = struct.unpack_from('<QQ', data, 120)
        units = list(struct.iter_unpack('<3Q2IQ2I', data[offset:offset + count * 48]))
        assert len(units) >= 2, 'fixture must include independent CVT and non-CVT TUs'
        assert all(u[6:] == (1, 0) for u in units), units
        assert all(u[5] in (all_bits, all_bits & ~cvt) for u in units), units
        assert {bool(u[5] & cvt) for u in units} == {False, True}, 'no independent TU'
        table, ntb = struct.unpack_from('<QQ', data, 72)
        return {struct.unpack_from('<Q', data, table + i * 56)[0]:
                units[struct.unpack_from('<I', data, table + i * 56 + 48)[0]][5]
                for i in range(ntb)}

    baseline = None
    cvt_entry = struct.unpack_from('<Q', guest.read_bytes(), 24)[0]
    expected = json.loads(Path(sys.argv[5]).read_text()) if len(sys.argv) > 5 else None
    for option in (0, 1):
        snapshot = work / f'config-{option}'
        run([prefix / 'bin/latx-x86_64', '--latc-translation-config-native',
             '--latc-translation-config-out', snapshot, guest],
            {'LATX_AOT_V2': '1', 'LATX_CVT_OPT': str(option)})
        for threads in (1, 2):
            output = work / f'{option}-{threads}.native'
            run([prefix / 'libexec/latc/scripts/compile-aot.sh', prefix / 'bin/latc',
                 prefix / 'bin/latx-x86_64', guest, work / 'unused', keys],
                {'LATX_CVT_OPT': str(1 - option), 'LATC_AOT_THREADS': str(threads),
                 'LATC_TRANSLATION_CONFIG_FROM': str(snapshot),
                 'LATC_COMPILE_TIMING': '1',
                 'LATC_NATIVE_IMAGE_OUT': str(output)})
            if threads == 2 and expected is not None:
                log = (work / f'{len(records) - 1}.stderr').read_text()
                workers = re.findall(r'AOT worker (\d+) tbs=(\d+)', log)
                assert {int(i) for i, count in workers if int(count)} == {0, 1}, log
            run([prefix / 'bin/latc', 'inspect-native', output])
            current = masks(output)
            assert current[cvt_entry] & cvt, 'CVT-reading entry must be dependent'
            if expected is not None:
                assert set(current) == {int(pc) for pc in expected}, current
                assert all(bool(current[int(pc)] & cvt) == value
                           for pc, value in expected.items()), current
            if baseline is None:
                baseline = current
            assert current == baseline, (baseline, current)
    # Any new direct read must be audited before preserving CVT-independent units.
    for source in (root / 'target/i386/latx').rglob('*'):
        if source.suffix in ('.c', '.h') and source.name not in (
                'latx-options.h', 'latx-options.c', 'latx-translation-config.c'):
            assert 'option_cvt_opt' not in source.read_text(), source
    for source in (root / 'target/i386/latx/translator').rglob('*.c'):
        text = source.read_text()
        for option in ('option_set_rounding_opt', 'option_vpaes', 'option_fast_atomic',
                       'option_enable_lasx'):
            assert option not in text, (source, option)
    print('real TU configuration dependency export passed')


if __name__ == '__main__':
    main()
