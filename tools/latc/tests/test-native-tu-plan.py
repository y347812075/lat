#!/usr/bin/env python3
"""Exercise installed TU planning on a native image from real translation."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def main():
    latc, native, keys, work = map(lambda p: Path(p).resolve(), sys.argv[1:5])
    work.mkdir()
    records = []

    def run(args, success=True):
        result = subprocess.run(list(map(str, args)), capture_output=True,
                                text=True, timeout=60)
        i = len(records)
        (work / f'{i}.stdout').write_text(result.stdout)
        (work / f'{i}.stderr').write_text(result.stderr)
        records.append({'command': list(map(str, args)), 'rc': result.returncode})
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert (result.returncode == 0) == success, records[-1] | {'stderr': result.stderr}
        return result

    original = keys.read_bytes()
    output = work / 'plan.tbset'
    run([latc, 'plan-native-tus', native, keys, '-o', output])
    data = output.read_bytes()
    assert data[:48] == original[:48] and data[56:64] == original[56:64]
    expected = set(struct.iter_unpack('<QII', original[64:]))
    actual = set(struct.iter_unpack('<QII', data[64:]))
    assert expected <= actual and len(actual) == struct.unpack_from('<Q', data, 48)[0]
    if len(sys.argv) > 5:
        assert len(actual) == int(sys.argv[5])
    for path in (output, work / 'symlink', work / 'fifo', work):
        if path.name == 'symlink':
            path.symlink_to(output)
        elif path.name == 'fifo':
            os.mkfifo(path)
        run([latc, 'plan-native-tus', native, keys, '-o', path], False)
    assert output.read_bytes() == data
    for label, mutate in (
        ('source', lambda b: b.__setitem__(16, b[16] ^ 1)),
        ('missing', lambda b: struct.pack_into('<Q', b, 64, 0xffffffffff)),
    ):
        altered = bytearray(original)
        mutate(altered)
        path = work / f'{label}.tbset'
        path.write_bytes(altered)
        rejected = work / f'{label}.out'
        run([latc, 'plan-native-tus', native, path, '-o', rejected], False)
        assert not rejected.exists()
    empty = bytearray(original[:64])
    struct.pack_into('<Q', empty, 48, 0)
    path = work / 'empty.tbset'
    path.write_bytes(empty)
    run([latc, 'plan-native-tus', native, path, '-o', work / 'empty.out'])
    assert (work / 'empty.out').read_bytes() == empty
    # Use the same build's ordinary export: the replay snapshot independently
    # binds the build and would reject first, hiding the CLI identity check.
    altered = bytearray((native.parent / '0-False.native').read_bytes())
    altered[184] ^= 1  # Native build identity, not code or configuration metadata.
    path = work / 'bad-build.native'
    path.write_bytes(altered)
    rejected = work / 'bad-build.out'
    result = run([latc, 'plan-native-tus', path, keys, '-o', rejected], False)
    assert 'codegen identity mismatch' in result.stderr
    assert not rejected.exists()
    print('test-native-tu-plan-cli: PASS real-native/empty/source/build/output')


if __name__ == '__main__':
    main()
