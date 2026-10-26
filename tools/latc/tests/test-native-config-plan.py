#!/usr/bin/env python3
"""Verify configuration-derived TU plans against real codegen metadata."""

import json
import os
import resource
import signal
from pathlib import Path
import struct
import subprocess
import sys


def main():
    latc, exports, expected_path, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    expected = json.loads(expected_path.read_text())
    records = []

    def run(native, config, output, success=True, write_failure=False):
        args = list(map(str, [latc, 'plan-native-config', native, config, '-o', output]))
        def limit_output():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (8, 8))

        result = subprocess.run(args, capture_output=True, text=True, timeout=60,
                                preexec_fn=limit_output if write_failure else None)
        i = len(records)
        (work / f'{i}.stdout').write_text(result.stdout)
        (work / f'{i}.stderr').write_text(result.stderr)
        records.append(dict(command=args, rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert (result.returncode == 0) == success, result.stderr
        if not success:
            return
        data = output.read_bytes()
        assert struct.unpack_from('<8sII', data) == (b'LATTBKS\0', 1, 64)
        assert struct.unpack_from('<Q', data, 56)[0] == 0
        keys = list(struct.iter_unpack('<QII', data[64:]))
        assert len(keys) == struct.unpack_from('<Q', data, 48)[0]
        assert keys == sorted(set(keys))
        assert all(flags == 3 and reserved == 0 for _, flags, reserved in keys)
        return {pc for pc, _, _ in keys}

    for option in (0, 1):
        native = exports / f'{option}-2.native'
        raw = native.read_bytes()
        bias = struct.unpack_from('<Q', raw, 32)[0]
        for target in (0, 1):
            output = work / f'{option}-{target}.tbset'
            actual = run(native, exports / f'config-{target}', output)
            want = {int(pc) - bias for pc, uses in expected.items()
                    if uses and option != target}
            assert actual == want, (len(actual), len(want))
            assert output.read_bytes()[16:48] == raw[136:168]
        existing = work / f'{option}-0.tbset'
        before = existing.read_bytes()
        run(native, exports / 'config-0', existing, False)
        assert existing.read_bytes() == before
    config = bytearray((exports / 'config-0').read_bytes())
    for name, content in [('truncated', config[:-1]), ('corrupt', bytes(len(config))),
                          ('oversized', bytes(1025))]:
        path = work / name
        path.write_bytes(content)
        output = work / f'{name}.out'
        run(exports / '0-2.native', path, output, False)
        assert not output.exists()
    output = work / 'write-failure.out'
    run(exports / '0-2.native', exports / 'config-1', output, False, True)
    assert not output.exists()
    for name in ('fifo', 'symlink', 'directory'):
        path = work / name
        if name == 'fifo':
            os.mkfifo(path)
        elif name == 'symlink':
            path.symlink_to(exports / 'config-0')
        else:
            path.mkdir()
        output = work / f'{name}.out'
        run(exports / '0-2.native', path, output, False)
        assert not output.exists()
    print('real config-to-TU plans passed: exact changed keys and empty no-op')


if __name__ == '__main__':
    main()
