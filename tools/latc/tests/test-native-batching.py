#!/usr/bin/env python3
"""Exercise product split parsing and recursive compilation failure handling."""

import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


HEADER = struct.Struct('<8sII32sQQ')
KEY = struct.Struct('<QII')


def main():
    latc = str(Path(sys.argv[1]).resolve())
    script = str(Path(sys.argv[2]).resolve())
    with tempfile.TemporaryDirectory(prefix='latc-batching-') as temporary:
        work = Path(temporary)
        guest = work / 'guest'
        guest.write_bytes(b'guest')
        digest = hashlib.sha256(guest.read_bytes()).digest()
        keys = [(0x1000 + index * 16, 3, 0) for index in range(9)]
        source = work / 'input.tbset'
        source.write_bytes(HEADER.pack(b'LATTBKS\0', 1, 64, digest, 9, 17) +
                           b''.join(KEY.pack(*key) for key in keys))
        left, right = work / 'left', work / 'right'
        subprocess.run([latc, 'split-tbset', source, left, right], check=True)
        restored = []
        for path in (left, right):
            data = path.read_bytes()
            magic, version, size, sha, count, sequence = HEADER.unpack_from(data)
            assert (magic, version, size, sha, sequence) == (
                b'LATTBKS\0', 1, 64, digest, 17)
            part = list(KEY.iter_unpack(data[size:]))
            assert len(part) == count and part
            restored.extend(part)
        assert restored == keys
        for invalid in ('truncated', 'singleton', 'invalid-flags'):
            data = source.read_bytes()
            if invalid == 'truncated':
                data = data[:-1]
            elif invalid == 'singleton':
                data = HEADER.pack(b'LATTBKS\0', 1, 64, digest, 1, 0) + KEY.pack(*keys[0])
            else:
                data = data[:72] + struct.pack('<I', 1) + data[76:]
            path = work / invalid
            path.write_bytes(data)
            outputs = [work / (invalid + suffix) for suffix in ('.left', '.right')]
            result = subprocess.run([latc, 'split-tbset', path, *outputs],
                                    capture_output=True)
            assert result.returncode and not any(p.exists() for p in outputs)
        sentinel = work / 'sentinel'
        sentinel.write_text('keep')
        assert subprocess.run([latc, 'split-tbset', source, work / 'new', sentinel],
                              capture_output=True).returncode
        assert sentinel.read_text() == 'keep' and not (work / 'new').exists()

        fake = work / 'latc'
        fake.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, struct, subprocess, sys
a = sys.argv
command = a[1]
with open(os.environ['CALLS'], 'a') as log:
    log.write(command + '\n')
if command == 'plan-tbset':
    directory = pathlib.Path(a[4])
    directory.mkdir()
    data = pathlib.Path(a[3]).read_bytes()
    if os.environ.get('MULTI_PLAN'):
        header = list(struct.unpack_from('<8sII32sQQ', data))
        for i, record in enumerate(struct.iter_unpack('<QII', data[64:])):
            header[4] = 1
            (directory/f'required-{i:08d}.tbset').write_bytes(
                struct.pack('<8sII32sQQ', *header) + struct.pack('<QII', *record))
    else:
        (directory/'required-00000000.tbset').write_bytes(data)
    sys.exit(0)
elif command == 'list-tbplan':
    for path in sorted(pathlib.Path(a[3]).glob('*.tbset')):
        print('exact ' + path.name)
    sys.exit(0)
elif command == 'split-tbset':
    sys.exit(subprocess.run([os.environ['REAL_LATC'], *a[1:]]).returncode)
elif command == 'validate-native-base':
    sys.exit(1 if os.environ.get('PAIR_FAIL') else 0)
elif command == 'missing-module-tbset':
    if os.environ.get('DIFFERENCE_FAIL'): sys.exit(1)
    data = pathlib.Path(a[3]).read_bytes()
    header = list(struct.unpack_from('<8sII32sQQ', data))
    covered = set(json.loads(pathlib.Path(a[2]).read_text()))
    keys = [r for r in struct.iter_unpack('<QII', data[64:]) if r[0] not in covered]
    header[4] = len(keys)
    pathlib.Path(a[5]).write_bytes(struct.pack('<8sII32sQQ', *header) +
        b''.join(struct.pack('<QII', *r) for r in keys))
    print('missing_tb_keys=' + str(len(keys)))
    sys.exit(0)
if command == 'emit-static-tbset':
    pathlib.Path(a[4]).write_bytes(pathlib.Path(os.environ['INPUT']).read_bytes())
elif command == 'compile':
    if os.environ.get('EXPECT_EXACT_STATIC'):
        assert os.environ['LATC_TBSET_SELECTION'] == 'exact-static'
        assert os.environ['LATC_NATIVE_STATIC_CHECK'] == '1'
    data = pathlib.Path(a[a.index('--tbset') + 1]).read_bytes()
    keys = [r[0] for r in struct.iter_unpack('<QII', data[64:])]
    if os.environ.get('LATC_NATIVE_BASE_MODULE'):
        covered = set(json.loads(pathlib.Path(os.environ['LATC_NATIVE_BASE_MODULE']).read_text()))
        assert not covered.intersection(keys), (covered, keys)
    failure = int(os.environ.get('FAILURE', '0'))
    code = '#!/usr/bin/env python3\nimport json, os, pathlib, sys\n'
    code += 'keys=' + repr(keys) + '\n'
    code += 'status=' + str(failure) + ' or (75 if len(keys)>2 else 0)\n'
    code += 'p=pathlib.Path(os.environ["LATC_NATIVE_IMAGE_OUT"])\n'
    code += 'p.write_text(json.dumps(keys))\nsys.exit(status)\n'
    out = pathlib.Path(a[a.index('-o') + 1])
    out.write_text(code)
    out.chmod(0o700)
elif command == 'merge-native':
    if os.environ.get('MERGE_FAIL'):
        pathlib.Path(a[5]).write_text('partial')
        sys.exit(1)
    keys = sorted(set(json.loads(pathlib.Path(a[2]).read_text()) +
                      json.loads(pathlib.Path(a[3]).read_text())))
    pathlib.Path(a[5]).write_text(json.dumps(keys))
elif command in ('inspect-native', 'mark-native-x86'):
    pass
else:
    sys.exit(2)
''')
        fake.chmod(0o700)
        env = {**os.environ, 'REAL_LATC': latc, 'INPUT': str(source),
               'TMPDIR': str(work), 'CALLS': str(work / 'calls')}
        output = work / 'image'
        for mode in ('success', 'static', 'exact-static', 'multi-plan', 'ordinary-failure', 'merge-failure',
                     'singleton-exhaustion', 'nonmodule-exhaustion',
                     'paired-mixed', 'paired-empty', 'paired-difference-fail',
                     'paired-invalid', 'paired-merge-fail'):
            run_env = {**env}
            if mode == 'multi-plan': run_env['MULTI_PLAN'] = '1'
            paired = mode.startswith('paired-')
            if paired:
                import json
                covered = [key[0] for key in keys if mode == 'paired-empty' or
                           key[0] != keys[4][0]]
                base = work/'base.native'
                base.write_text(json.dumps(covered))
                run_env.update(LATC_NATIVE_BASE=str(base),
                    LATC_NATIVE_BASE_MODULE=str(base), MULTI_PLAN='1')
                if mode == 'paired-difference-fail': run_env['DIFFERENCE_FAIL'] = '1'
                if mode == 'paired-invalid': run_env['PAIR_FAIL'] = '1'
                if mode == 'paired-merge-fail': run_env['MERGE_FAIL'] = '1'
            if mode == 'exact-static':
                run_env.update(LATC_TBSET_SELECTION='exact-static',
                               EXPECT_EXACT_STATIC='1')
            if mode == 'ordinary-failure':
                run_env['FAILURE'] = '1'
            if mode == 'merge-failure':
                run_env['MERGE_FAIL'] = '1'
            if mode in ('singleton-exhaustion', 'nonmodule-exhaustion'):
                run_env['FAILURE'] = '75'
            (work / 'calls').write_text('')
            args = [script, '--module', fake, work / 'runner', guest, output]
            if mode == 'nonmodule-exhaustion':
                args.remove('--module')
            if mode != 'static':
                args.append(source)
            result = subprocess.run(args, env=run_env, capture_output=True)
            calls = (work / 'calls').read_text().splitlines()
            if mode in ('success', 'static', 'exact-static', 'multi-plan',
                        'paired-mixed', 'paired-empty'):
                import json
                assert result.returncode == 0, result.stderr
                assert json.loads(output.read_text()) == [key[0] for key in keys]
                if paired:
                    assert calls.count('compile') == (0 if mode == 'paired-empty' else 1)
                    assert calls.count('merge-native') == (0 if mode == 'paired-empty' else 1)
                    assert calls.count('missing-module-tbset') == 9
                else:
                    assert calls.count('split-tbset') == (0 if mode == 'multi-plan' else 4)
                    assert calls.count('merge-native') == (8 if mode == 'multi-plan' else 4)
            else:
                assert result.returncode and not output.exists()
                if mode == 'ordinary-failure':
                    assert calls == ['plan-tbset', 'list-tbplan', 'compile'], calls
                if mode == 'singleton-exhaustion':
                    assert calls.count('split-tbset') <= 4, calls
                if mode == 'nonmodule-exhaustion':
                    assert calls == ['compile'], calls
            assert not list(work.glob('latc-native.*'))
            assert not list(work.glob('latc-aot.*'))
    print('test-native-batching: PASS')


if __name__ == '__main__':
    main()
