#!/usr/bin/env python3
"""Real native/module reuse, exact delta inputs and strict execution."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys


HEADER = struct.Struct('<8sII32sQQ')
KEY = struct.Struct('<QII')


def main():
    prefix, guest, work = map(lambda p: Path(p).resolve(), sys.argv[1:4])
    work.mkdir()
    latc = prefix/'bin/latc'
    runner = prefix/'bin/latx-x86_64'
    runtime = prefix/'lib'
    env = {**os.environ, 'TMPDIR': str(work), 'LATC_AOT_THREADS': '8',
           'LD_LIBRARY_PATH': str(runtime), 'LATC_TBSET_SELECTION': 'exact-static'}
    for key in ('LATC_NATIVE_BASE', 'LATC_NATIVE_BASE_MODULE', 'LATC_NATIVE_OUTPUT'):
        env.pop(key, None)
    commands = []

    def run(args, extra=None, success=True):
        args = list(map(str, args))
        result = subprocess.run(args, env={**env, **(extra or {})},
                                capture_output=True, text=True)
        number = len(commands)
        (work/f'{number:02d}.stdout').write_text(result.stdout)
        (work/f'{number:02d}.stderr').write_text(result.stderr)
        commands.append({'command': args, 'environment': extra or {},
                         'exit_code': result.returncode})
        (work/'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert (result.returncode == 0) == success, commands[-1] | {'stderr': result.stderr}
        return result

    requested = work/'requested.tbset'
    run([latc, 'emit-static-tbset', guest, '-o', requested])
    run([latc, 'split-tbset', requested, work/'left.tbset', work/'right.tbset'])
    run([latc, 'compile-module', guest, '-o', work/'base.so', '--runner', runner,
         '--runtime-dir', runtime, '--tbset', work/'left.tbset', '--static-tbset'],
        {'LATC_NATIVE_OUTPUT': str(work/'base.native')})
    run([latc, 'emit-module-tbset', work/'base.so', '-o', work/'base.actual'])
    script = prefix/'libexec/latc/scripts/compile-aot-v2-module.sh'
    # The wrapper observes actual product compile requests, not a fake compiler.
    wrapper = work/'record-latc'
    wrapper.write_text('''#!/usr/bin/env python3
import json, os, pathlib, struct, sys
a = sys.argv[1:]
with open(os.environ['ACTION_LOG'], 'a') as log:
    log.write(a[0] + '\\n')
if a[0] == 'validate-tbplan-module' and os.environ.get('BREAK_PLAN_MODULE'):
    pathlib.Path(a[3]).unlink()
    pathlib.Path(a[3]).write_bytes(pathlib.Path(os.environ['BREAK_PLAN_MODULE']).read_bytes())
if a[0] == 'compile':
    source = pathlib.Path(a[a.index('--tbset') + 1]).read_bytes()
    keys = list(struct.iter_unpack('<QII', source[64:]))
    base = pathlib.Path(os.environ['BASE_ACTUAL']).read_bytes()
    covered = set(struct.iter_unpack('<QII', base[64:]))
    assert keys and not covered.intersection(keys), (covered, keys)
    with open(os.environ['COMPILE_LOG'], 'a') as log:
        log.write(json.dumps(keys) + '\\n')
os.execv(os.environ['REAL_LATC'], [os.environ['REAL_LATC'], *a])
''')
    wrapper.chmod(0o700)
    observed = {'REAL_LATC': str(latc), 'BASE_ACTUAL': str(work/'base.actual'),
                'COMPILE_LOG': str(work/'compiled.jsonl'),
                'ACTION_LOG': str(work/'actions.log'),
                'LATC_TBSET_SELECTION': 'bounded',
                'LATC_NATIVE_BASE_MODULE': str(work/'base.so'),
                'LATC_NATIVE_BASE': str(work/'base.native')}
    run([script, '--static-tbset', wrapper, runner, guest, runtime,
         work/'mixed.so', requested], observed | {
             'LATC_NATIVE_OUTPUT': str(work/'mixed.native')})
    translated = [tuple(key) for line in (work/'compiled.jsonl').read_text().splitlines()
                  for key in json.loads(line)]
    assert translated and len(translated) == len(set(translated))
    actions = (work/'actions.log').read_text().splitlines()
    assert actions.count('merge-native') == 1, actions
    assert actions.count('validate-tbplan-module') == 1, actions
    assert actions.count('validate-module-replacement') == 1, actions
    run([latc, 'validate-module-replacement', work/'base.so', work/'mixed.so'])
    run([latc, 'missing-module-tbset', work/'mixed.so', requested,
         '-o', work/'mixed.missing'])
    assert HEADER.unpack((work/'mixed.missing').read_bytes())[4] == 0
    run([latc, 'emit-module-tbset', work/'mixed.so', '-o', work/'mixed.actual'])
    before = (work/'compiled.jsonl').read_bytes()
    (work/'actions.log').write_text('')
    run([script, '--static-tbset', wrapper, runner, guest, runtime,
         work/'empty.so', requested], observed | {
             'LATC_NATIVE_BASE_MODULE': str(work/'mixed.so'),
             'LATC_NATIVE_BASE': str(work/'mixed.native'),
             'LATC_NATIVE_OUTPUT': str(work/'empty.native'),
             'BASE_ACTUAL': str(work/'mixed.actual')})
    assert before == (work/'compiled.jsonl').read_bytes(), 'all-covered plan compiled again'
    assert (work/'empty.native').read_bytes() == (work/'mixed.native').read_bytes()
    actions = (work/'actions.log').read_text().splitlines()
    assert 'compile' not in actions and 'merge-native' not in actions, actions
    assert actions.count('validate-tbplan-module') == 1, actions
    assert actions.count('validate-module-replacement') == 1, actions
    run([script, '--static-tbset', wrapper, runner, guest, runtime,
         work/'broken.so', requested], observed | {
             'BREAK_PLAN_MODULE': str(work/'base.so')}, success=False)
    assert not (work/'broken.so').exists(), 'full-plan failure left output module'
    run([latc, 'validate-native-base', work/'mixed.so', work/'base.native'])
    # Equal source/build is not a content pairing proof: only daemon snapshots
    # establish that contract. The header check is deliberately weaker.
    run([runner, guest], {'LATX_AOT': '0', 'LATX_AOT_V2': '1',
        'LATX_AOT_V2_AUTOSTART': '0', 'LATC_STRICT_FILE_AOT': '1',
        'LATC_DISABLE_PRETRANSLATE': '1', 'LATX_AOT_V2_MODULE': str(work/'mixed.so'),
        'LATX_AOT_V2_SOURCE': str(guest), 'LATX_AOT_V2_REPORT': '1'})
    strict = (work/f'{len(commands)-1:02d}.stderr').read_text()
    import re
    for field in ('file_dispatch_misses', 'compiler_submissions',
                  'compiler_submission_failures', 'jit_fallbacks'):
        values = re.findall(rf'\b{field}=(\d+)', strict)
        assert values and all(int(value) == 0 for value in values), (field, values)
    lookups = sum(map(int, re.findall(r'\baot_lookups=(\d+)', strict)))
    direct = sum(map(int, re.findall(r'\bdirect_targets=(\d+)', strict)))
    assert 'registered module with' in strict and lookups + direct > 0
    assert not re.search(r'(?i)reject|strict.*miss', strict)
    print('test-aot-v2-base-dedup: PASS, translated unique delta keys=', len(translated))


if __name__ == '__main__':
    main()
