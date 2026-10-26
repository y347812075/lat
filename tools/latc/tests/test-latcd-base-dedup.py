#!/usr/bin/env python3
"""End-to-end incremental publication with a content-bound native/module pair."""

import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time


def main():
    prefix, guest, work = map(lambda p: Path(p).resolve(), sys.argv[1:4])
    work.mkdir(mode=0o700)
    runtime = prefix/'lib'
    latc, latcd, runner = [prefix/'bin'/name for name in ('latc', 'latcd', 'latx-x86_64')]
    env = {**os.environ, 'TMPDIR': str(work), 'LATCD_COMPILE_TMPDIR': str(work),
           'LD_LIBRARY_PATH': str(runtime), 'LATC_TBSET_SELECTION': 'exact-static'}
    for name in ('LATC_NATIVE_BASE', 'LATC_NATIVE_BASE_MODULE', 'LATC_NATIVE_OUTPUT'):
        env.pop(name, None)
    commands = []

    def run(args, extra=None):
        args = list(map(str, args))
        result = subprocess.run(args, env={**env, **(extra or {})}, capture_output=True, text=True)
        index = len(commands)
        (work/f'{index:02d}.stdout').write_text(result.stdout)
        (work/f'{index:02d}.stderr').write_text(result.stderr)
        commands.append({'command': args, 'environment': extra or {}, 'exit_code': result.returncode})
        (work/'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert result.returncode == 0, commands[-1] | {'stderr': result.stderr}

    run([latc, 'emit-static-tbset', guest, '-o', work/'all.tbset'])
    run([latc, 'split-tbset', work/'all.tbset', work/'left.tbset', work/'right.tbset'])
    run([latc, 'compile-module', guest, '-o', work/'base.so', '--runner', runner,
         '--runtime-dir', runtime, '--tbset', work/'left.tbset', '--static-tbset'],
        {'LATC_NATIVE_OUTPUT': str(work/'base.native')})
    sha = hashlib.sha256(guest.read_bytes()).hexdigest()
    cache = work/'cache'
    cache.mkdir()
    module_name, native_name, tbset_name = [sha+'-base'+suffix for suffix in ('.so', '.native', '.tbset')]
    for source, name in (('base.so', module_name), ('base.native', native_name), ('left.tbset', tbset_name)):
        (cache/name).write_bytes((work/source).read_bytes())
        (cache/name).chmod(0o444)
    note = json.loads(subprocess.check_output([latc, 'inspect-module', '--json', cache/module_name], env=env))
    # This controlled test seeds a genuine compile pair; product creates these
    # hashes only at successful publication, never by upgrading a historical hit.
    old = {'version': 2, 'module': module_name, 'native': native_name, 'tbset': tbset_name,
           'source_sha256': sha, 'codegen_id': note['codegen_id'], 'published_sequence': 1,
           'module_sha256': hashlib.sha256((cache/module_name).read_bytes()).hexdigest(),
           'native_sha256': hashlib.sha256((cache/native_name).read_bytes()).hexdigest()}
    manifest = cache/(sha+'.current')
    manifest.write_text(json.dumps(old, separators=(',', ':')) + '\n')
    manifest.chmod(0o444)
    wrapper = work/'record-latc'
    wrapper.write_text(f'''#!/usr/bin/env python3
import json, os, pathlib, sys
if sys.argv[1] == 'compile-module':
    module = os.environ.get('LATC_NATIVE_BASE_MODULE')
    native = os.environ.get('LATC_NATIVE_BASE')
    assert module and native
    with open({str(work/'worker-pair.jsonl')!r}, 'a') as out:
        out.write(json.dumps(dict(module=module,native=native)) + '\\n')
os.execv({str(latc)!r}, [{str(latc)!r}, *sys.argv[1:]])
''')
    wrapper.chmod(0o700)
    socket = work/'latcd.sock'
    daemon_args = list(map(str, [latcd, '--serve', '--socket', socket, '--cache-dir', cache,
        '--latc', wrapper, '--runner', runner, '--runtime-dir', runtime,
        '--workers', '1', '--flush-only', '--stats', work/'stats.json']))
    out = (work/'daemon.stdout').open('w')
    err = (work/'daemon.stderr').open('w')
    daemon = subprocess.Popen(daemon_args, env={**env, 'LATC_TBSET_SELECTION': 'bounded'}, stdout=out, stderr=err)
    (work/'daemon-command.json').write_text(json.dumps(daemon_args, indent=2) + '\n')
    try:
        deadline = time.monotonic() + 20
        while not socket.exists():
            assert daemon.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        run([latcd, '--submit', '--socket', socket, '--tbset', work/'all.tbset', guest])
        run([latcd, '--flush-source', '--socket', socket, guest])
    finally:
        if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
        assert daemon.wait(timeout=30) == 0
        out.close()
        err.close()
    current = json.loads(manifest.read_text())
    assert current['module'] != old['module']
    for kind in ('module', 'native'):
        assert hashlib.sha256((cache/current[kind]).read_bytes()).hexdigest() == current[kind+'_sha256']
    assert len((work/'worker-pair.jsonl').read_text().splitlines()) == 1
    assert 'retrying full compile' not in (work/'daemon.stderr').read_text()
    run([latc, 'validate-module-replacement', work/'base.so', cache/current['module']])
    run([latc, 'missing-module-tbset', cache/current['module'], work/'all.tbset', '-o', work/'missing.tbset'])
    assert struct.unpack('<8sII32sQQ', (work/'missing.tbset').read_bytes())[4] == 0
    run([runner, guest], {'LATX_AOT': '0', 'LATX_AOT_V2': '1',
        'LATX_AOT_V2_AUTOSTART': '0', 'LATC_STRICT_FILE_AOT': '1',
        'LATC_DISABLE_PRETRANSLATE': '1', 'LATX_AOT_V2_REPORT': '1',
        'LATX_AOT_V2_CACHE_DIR': str(cache)})
    import re
    strict = (work/f'{len(commands)-1:02d}.stderr').read_text()
    for field in ('file_dispatch_misses', 'compiler_submissions',
                  'compiler_submission_failures', 'jit_fallbacks'):
        values = re.findall(rf'\b{field}=(\d+)', strict)
        assert values and all(int(value) == 0 for value in values), (field, values)
    assert sum(map(int, re.findall(r'\baot_lookups=(\d+)', strict))) > 0
    assert not re.search(r'(?i)reject|strict.*miss', strict)
    print('test-latcd-base-dedup: PASS')


if __name__ == '__main__':
    main()
