#!/usr/bin/env python3
"""Hold a captured module across a real incremental publication."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from tb_key_set import read_key_set, write_key_set


def main(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cache, sock = work / 'cache', work / 'socket'
    latcd, latc, runner = (prefix / 'bin' / name for name in ('latcd', 'latc', 'latx-x86_64'))
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'))
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    initial, middle, full = (work / (name + '.tbset') for name in ('initial', 'middle', 'full'))
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(initial)], check=True, env=env)
    subprocess.run([str(latc), 'emit-static-tbset', str(guest), '-o', str(full)], check=True, env=env)
    assert set(read_key_set(initial)[2]) < set(read_key_set(full)[2])
    symbols = subprocess.check_output(['readelf', '-sW', str(guest)], text=True)
    extra = next(int(line.split()[1], 16) for line in symbols.splitlines()
                 if line.split() and line.split()[-1] == 'extra_entry')
    segments = subprocess.check_output(['readelf', '-lW', str(guest)], text=True)
    bases = [int(line.split()[2], 16) for line in segments.splitlines()
             if line.strip().startswith('LOAD')]
    extra_key = (extra - min(bases), 3)
    assert extra_key in set(read_key_set(full)[2])
    write_key_set(guest, middle, set(read_key_set(initial)[2]) | {extra_key})
    args = [str(latcd), '--once', '--socket', str(sock), '--cache-dir', str(cache),
            '--latc', str(latc), '--runner', str(runner), '--runtime-dir', str(prefix / 'lib')]

    def publish(tbset):
        with (work / (tbset.stem + '.log')).open('wb') as log:
            daemon = subprocess.Popen(args, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while not sock.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.01)
                subprocess.run([str(latcd), '--submit', '--socket', str(sock), '--tbset',
                                str(tbset), str(guest)], env=env, stdout=log, stderr=log,
                               check=True, timeout=120)
                assert daemon.wait(timeout=30) == 0
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait()

    publish(initial)
    manifest = cache / (source + '.current')
    old = json.loads(manifest.read_text())
    ready, release = work / 'ready', work / 'release'
    child_env = dict(env, LATX_AOT_V2_CACHE_DIR=str(cache), LATX_AOT_V2_AUTOSTART='0',
                     LATX_AOT_V2_STRICT='1', LATX_AOT_V2_REPORT='1',
                     LATC_DISABLE_PRETRANSLATE='1', LATC_STRICT_AOT='1',
                     LATX_AOT_V2_TEST_CAPTURE_READY=str(ready),
                     LATX_AOT_V2_TEST_CAPTURE_RELEASE=str(release))
    with (work / 'runner.log').open('wb') as log:
        child = subprocess.Popen([str(runner), str(guest)], env=child_env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not ready.exists():
                assert child.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            with (cache / '.gc/source-locks' / (source + '.lock')).open('rb') as latch:
                fcntl.flock(latch, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (cache / old['module']).open('rb') as module:
                try:
                    fcntl.flock(module, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    raise AssertionError('captured module not pinned')
                except BlockingIOError:
                    pass
            publish(middle)
            intermediate = json.loads(manifest.read_text())
            assert intermediate['module'] != old['module']
            publish(full)
            assert json.loads(manifest.read_text())['module'] not in (old['module'], intermediate['module'])
            release.touch()
            assert child.wait(timeout=30) == 42
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    assert 'module=registered' in (work / 'runner.log').read_text()
    print('test-capture-publish: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-capture-publish.py PREFIX X86_GUEST NEW_WORKDIR')
    main(*(Path(arg).resolve() for arg in sys.argv[1:]))
