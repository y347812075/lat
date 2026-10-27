#!/usr/bin/env python3
"""Verify guest close_range preserves the AOT module lifetime descriptor."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cache, socket = work / 'cache', work / 'latcd.sock'
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd, latc = prefix / 'bin/latcd', prefix / 'bin/latc'
    runner = prefix / 'bin/latx-x86_64'
    full = work / 'full.tbset'
    result = subprocess.run([str(latc), 'emit-static-tbset', str(guest), '-o', str(full)],
        env=env, capture_output=True, timeout=180)
    (work / 'static.log').write_bytes(result.stdout + result.stderr)
    assert result.returncode == 0
    command = [str(latcd), '--once', '--socket', str(socket), '--cache-dir', str(cache),
               '--latc', str(latc), '--runner', str(runner), '--runtime-dir', str(prefix / 'lib')]
    runner_process = None
    with (work / 'daemon.stdout').open('wb') as stdout, (work / 'daemon.stderr').open('wb') as stderr:
        daemon = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            result = subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                '--tbset', str(full), str(guest)], env=env, capture_output=True, timeout=180)
            (work / 'submit.client').write_bytes(result.stdout + result.stderr)
            assert result.returncode == 0
            assert daemon.wait(timeout=180) == 0
        finally:
            if daemon.poll() is None:
                daemon.kill()
                daemon.wait(timeout=10)
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    manifest = json.loads((cache / (source + '.current')).read_bytes())
    module = cache / manifest['module']
    assert module.is_file()
    guest_env = dict(env, LATX_AOT='0', LATX_AOT_V2_CACHE_DIR=str(cache),
        LATX_AOT_V2_AUTOSTART='0', LATX_AOT_V2_STRICT='1', LATX_AOT_V2_REPORT='1',
        LATC_DISABLE_PRETRANSLATE='1', LATC_STRICT_AOT='1')
    with (work / 'guest.stdout').open('wb') as guest_stdout, (work / 'guest.stderr').open('wb') as guest_stderr:
        runner_process = subprocess.Popen([str(runner), str(guest)], env=guest_env,
                                          stdout=guest_stdout, stderr=guest_stderr)
    try:
        deadline = time.monotonic() + 60
        output = work / 'guest.stdout'
        while b'CLOSED\n' not in output.read_bytes():
            assert runner_process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        assert b'module=registered' in (work / 'guest.stderr').read_bytes()
        with module.open('rb') as lease:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('close_range released the AOT module lifetime lease')
    finally:
        if runner_process.poll() is None:
            runner_process.terminate()
        assert runner_process.wait(timeout=30) is not None
    with module.open('rb') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lease, fcntl.LOCK_UN)
    print('test-cache-close-range: full-static/CLOEXEC/wide-close/lease PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-cache-close-range.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
