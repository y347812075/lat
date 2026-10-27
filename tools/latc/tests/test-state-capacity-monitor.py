#!/usr/bin/env python3
"""Installed daemon detects external persistent state writes in isolated caches."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'), LATCD_COMPILE_TMPDIR=str(work))
    latcd = prefix / 'bin/latcd'
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    keys = work / 'keys.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)

    for kind in ('current', 'tbsets', 'identities'):
        case = work / kind
        case.mkdir(mode=0o700)
        cache, socket, stats = case / 'cache', case / 'socket', case / 'stats.json'
        command = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                   '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                   '--runtime-dir', str(prefix / 'lib'), '--stats', str(stats)]
        with (case / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while not socket.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                for operation, extra in (('submit', ['--tbset', str(keys)]), ('flush-source', [])):
                    result = subprocess.run([str(latcd), '--' + operation, '--socket', str(socket),
                                             *extra, str(guest)], env=env, capture_output=True, timeout=120)
                    (case / (operation + '.log')).write_bytes(result.stdout + result.stderr)
                    assert result.returncode == 0, result.stdout
                deadline = time.monotonic() + 10
                while True:
                    value = json.loads(stats.read_bytes())
                    if value['compiled'] == 1 and not value['active_jobs']:
                        break
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                assert value['generation_capacity_ready'], value
                manifest = cache / (source + '.current')
                original = manifest.read_bytes()
                target = manifest if kind == 'current' else next((cache / ('.' + kind)).iterdir())
                # Keep format, size and permissions unchanged: inode modification
                # events must detect this even without namespace replacement.
                mode = target.stat().st_mode & 0o777
                target.chmod(0o600)
                try:
                    with target.open('r+b') as stream:
                        first = stream.read(1)
                        stream.seek(0)
                        stream.write(first)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    target.chmod(mode)
                deadline = time.monotonic() + 10
                while True:
                    value = json.loads(stats.read_bytes())
                    if not value['generation_capacity_ready']:
                        break
                    assert daemon.poll() is None and time.monotonic() < deadline, value
                    time.sleep(.02)
                other = case / 'other.elf'
                shutil.copyfile(guest, other)
                with other.open('ab') as stream:
                    stream.write(b'new-source')
                other_keys = case / 'other.tbset'
                subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                                str(other), str(other_keys)], env=env, check=True)
                result = subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                         '--tbset', str(other_keys), str(other)],
                                        env=env, capture_output=True, timeout=30)
                (case / 'rejected.log').write_bytes(result.stdout + result.stderr)
                assert result.returncode != 0 and b'capacity:' in result.stdout
                assert b'accepted_sequence=0\n' in result.stdout
                assert manifest.read_bytes() == original
                assert not value['automatic_deletion_enabled']
            finally:
                if daemon.poll() is None:
                    daemon.terminate()
                assert daemon.wait(timeout=20) == 0
        print(kind + ': external state change closes admission PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-state-capacity-monitor.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
