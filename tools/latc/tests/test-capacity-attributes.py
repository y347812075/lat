#!/usr/bin/env python3
"""Attribute-only generation changes invalidate admission; cache hits do not touch it."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    keys = work / 'input.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)
    other = work / 'other.elf'
    other.write_bytes(guest.read_bytes() + b'distinct source identity')
    other.chmod(0o700)
    other_keys = work / 'other.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(other), str(other_keys)], env=env, check=True)
    for mutation in ('mode', 'hardlink', 'timestamp'):
        directory = work / mutation
        directory.mkdir(mode=0o700)
        cache, socket, stats = directory / 'cache', directory / 's', directory / 'stats.json'
        args = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                '--runtime-dir', str(prefix / 'lib'), '--workers', '1', '--stats', str(stats)]

        def client(operation, source, tbset, log):
            return subprocess.run([str(latcd), '--' + operation, '--socket', str(socket),
                *(['--tbset', str(tbset)] if tbset else []), str(source)], env=env,
                stdout=log, stderr=log, timeout=120)

        with (directory / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(args, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while not socket.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.01)
                assert client('submit', guest, keys, log).returncode == 0
                assert client('flush-source', guest, None, log).returncode == 0
                current = next(cache.glob('*.current'))
                original = current.read_bytes()
                module = cache / json.loads(original)['module']
                before = module.stat()
                # Existing-generation publication still succeeds and preserves
                # immutable object timestamps and capacity readiness.
                assert client('submit', guest, keys, log).returncode == 0
                assert client('flush-source', guest, None, log).returncode == 0
                after = module.stat()
                assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
                    after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
                deadline = time.monotonic() + 10
                while True:
                    observed = json.loads(stats.read_bytes())
                    if not observed['active_jobs']:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                assert observed['generation_capacity_ready'], observed
                compiled = observed['compiled']
                failed = observed['failed']
                if mutation == 'mode':
                    module.chmod(0o600)
                elif mutation == 'hardlink':
                    os.link(module, directory / 'outside-alias')
                else:
                    os.utime(module, ns=(after.st_atime_ns, 1_000_000_000))
                deadline = time.monotonic() + 10
                while True:
                    observed = json.loads(stats.read_bytes())
                    if not observed['generation_capacity_ready']:
                        break
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                assert current.read_bytes() == original
                assert client('submit', other, other_keys, log).returncode == 0
                # submit/flush ACK acceptance; the compiler result is reported
                # in response status and daemon stats, not this client exit code.
                client('flush-source', other, None, log)
                # Graceful stop drains accepted work before exposing the final
                # result, avoiding a race between flush ACK and worker stats.
                daemon.terminate()
                assert daemon.wait(timeout=30) == 0
                observed = json.loads(stats.read_bytes())
                assert not observed['active_jobs'], observed
                assert not observed['generation_capacity_ready'], observed
                assert observed['compiled'] == compiled, observed
                assert observed['failed'] >= failed, observed
                assert current.read_bytes() == original
                assert not (cache / (hashlib.sha256(other.read_bytes()).hexdigest() + '.current')).exists()
                assert not observed['automatic_deletion_enabled']
                (directory / 'observations.json').write_text(json.dumps(observed, indent=2))
            finally:
                if daemon.poll() is None:
                    daemon.terminate()
                    assert daemon.wait(timeout=30) == 0
    print('test-capacity-attributes: chmod/external-hardlink/timestamp/cache-hit PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-capacity-attributes.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
