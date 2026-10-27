#!/usr/bin/env python3
"""Verify installed daemon exit handoff; never enables cache deletion."""

import configparser
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'), LATCD_COMPILE_TMPDIR=str(work))
    latcd = prefix / 'bin/latcd'
    keys = work / 'keys.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)
    full = work / 'full.tbset'
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest), '-o', str(full)],
                   env=env, check=True)
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    for mode in ('idle', 'stop'):
        case = work / mode
        case.mkdir(mode=0o700)
        cache, socket = case / 'cache', case / 'socket'
        args = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                '--runtime-dir', str(prefix / 'lib'), '--idle-seconds', '2' if mode == 'idle' else '0']
        previous_manifest = None
        retained = None
        for iteration in range(2):
            with (case / f'daemon-{iteration}.log').open('wb') as log:
                daemon = subprocess.Popen(args, env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while not socket.is_socket():
                        assert daemon.poll() is None and time.monotonic() < deadline
                        time.sleep(.01)
                    for operation, extra in (('submit', ['--tbset', str(keys)]), ('flush-source', [])):
                        result = subprocess.run([str(latcd), '--' + operation, '--socket', str(socket),
                                                 *extra, str(guest)], env=env, capture_output=True, timeout=120)
                        (case / f'{operation}-{iteration}.log').write_bytes(result.stdout + result.stderr)
                        assert result.returncode == 0, result.stdout + result.stderr
                    if iteration == 0:
                        for operation, extra in (('submit', ['--tbset', str(full)]), ('flush-source', [])):
                            result = subprocess.run([str(latcd), '--' + operation, '--socket', str(socket),
                                                     *extra, str(guest)], env=env, capture_output=True, timeout=120)
                            (case / f'{operation}-replacement.log').write_bytes(result.stdout + result.stderr)
                            assert result.returncode == 0, result.stdout + result.stderr
                    manifest = (cache / (source + '.current')).read_bytes()
                    if previous_manifest is not None:
                        assert manifest == previous_manifest
                    previous_manifest = manifest
                    if mode == 'stop':
                        daemon.terminate()
                    assert daemon.wait(timeout=30) == 0
                finally:
                    if daemon.poll() is None:
                        daemon.kill()
                        daemon.wait()
            record = configparser.ConfigParser(interpolation=None, strict=True)
            record.read(cache / '.gc/retirement-handoff.ini')
            value = record['handoff']
            assert value['version'] == '1' and value['reason'] == mode.upper()
            assert value['state'] == 'PENDING_RESCAN'
            assert not value.getboolean('unattended_gc_guaranteed')
            assert not value.getboolean('automatic_deletion_enabled')
            st = cache.stat()
            assert (value.getint('cache_device'), value.getint('cache_inode')) == (st.st_dev, st.st_ino)
            assert value['boot'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            assert value.getint('recorded_boottime_us') > 0
            assert value.getint('known_candidates') > 0, 'fixture must produce a replacement generation'
            objects = {}
            for transaction in (cache / '.gc/transactions').glob('*.ini'):
                tx = configparser.ConfigParser(interpolation=None, strict=True)
                tx.read(transaction)
                evidence = configparser.ConfigParser(interpolation=None, strict=True)
                evidence.read_string(base64.b64decode(tx['transaction']['objects']).decode())
                for i in range(evidence.getint('objects', 'count')):
                    name = evidence[f'object{i}']['name']
                    objects[name] = hashlib.sha256((cache / name).read_bytes()).hexdigest()
            if retained is not None:
                assert objects == retained
            retained = objects
            assert (cache / '.gc/retirement-scheduler.ini').is_file()
            assert 'no unattended GC guarantee' in (case / f'daemon-{iteration}.log').read_text()
    print('retirement exit handoff idle/stop/restart: PASS')


if __name__ == '__main__':
    run(*(Path(arg).resolve() for arg in sys.argv[1:]))
