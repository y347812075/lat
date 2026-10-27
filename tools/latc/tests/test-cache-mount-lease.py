#!/usr/bin/env python3
"""Exercise persistent controlled-mount leases through the latcd CLI."""

import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


def run(prefix, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    latcd = prefix / 'bin/latcd'
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))

    def hold(cache, lease_id, log):
        process = subprocess.Popen([str(latcd), 'gc', '--hold-mount-lease',
            '--cache-dir', str(cache), '--lease-id', lease_id, '--scope', 'CACHE'],
            env=env, stdout=log, stderr=log)
        record = cache / '.gc/mount-leases' / (lease_id + '.ini')
        deadline = time.monotonic() + 20
        while not record.exists() or 'state=ACTIVE' not in record.read_text():
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        return process, record

    def assert_exclusive(cache, expected):
        with (cache / '.gc/reference-roots.lock').open('rb') as root_lock:
            try:
                fcntl.flock(root_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                observed = False
            else:
                observed = True
                fcntl.flock(root_lock, fcntl.LOCK_UN)
            assert observed is expected

    cache = work / 'cache'
    cache.mkdir(mode=0o700)
    graceful_id = str(uuid.uuid4())
    with (work / 'graceful.log').open('wb') as log:
        process, record = hold(cache, graceful_id, log)
        assert_exclusive(cache, False)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=20) == 0
    assert 'state=RELEASED' in record.read_text()
    assert_exclusive(cache, True)

    crash_id = str(uuid.uuid4())
    with (work / 'crash.log').open('wb') as log:
        process, record = hold(cache, crash_id, log)
        process.kill()
        assert process.wait(timeout=20) == -signal.SIGKILL
    assert 'state=ACTIVE' in record.read_text()
    assert_exclusive(cache, True)
    plan = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
        env=env, capture_output=True, text=True, timeout=20)
    parsed = json.loads(plan.stdout)
    assert parsed['mount_lease_count'] == 2
    assert any(lease['state'] == 'ACTIVE' for lease in parsed['mount_leases'].values())
    released = subprocess.run([str(latcd), 'gc', '--release-mount-lease',
        '--cache-dir', str(cache), '--lease-id', crash_id], env=env,
        capture_output=True, text=True, timeout=20)
    (work / 'release.log').write_text(released.stdout + released.stderr)
    assert released.returncode == 0
    assert 'state=RELEASED' in record.read_text()

    record.chmod(0o600)
    record.write_text('partial lease\n')
    record.chmod(0o400)
    invalid = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
        env=env, capture_output=True, text=True, timeout=20)
    assert invalid.returncode != 0
    assert any(error['reason'] == 'invalid_mount_lease'
               for error in json.loads(invalid.stdout)['errors'])
    print('test-cache-mount-lease: active/crash/release/invalid PASS')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: test-cache-mount-lease.py PREFIX NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
