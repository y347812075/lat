#!/usr/bin/env python3
"""Deterministic task-root registration versus reference-root exclusion."""

import fcntl
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    keys, full = work / 'keys.tbset', work / 'full.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], env=env, check=True)
    for kind in ('COMPILER', 'COPY'):
        for exclusive in (True, False):
            directory = work / (kind.lower() + ('-exclusive' if exclusive else '-shared'))
            directory.mkdir(mode=0o700)
            cache, socket = directory / 'cache', directory / 's'
            args = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                    '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                    '--runtime-dir', str(prefix / 'lib'), '--workers', '1']

            def start(extra, log, fds=()):
                daemon = subprocess.Popen(args, env=dict(env, **extra), stdout=log,
                                          stderr=log, pass_fds=fds)
                deadline = time.monotonic() + 30
                while not socket.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.01)
                return daemon

            def submit(tbset, log):
                subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                '--tbset', str(tbset), str(guest)], env=env,
                               stdout=log, stderr=log, check=True, timeout=30)

            flush_args = [str(latcd), '--flush-source', '--socket', str(socket), str(guest)]
            with (directory / 'baseline.log').open('wb') as log:
                daemon = start({}, log)
                try:
                    submit(keys, log)
                    subprocess.run(flush_args, env=env, stdout=log, stderr=log,
                                   check=True, timeout=120)
                finally:
                    daemon.terminate()
                    daemon.wait(timeout=30)
            current = next(cache.glob('*.current'))
            original = current.read_bytes()
            tasks = cache / '.gc/tasks'
            original_tasks = set(tasks.iterdir())
            ready, notify = os.pipe()
            resume, release = os.pipe()
            daemon = flush = gate = None
            events = []
            before_registration = None
            with (directory / 'daemon.log').open('wb') as log:
                try:
                    daemon = start(dict(LATCD_TEST_TASK_ROOT_KIND=kind,
                        LATCD_TEST_TASK_ROOT_NOTIFY_FD=str(notify),
                        LATCD_TEST_TASK_ROOT_RESUME_FD=str(resume)), log, (notify, resume))
                    submit(full, log)
                    flush = subprocess.Popen(flush_args, env=env, stdout=log, stderr=log)
                    deadline = time.monotonic() + 120
                    while flush.poll() is None:
                        assert time.monotonic() < deadline, events
                        if not select.select([ready], [], [], .1)[0]:
                            continue
                        stage = os.read(ready, 1)
                        events.append(stage.decode())
                        if stage == b'b':
                            if exclusive and gate is not None:
                                # The daemon may retry a failed compile. Observe
                                # rejection before stopping its next attempt.
                                assert set(tasks.iterdir()) == before_registration
                                assert current.read_bytes() == original
                                daemon.kill()
                                daemon.wait(timeout=10)
                                break
                            assert gate is None
                            before_registration = set(tasks.iterdir())
                            gate = (cache / '.gc/reference-roots.lock').open('rb')
                            fcntl.flock(gate, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                                        | fcntl.LOCK_NB)
                        else:
                            assert not exclusive and stage in (b'l', b'p'), events
                            if stage == b'l':
                                assert gate is not None
                                gate.close()
                                gate = None
                            probe = (cache / '.gc/reference-roots.lock').open('rb')
                            try:
                                try:
                                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                except BlockingIOError:
                                    pass
                                else:
                                    raise AssertionError('task registration lost roots SH')
                            finally:
                                probe.close()
                            if stage == b'p':
                                assert set(tasks.iterdir()) > original_tasks
                        assert current.read_bytes() == original
                        os.write(release, b'x')
                    result = flush.wait(timeout=10)
                    if exclusive:
                        assert result != 0 and events in (['b'], ['b', 'b']), (result, events)
                        assert set(tasks.iterdir()) == before_registration
                        assert current.read_bytes() == original
                    else:
                        assert result == 0, result
                        assert events == ['b', 'l', 'p'] * (2 if kind == 'COPY' else 1), events
                        assert current.read_bytes() != original
                    (directory / 'observations.json').write_text(json.dumps(
                        dict(kind=kind, exclusive=exclusive, events=events, flush_rc=result), indent=2))
                finally:
                    if gate is not None:
                        gate.close()
                    if flush is not None and flush.poll() is None:
                        flush.kill()
                        flush.wait(timeout=10)
                    if daemon is not None and daemon.poll() is None:
                        daemon.kill()
                        daemon.wait(timeout=10)
                    for fd in (ready, notify, resume, release):
                        os.close(fd)
    print('test-task-root-latch: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-task-root-latch.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
