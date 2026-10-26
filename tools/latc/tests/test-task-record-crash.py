#!/usr/bin/env python3
"""Anonymous task staging leaves no named partial record after daemon death."""

import configparser
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    keys, full = work / 'input.tbset', work / 'full.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], env=env, check=True)
    for kind in ('COMPILER', 'COPY'):
        for stage in ('created', 'partial', 'synced', 'linked'):
            directory = work / (kind.lower() + '-' + stage)
            directory.mkdir(mode=0o700)
            cache, socket = directory / 'cache', directory / 's'
            args = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                    '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                    '--runtime-dir', str(prefix / 'lib'), '--workers', '1']

            def start(extra, log):
                daemon = subprocess.Popen(args, env=dict(env, **extra), stdout=log, stderr=log)
                deadline = time.monotonic() + 30
                while not socket.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.01)
                return daemon

            def submit(tbset, log):
                # Publication is asynchronous: registration fault may kill the
                # service before submit ACK, so death is verified separately.
                return subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                    '--tbset', str(tbset), str(guest)], env=env, stdout=log,
                    stderr=log, timeout=30)

            with (directory / 'baseline.log').open('wb') as log:
                daemon = start({}, log)
                try:
                    assert submit(keys, log).returncode == 0
                    subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(guest)],
                        env=env, stdout=log, stderr=log, check=True, timeout=120)
                finally:
                    daemon.terminate()
                    daemon.wait(timeout=30)
            current = next(cache.glob('*.current'))
            original = current.read_bytes()
            tasks = cache / '.gc/tasks'
            old = set(tasks.iterdir())
            with (directory / 'crash.log').open('wb') as log:
                daemon = start(dict(LATCD_TEST_TASK_RECORD_KIND=kind,
                                    LATCD_TEST_TASK_RECORD_CRASH=stage), log)
                try:
                    submit(full, log)
                    assert daemon.wait(timeout=30) == -signal.SIGKILL
                finally:
                    if daemon.poll() is None:
                        daemon.kill()
                        daemon.wait(timeout=10)
            added = set(tasks.iterdir()) - old
            expected = (2 if kind == 'COMPILER' else 0) + int(stage == 'linked')
            assert len(added) == expected, (kind, stage, added)
            assert not list((cache / '.gc').rglob('.write-*'))
            for task in added:
                parsed = configparser.ConfigParser(interpolation=None)
                parsed.read(task)
                assert parsed['task']['state'] == 'BOUND'
                assert task.stat().st_nlink == 1 and not task.stat().st_mode & 0o222
            assert current.read_bytes() == original
            plan = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
                env=env, capture_output=True, text=True, timeout=30)
            (directory / 'plan.json').write_text(plan.stdout)
            assert plan.returncode == 0, plan.stdout + plan.stderr
            parsed_plan = json.loads(plan.stdout)
            if kind == 'COMPILER' and stage == 'linked':
                assert parsed_plan['compiler_budget_summary']['unknown_compiler_task_count'] == 1
            socket.unlink(missing_ok=True)
            with (directory / 'restart.log').open('wb') as log:
                result = subprocess.run(args + ['--idle-seconds', '1'], env=env,
                    stdout=log, stderr=log, timeout=30)
                assert result.returncode == 0
            assert current.read_bytes() == original and all(task.exists() for task in added)
            assert not list((cache / '.gc').rglob('.write-*'))
            (directory / 'observations.json').write_text(json.dumps(dict(
                kind=kind, stage=stage, added_tasks=sorted(path.name for path in added),
                restart_rc=result.returncode), indent=2))
    print('test-task-record-crash: compiler/COPY created/partial/synced/linked PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-task-record-crash.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
