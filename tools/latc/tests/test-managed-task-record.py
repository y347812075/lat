#!/usr/bin/env python3
"""Exercise the real managed task writer without opening production admission."""

import configparser
import fcntl
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def run(binary):
    with tempfile.TemporaryDirectory(prefix='latcd-managed-task-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        source = root / '.tmp/input'
        source.write_bytes(b'test input')
        process = subprocess.Popen([binary, '--test-managed-task', str(root)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            task_id = process.stdout.readline().strip()
            if not task_id:
                raise AssertionError(process.stderr.read())
            task_path = root / '.gc/tasks' / (task_id + '.ini')
            state_path = root / '.gc/managed-task-state' / (task_id + '.ini')
            raw = task_path.read_bytes()
            task, state = configparser.ConfigParser(), configparser.ConfigParser()
            task.read_string(raw.decode())
            state.read(state_path)
            assert task['task']['version'] == '3'
            assert task['task']['kind'] == 'MANAGED_COMPILER'
            assert task['task']['state'] == 'PREPARED'
            assert task['task']['id'] == task_id
            assert int(task['source']['inode']) == source.stat().st_ino
            assert state['managed']['state'] == 'PREPARED'
            assert state['managed']['task_id'] == task_id
            assert int(state['managed']['task_device']) == task_path.stat().st_dev
            assert int(state['managed']['task_inode']) == task_path.stat().st_ino
            assert state['managed']['task_sha256'] == hashlib.sha256(raw).hexdigest()
            with task_path.open('rb') as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('task lease not held')
            process.stdin.write('x')
            process.stdin.flush()
            assert process.wait(timeout=10) == 0, process.stderr.read()
            with task_path.open('rb') as probe:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
    with tempfile.TemporaryDirectory(prefix='latcd-managed-crash-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        (root / '.tmp/input').write_bytes(b'test input')
        env = dict(os.environ, LATCD_TEST_MANAGED_AFTER_ROOT='1')
        process = subprocess.run([binary, '--test-managed-task', str(root)],
                                 env=env, capture_output=True, timeout=10)
        assert process.returncode == -signal.SIGKILL, process.stderr
        tasks = list((root / '.gc/tasks').iterdir())
        assert len(tasks) == 1
        task = configparser.ConfigParser()
        task.read(tasks[0])
        assert task['task']['kind'] == 'MANAGED_COMPILER'
        assert task['task']['state'] == 'PREPARED'
        assert not list((root / '.gc/managed-task-state').iterdir())
        with tasks[0].open('rb') as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print('test-managed-task-record: PASS')


if __name__ == '__main__':
    run(os.path.abspath(sys.argv[1]))
