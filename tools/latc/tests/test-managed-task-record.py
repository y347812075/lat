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
    with tempfile.TemporaryDirectory(prefix='latcd-managed-replay-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_REPLAY_RECORD': '1'}
        result = subprocess.run([binary, '--test-managed-task', str(root)], input='x',
                                capture_output=True, text=True, env=env, timeout=20)
        assert result.returncode == 0, result.stderr
        task_id = result.stdout.strip()
        task, state = configparser.ConfigParser(), configparser.ConfigParser()
        task.read(root / '.gc/tasks' / (task_id + '.ini'))
        state.read(root / '.gc/managed-task-state' / (task_id + '.ini'))
        assert task['task']['kind'] == 'MANAGED_REPLAY'
        assert task['config']['name'] == 'configuration'
        assert state['managed']['state'] == 'REPLAY_DISCARDED'
    with tempfile.TemporaryDirectory(prefix='latcd-managed-output-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        native, module = root / 'output.native', root / 'output.so'
        native.write_bytes(b'abc')
        module.write_bytes(b'defg')

        def accepted(reservation):
            return subprocess.run([binary, '--test-managed-output-pair', str(root),
                                   str(reservation)], timeout=10).returncode == 0

        assert accepted(7)
        assert not accepted(6)
        assert not accepted(0)
        module.unlink()
        module.symlink_to(native)
        assert not accepted(7)
        module.unlink()
        module.write_bytes(b'')
        assert not accepted(7)
    with tempfile.TemporaryDirectory(prefix='latcd-managed-scan-',
                                     dir=Path.home() / 'tmp') as directory:
        subprocess.run([binary, '--test-managed-scan-identity', directory],
                       check=True, timeout=20)
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
            budget_path = root / '.gc/compiler-budgets' / (task_id + '.ini')
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
            budget = configparser.ConfigParser()
            budget.read(budget_path)
            assert budget['budget']['task_id'] == task_id
            assert int(budget['budget']['task_device']) == task_path.stat().st_dev
            assert int(budget['budget']['task_inode']) == task_path.stat().st_ino
            assert int(budget['budget']['bytes']) == 4096
            with task_path.open('rb') as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('task lease not held')
            subprocess.run([binary, '--test-managed-scan-busy', str(root)],
                           check=True, timeout=20)
            assert state_path.is_file() and budget_path.is_file()
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
    for point in ('ROOT', 'BUDGET'):
        with tempfile.TemporaryDirectory(prefix='latcd-managed-crash-',
                                         dir=Path.home() / 'tmp') as directory:
            root = Path(directory)
            (root / '.tmp').mkdir(mode=0o700)
            (root / '.tmp/input').write_bytes(b'test input')
            env = dict(os.environ, **{'LATCD_TEST_MANAGED_AFTER_' + point: '1'})
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
            budgets = list((root / '.gc/compiler-budgets').iterdir())
            assert len(budgets) == (point == 'BUDGET')
            if budgets:
                budget = configparser.ConfigParser()
                budget.read(budgets[0])
                assert int(budget['budget']['task_inode']) == tasks[0].stat().st_ino
            with tasks[0].open('rb') as probe:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print('test-managed-task-record: PASS')


if __name__ == '__main__':
    run(os.path.abspath(sys.argv[1]))
