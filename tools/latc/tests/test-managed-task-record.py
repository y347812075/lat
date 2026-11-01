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


def run(binary, scanner):
    for with_base in (False, True):
        with tempfile.TemporaryDirectory(prefix='latcd-publish-prepared-',
                                         dir=Path.home() / 'tmp') as directory:
            root = Path(directory)
            (root / '.tmp').mkdir(mode=0o700)
            for name in ('input', 'tbset', 'configuration', 'base-native'):
                (root / '.tmp' / name).write_bytes(name.encode())
            env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1',
                                'LATCD_TEST_JOURNAL_PUBLISH_RECORD': '1',
                                'LATCD_TEST_MANAGED_AFTER_PREPARE': '1'}
            if with_base:
                env['LATCD_TEST_JOURNAL_BASE'] = '1'
            result = subprocess.run([binary, '--test-managed-task', str(root)],
                                    capture_output=True, env=env, timeout=20)
            assert result.returncode == -signal.SIGKILL
            task_path, = (root / '.gc/tasks').glob('*.ini')
            task_id = task_path.stem
            task, state = configparser.ConfigParser(), configparser.ConfigParser()
            task.read(task_path)
            state_path = root / '.gc/managed-task-state' / (task_id + '.ini')
            state.read(state_path)
            assert task['task']['version'] == ('7' if with_base else '6')
            assert state['managed']['state'] == 'PREPARED'
            if with_base:
                status = [scanner, '--task-status', str(root), '.tmp/base-native']
                assert int(subprocess.check_output(status, text=True)) == 1
            command = [binary, '--test-managed-adoption-recovery', str(root), task_id]
            subprocess.run(command, check=True, timeout=20)
            state.read(state_path)
            assert state['managed']['state'] == 'PREEXEC_CANCELLED'
            subprocess.run(command, check=True, timeout=20)
            if with_base:
                assert int(subprocess.check_output(status, text=True)) == 0
                assert (root / '.tmp/base-native').read_bytes() == b'base-native'
    with tempfile.TemporaryDirectory(prefix='latcd-journal-publish-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration', 'base-native'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1',
                            'LATCD_TEST_JOURNAL_BASE': '1',
                            'LATCD_TEST_JOURNAL_PUBLISH_RECORD': '1'}
        process = subprocess.Popen([binary, '--test-managed-task', str(root)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
        task_id = process.stdout.readline().strip()
        assert task_id, process.stderr.read()
        task, state = configparser.ConfigParser(), configparser.ConfigParser()
        task.read(root / '.gc/tasks' / (task_id + '.ini'))
        state.read(root / '.gc/managed-task-state' / (task_id + '.ini'))
        assert task['task']['version'] == '7'
        assert task['task']['kind'] == 'MANAGED_JOURNAL_COMPILER'
        assert state['managed']['state'] == 'ADOPTING'
        def status():
            return int(subprocess.check_output([scanner, '--task-status', str(root),
                                                '.tmp/base-native'], text=True))
        assert status() == 1
        process.stdin.write('x')
        process.stdin.flush()
        assert process.wait(timeout=20) == 0, process.stderr.read()
        assert status() == 1
        output = root / '.tmp/output-native'
        output.write_bytes(b'unidentified output')
        command = [binary, '--test-managed-adoption-recovery', str(root), task_id]
        assert subprocess.run(command, timeout=20).returncode != 0
        assert status() == 1
        output.unlink()
        subprocess.run(command, check=True, timeout=20)
        state.read(root / '.gc/managed-task-state' / (task_id + '.ini'))
        assert state['managed']['state'] == 'OUTPUTS_REMOVED'
        assert status() == 0
    with tempfile.TemporaryDirectory(prefix='latcd-journal-base-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration', 'base-native'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1',
                            'LATCD_TEST_JOURNAL_BASE': '1'}
        process = subprocess.Popen([binary, '--test-managed-task', str(root)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
        task_id = process.stdout.readline().strip()
        assert task_id, process.stderr.read()
        task = configparser.ConfigParser()
        task.read(root / '.gc/tasks' / (task_id + '.ini'))
        assert task['task']['version'] == '5'
        assert task['base_native']['name'] == 'base-native'
        assert int(task['base_native']['inode']) == (root / '.tmp/base-native').stat().st_ino
        assert task['base_native']['directory'] == 'temporary'
        def status():
            return int(subprocess.check_output([scanner, '--task-status', str(root),
                                                '.tmp/base-native'], text=True))
        assert status() == 1
        process.stdin.write('x')
        process.stdin.flush()
        assert process.wait(timeout=20) == 0, process.stderr.read()
        assert status() == 0
    with tempfile.TemporaryDirectory(prefix='latcd-journal-base-crash-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration', 'base-native'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1',
                            'LATCD_TEST_JOURNAL_BASE': '1',
                            'LATCD_TEST_MANAGED_AFTER_ROOT': '1'}
        result = subprocess.run([binary, '--test-managed-task', str(root)],
                                capture_output=True, env=env, timeout=20)
        assert result.returncode == -signal.SIGKILL
        subprocess.run([binary, '--test-managed-budget-unknown', str(root)],
                       check=True, timeout=20)
    with tempfile.TemporaryDirectory(prefix='latcd-journal-task-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1'}
        result = subprocess.run([binary, '--test-managed-task', str(root)], input='x',
                                capture_output=True, text=True, env=env, timeout=20)
        assert result.returncode == 0, result.stderr
        task_id = result.stdout.strip()
        task, state = configparser.ConfigParser(), configparser.ConfigParser()
        task.read(root / '.gc/tasks' / (task_id + '.ini'))
        state.read(root / '.gc/managed-task-state' / (task_id + '.ini'))
        assert task['task']['version'] == '4'
        assert task['task']['kind'] == 'MANAGED_REPLAY'
        assert not any(role in task for role in ('source', 'tbset', 'config'))
        assert [int(task['journal'][name]) for name in
                ('source_size', 'receipt_size', 'config_size')] == [1, 2, 3]
        assert state['managed']['state'] == 'REPLAY_DISCARDED'
    with tempfile.TemporaryDirectory(prefix='latcd-journal-task-crash-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_JOURNAL_RECORD': '1',
                            'LATCD_TEST_MANAGED_AFTER_ROOT': '1'}
        result = subprocess.run([binary, '--test-managed-task', str(root)],
                                capture_output=True, env=env, timeout=20)
        assert result.returncode == -signal.SIGKILL
        subprocess.run([binary, '--test-managed-budget-unknown', str(root)],
                       check=True, timeout=20)
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
    with tempfile.TemporaryDirectory(prefix='latcd-replay-budget-crash-',
                                     dir=Path.home() / 'tmp') as directory:
        root = Path(directory)
        (root / '.tmp').mkdir(mode=0o700)
        for name in ('input', 'tbset', 'configuration'):
            (root / '.tmp' / name).write_bytes(name.encode())
        env = os.environ | {'LATCD_TEST_REPLAY_RECORD': '1',
                            'LATCD_TEST_MANAGED_AFTER_ROOT': '1'}
        process = subprocess.run([binary, '--test-managed-task', str(root)],
                                 env=env, capture_output=True, timeout=10)
        assert process.returncode == -signal.SIGKILL, process.stderr
        subprocess.run([binary, '--test-managed-budget-unknown', str(root)],
                       check=True, timeout=20)
        task = next((root / '.gc/tasks').iterdir())
        raw = task.read_text()
        task.chmod(0o600)
        task.write_text(raw.replace('kind=MANAGED_REPLAY', 'kind=UNKNOWN'))
        task.chmod(0o400)
        assert subprocess.run([binary, '--test-managed-budget-unknown', str(root)],
                              timeout=20).returncode != 0
    print('test-managed-task-record: PASS')


if __name__ == '__main__':
    run(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]))
