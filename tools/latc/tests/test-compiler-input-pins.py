#!/usr/bin/env python3
"""Compiler input leases survive daemon death and descendant handoff."""

import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time


WRAPPER = '''#!/usr/bin/python3
import json, os, pathlib, socket, sys
config = json.loads(pathlib.Path(__file__).with_suffix('.json').read_text())
if sys.argv[1] == 'build-id':
    os.execv(config['latc'], [config['latc'], 'build-id'])
inputs = [sys.argv[2], sys.argv[sys.argv.index('--tbset') + 1]]
inputs += [os.environ[name] for name in ('LATC_NATIVE_BASE', 'LATC_NATIVE_BASE_MODULE')
           if name in os.environ]
channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
channel.connect(config['socket'])
channel.sendall((json.dumps(dict(pid=os.getpid(), inputs=inputs)) + '\\n').encode())
assert channel.recv(1) == b'f'
child = os.fork()
if child:
    os._exit(0)
channel.sendall((json.dumps(dict(child=os.getpid())) + '\\n').encode())
assert channel.recv(1) == b'x'
os._exit(0)
'''


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    tbset = work / 'input.tbset'
    full = work / 'full.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(tbset)], env=env, check=True)
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], env=env, check=True)
    for incremental in (False, True):
        directory = work / ('incremental' if incremental else 'initial')
        directory.mkdir(mode=0o700)
        cache, service_socket = directory / 'cache', directory / 's'
        stats = directory / 'stats.json'
        def args(compiler):
            return [str(latcd), '--serve', '--socket', str(service_socket),
                    '--cache-dir', str(cache), '--latc', str(compiler), '--runner',
                    str(prefix / 'bin/latx-x86_64'), '--runtime-dir', str(prefix / 'lib'),
                    '--stats', str(stats)]
        def start(compiler, log):
            daemon = subprocess.Popen(args(compiler), env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 30
            while not service_socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            return daemon
        def submit(keys, log):
            subprocess.run([str(latcd), '--submit', '--socket', str(service_socket),
                            '--tbset', str(keys), str(guest)], env=env,
                           stdout=log, stderr=log, check=True, timeout=30)
        if incremental:
            with (directory / 'baseline.log').open('wb') as log:
                daemon = start(prefix / 'bin/latc', log)
                try:
                    submit(tbset, log)
                    subprocess.run([str(latcd), '--flush-source', '--socket', str(service_socket),
                                    str(guest)], env=env, stdout=log, stderr=log,
                                   check=True, timeout=120)
                finally:
                    daemon.terminate()
                    daemon.wait(timeout=30)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(directory / 'barrier'))
        listener.listen(1)
        listener.settimeout(30)
        wrapper = directory / 'compiler.py'
        wrapper.write_text(WRAPPER)
        wrapper.chmod(0o700)
        wrapper.with_suffix('.json').write_text(json.dumps(
            dict(latc=str(prefix / 'bin/latc'), socket=str(directory / 'barrier'))))
        daemon = channel = stream = None
        compiler_pid = None
        probes = []
        publisher_active = True
        with (directory / 'daemon.log').open('wb') as log:
            try:
                daemon = start(wrapper, log)
                submit(full if incremental else tbset, log)
                channel, _ = listener.accept()
                channel.settimeout(10)
                stream = channel.makefile('rb')
                report = json.loads(stream.readline())
                compiler_pid = report['pid']
                inputs = report['inputs']
                assert len(inputs) == (4 if incremental else 2), inputs
                (directory / 'inputs.json').write_text(json.dumps(report, indent=2))
                def assert_pinned():
                    for probe in probes:
                        try:
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            raise AssertionError('compiler input lease was released')
                        except BlockingIOError:
                            pass
                for path in inputs:
                    probes.append(os.open(path, os.O_RDONLY))
                def task_plan(expected):
                    result = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir',
                        str(cache)], env=env, capture_output=True, text=True, timeout=10)
                    assert result.returncode == 0, result.stdout + result.stderr
                    plan = json.loads(result.stdout)
                    tasks = [(path, task) for path, task in plan['tasks'].items()
                             if task['lease_observation'] == expected and task.get('kind') != 'COPY']
                    if expected == 'HELD_OBSERVED':
                        assert len(tasks) == 1, plan
                        path, task = tasks[0]
                        assert set(obj['name'] for role, obj in task['objects'].items()
                                   if role in ('source', 'tbset', 'base_native', 'base_module')) == {
                                       Path(path).name for path in inputs}
                        assert not task['completion_verified']
                        assert not task.get('compiler_inputs_released', False)
                        assert not task.get('compiler_outputs_released', False)
                        assert task['objects']['output_native']['name']
                        assert task['objects']['output_module']['name']
                        budget_path = cache / '.gc/compiler-budgets' / Path(path).name
                        missing = not budget_path.exists()
                        assert task['compiler_budget_status'] == ('MISSING' if missing else 'BOUND'), task
                        assert plan['compiler_budget_summary']['unknown_compiler_task_count'] == int(missing), plan
                        if not missing:
                            assert task['compiler_peak_budget_bytes'] >= 64 * 1024 * 1024, task
                        assert not plan['compiler_budget_summary']['daemon_reservation_verified']
                        copies = [value for value in plan['tasks'].values()
                                  if value.get('kind') == 'COPY']
                        assert len(copies) == (2 if incremental else 0)
                        assert all(value['compiler_budget_status'] == 'NOT_APPLICABLE' for value in copies)
                        if publisher_active:
                            assert all(value['lease_observation'] == 'HELD_OBSERVED'
                                       for value in copies)
                        else:
                            assert all(value['lease_observation'] == 'NO_HOLDER_OBSERVED'
                                       for value in copies)
                        return cache / path
                    assert not any(task['lease_observation'] == 'HELD_OBSERVED'
                                   for task in plan['tasks'].values()), plan
                task_record = task_plan('HELD_OBSERVED')
                probes.append(os.open(task_record, os.O_RDONLY))
                assert_pinned()
                daemon.kill()
                assert daemon.wait(timeout=10) == -signal.SIGKILL
                publisher_active = False
                assert_pinned()
                task_plan('HELD_OBSERVED')
                # A restarted daemon must not infer input release from the old
                # daemon's death while the compiler retains the task SH OFD.
                service_socket.unlink(missing_ok=True)
                if incremental:
                    # Simulate an absent legacy/lost budget without touching
                    # user caches: task and inherited SH remain intact.
                    (cache / '.gc/compiler-budgets' / task_record.name).unlink()
                daemon = start(prefix / 'bin/latc', log)
                deadline = time.monotonic() + 10
                while True:
                    value = json.loads(stats.read_bytes())
                    if value['cache_owner_pid'] == daemon.pid:
                        if incremental:
                            assert value['unknown_compiler_budget_tasks'] == 1, value
                        else:
                            assert value['recovered_compiler_reserved_bytes'] >= 64 * 1024 * 1024, value
                            assert value['unknown_compiler_budget_tasks'] == 0, value
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                assert_pinned()
                task_plan('HELD_OBSERVED')
                if incremental:
                    other = directory / 'other.elf'
                    other.write_bytes(guest.read_bytes() + b'capacity-unknown-source')
                    other.chmod(0o700)
                    other_keys = directory / 'other.tbset'
                    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                        str(other), str(other_keys)], env=env, stdout=log, stderr=log, check=True)
                    subprocess.run([str(latcd), '--submit', '--socket', str(service_socket),
                        '--tbset', str(other_keys), str(other)], env=env,
                        stdout=log, stderr=log, check=True, timeout=30)
                    rejected = subprocess.run([str(latcd), '--flush-source', '--socket',
                        str(service_socket), str(other)], env=env, capture_output=True, timeout=30)
                    assert rejected.returncode != 0, rejected.stdout + rejected.stderr
                    assert b'capacity:' in (directory / 'daemon.log').read_bytes()
                channel.sendall(b'f')
                child = json.loads(stream.readline())['child']
                (directory / 'descendant.json').write_text(json.dumps(dict(child=child)))
                assert_pinned()
                task_plan('HELD_OBSERVED')
                channel.sendall(b'x')
                assert stream.read() == b''
                # EOF precedes final kernel fd release by a small interval.
                deadline = time.monotonic() + 10
                for probe in probes:
                    while True:
                        try:
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            assert time.monotonic() < deadline
                            time.sleep(.01)
                for probe in probes:
                    fcntl.flock(probe, fcntl.LOCK_UN)
                # The same daemon must retry a busy task after its descendant
                # exits; observe the receipt, not a fixed sleep or another restart.
                deadline = time.monotonic() + 20
                while True:
                    result = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir',
                        str(cache)], env=env, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        recovered = json.loads(result.stdout)['tasks'][str(task_record.relative_to(cache))]
                        if recovered.get('compiler_inputs_released', False) and recovered.get('compiler_outputs_released', False):
                            break
                    assert daemon.poll() is None and time.monotonic() < deadline, result.stdout + result.stderr
                    time.sleep(.05)
                assert recovered['compiler_outputs_released'], recovered
                assert not recovered['completion_verified']
                daemon.terminate()
                assert daemon.wait(timeout=30) == 0
                assert json.loads(stats.read_bytes())['unknown_compiler_budget_tasks'] == 0
            finally:
                if compiler_pid is not None:
                    try:
                        os.killpg(compiler_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if daemon is not None and daemon.poll() is None:
                    daemon.kill()
                    daemon.wait(timeout=10)
                if stream is not None:
                    stream.close()
                if channel is not None:
                    channel.close()
                listener.close()
                for probe in probes:
                    os.close(probe)
    print('test-compiler-input-pins: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-compiler-input-pins.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
