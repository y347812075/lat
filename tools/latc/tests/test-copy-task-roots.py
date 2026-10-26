#!/usr/bin/env python3
"""Observe durable copy roots before output creation and after copied fsync."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    tbset, full = work / 'input.tbset', work / 'full.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(tbset)], env=env, check=True)
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], env=env, check=True)
    for stage in ('recorded', 'synced', 'copied', 'handedoff', 'released'):
        directory = work / stage
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
        def submit(keys, log):
            subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                            '--tbset', str(keys), str(guest)], env=env,
                           stdout=log, stderr=log, check=True, timeout=30)
        def plan():
            result = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
                                    env=env, capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, result.stdout + result.stderr
            return json.loads(result.stdout)
        with (directory / 'baseline.log').open('wb') as log:
            daemon = start({}, log)
            try:
                submit(tbset, log)
                subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(guest)],
                               env=env, stdout=log, stderr=log, check=True, timeout=120)
            finally:
                daemon.terminate()
                daemon.wait(timeout=30)
        current = next(cache.glob('*.current'))
        original = current.read_bytes()
        if stage == 'released':
            with (directory / 'daemon.log').open('wb') as log:
                daemon = start({}, log)
                try:
                    submit(full, log)
                    subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(guest)],
                                   env=env, stdout=log, stderr=log, check=True, timeout=120)
                finally:
                    daemon.terminate()
                    daemon.wait(timeout=30)
            observed = plan()
            (directory / 'released-plan.json').write_text(json.dumps(observed, indent=2))
            copies = [task for task in observed['tasks'].values() if task.get('kind') == 'COPY']
            assert len(copies) == 2
            assert observed['copy_release_count'] == 2
            compilers = [task for task in observed['tasks'].values() if task['version'] == '1']
            assert len(compilers) >= 2
            assert all(task['compiler_inputs_released'] for task in compilers)
            assert observed['compiler_release_count'] == len(compilers)
            assert all(task['copy_released'] for task in copies)
            assert all(not (cache / '.tmp' / task['objects']['output']['name']).exists() for task in copies)
            copy_names = {'.gc/tasks/' + task['id'] + '.ini' for task in copies}
            assert not any(ref['task'] in copy_names for row in observed['entries']
                           for ref in row['task_references'])
            assert current.read_bytes() != original
            continue
        ready, notify = os.pipe()
        resume, release = os.pipe()
        daemon = None
        probes = []
        with (directory / 'daemon.log').open('wb') as log:
            try:
                daemon = start(dict(LATCD_TEST_COPY_STAGE=stage,
                                    LATCD_TEST_COPY_NOTIFY_FD=str(notify),
                                    LATCD_TEST_COPY_RESUME_FD=str(resume)), log, (notify, resume))
                submit(full, log)
                assert select.select([ready], [], [], 30)[0], 'copy barrier not reached'
                assert os.read(ready, 1) == b'x'
                observed = plan()
                (directory / 'active-plan.json').write_text(json.dumps(observed, indent=2))
                copies = [(path, task) for path, task in observed['tasks'].items()
                          if task.get('kind') == 'COPY']
                assert len(copies) == (2 if stage == 'handedoff' else 1), copies
                record, task = copies[0]
                assert task['lease_observation'] == 'HELD_OBSERVED'
                source = task['objects']['input']
                assert source['directory'] == 'cache'
                output = cache / '.tmp' / task['objects']['output']['name']
                paths = [cache / record, cache / source['name']]
                assert output.exists() == (stage != 'recorded')
                assert observed['copy_receipt_count'] == (2 if stage == 'handedoff' else
                                                         1 if stage == 'copied' else 0)
                assert observed['copy_handoff_count'] == (2 if stage == 'handedoff' else 0)
                if stage in ('copied', 'handedoff'):
                    receipt = observed['copy_receipts']['.gc/copy-receipts/' + task['id'] + '.ini']
                    assert receipt['binding_observed']
                    assert not receipt['content_validated']
                    assert receipt['output']['sha256'] == hashlib.sha256(output.read_bytes()).hexdigest()
                if output.exists():
                    assert output.read_bytes() == paths[1].read_bytes()
                    assert output.stat().st_mode & 0o222 == 0
                    paths.append(output)
                for path in paths:
                    fd = os.open(path, os.O_RDONLY)
                    probes.append(fd)
                    if stage == 'handedoff' and path == cache / source['name']:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(fd, fcntl.LOCK_UN)
                        continue
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        raise AssertionError('copy lease missing: ' + str(path))
                    except BlockingIOError:
                        pass
                assert current.read_bytes() == original
                if stage == 'handedoff':
                    for copy_path, copied_task in copies:
                        assert copied_task['input_reference_released']
                        copied_source = cache / copied_task['objects']['input']['name']
                        with copied_source.open('rb') as pin:
                            fcntl.flock(pin, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    assert task['input_reference_released']
                    input_row = next(row for row in observed['entries']
                                     if row['path'] == source['name'])
                    assert not input_row['task_references']
                    output_row = next(row for row in observed['entries']
                                      if row['path'] == '.tmp/' + output.name)
                    assert output_row['task_references']
                daemon.kill()
                assert daemon.wait(timeout=10) == -signal.SIGKILL
                after = plan()
                assert after['tasks'][record]['lease_observation'] == 'NO_HOLDER_OBSERVED'
                assert not after['tasks'][record]['completion_verified']
                assert not after['delete_authorized']
                if stage == 'handedoff':
                    assert all(after['tasks'][path]['input_reference_released']
                               for path, _ in copies)
                assert current.read_bytes() == original
                if stage == 'handedoff':
                    assert all(plan()['tasks'][path]['input_reference_released']
                               for path, _ in copies)
                    marker = cache / '.gc/copy-handoffs' / (task['id'] + '.ini')
                    marker.chmod(0o600)
                    raw = marker.read_text()
                    marker.write_text(raw.replace('state=SNAPSHOT_OWNED', 'state=INVALID'))
                    marker.chmod(0o400)
                    invalid = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
                                             env=env, capture_output=True, text=True, timeout=10)
                    assert invalid.returncode == 1
                    bad = json.loads(invalid.stdout)
                    assert not bad['tasks'][record].get('input_reference_released', False)
                    assert any(error['reason'] == 'invalid_copy_handoff' for error in bad['errors'])
                    assert current.read_bytes() == original
                for fd in probes:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                restarted = subprocess.run(args + ['--idle-seconds', '1'], env=env,
                    stdout=log, stderr=log, timeout=30)
                assert restarted.returncode == 0
                assert (cache / record).exists()
                assert output.exists() == (stage != 'recorded')
                assert current.read_bytes() == original
            finally:
                if daemon is not None and daemon.poll() is None:
                    daemon.kill()
                    daemon.wait(timeout=10)
                for fd in probes + [ready, notify, resume, release]:
                    os.close(fd)
    print('test-copy-task-roots: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-copy-task-roots.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
