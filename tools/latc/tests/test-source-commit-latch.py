#!/usr/bin/env python3
"""A publisher waits outside C, then rechecks its selection under S."""

import fcntl
import hashlib
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
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    tbset = work / 'input.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(tbset)], env=env, check=True)
    full_tbset = work / 'full.tbset'
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full_tbset)], env=env, check=True)
    for mutation in ('none', 'current', 'module', 'native', 'tbset'):
        directory = work / mutation
        directory.mkdir(mode=0o700)
        cache = directory / 'cache'
        socket = directory / 's'
        args = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                '--latc', str(prefix / 'bin/latc'), '--runner',
                str(prefix / 'bin/latx-x86_64'), '--runtime-dir', str(prefix / 'lib'),
                '--workers', '2']
        submit = [str(latcd), '--submit', '--socket', str(socket),
                  '--tbset', str(tbset), str(guest)]

        def start(extra_env, log):
            daemon = subprocess.Popen(args, env=extra_env, stdout=log, stderr=log,
                                      pass_fds=tuple(int(extra_env[name]) for name in (
                                          'LATCD_TEST_SOURCE_COMMIT_FD',
                                          'LATCD_TEST_SOURCE_COMMIT_RESUME_FD') if name in extra_env))
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            return daemon

        with (directory / 'baseline.log').open('wb') as log:
            baseline = start(env, log)
            try:
                subprocess.run(submit, env=env, stdout=log, stderr=log, check=True, timeout=120)
                subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(guest)],
                               env=env, stdout=log, stderr=log, check=True, timeout=120)
            finally:
                baseline.terminate()
                baseline.wait(timeout=30)
        assert not socket.exists()
        manifest = cache / (source + '.current')
        original = manifest.read_bytes()
        selected = json.loads(original)
        baseline_names = {path.name for path in cache.iterdir()}
        ready, notify = os.pipe()
        resume, release = os.pipe()
        client = daemon = None
        gate = None
        with (directory / 'daemon.log').open('wb') as log, (directory / 'submit.log').open('wb') as client_log:
            try:
                daemon = start(dict(env, LATCD_TEST_SOURCE_COMMIT_FD=str(notify),
                                    LATCD_TEST_SOURCE_COMMIT_RESUME_FD=str(resume)), log)
                replacement_submit = list(submit)
                replacement_submit[replacement_submit.index(str(tbset))] = str(full_tbset)
                client = subprocess.Popen(replacement_submit, env=env, stdout=client_log, stderr=client_log)
                assert select.select([ready], [], [], 30)[0], 'publisher did not reach source latch'
                assert os.read(ready, 1) == b'x'
                gate = (cache / '.gc/source-locks' / (source + '.lock')).open('rb')
                fcntl.flock(gate, fcntl.LOCK_EX)
                os.write(release, b'x')
                # An independent publication must finish while this source waits.
                other = directory / 'other-guest'
                # The independent publication uses the same test-only handshake.
                os.write(release, b'x')
                other.write_bytes(guest.read_bytes() + b'other source identity\n')
                other.chmod(0o700)
                other_tbset = directory / 'other.tbset'
                subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                                str(other), str(other_tbset)], env=env, check=True)
                subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                '--tbset', str(other_tbset), str(other)], env=env,
                               stdout=log, stderr=log, check=True, timeout=30)
                subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(other)],
                               env=env, stdout=log, stderr=log, check=True, timeout=30)
                if mutation == 'current':
                    selected['published_sequence'] += 100
                    replacement = directory / 'replacement-current'
                    replacement.write_text(json.dumps(selected, separators=(',', ':')))
                    replacement.chmod(0o444)
                    replacement.replace(manifest)
                elif mutation in ('module', 'native', 'tbset'):
                    suffix = {'module': '.so', 'native': '.native', 'tbset': '.tbset'}[mutation]
                    candidates = [path for path in cache.iterdir()
                                  if path.name.startswith(source) and path.name.endswith(suffix)
                                  and path.name not in baseline_names]
                    assert len(candidates) == 1, candidates
                    path = candidates[0]
                    replacement = directory / 'replacement-object'
                    replacement.write_bytes(path.read_bytes())
                    replacement.chmod(0o444)
                    replacement.replace(path)
                expected = manifest.read_bytes()
                fcntl.flock(gate, fcntl.LOCK_UN)
                gate.close()
                gate = None
                result = client.wait(timeout=30)
                assert result == 0, 'submission admission failed before publication'
                result = subprocess.run([str(latcd), '--flush-source', '--socket', str(socket), str(guest)],
                                        env=env, stdout=client_log, stderr=client_log,
                                        timeout=30).returncode
                assert (result == 0) == (mutation == 'none'), (mutation, result)
                if mutation != 'none':
                    assert manifest.read_bytes() == expected, 'stale publisher overwrote current'
                    assert 'changed during digest' in (directory / 'daemon.log').read_text()
            finally:
                if gate is not None:
                    gate.close()
                if client is not None and client.poll() is None:
                    client.kill()
                    client.wait(timeout=10)
                if daemon is not None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=10)
                os.close(ready)
                os.close(notify)
                os.close(resume)
                os.close(release)
    print('test-source-commit-latch: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-source-commit-latch.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
