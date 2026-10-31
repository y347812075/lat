#!/usr/bin/env python3
"""Exercise managed publisher crashes inside an already delegated test scope."""

import configparser
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def start(arguments, env, log, socket):
    process = subprocess.Popen(arguments, env=env, stdout=log, stderr=log)
    deadline = time.monotonic() + 30
    while not socket.is_socket():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('daemon did not start')
        time.sleep(0.05)
    return process


def submit(client, socket, tbset, guest, env):
    deadline = time.monotonic() + 15
    while True:
        result = subprocess.run([str(client), '--submit', '--socket', str(socket),
                                 '--tbset', str(tbset), str(guest)],
                                env=env, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return
        assert ('recovery pending or unsafe' in result.stdout + result.stderr and
                time.monotonic() < deadline), result.stdout + result.stderr
        time.sleep(0.1)


def run(test_daemon, prefix, guest, work):
    work.mkdir(mode=0o700)
    client = prefix / 'bin/latcd'
    tbset = work / 'input.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(tbset)], check=True)
    full = work / 'full.tbset'
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], check=True)
    digest = hashlib.sha256(guest.read_bytes()).hexdigest()
    env = dict(os.environ, LD_LIBRARY_PATH=str(prefix / 'lib'))
    for phase, replacement in ((p, r) for r in (False, True)
                               for p in ('ADOPTING', 'OUTPUT_PREPARED', 'PARTIAL_ADOPTION', 'OUTPUT_ADOPTED', 'OUTPUT_UNLINK', 'CURRENT_SYNCED')):
        directory = work / (phase + ('-replacement' if replacement else '-first'))
        directory.mkdir(mode=0o700)
        cache, socket = directory / 'cache', directory / 'd.sock'
        args = [test_daemon, '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                '--runtime-dir', str(prefix / 'lib'), '--workers', '1', '--flush-only',
                '--idle-seconds', '0']
        current = cache / (digest + '.current')
        old = None
        if replacement:
            with (directory / 'baseline.log').open('wb') as log:
                daemon = start(args, env, log, socket)
                try:
                    submit(client, socket, tbset, guest, env)
                    subprocess.run([str(client), '--flush-source', '--socket', str(socket),
                                    str(guest)], env=env, check=True, stdout=subprocess.DEVNULL,
                                   timeout=120)
                finally:
                    daemon.terminate(); daemon.wait(timeout=30)
            old = current.read_bytes()
            socket.unlink(missing_ok=True)
        crash_env = dict(env)
        crash_env['LATCD_TEST_RETIREMENT_CRASH' if phase == 'CURRENT_SYNCED' else
                  'LATCD_TEST_CRASH_AFTER_' + phase] = 'current-synced' if phase == 'CURRENT_SYNCED' else '1'
        with (directory / 'crash.log').open('wb') as log:
            daemon = start(args, crash_env, log, socket)
            try:
                submit(client, socket, full if replacement else tbset, guest, env)
                subprocess.run([str(client), '--flush-source', '--socket', str(socket), str(guest)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                assert daemon.wait(timeout=120) == -signal.SIGKILL
            finally:
                if daemon.poll() is None:
                    daemon.kill(); daemon.wait()
        if phase == 'CURRENT_SYNCED':
            assert current.is_file() and (not old or current.read_bytes() != old)
        elif replacement:
            assert current.read_bytes() == old
        else:
            assert not current.exists()
        if old:
            manifest = json.loads(old)
            assert all((cache / manifest[k]).is_file() for k in ('module', 'native', 'tbset'))
        states = list((cache / '.gc/managed-task-state').glob('*.ini'))
        adopted = []
        for path in states:
            record = configparser.ConfigParser(); record.read(path)
            if record['managed']['state'] == ('ADOPTING' if phase == 'ADOPTING' else 'OUTPUT_ADOPTED'):
                adopted.append(path)
        assert len(adopted) == 1
        state = configparser.ConfigParser(); state.read(adopted[0])
        assert state['managed']['state'] == ('ADOPTING' if phase == 'ADOPTING' else 'OUTPUT_ADOPTED')
        socket.unlink(missing_ok=True)
        with (directory / 'restart.log').open('wb') as log:
            daemon = start(args, env, log, socket)
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    state.read(adopted[0])
                    if state['managed']['state'] == 'OUTPUTS_REMOVED':
                        break
                    time.sleep(0.05)
                assert state['managed']['state'] == 'OUTPUTS_REMOVED'
                if phase == 'CURRENT_SYNCED':
                    manifest = json.loads(current.read_bytes())
                    assert all((cache / manifest[k]).is_file() for k in ('module', 'native', 'tbset'))
                elif replacement:
                    assert current.read_bytes() == old
                else:
                    assert not current.exists()
                submit(client, socket, full if replacement else tbset, guest, env)
                subprocess.run([str(client), '--flush-source', '--socket', str(socket), str(guest)],
                               env=env, check=True, stdout=subprocess.DEVNULL, timeout=120)
                manifest = json.loads(current.read_bytes())
                assert all((cache / manifest[k]).is_file() for k in ('module', 'native', 'tbset'))
            finally:
                daemon.terminate(); daemon.wait(timeout=30)
        restart_log = (directory / 'restart.log').read_text()
        assert 'cannot scan compiler task roots' not in restart_log
    print('test-managed-publication-crash: PASS')


if __name__ == '__main__':
    run(os.path.abspath(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
