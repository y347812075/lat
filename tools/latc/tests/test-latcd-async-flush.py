#!/usr/bin/env python3
"""Keep requests responsive and flush targets fixed while compilation is gated."""

import array
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time


def main():
    prefix, guest, work = [Path(p).resolve() for p in sys.argv[1:4]]
    deferred = sys.argv[4:] == ['--deferred']
    static_failure = sys.argv[4:] == ['--static-failure']
    static_duplicate = sys.argv[4:] == ['--static-duplicate']
    assert not sys.argv[4:] or deferred or static_failure or static_duplicate
    work.mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(work), LATCD_COMPILE_TMPDIR=str(work),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latc, latcd, runner = [prefix / 'bin' / name for name in
                          ('latc', 'latcd', 'latx-x86_64')]
    other = work / 'other-elf'
    other.write_bytes(guest.read_bytes() + b'other-source')
    inputs = (guest, other)
    script_dir = Path(__file__).resolve().parent
    commands = []
    sys.path.insert(0, str(script_dir))
    from tb_key_set import read_key_set, write_key_set
    for i, source in enumerate(inputs):
        command = ['python3', str(script_dir / 'make-tbset.py'), str(source),
                   str(work / f'keys-{i}.tbset')]
        run = subprocess.run(command, env=env, capture_output=True, text=True)
        commands.append(dict(command=command, exit_code=run.returncode,
                             stdout=run.stdout, stderr=run.stderr))
        assert run.returncode == 0, commands[-1]
        _, _, records = read_key_set(work / f'keys-{i}.tbset')
        write_key_set(source, work / f'new-{i}.tbset', [(records[0][0] + 5, 3)])
        write_key_set(source, work / f'later-{i}.tbset', [(records[0][0] + 10, 3)])
    wrapper = work / 'gated-compiler'
    wrapper.write_text('''#!/usr/bin/env python3
import hashlib, os, pathlib, sys, time
root = pathlib.Path(%r)
if sys.argv[1] == 'compile-module':
    sha = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
    if '--static-tbset' in sys.argv and (root / 'fail-static').exists():
        (root / 'static-failed').touch()
        sys.exit(1)
    if '--static-tbset' in sys.argv and (root / 'separate-static').exists():
        sha += '.static'
    (root / (sha + '.entered')).touch()
    deadline = time.monotonic() + 60
    while not (root / (sha + '.release')).exists():
        assert time.monotonic() < deadline, 'test compile gate expired'
        time.sleep(0.01)
os.execv(%r, [%r, *sys.argv[1:]])
''' % (str(work), str(latc), str(latc)))
    wrapper.chmod(0o700)
    args = list(map(str, [latcd, '--serve', '--socket', work / 'socket',
        '--cache-dir', work / 'cache', '--latc', wrapper, '--runner', runner,
        '--runtime-dir', prefix / 'lib', '--workers', '1', '--flush-only',
        '--stats', work / 'stats.json']))
    if static_failure:
        args.remove('--flush-only')
        (work / 'fail-static').touch()
    if static_duplicate:
        (work / 'separate-static').touch()
    (work / 'command.json').write_text(json.dumps(dict(command=args, env=env,
        inputs={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
        preparation=commands), indent=2) + '\n')
    events = []
    sockets = []
    sha = [hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs]

    def event(name, **values):
        events.append(dict(name=name, **values))
        (work / 'events.json').write_text(json.dumps(events, indent=2) + '\n')

    def connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect(str(work / 'socket'))
        sockets.append(s)
        return s

    def send(s, op, number, fds=(), channel=False, priority=0):
        packet = struct.pack('<IHHIIQQ', 0x4c415443 if channel else 0x4c415444,
                             2, 32, op, priority, number, 0)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
        assert s.sendmsg([packet], ancillary) == 32

    def receive(s, number, timeout, status=0):
        s.settimeout(timeout)
        packet = s.recv(1024)
        assert len(packet) == 264, packet
        header = struct.unpack_from('<IHHiiQ', packet)
        assert header == (0x4c415452, 2, 264, status, 0, number), (header, packet)
        return dict(accepted=struct.unpack_from('<Q', packet, 24)[0],
                    published=struct.unpack_from('<Q', packet, 32)[0])

    def wait_for(test):
        deadline = time.monotonic() + 30
        while not test():
            assert daemon.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)

    def submit(index, number, channel=None, changed=False, later=False, static=False):
        keys_path = work / f'{"later" if later else "new" if changed else "keys"}-{index}.tbset'
        with inputs[index].open('rb') as source, keys_path.open('rb') as keys:
            s = connect() if channel is None else channel
            fds = [source.fileno(), keys.fileno()]
            reply = s
            if channel is not None:
                reply, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                sockets.extend([reply, remote])
                fds.append(remote.fileno())
            send(s, 6 if static else 1, number, fds, channel is not None,
                 priority=250 if static else 200 if index == 0 else 0)
            return receive(reply, number, 5)

    with (work / 'daemon.stdout').open('w') as out, (work / 'daemon.stderr').open('w') as err:
        daemon = subprocess.Popen(args, env=env, stdout=out, stderr=err)
        try:
            wait_for(lambda: (work / 'socket').exists())
            channel = connect()
            send(channel, 7, 1)
            receive(channel, 1, 3)
            if static_duplicate:
                submit(0, 40, static=True)
                first_flush = connect()
                with guest.open('rb') as source:
                    send(first_flush, 2, 41, [source.fileno()])
                wait_for(lambda: (work / (sha[0] + '.static.entered')).exists())
                runtime = submit(0, 42, changed=True)
                old = connect()
                with guest.open('rb') as source:
                    send(old, 2, 43, [source.fileno()])
                ordered = connect()
                send(ordered, 5, 44)
                receive(ordered, 44, 3)
                submit(0, 45, static=True)
                (work / (sha[0] + '.static.release')).touch()
                receive(first_flush, 41, 30)
                wait_for(lambda: (work / (sha[0] + '.entered')).exists())
                current = json.loads((work / 'cache' / (sha[0] + '.current')).read_text())
                missing = work / 'before-runtime.tbset'
                check = subprocess.run([str(latc), 'missing-module-tbset',
                    str(work / 'cache' / current['module']), str(work / 'new-0.tbset'),
                    '-o', str(missing)], env=env, capture_output=True, text=True)
                assert check.returncode == 0 and read_key_set(missing)[2], check.stderr
                old.settimeout(0.6)
                try:
                    reply = old.recv(1024)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(('static duplicate completed runtime flush', reply))
                event('static-duplicate-does-not-complete-runtime-flush')
                (work / (sha[0] + '.release')).touch()
                result = receive(old, 43, 30)
                assert result['accepted'] == runtime['accepted']
                current = json.loads((work / 'cache' / (sha[0] + '.current')).read_text())
                check = subprocess.run([str(latc), 'missing-module-tbset',
                    str(work / 'cache' / current['module']), str(work / 'new-0.tbset'),
                    '-o', str(work / 'after-runtime.tbset')], env=env,
                    capture_output=True, text=True)
                assert check.returncode == 0 and not read_key_set(work / 'after-runtime.tbset')[2]
                event('runtime-flush-publishes-own-keys', **result)
                print('test-latcd-async-flush static duplicate: PASS')
                return
            if static_failure:
                submit(1, 30)
                wait_for(lambda: (work / (sha[1] + '.entered')).exists())
                first = submit(0, 31)
                old = connect()
                with guest.open('rb') as source:
                    send(old, 2, 32, [source.fileno()])
                ordered = connect()
                send(ordered, 5, 33)
                receive(ordered, 33, 3)
                later = submit(0, 34, changed=True, static=True)
                (work / (sha[1] + '.release')).touch()
                wait_for(lambda: (work / 'static-failed').exists())
                wait_for(lambda: (work / (sha[0] + '.entered')).exists())
                old.settimeout(0.6)
                try:
                    reply = old.recv(1024)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(('later static failure completed old flush', reply))
                event('later-static-failure-does-not-complete-old-flush')
                (work / (sha[0] + '.release')).touch()
                result = receive(old, 32, 30)
                assert result['accepted'] == first['accepted']
                final = connect()
                with guest.open('rb') as source:
                    send(final, 2, 35, [source.fileno()])
                result = receive(final, 35, 5, status=3)
                assert result['accepted'] == later['accepted']
                event('later-flush-reports-own-static-failure')
                print('test-latcd-async-flush static failure: PASS')
                return
            first = submit(0, 2)
            flush = connect()
            send(flush, 3, 3)
            wait_for(lambda: (work / (sha[0] + '.entered')).exists())
            started = time.monotonic()
            hello = connect()
            send(hello, 5, 4)
            receive(hello, 4, 3)
            event('hello-during-flush', elapsed=time.monotonic() - started)
            started = time.monotonic()
            duplicate = submit(0, 5, channel, changed=True)
            event('channel-submit-during-flush', elapsed=time.monotonic() - started,
                  **duplicate)
            if deferred:
                (work / (sha[0] + '.release')).touch()
                first_result = receive(flush, 3, 30)
                assert first_result['accepted'] == first['accepted']
                wait_for(lambda: json.loads((work / 'stats.json').read_text())['compiled'] == 1)
                newest = submit(0, 20, later=True)
                # New-source admission wakes the worker, but neither source
                # has an outstanding flush for these later keys.
                submit(1, 22)
                time.sleep(0.75)
                stats = json.loads((work / 'stats.json').read_text())
                assert stats['compiled'] == 1 and stats['queue_depth'] == 2, stats
                event('completed-flush-does-not-schedule-later-keys', **stats)
                final = connect()
                with guest.open('rb') as source:
                    send(final, 2, 21, [source.fileno()])
                result = receive(final, 21, 30)
                assert result['accepted'] == newest['accepted']
                current = json.loads((work / 'cache' / (sha[0] + '.current')).read_text())
                for kind in ('new', 'later'):
                    missing = work / f'missing-{kind}.tbset'
                    check = subprocess.run([str(latc), 'missing-module-tbset',
                        str(work / 'cache' / current['module']), str(work / f'{kind}-0.tbset'),
                        '-o', str(missing)], env=env, capture_output=True, text=True)
                    assert check.returncode == 0 and not read_key_set(missing)[2], check.stderr
                event('later-flush-publishes-deferred-keys', **result)
                print('test-latcd-async-flush deferred: PASS')
                return
            later = submit(1, 6)
            assert later['accepted'] > first['accepted']
            assert not (work / (sha[1] + '.entered')).exists()
            source_flush = connect()
            with guest.open('rb') as source:
                send(source_flush, 2, 7, [source.fileno()])
            queued_flush = connect()
            with other.open('rb') as source:
                send(queued_flush, 2, 8, [source.fileno()])
            # A following HELLO orders both admissions before the next submit.
            ordered = connect()
            send(ordered, 5, 9)
            receive(ordered, 9, 3)
            changed_other = submit(1, 10, changed=True)
            (work / (sha[0] + '.release')).touch()
            result = receive(flush, 3, 30)
            assert result['accepted'] == first['accepted'], result
            assert result['published'] >= first['accepted']
            assert not (work / (sha[1] + '.release')).exists()
            event('frozen-flush-excludes-later-source', later=later, **result)
            # Source flush must also preserve its own request identity/barrier.
            source_result = receive(source_flush, 7, 30)
            assert source_result['accepted'] == duplicate['accepted']
            event('source-flush', **source_result)
            current = json.loads((work / 'cache' / (sha[0] + '.current')).read_text())
            missing = work / 'missing-new.tbset'
            check = subprocess.run([str(latc), 'missing-module-tbset',
                str(work / 'cache' / current['module']), str(work / 'new-0.tbset'),
                '-o', str(missing)], env=env, capture_output=True, text=True)
            assert check.returncode == 0, check.stderr
            assert not read_key_set(missing)[2]
            event('running-new-key-published')
            wait_for(lambda: (work / (sha[1] + '.entered')).exists())
            event('queued-flush-wakeup-survives-new-key', **changed_other)
            # Keep another compile gated to exercise admission and disconnects.
            waiting = []
            for i in range(127):
                s = connect()
                send(s, 3, 1000 + i)
                waiting.append(s)
            wait_for(lambda: (work / (sha[1] + '.entered')).exists())
            excess = connect()
            send(excess, 3, 2000)
            receive(excess, 2000, 5, status=6)
            event('flush-admission-bounded')
            for s in waiting: s.close()
            # HELLO completes after the prior requests were admitted; a later
            # poll cycle retires disconnected waiters before new admission.
            time.sleep(0.3)
            pending = connect()
            send(pending, 3, 2001)
            hello = connect()
            send(hello, 5, 2002)
            receive(hello, 2002, 3)
            daemon.send_signal(signal.SIGTERM)
            receive(pending, 2001, 5, status=5)
            event('shutdown-replies-to-pending-flush')
        finally:
            for text in sha: (work / (text + '.release')).touch()
            for text in sha: (work / (text + '.static.release')).touch()
            for s in sockets: s.close()
            if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
            code = daemon.wait(timeout=30)
            event('daemon-exit', exit_code=code)
            assert code == 0
    print('test-latcd-async-flush: PASS')


if __name__ == '__main__':
    main()
