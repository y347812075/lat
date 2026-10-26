#!/usr/bin/env python3
"""Require guest isolation of a real journal fd, with controlled fd disclosure.

Build x86-journal-fd.S with -DATTACK=0..4 as guest-control/truncate/setfl/
overwrite/dup in GUEST_DIR. Run with PREFIX GUEST_DIR NEW_WORKDIR (under ~/tmp).
This standalone regression is intentionally RED until fd isolation is fixed;
it is not part of the default suite and never treats corruption as a pass.
"""

import argparse
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from tb_key_set import read_key_set


MODES = ('control', 'truncate', 'setfl', 'overwrite', 'dup')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def exact(stream, count):
    output = b''
    deadline = time.monotonic() + 20
    while len(output) < count:
        require(time.monotonic() < deadline, 'guest output timeout')
        if select.select([stream], [], [], .1)[0]:
            data = os.read(stream.fileno(), count - len(output))
            require(data, 'guest closed stdout before returning syscall result')
            output += data
    return output


def fd_snapshot(pid, fd):
    path = Path(f'/proc/{pid}/fd/{fd}')
    try:
        stat = path.stat()
        return {'target': os.readlink(path), 'device': stat.st_dev,
                'inode': stat.st_ino,
                'fdinfo': Path(f'/proc/{pid}/fdinfo/{fd}').read_text()}
    except FileNotFoundError:
        return None


def collect(endpoint, work):
    request_id = 88
    request = struct.pack('<IHHIIQQ', 0x4c415444, 2, 32, 9, 0, request_id, 0)
    (work / 'collect-request.bin').write_bytes(request)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(10)
        peer.connect(endpoint)
        require(peer.send(request) == len(request), 'short collector request')
        response, ancillary, flags, _ = peer.recvmsg(265, socket.CMSG_SPACE(256))
    (work / 'collect-response.bin').write_bytes(response)
    require(not ancillary and not flags, 'unexpected/truncated collector response')
    require(len(response) == 264, 'wrong collector response length')
    magic, version, size, status, reserved, identity = struct.unpack_from('<IHH i I Q', response)
    require((magic, version, size, reserved, identity) ==
            (0x4c415452, 2, 264, 0, request_id), 'wrong collector response identity')
    return status


def receipt_keys(path, guest):
    raw = path.read_bytes()
    require(len(raw) >= 64, 'short receipt')
    magic, version, size, source, count, sequence = struct.unpack_from('<8sII32sQQ', raw)
    require((magic, version, size) == (b'LATTBKS\0', 1, 64), 'bad receipt header')
    require(source.hex() == digest(guest), 'wrong receipt source')
    require(sequence == 0, 'unexpected receipt publication sequence')
    require(len(raw) == 64 + count * 16, 'wrong receipt record count')
    keys = [struct.unpack_from('<QII', raw, i) for i in range(64, len(raw), 16)]
    require(all(flags == 3 and reserved == 0 for _, flags, reserved in keys),
            'invalid receipt key')
    return keys


def run_case(prefix, guests, root, mode):
    work = root / mode
    work.mkdir(mode=0o700)
    cache = work / 'cache'
    cache.mkdir()
    endpoint = str(work / 'socket')
    require(len(os.fsencode(endpoint)) < 108, 'use a shorter work path for AF_UNIX')
    guest = guests / ('guest-' + mode)
    env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TZ')
           if key in os.environ}
    env.update(HOME=str(work), TMPDIR=str(root), LATX_AOT='0', LATX_AOT_V2='1',
               LATX_AOT_V2_AUTOSTART='0', LATX_AOT_V2_REPORT='1',
               LATX_AOT_V2_CACHE_DIR=str(cache), LATX_AOT_V2_LATCD_SOCKET=endpoint,
               LATX_AOT_V2_KEY_JOURNAL='1', LATC_DISABLE_PRETRANSLATE='1',
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    evidence = {'mode': mode, 'environment': env, 'commands': [],
                'scope': 'controlled host-fd disclosure; no natural discovery or sandbox claim',
                'guest_sha256': digest(guest),
                'installed_sha256': {name: digest(prefix / name) for name in
                    ('bin/latx-x86_64', 'bin/latc', 'bin/latcd',
                     'lib/liblat-aot-runtime.so.2')}}
    daemon = runner = None
    failures = []
    try:
        command = ['python3', str(Path(__file__).with_name('make-symbol-tbset.py')),
                   str(guest), '_start|delivery_target', str(work / 'expected.tbset')]
        evidence['commands'].append(command)
        subprocess.run(command, check=True)
        _, _, expected = read_key_set(work / 'expected.tbset')
        require(len(expected) == 2, 'expected distinct entry and delivery target keys')
        evidence['expected_keys'] = sorted(expected)
        with (work / 'daemon.log').open('wb') as log, (work / 'runner.log').open('wb') as err:
            command = [str(prefix / 'bin/latcd'), '--serve', '--socket', endpoint,
                       '--cache-dir', str(cache), '--latc', str(prefix / 'bin/latc'),
                       '--runner', str(prefix / 'bin/latx-x86_64'), '--runtime-dir',
                       str(prefix / 'lib'), '--workers', '1', '--idle-seconds', '0',
                       '--flush-only']
            evidence['commands'].append(command)
            daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 10
            while not Path(endpoint).exists():
                require(daemon.poll() is None and time.monotonic() < deadline,
                        'daemon startup failed')
                time.sleep(.01)
            command = [str(prefix / 'bin/latx-x86_64'), str(guest)]
            evidence['commands'].append(command)
            runner = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=err)
            require(exact(runner.stdout, 1) == b'R', 'missing guest ready handshake')
            journals = list((cache / '.journals').glob('*/keys'))
            require(len(journals) == 1, 'expected one registered journal')
            journal = journals[0]
            stat = journal.stat()
            descriptors = []
            for path in Path(f'/proc/{runner.pid}/fd').iterdir():
                snap = fd_snapshot(runner.pid, int(path.name))
                if snap and (snap['device'], snap['inode']) == (stat.st_dev, stat.st_ino):
                    descriptors.append(int(path.name))
            require(len(descriptors) == 1, 'expected one internal writer fd')
            fd = descriptors[0]
            before = journal.read_bytes()
            require(len(before) >= 224, 'short initial journal')
            target = struct.unpack_from('<QQQQ', before, 192)
            require(target[0] == 3 and target[2:] == (3, 0), 'entry slot not committed')
            evidence.update(journal_fd=fd, fd_before=fd_snapshot(runner.pid, fd),
                            entry_record=target)
            (work / 'journal-before.gz').write_bytes(gzip.compress(before, mtime=0))
            runner.stdin.write(struct.pack('<i', fd))
            runner.stdin.flush()
            try:
                result = struct.unpack('<q', exact(runner.stdout, 8))[0]
                evidence['guest_result'] = result
                evidence['fd_after'] = fd_snapshot(runner.pid, fd)
                if mode == 'dup' and result >= 0:
                    evidence['dup_fd'] = fd_snapshot(runner.pid, result)
                    if evidence['dup_fd'] and (
                            evidence['dup_fd']['device'], evidence['dup_fd']['inode']) == (
                            stat.st_dev, stat.st_ino):
                        failures.append('guest duplicated the internal journal')
                if result != -errno.EBADF:
                    failures.append(f'internal descriptor syscall returned {result}, expected EBADF')
                runner.stdin.write(b'x')
                runner.stdin.flush()
                require(exact(runner.stdout, 1) == b'T', 'target did not execute after operation')
            except (AssertionError, BrokenPipeError) as error:
                failures.append(str(error))
            if runner.poll() is None:
                runner.kill()
            producer_rc = runner.wait(timeout=10)
            evidence['producer_rc'] = producer_rc
            if producer_rc != -signal.SIGKILL:
                failures.append('producer rejected instead of continuing safely')
            after = journal.read_bytes()
            (work / 'journal-after.gz').write_bytes(gzip.compress(after, mtime=0))
            if len(after) != len(before) or after[:224] != before[:224]:
                failures.append('guest altered journal size/header/committed entry slot')
            status = collect(endpoint, work)
            evidence['collector_status'] = status
            if status != 0:
                failures.append('collector rejected damaged journal')
            receipt = journal.parent / 'received.tbset'
            evidence['receipt_exists'] = receipt.exists()
            if receipt.exists():
                receipt_data = receipt.read_bytes()
                (work / 'received.tbset').write_bytes(receipt_data)
                evidence['receipt_sha256'] = hashlib.sha256(receipt_data).hexdigest()
                keys = receipt_keys(receipt, guest)
                evidence['received'] = keys
                if target[1:] not in map(tuple, keys):
                    failures.append('collector lost already executed entry key')
                missing = set(expected) - {(rva, flags) for rva, flags, _ in keys}
                if missing:
                    failures.append(f'collector missing executed fixture keys: {sorted(missing)}')
            else:
                failures.append('collector did not publish a receipt')
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        failures.append(str(error))
    finally:
        if runner is not None and runner.poll() is None:
            runner.kill()
            runner.wait(timeout=10)
        if daemon is not None:
            if daemon.poll() is None:
                daemon.terminate()
            try:
                evidence['daemon_rc'] = daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                evidence['daemon_rc'] = daemon.wait(timeout=10)
            if evidence['daemon_rc'] != 0:
                failures.append('daemon did not exit cleanly')
        evidence['failures'] = failures
        (work / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(mode + ': ' + ('FAIL: ' + '; '.join(failures) if failures else 'PASS'), flush=True)
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', type=Path)
    parser.add_argument('guest_dir', type=Path)
    parser.add_argument('workdir', type=Path)
    args = parser.parse_args()
    root = args.workdir.resolve()
    require(root.is_relative_to((Path.home() / 'tmp').resolve()), 'workdir must be under ~/tmp')
    root.mkdir(mode=0o700)
    results = {mode: run_case(args.prefix.resolve(), args.guest_dir.resolve(), root, mode)
               for mode in MODES}
    (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if all(results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
