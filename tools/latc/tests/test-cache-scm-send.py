#!/usr/bin/env python3
"""SCM_RIGHTS cannot export inherited AOT pins; ordinary sends still work."""

import array
import errno
import fcntl
import os
from pathlib import Path
import select
import socket
import subprocess
import sys


def line(child):
    assert select.select([child.stdout], [], [], 20)[0], 'guest response timeout'
    return child.stdout.readline().decode().strip()


def run(prefix, module, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LATC_', 'LATX_', 'LAT_LD_'))}
    env.update(TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATX_AOT='0', LATX_AOT_V2_AUTOSTART='0', LATC_DISABLE_PRETRANSLATE='1')
    for mode in range(6):
        path = work / f'pin-{mode}.so'
        path.write_bytes(module.read_bytes())
        path.chmod(0o400)
        ordinary_path = work / f'ordinary-{mode}'
        ordinary_path.write_bytes(b'ordinary guest data')
        pin = os.open(path, os.O_RDONLY)
        probe = os.open(path, os.O_RDONLY)
        ordinary = os.open(ordinary_path, os.O_RDONLY)
        fcntl.flock(pin, fcntl.LOCK_SH)
        peer, channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        child = None
        try:
            with (work / f'{mode}.stderr').open('wb') as log:
                child = subprocess.Popen([str(prefix / 'bin/latx-x86_64'), str(guest),
                    str(channel.fileno()), str(ordinary), str(pin), str(mode)],
                    env=env, pass_fds=(channel.fileno(), ordinary, pin),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
                assert line(child) == 'READY'
                os.close(pin)
                pin = -1
                before = set(Path(f'/proc/{child.pid}/fd').iterdir())
                child.stdin.write(b'x')
                child.stdin.flush()
                result, error = map(int, line(child).split())
                expected = -1 if mode in (1, 2, 4) else 2 if mode == 3 else 1
                assert result == expected, (mode, result, error)
                if result == -1:
                    assert error == errno.EACCES, (mode, result, error)
                after = set(Path(f'/proc/{child.pid}/fd').iterdir())
                assert before == after, (mode, before, after)
                received = []
                peer.settimeout(.1)
                while True:
                    try:
                        data, controls, flags, _ = peer.recvmsg(8, socket.CMSG_SPACE(8))
                    except socket.timeout:
                        break
                    assert data == b'x' and not flags
                    for level, kind, raw in controls:
                        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                        fds = array.array('i')
                        fds.frombytes(raw)
                        for fd in fds:
                            try:
                                st = os.fstat(fd)
                                assert (st.st_dev, st.st_ino) == (os.fstat(ordinary).st_dev,
                                                                os.fstat(ordinary).st_ino)
                                received.append(fd)
                            finally:
                                os.close(fd)
                assert len(received) == max(0, expected), (mode, received)
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    raise AssertionError('inherited module pin unexpectedly unlocked')
                except BlockingIOError:
                    pass
                child.stdin.write(b'x')
                child.stdin.flush()
                assert child.wait(timeout=20) == 0
                (work / f'{mode}.result').write_text(f'result={result} errno={error} received={len(received)}\n')
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            peer.close()
            channel.close()
            if pin >= 0:
                os.close(pin)
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(probe)
            os.close(ordinary)
    print('test-cache-scm-send: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 5:
        raise SystemExit('usage: test-cache-scm-send.py PREFIX AOT_MODULE X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
