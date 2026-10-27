#!/usr/bin/env python3
"""Exercise real guest fd operations against an inherited AOT pin and controls."""

import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import time


def exact(stream, length):
    data = b''
    deadline = time.monotonic() + 20
    while len(data) < length:
        assert select.select([stream], [], [], max(0, deadline - time.monotonic()))[0], 'guest timeout'
        chunk = os.read(stream.fileno(), length - len(data))
        assert chunk, 'guest exited before response'
        data += chunk
    return data


def run(prefix, module, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LATC_', 'LATX_', 'LAT_LD_'))}
    env.update(TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATX_AOT='0', LATX_AOT_V2_AUTOSTART='0', LATX_AOT_V2_REPORT='1',
               LATX_AOT_V2_CACHE_DIR=str(work / 'cache'), LATC_DISABLE_PRETRANSLATE='1')
    copied = work / 'inherited.so'
    copied.write_bytes(module.read_bytes())
    copied.chmod(0o600)
    control = work / 'ordinary'
    control.write_bytes(b'ordinary guest data\n')
    pin = os.open(copied, os.O_RDONLY)
    contender = os.open(copied, os.O_RDONLY)
    ordinary = os.open(control, os.O_RDWR)
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(pin, fcntl.LOCK_SH)
    os.lseek(pin, 7, os.SEEK_SET)
    child = None
    evidence = []
    try:
        with (work / 'runner.log').open('wb') as log:
            child = subprocess.Popen([str(prefix / 'bin/latx-x86_64'), str(guest)],
                                     env=env, pass_fds=(pin, ordinary, directory),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
            assert exact(child.stdout, 6) == b'READY\n'
            inherited_number = pin
            os.close(pin)
            pin = -1

            def operation(nr, fd, arguments):
                request = [nr, fd, *arguments]
                request.extend([0] * (7 - len(request)))
                child.stdin.write(struct.pack('<7q', *request))
                child.stdin.flush()
                return struct.unpack('<q', exact(child.stdout, 8))[0]

            # Kernel numbers are x86-64. -1/-2 encode fixture buffer/name pointers.
            cases = [('lseek', 8, [3, 0], 3), ('fstat', 5, [-1], 0),
                     ('fstatfs', 138, [-1], 0), ('fsync', 74, [], 0),
                     ('fdatasync', 75, [], 0), ('readahead', 187, [0, 1], 0),
                     ('fadvise64', 221, [0, 0, 0], 0),
                     ('sync_file_range', 277, [0, 1, 0], 0),
                     ('flistxattr', 196, [0, 0], 0),
                     ('fgetxattr', 193, [-2, 0, 0], -errno.ENODATA),
                     ('ioctl', 16, [0x541B, -1], 0),
                     ('fchdir', 81, [], 0),
                     ('ftruncate', 77, [control.stat().st_size], 0),
                     ('fchmod', 91, [0o600], 0),
                     ('fchown', 93, [os.getuid(), os.getgid()], 0),
                     ('fallocate', 285, [1, 0, 4096], 0),
                     ('fsetxattr', 190, [-2, 0, 0, 0], 0),
                     ('fgetxattr-after-set', 193, [-2, 0, 0], 0),
                     ('fremovexattr', 199, [-2], 0),
                     ('fadvise-invalid', 221, [0, 0, 0x7fffffff], -errno.EINVAL),
                     ('ftruncate-invalid', 77, [-3], -errno.EINVAL),
                     ('fcntl-getfl', 72, [3, 0], 2),
                     ('fcntl-setfl-append', 72, [4, 0x402], 0),
                     ('fcntl-getfl-append', 72, [3, 0], 0x402),
                     ('fcntl-setfl-reset', 72, [4, 2], 0),
                     ('fcntl-getlk', 72, [5, -1], 0),
                     ('fcntl-setlk', 72, [6, -1], 0),
                     ('fcntl-unlock', 72, [6, -4], 0),
                     ('fcntl-ofd-getlk', 72, [36, -1], 0),
                     ('fcntl-ofd-setlk', 72, [37, -1], 0),
                     ('fcntl-ofd-unlock', 72, [37, -4], 0),
                     ('fcntl-getsig', 72, [11, 0], 0),
                     ('fcntl-setsig', 72, [10, 0], 0),
                     ('fcntl-getown', 72, [9, 0], 0),
                     ('fcntl-setown', 72, [8, 0], 0),
                     ('fcntl-getown-ex', 72, [16, -1], 0),
                     ('fcntl-setown-ex', 72, [15, -1], 0),
                     ('fcntl-getlease', 72, [1025, 0], 2),
                     ('fcntl-getpipe-invalid', 72, [1032, 0], -errno.EBADF),
                     ('fcntl-setpipe-invalid', 72, [1031, 4096], -errno.EBADF),
                     ('fcntl-getseals-invalid', 72, [1034, 0], -errno.EINVAL),
                     ('fcntl-addseals-invalid', 72, [1033, 0], -errno.EINVAL)]
            for name, nr, arguments, expected in cases:
                protected = operation(nr, inherited_number, arguments)
                normal = operation(nr, directory if name == 'fchdir' else ordinary, arguments)
                evidence.append(dict(name=name, protected=protected, ordinary=normal))
                assert protected == -errno.EACCES, evidence[-1]
                assert normal == expected, evidence[-1]
                if name in ('fcntl-setlk', 'fcntl-ofd-setlk'):
                    try:
                        fcntl.lockf(ordinary, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        raise AssertionError('guest record lock was not retained')
                    except BlockingIOError:
                        pass
                elif name in ('fcntl-unlock', 'fcntl-ofd-unlock'):
                    fcntl.lockf(ordinary, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.lockf(ordinary, fcntl.LOCK_UN)
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    raise AssertionError('guest operation released module lifetime pin')
                except BlockingIOError:
                    pass
                info = Path(f'/proc/{child.pid}/fdinfo/{inherited_number}').read_text()
                position = next(line.split(':', 1)[1].strip() for line in info.splitlines()
                                if line.startswith('pos:'))
                assert int(position) == 7, 'guest changed the inherited pin offset'
            assert hashlib.sha256(copied.read_bytes()).digest() == hashlib.sha256(module.read_bytes()).digest()
            assert os.lseek(ordinary, 0, os.SEEK_CUR) == 3
            child.stdin.close()
            assert child.wait(timeout=20) == 0
            child.stdout.close()
        assert 'inherited AOT pins retained=1 ' in (work / 'runner.log').read_text()
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        for fd in (pin, contender, ordinary, directory):
            if fd >= 0:
                os.close(fd)
        (work / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('cache fd operations protected/control and lifetime pin: PASS')


if __name__ == '__main__':
    run(*(Path(value).resolve() for value in sys.argv[1:]))
