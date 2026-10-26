#!/usr/bin/env python3
"""Check guest descriptor flags and fcntl duplication through fd admission."""

import os
from pathlib import Path
import subprocess
import sys


def run(prefix, rootfs, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    guest = r'''
import errno, fcntl, os, resource
fd = os.open('/dev/null', os.O_RDONLY)
assert fcntl.fcntl(fd, fcntl.F_GETFD) == fcntl.FD_CLOEXEC
fcntl.fcntl(fd, fcntl.F_SETFD, 0)
assert fcntl.fcntl(fd, fcntl.F_GETFD) == 0
fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
assert fcntl.fcntl(fd, fcntl.F_GETFD) == fcntl.FD_CLOEXEC
for command, cloexec in ((fcntl.F_DUPFD, False), (fcntl.F_DUPFD_CLOEXEC, True)):
    copy = fcntl.fcntl(fd, command, 32)
    assert copy >= 32
    assert bool(fcntl.fcntl(copy, fcntl.F_GETFD) & fcntl.FD_CLOEXEC) == cloexec
    assert os.fstat(copy) == os.fstat(fd)
    os.close(copy)
    try:
        fcntl.fcntl(fd, command, -1)
        raise AssertionError('negative minimum accepted')
    except OSError as exc:
        assert exc.errno == errno.EINVAL
read, write = os.pipe()
for copy in (os.dup(write), fcntl.fcntl(write, fcntl.F_DUPFD, 32),
             fcntl.fcntl(write, fcntl.F_DUPFD_CLOEXEC, 32)):
    assert os.write(copy, b'x') == 1
    os.close(copy)
assert os.read(read, 3) == b'xxx'
os.close(read)
os.close(write)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, soft), hard))
fill = []
try:
    while True:
        fill.append(os.open('/dev/null', os.O_RDONLY))
except OSError as exc:
    assert exc.errno == errno.EMFILE
fcntl.fcntl(fd, fcntl.F_SETFD, 0)
assert fcntl.fcntl(fd, fcntl.F_GETFD) == 0
for command in (fcntl.F_DUPFD, fcntl.F_DUPFD_CLOEXEC):
    try:
        fcntl.fcntl(fd, command, 0)
        raise AssertionError('dup with exhausted fd table succeeded')
    except OSError as exc:
        assert exc.errno == errno.EMFILE
for copy in fill:
    os.close(copy)
resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
os.close(fd)
try:
    fcntl.fcntl(fd, fcntl.F_GETFD)
    raise AssertionError('closed fd accepted')
except OSError as exc:
    assert exc.errno == errno.EBADF
print('guest-fcntl: PASS', flush=True)
'''
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LATC_', 'LATX_', 'LAT_LD_'))}
    env.update(TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LAT_LD_PREFIX=str(rootfs), LATX_AOT='0', LATX_AOT_V2_AUTOSTART='0',
               LATC_DISABLE_PRETRANSLATE='1')
    command = [str(prefix / 'bin/latx-x86_64'), '-L', str(rootfs),
               str(rootfs / 'usr/bin/python3'), '-S', '-c', guest]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    (work / 'stdout.log').write_text(result.stdout)
    (work / 'stderr.log').write_text(result.stderr)
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert 'guest-fcntl: PASS' in result.stdout
    print('test-cache-fcntl: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-cache-fcntl.py PREFIX X86_ROOTFS NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
