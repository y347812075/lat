#!/usr/bin/env python3
"""Exercise ordinary guest flock contention without blocking internal fd work."""

import os
from pathlib import Path
import subprocess
import sys


def run(prefix, rootfs, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    guest = r'''
import fcntl, os, resource, signal, sys, threading, time
path = sys.argv[1]
first = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
second = os.open(path, os.O_RDWR)
fcntl.flock(first, fcntl.LOCK_EX)
try:
    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
    raise AssertionError('contender acquired EX')
except BlockingIOError:
    pass
started = threading.Event()
finished = threading.Event()
def wait_lock():
    started.set()
    fcntl.flock(second, fcntl.LOCK_EX)
    finished.set()
worker = threading.Thread(target=wait_lock)
worker.start()
assert started.wait(5)
time.sleep(.2)
assert not finished.is_set()
# This thread must be able to enter the internal registry while flock waits.
ordinary = os.open('/dev/null', os.O_RDONLY)
copy = os.dup(ordinary)
os.dup2(ordinary, copy)
os.close(copy)
os.close(ordinary)
fcntl.flock(first, fcntl.LOCK_UN)
assert finished.wait(5), 'blocking flock held internal registry lock'
worker.join()
fcntl.flock(second, fcntl.LOCK_UN)
# Native flock on a duplicate must address the same open description.
copy = os.dup(second)
fcntl.flock(second, fcntl.LOCK_EX)
fcntl.flock(copy, fcntl.LOCK_UN)
fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
fcntl.flock(first, fcntl.LOCK_UN)
# The blocking slow path must remain interruptible through safe_flock.
fcntl.flock(first, fcntl.LOCK_EX)
class Interrupted(Exception):
    pass
def interrupt(signum, frame):
    raise Interrupted()
signal.signal(signal.SIGALRM, interrupt)
signal.setitimer(signal.ITIMER_REAL, .2)
try:
    fcntl.flock(second, fcntl.LOCK_EX)
    raise AssertionError('contended lock was not interrupted')
except Interrupted:
    pass
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
fcntl.flock(first, fcntl.LOCK_UN)
# Unlock and immediate/nonblocking operations must work with no free fd slots.
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, soft), hard))
fill = []
try:
    while True:
        fill.append(os.open('/dev/null', os.O_RDONLY))
except OSError as exc:
    import errno
    assert exc.errno == errno.EMFILE
fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
fcntl.flock(first, fcntl.LOCK_UN)
for fd in fill:
    os.close(fd)
resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
os.close(copy)
os.close(first)
os.close(second)
os.unlink(path)
print('guest-flock: PASS', flush=True)
'''
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LATC_', 'LATX_', 'LAT_LD_'))}
    env.update(TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LAT_LD_PREFIX=str(rootfs), LATX_AOT='0', LATX_AOT_V2_AUTOSTART='0',
               LATC_DISABLE_PRETRANSLATE='1')
    command = [str(prefix / 'bin/latx-x86_64'), '-L', str(rootfs),
               str(rootfs / 'usr/bin/python3'), '-S', '-c', guest, str(work / 'lock')]
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=30)
    (work / 'stdout.log').write_text(result.stdout)
    (work / 'stderr.log').write_text(result.stderr)
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert 'guest-flock: PASS' in result.stdout
    print('test-cache-flock: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-cache-flock.py PREFIX X86_ROOTFS NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
