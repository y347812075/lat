#!/usr/bin/env python3
"""Inherited AOT descriptors remain pinned and protected in a fresh runner."""

import fcntl
import os
from pathlib import Path
import select
import subprocess
import struct
import sys


def run(prefix, module, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LATC_', 'LATX_', 'LAT_LD_'))}
    env.update(TMPDIR=str(Path.home() / 'tmp'), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATX_AOT='0', LATX_AOT_V2_AUTOSTART='0', LATX_AOT_V2_REPORT='1',
               LATC_DISABLE_PRETRANSLATE='1')
    # The synthetic module need not match the runner: no inherited code executes.
    image = module.read_bytes()
    bad_machine = bytearray(image)
    struct.pack_into('<H', bad_machine, 18, 62)
    bad_note = bytearray(image)
    phoff = struct.unpack_from('<Q', image, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', image, 54)
    changed = False
    for index in range(phnum):
        program = phoff + index * phentsize
        if struct.unpack_from('<I', image, program)[0] != 4:
            continue
        offset = struct.unpack_from('<Q', image, program + 8)[0]
        size = struct.unpack_from('<Q', image, program + 32)[0]
        end = offset + size
        while offset + 12 <= end:
            names, desc, kind = struct.unpack_from('<III', image, offset)
            if kind == 0x4c415432:
                struct.pack_into('<I', bad_note, offset + 4, 0xffffffff)
                changed = True
            offset += 12 + ((names + 3) & ~3) + ((desc + 3) & ~3)
    assert changed, 'fixture has no AOT note'
    cases = [('original', image, True), ('unlinked', image, True),
             ('ordinary', b'ordinary inherited guest file\n', False),
             ('truncated', image[:32], False),
             ('wrong-machine', bad_machine, False), ('bad-note', bad_note, False)]
    for name, contents, protected in cases:
        copied = work / (name + '.so')
        copied.write_bytes(contents)
        copied.chmod(0o600)
        pin = os.open(copied, os.O_RDONLY)
        contender = os.open(copied, os.O_RDONLY)
        fcntl.flock(pin, fcntl.LOCK_SH)
        os.lseek(pin, 7, os.SEEK_SET)
        if name == 'unlinked':
            copied.unlink()
        stderr = (work / (name + '.stderr')).open('w')
        child = None
        try:
            child = subprocess.Popen([str(prefix / 'bin/latx-x86_64'), str(guest)],
                                     env=env, pass_fds=(pin,), stdout=subprocess.PIPE,
                                     stderr=stderr)
            readable, _, _ = select.select([child.stdout], [], [], 20)
            assert readable, 'guest did not reach fd mutation barrier'
            assert child.stdout.readline() == b'CLOSED\n'
            assert child.poll() is None
            assert os.lseek(pin, 0, os.SEEK_CUR) == 7, 'recognition changed inherited offset'
            os.close(pin)
            pin = -1
            try:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                assert not protected, 'guest released inherited module pin'
            except BlockingIOError:
                assert protected, 'ordinary inherited fd was incorrectly protected'
            stderr.flush()
            report = (work / (name + '.stderr')).read_text()
            assert f'inherited AOT pins retained={int(protected)} ' in report, report
            assert f'retained_bytes={len(contents) if protected else 0} ' in report, report
        finally:
            if pin >= 0:
                os.close(pin)
            if child is not None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
            stderr.close()
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(contender)
    print('test-cache-inherited-pin: PASS')


if __name__ == '__main__':
    if len(sys.argv) != 5:
        raise SystemExit('usage: test-cache-inherited-pin.py PREFIX AOT_MODULE X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
