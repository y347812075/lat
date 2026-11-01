#!/usr/bin/env python3
"""Check a test daemon's offline snapshot against its published manifest."""
import array
import fcntl
import hashlib
import json
import os
import pathlib
import socket
import struct
import sys
import time

sockpath, cache, guest = sys.argv[1:4]
hold = len(sys.argv) == 6
if len(sys.argv) not in (4, 6):
    raise ValueError('expected socket cache guest [ready release]')
cache = pathlib.Path(cache)
data = pathlib.Path(guest).read_bytes()
digest = hashlib.sha256(data).digest()
manifest = json.loads((cache / (digest.hex() + '.current')).read_text())
module = cache / manifest['module']
source = os.memfd_create('broker-source', os.MFD_ALLOW_SEALING)
fds = []
try:
    with os.fdopen(os.dup(source), 'wb') as out:
        out.write(data)
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    fcntl.fcntl(source, fcntl.F_ADD_SEALS, seals)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(15)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        s.connect(sockpath)
        pid, uid, gid = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == os.geteuid()
        request = struct.pack('=IIQ32s', 2, 0, len(data), digest)
        assert s.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [source]))]) == len(request)
        packet, ancillary, flags, _ = s.recvmsg(88, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        credentials = []
        for level, kind, value in ancillary:
            assert level == socket.SOL_SOCKET
            if kind == socket.SCM_RIGHTS:
                received = array.array('i')
                received.frombytes(value)
                fds.extend(received)
            elif kind == socket.SCM_CREDENTIALS:
                credentials.append(struct.unpack('3i', value))
            else:
                raise AssertionError('unexpected ancillary data')
        assert credentials == [(pid, uid, gid)] and len(fds) == 1
        version, status, purpose, authorized, size, source_hash, module_hash = struct.unpack('=IIIIQ32s32s', packet)
        assert (version, status, purpose, authorized) == (2, 0, 1, 0)
        assert source_hash == digest and module_hash.hex() == manifest['module_sha256']
        fd = fds[0]
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals
        stat = os.fstat(fd)
        assert stat.st_size == size == module.stat().st_size
        assert (stat.st_dev, stat.st_ino) != (module.stat().st_dev, module.stat().st_ino)
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), 'rb') as snapshot:
            assert hashlib.file_digest(snapshot, 'sha256').digest() == module_hash
        if hold:
            pathlib.Path(sys.argv[4]).touch()
            deadline = time.monotonic() + 180
            while not pathlib.Path(sys.argv[5]).exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError('snapshot release not signalled')
                time.sleep(0.05)
            assert not module.exists()
            assert hashlib.sha256(os.pread(fd, size, 0)).digest() == module_hash
finally:
    for fd in fds:
        os.close(fd)
    os.close(source)
