#!/usr/bin/env python3
"""Export an offline module snapshot; this does not authorize execution."""
import argparse
import array
import fcntl
import hashlib
import os
import socket
import stat
import struct
import sys

LIMIT = 1024 * 1024 * 1024
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def export(socket_path, service_uid, source_path, output_path):
    source = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC)
    snapshot = -1
    received = []
    output = -1
    created = False
    try:
        snapshot = os.memfd_create('latcd-broker-source', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        st = os.fstat(source)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= LIMIT:
            raise ValueError('invalid source size or type')
        checksum = hashlib.sha256()
        remaining = st.st_size
        while remaining:
            data = os.read(source, min(remaining, 131072))
            if not data:
                raise ValueError('source changed during snapshot')
            checksum.update(data)
            view = memoryview(data)
            while view:
                count = os.write(snapshot, view)
                if not count:
                    raise OSError('short snapshot write')
                view = view[count:]
            remaining -= len(data)
        if os.read(source, 1):
            raise ValueError('source changed during snapshot')
        digest = checksum.digest()
        fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, SEALS)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
            conn.settimeout(30)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            conn.connect(socket_path)
            peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[1] != service_uid:
                raise ValueError('unexpected service UID')
            request = struct.pack('=IIQ32s', 2, 0, st.st_size, digest)
            if conn.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [snapshot]))]) != len(request):
                raise ValueError('short request')
            packet, ancillary, flags, _ = conn.recvmsg(88, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(32), socket.MSG_CMSG_CLOEXEC)
            credentials = []
            unexpected = False
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array('i')
                    fds.frombytes(value)
                    received.extend(fds)
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack('3i', value))
                else:
                    unexpected = True
            if unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or credentials != [peer] or len(received) != 1:
                raise ValueError('invalid response credentials or descriptors')
            version, status, purpose, authorized, size, source_hash, module_hash = struct.unpack('=IIIIQ32s32s', packet)
            fd = received[0]
            result = os.fstat(fd)
            if ((version, status, purpose, authorized) != (2, 0, 1, 0) or source_hash != digest or
                    not stat.S_ISREG(result.st_mode) or not 0 < size <= LIMIT or result.st_size != size or
                    fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS):
                raise ValueError('invalid offline snapshot')
            checksum = hashlib.sha256()
            offset = 0
            while offset < size:
                data = os.pread(fd, min(size - offset, 131072), offset)
                if not data:
                    raise ValueError('short snapshot')
                checksum.update(data)
                offset += len(data)
            if checksum.digest() != module_hash:
                raise ValueError('module digest mismatch')
            output = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            created = True
            offset = 0
            while offset < size:
                data = os.pread(fd, min(size - offset, 131072), offset)
                if not data:
                    raise ValueError('short snapshot')
                view = memoryview(data)
                while view:
                    count = os.write(output, view)
                    if not count:
                        raise OSError('short output write')
                    view = view[count:]
                offset += len(data)
            os.fsync(output)
            created = False
    finally:
        if output >= 0:
            if created:
                try:
                    current = os.stat(output_path, follow_symlinks=False)
                    written = os.fstat(output)
                    if (current.st_dev, current.st_ino) == (written.st_dev, written.st_ino):
                        os.unlink(output_path)
                except OSError:
                    pass
            os.close(output)
        for fd in received:
            os.close(fd)
        if snapshot >= 0:
            os.close(snapshot)
        os.close(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--service-uid', type=int, required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('source')
    args = parser.parse_args()
    if not 0 <= args.service_uid < 2**32 - 1:
        parser.error('invalid service UID')
    try:
        export(args.socket, args.service_uid, args.source, args.output)
    except (OSError, ValueError, struct.error) as error:
        print('latcd-broker-export:', error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
