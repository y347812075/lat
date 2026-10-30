#!/usr/bin/env python3
import array
import fcntl
import hashlib
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading

client, source = map(pathlib.Path, sys.argv[1:])
seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
    root = pathlib.Path(directory)
    for case in ('ok', 'digest', 'unsealed', 'authorized', 'extra'):
        path = str(root / (case + '.sock'))
        output = root / (case + '.out')
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.bind(path)
        server.listen()
        def serve():
            with server, server.accept()[0] as conn:
                request, anc, _, _ = conn.recvmsg(48, socket.CMSG_SPACE(4))
                for level, kind, value in anc:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds = array.array('i'); fds.frombytes(value)
                        for fd in fds: os.close(fd)
                _, _, _, source_hash = struct.unpack('=IIQ32s', request)
                data = b'offline snapshot'
                fd = os.memfd_create('fake', os.MFD_ALLOW_SEALING)
                try:
                    os.write(fd, data)
                    if case != 'unsealed': fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
                    digest = hashlib.sha256(data).digest() if case != 'digest' else bytes(32)
                    response = struct.pack('=IIIIQ32s32s', 2, 0, 1, int(case == 'authorized'), len(data), source_hash, digest)
                    rights = [fd, fd] if case == 'extra' else [fd]
                    conn.sendmsg([response], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
                finally:
                    os.close(fd)
        thread = threading.Thread(target=serve)
        thread.start()
        result = subprocess.run([sys.executable, str(client), '--socket', path, '--service-uid', str(os.geteuid()), '--output', str(output), str(source)], capture_output=True)
        thread.join()
        assert (result.returncode == 0) == (case == 'ok'), (case, result.stderr)
        assert output.exists() == (case == 'ok')
        if case == 'ok': assert output.read_bytes() == b'offline snapshot'
