#!/usr/bin/env python3
import array
import os
import socket
import sys

bootstrap = os.path.abspath(sys.argv[1])
parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
pid = os.fork()
if pid == 0:
    parent.close()
    channel = os.dup(child.fileno())
    sentinel = os.open('/dev/null', os.O_RDONLY)
    os.dup2(channel, 3, inheritable=True)
    os.dup2(sentinel, 4, inheritable=True)
    os.set_inheritable(3, True)
    os.closerange(5, 256)
    os.execv('/usr/bin/bwrap', [
        'bwrap', '--unshare-all', '--die-with-parent',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--proc', '/proc', '--tmpfs', '/work', '--ro-bind', bootstrap, '/bootstrap', '--',
        '/bootstrap', '/bin/sh', '-c', 'test ! -e /proc/self/fd/4',
    ])
child.close()
message, ancillary, flags, _ = parent.recvmsg(64, socket.CMSG_SPACE(array.array('i').itemsize))
assert message == b'LATCD-WORKSPACE-1\0' and not flags
assert len(ancillary) == 1
level, kind, data = ancillary[0]
assert level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
fds = array.array('i'); fds.frombytes(data[:fds.itemsize])
assert len(fds) == 1 and os.path.isdir('/proc/self/fd/%d' % fds[0])
os.close(fds[0])
parent.sendall(b'1')
parent.close()
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0
