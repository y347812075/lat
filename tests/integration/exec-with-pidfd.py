#!/usr/bin/env python3
import os
import sys


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: exec-with-pidfd.py PID EMULATOR GUEST")

    pidfd = os.pidfd_open(int(sys.argv[1]))
    os.dup2(pidfd, 9, inheritable=True)
    env = os.environ.copy()
    env["LATX_AOT"] = "0"
    env["LATX_KZT"] = "0"
    os.execve(sys.argv[2], [sys.argv[2], sys.argv[3]], env)


if __name__ == "__main__":
    main()
