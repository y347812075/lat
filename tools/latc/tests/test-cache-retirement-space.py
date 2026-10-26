#!/usr/bin/env python3
"""Measure executor free-space observations on a private, otherwise idle tmpfs."""

from pathlib import Path
import subprocess
import sys


def run(binary, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=64m,mode=700',
                    'tmpfs', str(work)], check=True)
    try:
        subprocess.run([str(binary), '--space-root', str(work)], check=True)
        assert not list(work.iterdir())
    finally:
        subprocess.run(['umount', str(work)], check=True)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--inside':
        run(*(Path(value).resolve() for value in sys.argv[2:]))
    elif len(sys.argv) == 3:
        raise SystemExit(subprocess.run(['unshare', '-Urm', sys.executable,
            str(Path(__file__).resolve()), '--inside', *sys.argv[1:]]).returncode)
    else:
        raise SystemExit('usage: test-cache-retirement-space.py TEST_BINARY NEW_WORKDIR')
