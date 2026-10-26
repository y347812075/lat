#!/usr/bin/env python3
"""Check real statvfs rejection without filling a host filesystem."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    small = work / "small"
    small.mkdir(mode=0o700)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=32m,mode=700", "tmpfs", str(small)], check=True)
    env = dict(os.environ, TMPDIR=str(work), LATCD_COMPILE_TMPDIR=str(work),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    cache = work / "cache"
    socket = work / "d.sock"
    arguments = [str(prefix / "bin/latcd"), "--once", "--socket", str(socket),
        "--cache-dir", str(cache), "--latc", str(prefix / "bin/latc"),
        "--runner", str(prefix / "bin/latx-x86_64"), "--runtime-dir", str(prefix / "lib")]
    tbset = work / "first.tbset"
    full = work / "full.tbset"
    subprocess.run([sys.executable, str(Path(__file__).with_name("make-tbset.py")),
                    str(guest), str(tbset)], env=env, check=True)
    subprocess.run([str(prefix / "bin/latc"), "emit-static-tbset", str(guest),
                    "-o", str(full)], env=env, check=True)

    def submit(label, selected, environment, success):
        with (work / (label + ".daemon.log")).open("wb") as log:
            daemon = subprocess.Popen(arguments, env=environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while not socket.is_socket():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
                client = subprocess.run([str(prefix / "bin/latcd"), "--submit", "--socket",
                    str(socket), "--tbset", str(selected), str(guest)], env=environment,
                    capture_output=True, timeout=120)
                (work / (label + ".client.log")).write_bytes(client.stdout + client.stderr)
                assert (client.returncode == 0) == success
                assert daemon.wait(timeout=30) == (0 if success else 1)
                if not success:
                    assert b"capacity:" in client.stdout + client.stderr
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait()

    submit("baseline", tbset, env, True)
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    current = cache / (source + ".current")
    original = current.read_bytes()
    value = json.loads(original)
    objects = {value[role]: (cache / value[role]).read_bytes() for role in ("module", "native", "tbset")}
    submit("pressure", full, dict(env, LATCD_COMPILE_TMPDIR=str(small)), False)
    assert current.read_bytes() == original
    assert all((cache / name).read_bytes() == raw for name, raw in objects.items())
    assert not list(small.iterdir()), "compiler was launched despite insufficient reservation"
    submit("retry", full, env, True)
    result = subprocess.run([str(prefix / "bin/latx-x86_64"), str(guest)],
        env=dict(env, LATX_AOT="0", LATX_AOT_V2="1", LATX_AOT_V2_CACHE_DIR=str(cache),
                 LATX_AOT_V2_AUTOSTART="0", LATC_STRICT_FILE_AOT="1", LATC_DISABLE_PRETRANSLATE="1"),
        capture_output=True, timeout=30)
    assert result.returncode == 42
    print("compile-space: low-space rejection/current-and-baseline-preserved/retry/strict42 PASS")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--inside":
        run(*(Path(value).resolve() for value in sys.argv[2:]))
    elif len(sys.argv) == 4:
        raise SystemExit(subprocess.run(["unshare", "-Urm", sys.executable,
            str(Path(__file__).resolve()), "--inside", *sys.argv[1:]]).returncode)
    else:
        raise SystemExit("usage: test-compile-space.py PREFIX X86_EXIT42 NEW_WORKDIR")
