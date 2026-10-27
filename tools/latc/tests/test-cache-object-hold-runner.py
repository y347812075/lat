#!/usr/bin/env python3
"""Check real publication, offline holds, owner exclusion and strict loading."""

import configparser
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cache, socket = work / "cache", work / "daemon.sock"
    env = dict(os.environ, TMPDIR=str(Path.home() / "tmp"),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    latcd = prefix / "bin/latcd"
    keys = work / "full.tbset"
    with (work / "emit.log").open("wb") as log:
        subprocess.run([str(prefix / "bin/latc"), "emit-static-tbset", str(guest),
                        "-o", str(keys)], env=env, stdout=log, stderr=log,
                       check=True, timeout=120)
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    args = [str(latcd), "--serve", "--socket", str(socket), "--cache-dir", str(cache),
            "--latc", str(prefix / "bin/latc"), "--runner", str(prefix / "bin/latx-x86_64"),
            "--runtime-dir", str(prefix / "lib")]
    count = 0

    def hold(name, identity, reason="ROLLBACK", release=False, expected=0):
        nonlocal count
        result = subprocess.run([str(latcd), "gc",
            "--release-object-hold" if release else "--hold-object",
            "--cache-dir", str(cache), "--source", source, "--name", name,
            "--hold-id", identity, "--reason", reason], env=env,
            capture_output=True, timeout=20)
        (work / f"hold-{count}.log").write_bytes(result.stdout + result.stderr)
        count += 1
        assert result.returncode == expected, result.stdout + result.stderr

    with (work / "daemon.log").open("wb") as log:
        daemon = subprocess.Popen(args, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            for operation, extra in (("submit", ["--tbset", str(keys)]), ("flush-source", [])):
                subprocess.run([str(latcd), "--" + operation, "--socket", str(socket),
                    *extra, str(guest)], env=env, stdout=log, stderr=log, check=True, timeout=180)
            current = cache / (source + ".current")
            original = current.read_bytes()
            manifest = json.loads(original)
            names = [manifest[role] for role in ("module", "native", "tbset")]
            identities = [str(uuid.uuid4()) for _ in names]
            for name, identity in zip(names, identities):
                hold(name, identity, expected=1)
            assert not (cache / ".gc/holds").exists()
        finally:
            if daemon.poll() is None:
                daemon.terminate()
            assert daemon.wait(timeout=60) == 0
    hashes = {name: hashlib.sha256((cache / name).read_bytes()).hexdigest() for name in names}
    for name, identity, reason in zip(names, identities, ("ROLLBACK", "MIGRATION", "EXTERNAL")):
        hold(name, identity, reason)
    plan = subprocess.run([str(latcd), "gc", "--plan", "--cache-dir", str(cache)],
                          env=env, capture_output=True, timeout=30)
    (work / "plan-active.json").write_bytes(plan.stdout)
    (work / "plan-active.stderr").write_bytes(plan.stderr)
    assert plan.returncode == 0, plan.stderr + plan.stdout
    report = json.loads(plan.stdout)
    assert report["explicit_hold_count"] == 3 and not report["delete_authorized"]
    assert all(value["binding_observed"] and value["state"] == "ACTIVE"
               for value in report["explicit_holds"].values())
    with (work / "restart.log").open("wb") as log:
        daemon = subprocess.Popen(args, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            for name, identity, reason in zip(names, identities, ("ROLLBACK", "MIGRATION", "EXTERNAL")):
                path = cache / ".gc/holds" / name / (identity + ".ini")
                before = path.read_bytes()
                hold(name, identity, reason, release=True, expected=1)
                assert path.read_bytes() == before
        finally:
            if daemon.poll() is None:
                daemon.terminate()
            assert daemon.wait(timeout=60) == 0
    run_env = dict(env, LATX_AOT="0", LATX_AOT_V2="1", LATX_AOT_V2_CACHE_DIR=str(cache),
                   LATX_AOT_V2_AUTOSTART="0", LATX_AOT_V2_LATCD_SOCKET=str(work / "absent.sock"),
                   LATC_STRICT_FILE_AOT="1", LATC_DISABLE_PRETRANSLATE="1", LATX_AOT_V2_REPORT="1")
    for key in ("LATX_AOT_V2_MODULE", "LATX_AOT_V2_SOURCE", "LATX_AOT_V2_COLLECT_ONLY"):
        run_env.pop(key, None)
    result = subprocess.run([str(prefix / "bin/latx-x86_64"), str(guest)], env=run_env,
                            capture_output=True, timeout=60)
    (work / "strict.stdout").write_bytes(result.stdout)
    (work / "strict.stderr").write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr
    assert b"module=registered" in result.stderr or b"registered module with" in result.stderr
    for name, identity, reason in zip(names, identities, ("ROLLBACK", "MIGRATION", "EXTERNAL")):
        hold(name, identity, reason, release=True)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read(cache / ".gc/holds" / name / (identity + ".ini"))
        assert parser["hold"]["state"] == "RELEASED"
    assert current.read_bytes() == original
    assert hashes == {name: hashlib.sha256((cache / name).read_bytes()).hexdigest() for name in names}
    print("test-cache-object-hold-runner: owner exclusion/restart/three reasons/plan/strict/preservation PASS")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: test-cache-object-hold-runner.py PREFIX X86_STATIC_HELLO NEW_WORKDIR")
    run(*(Path(value).resolve() for value in sys.argv[1:]))
