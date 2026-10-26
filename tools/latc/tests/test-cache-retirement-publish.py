#!/usr/bin/env python3
"""Crash real publication boundaries in an isolated cache, then recover."""

import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / "tmp"),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    latcd = prefix / "bin/latcd"
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    tbset = work / "input.tbset"
    subprocess.run([sys.executable, str(Path(__file__).with_name("make-tbset.py")),
                    str(guest), str(tbset)], check=True, env=env)
    full_tbset = work / "full.tbset"
    subprocess.run([str(prefix / "bin/latc"), "emit-static-tbset", str(guest),
                    "-o", str(full_tbset)], check=True, env=env)
    phases = ("prepared", "current", "current-synced", "retired")
    for phase, initial in [(phase, initial) for initial in (False, True) for phase in phases]:
        label = phase + ("-replacement" if initial else "-first")
        directory = work / label
        directory.mkdir(mode=0o700)
        cache = directory / "cache"
        socket = directory / "d.sock"
        arguments = [str(latcd), "--socket", str(socket), "--cache-dir", str(cache),
                     "--latc", str(prefix / "bin/latc"),
                     "--runner", str(prefix / "bin/latx-x86_64"),
                     "--runtime-dir", str(prefix / "lib")]
        old_manifest = None
        if initial:
            with (directory / "baseline.log").open("wb") as log:
                baseline = subprocess.Popen(arguments + ["--once"], env=env,
                                            stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while not socket.is_socket():
                        assert baseline.poll() is None and time.monotonic() < deadline
                        time.sleep(0.01)
                    subprocess.run([str(latcd), "--submit", "--socket", str(socket),
                        "--tbset", str(tbset), str(guest)], env=env,
                        stdout=log, stderr=log, check=True, timeout=120)
                    assert baseline.wait(timeout=30) == 0
                finally:
                    if baseline.poll() is None:
                        baseline.kill()
                        baseline.wait()
            old_manifest = (cache / (source + ".current")).read_bytes()
        previous_records = set((cache / ".gc/transactions").glob("*.ini")) if initial else set()
        crash_env = dict(env, LATCD_TEST_RETIREMENT_CRASH=phase)
        with (directory / "daemon.log").open("wb") as log:
            daemon = subprocess.Popen(arguments + ["--once"], env=crash_env,
                                      stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while not socket.is_socket():
                    if daemon.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError("daemon did not start")
                    time.sleep(0.01)
                with (directory / "submit.log").open("wb") as client_log:
                    client = subprocess.run([str(latcd), "--submit", "--socket",
                        str(socket), "--tbset", str(full_tbset if initial else tbset), str(guest)], env=env,
                        stdout=client_log, stderr=client_log, timeout=120)
                assert client.returncode != 0
                assert daemon.wait(timeout=30) == -signal.SIGKILL
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait()
        records = list(set((cache / ".gc/transactions").glob("*.ini")) - previous_records)
        assert len(records) == 1

        def record():
            value = configparser.ConfigParser(interpolation=None, strict=True)
            value.read(records[0])
            return value["transaction"]

        before = record()
        assert before["version"] == "2"
        objects = configparser.ConfigParser(interpolation=None, strict=True)
        objects.read_string(base64.b64decode(before["objects"], validate=True).decode())
        expected_names = set()
        for encoded in (before["previous"], before["next"]):
            snapshot = base64.b64decode(encoded, validate=True)
            if snapshot:
                expected_names.update(value for key, value in json.loads(snapshot).items()
                                      if key in {"module", "native", "tbset"} and value)
        recorded_names = set()
        for i in range(objects.getint("objects", "count")):
            obj = objects[f"object{i}"]
            path = cache / obj["name"]
            st = path.stat()
            assert (st.st_dev, st.st_ino, st.st_size, st.st_blocks * 512) == tuple(
                int(obj[key]) for key in ("device", "inode", "size", "allocated"))
            assert hashlib.sha256(path.read_bytes()).hexdigest() == obj["sha256"]
            recorded_names.add(obj["name"])
        assert recorded_names == expected_names
        assert base64.b64decode(before["previous"], validate=True) == (old_manifest or b"")
        assert before["state"] == ("RETIRED" if phase == "retired" else "PREPARED")
        manifest = cache / (source + ".current")
        current_before = manifest.read_bytes() if manifest.exists() else None
        with (directory / "recovery.log").open("wb") as log:
            recovered = subprocess.run(arguments + ["--serve", "--idle-seconds", "1"],
                                       env=env, stdout=log, stderr=log, timeout=30)
        assert recovered.returncode == 0
        after = record()
        assert after["objects_status"] == "RECORDED"
        assert after["binding_status"] == "COMPLETE"
        assert after["state"] == ("ABORTED" if phase == "prepared" else "RETIRED")
        if phase == "prepared":
            assert current_before == old_manifest
            assert (manifest.read_bytes() if manifest.exists() else None) == old_manifest
        else:
            assert manifest.read_bytes() == current_before
            assert base64.b64decode(after["next"], validate=True) == current_before
            value = json.loads(current_before)
            for role in ("module", "native", "tbset"):
                assert (cache / value[role]).is_file()
            for role in ("module", "native"):
                assert hashlib.sha256((cache / value[role]).read_bytes()).hexdigest() == value[role + "_sha256"]
            run_env = dict(env, LATX_AOT="0", LATX_AOT_V2="1",
                LATX_AOT_V2_CACHE_DIR=str(cache), LATX_AOT_V2_AUTOSTART="0",
                LATC_STRICT_FILE_AOT="1", LATC_DISABLE_PRETRANSLATE="1",
                LATX_AOT_V2_REPORT="1")
            with (directory / "runner.log").open("wb") as log:
                result = subprocess.run([str(prefix / "bin/latx-x86_64"), str(guest)],
                    env=run_env, stdout=log, stderr=log, timeout=30)
            assert result.returncode == 42
            assert "module=registered" in (directory / "runner.log").read_text()
            # A persisted intent must block new loads even after the GC's EX
            # lease is gone. Corrupt intent is equally conservative.
            tombstones = cache / ".gc/tombstones"
            tombstones.mkdir(mode=0o700)
            marker = tombstones / json.loads((cache / (source + ".current")).read_bytes())["module"]
            marker.write_bytes(b"deliberately invalid tombstone\n")
            marker.chmod(0o400)
            with (directory / "tombstone-runner.log").open("wb") as log:
                blocked = subprocess.run([str(prefix / "bin/latx-x86_64"), str(guest)],
                    env=run_env, stdout=log, stderr=log, timeout=30)
            assert blocked.returncode != 42
            assert "tombstoned" in (directory / "tombstone-runner.log").read_text()
            marker.unlink()
            tombstones.rmdir()
        if old_manifest:
            for role in ("module", "native", "tbset"):
                assert (cache / json.loads(old_manifest)[role]).is_file()
        print(f"{label}: crash/recovery PASS")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: test-cache-retirement-publish.py PREFIX X86_EXIT42 NEW_WORKDIR")
    run(*(Path(value).resolve() for value in sys.argv[1:]))
