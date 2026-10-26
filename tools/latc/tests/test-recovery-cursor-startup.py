#!/usr/bin/env python3
"""Interrupt real startup hashing, then restart against the same private cache."""

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


def run(prefix, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = "a" * 64
    for tombstones in (False, True):
        directory = work / ("tombstones" if tombstones else "transactions")
        directory.mkdir(mode=0o700)
        cache = directory / "cache"
        cache.mkdir(mode=0o700)
        name = source + ".so"
        path = cache / name
        with path.open("wb") as stream:
            stream.truncate(256 * 1024 * 1024)
        path.chmod(0o400)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        st = path.stat()
        gc = cache / ".gc"
        gc.mkdir(mode=0o700)
        store = gc / ("tombstones" if tombstones else "transactions")
        store.mkdir(mode=0o700)
        numbers = (f"device={st.st_dev}\ninode={st.st_ino}\nsize={st.st_size}\n"
                   f"allocated={st.st_blocks * 512}\nsha256={digest}\n")
        if tombstones:
            record = store / name
            raw = (f"[tombstone]\nversion=1\nsource={source}\nname={name}\n"
                   "state=DELETING\n" + numbers)
        else:
            native = cache / (source + ".native")
            native.write_bytes(b"native fixture")
            native.chmod(0o400)
            ns = native.stat()
            manifest = dict(version=2, module=name, native=native.name, tbset="",
                            source_sha256=source, codegen_id=source, published_sequence=1)
            current = cache / (source + ".current")
            current.write_text(json.dumps(manifest))
            current.chmod(0o400)
            evidence = (f"[objects]\ncount=2\n[object0]\nname={name}\n" + numbers +
                f"[object1]\nname={native.name}\ndevice={ns.st_dev}\ninode={ns.st_ino}\n"
                f"size={ns.st_size}\nallocated={ns.st_blocks * 512}\n"
                f"sha256={hashlib.sha256(native.read_bytes()).hexdigest()}\n")
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            stamp = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000
            record = store / "12345678-1234-4234-8234-123456789abc.ini"
            raw = (f"[transaction]\nversion=2\nsource={source}\nstate=RETIRED\nprevious=\n"
                   f"next={base64.b64encode(current.read_bytes()).decode()}\n"
                   f"objects={base64.b64encode(evidence.encode()).decode()}\n"
                   "objects_status=RECORDED\nbinding_status=COMPLETE\n"
                   f"retired_boot={boot}\nretired_boottime_us={stamp}\n")
        record.write_text(raw)
        record.chmod(0o400)
        socket = directory / "daemon.sock"
        command = [str(prefix / "bin/latcd"), "--serve", "--idle-seconds", "1",
                   "--socket", str(socket), "--cache-dir", str(cache),
                   "--latc", str(prefix / "bin/latc"),
                   "--runner", str(prefix / "bin/latx-x86_64"),
                   "--runtime-dir", str(prefix / "lib")]
        env = dict(os.environ, TMPDIR=str(Path.home() / "tmp"),
                   LD_LIBRARY_PATH=str(prefix / "lib"))
        before = record.read_bytes()
        with (directory / "interrupted.log").open("wb") as log:
            daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    assert daemon.poll() is None, "daemon exited before interrupted hashing"
                    io = dict(line.split(": ") for line in Path(f"/proc/{daemon.pid}/io").read_text().splitlines())
                    if int(io["rchar"]) >= 8 * 1024 * 1024:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.001)
                assert not socket.exists(), "requests admitted before recovery completed"
                daemon.send_signal(signal.SIGTERM)
                assert daemon.wait(timeout=5) == 0
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait()
        assert "recovery interrupted" in (directory / "interrupted.log").read_text()
        assert record.read_bytes() == before and path.stat().st_ino == st.st_ino
        assert not socket.exists()
        with (directory / "restart.log").open("wb") as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=log, timeout=30)
        assert result.returncode == 0 and path.stat().st_ino == st.st_ino
        parsed = configparser.ConfigParser(interpolation=None, strict=True)
        parsed.read(record)
        if tombstones:
            assert parsed["tombstone"]["recovery_status"] == "MATCHED"
        else:
            assert parsed["transaction"]["state"] == "RETIRED"
            assert parsed["transaction"]["objects_status"] == "RECORDED"
        assert f"hashed_bytes={st.st_size + (0 if tombstones else ns.st_size)}" in (
            directory / "restart.log").read_text()
        # The sparse fixture is reproducible; keep records/logs, not large files.
        path.unlink()
        print(f"{directory.name}: interrupt/restart/no-admission PASS")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: test-recovery-cursor-startup.py PREFIX NEW_WORKDIR")
    run(*(Path(value).resolve() for value in sys.argv[1:]))
