#!/usr/bin/env python3
"""Exercise installed daemon startup reconciliation in an isolated cache."""

import configparser
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def run(prefix, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / "tmp"),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    source = "a" * 64
    name = source + ".native"
    for case in ("matched", "missing", "replaced", "content", "hardlink",
                 "symlink", "current", "busy", "corrupt"):
        directory = work / case
        directory.mkdir(mode=0o700)
        cache = directory / "cache"
        store = cache / ".gc/tombstones"
        store.mkdir(mode=0o700, parents=True)
        cache.chmod(0o700)
        (cache / ".gc").chmod(0o700)
        path = cache / name
        data = b"immutable retired native fixture\n"
        path.write_bytes(data)
        path.chmod(0o400)
        st = path.stat()
        record = configparser.ConfigParser(interpolation=None)
        record["tombstone"] = dict(version="1", source=source, name=name,
            state="DELETING", device=str(st.st_dev), inode=str(st.st_ino),
            size=str(st.st_size), allocated=str(st.st_blocks * 512),
            sha256=hashlib.sha256(data).hexdigest())
        marker = store / name
        with marker.open("w") as stream:
            record.write(stream, space_around_delimiters=False)
        marker.chmod(0o400)
        expected = "MATCHED"
        lease = None
        if case == "missing":
            path.unlink()
            expected = "MISSING"
        elif case == "replaced":
            temporary = cache / "replacement"
            temporary.write_bytes(data)
            temporary.chmod(0o400)
            temporary.replace(path)
            expected = "UNKNOWN"
        elif case == "content":
            path.chmod(0o600)
            path.write_bytes(b"X" + data[1:])
            path.chmod(0o400)
            expected = "UNKNOWN"
        elif case == "hardlink":
            os.link(path, cache / "alias")
            expected = "UNKNOWN"
        elif case == "symlink":
            path.rename(cache / "original")
            path.symlink_to("original")
            expected = "UNKNOWN"
        elif case == "current":
            manifest = dict(version=2, module=source + ".so", native=name,
                tbset="", source_sha256=source, codegen_id=source, published_sequence=1)
            current = cache / (source + ".current")
            current.write_text(json.dumps(manifest))
            current.chmod(0o400)
            expected = "UNKNOWN"
        elif case == "busy":
            lease = path.open("rb")
            fcntl.flock(lease, fcntl.LOCK_SH)
            expected = "BUSY"
        elif case == "corrupt":
            marker.chmod(0o600)
            marker.write_bytes(b"[tombstone]\nversion=1\nversion=1\n")
            marker.chmod(0o400)
        before = {p.name: p.read_bytes() for p in cache.glob("*.current")}
        arguments = [str(prefix / "bin/latcd"), "--serve", "--idle-seconds", "1",
            "--socket", str(directory / "d.sock"), "--cache-dir", str(cache),
            "--latc", str(prefix / "bin/latc"), "--runner", str(prefix / "bin/latx-x86_64"),
            "--runtime-dir", str(prefix / "lib")]
        for attempt in range(2):
            with (directory / f"daemon-{attempt}.log").open("wb") as log:
                result = subprocess.run(arguments, env=env, stdout=log, stderr=log, timeout=20)
            assert result.returncode == (1 if case == "corrupt" else 0), case
            assert before == {p.name: p.read_bytes() for p in cache.glob("*.current")}
            assert path.exists() == (case != "missing")
            if case != "corrupt":
                observed = configparser.ConfigParser(interpolation=None, strict=True)
                observed.read(marker)
                assert observed["tombstone"]["recovery_status"] == expected, case
                assert observed["tombstone"]["state"] == "DELETING"
        if lease:
            lease.close()
        with (directory / "plan.json").open("wb") as output:
            plan_result = subprocess.run([str(prefix / "bin/latcd"), "gc", "--plan",
                "--cache-dir", str(cache)], env=env, stdout=output, timeout=20)
        assert plan_result.returncode == 1, case
        plan = json.loads((directory / "plan.json").read_bytes())
        assert not plan["delete_authorized"]
        if case != "corrupt":
            assert plan["tombstones"][".gc/tombstones/" + name]["recovery_status"] == expected
        else:
            assert plan["tombstone_count"] == 0
        print(f"{case}: startup/repeat/no-unlink PASS")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: test-tombstone-recovery.py PREFIX NEW_WORKDIR")
    run(*(Path(value).resolve() for value in sys.argv[1:]))
