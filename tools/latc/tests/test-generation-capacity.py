#!/usr/bin/env python3
"""Exercise indexed publication reservations in an isolated real daemon."""

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
    cache = work / "cache"
    socket = work / "daemon.sock"
    stats = work / "stats.json"
    marker = work / "fail-before-manifest"
    env = dict(os.environ, TMPDIR=str(Path.home() / "tmp"),
               LATCD_COMPILE_TMPDIR=str(work), LATCD_TEST_FAIL_BEFORE_MANIFEST=str(marker),
               LD_LIBRARY_PATH=str(prefix / "lib"))
    latcd = prefix / "bin/latcd"
    first, full = work / "first.tbset", work / "full.tbset"
    subprocess.run([sys.executable, str(Path(__file__).with_name("make-tbset.py")),
                    str(guest), str(first)], env=env, check=True)
    subprocess.run([str(prefix / "bin/latc"), "emit-static-tbset", str(guest),
                    "-o", str(full)], env=env, check=True)
    command = [str(latcd), "--serve", "--socket", str(socket), "--cache-dir", str(cache),
               "--latc", str(prefix / "bin/latc"), "--runner", str(prefix / "bin/latx-x86_64"),
               "--runtime-dir", str(prefix / "lib"), "--stats", str(stats), "--negative-ms", "1"]

    def client(label, selected, source, success):
        for operation, extra in (("submit", ["--tbset", str(selected)]), ("flush-source", [])):
            result = subprocess.run([str(latcd), "--" + operation, "--socket", str(socket),
                                     *extra, str(source)], env=env, capture_output=True, timeout=120)
            (work / f"{label}-{operation}.log").write_bytes(result.stdout + result.stderr)
            assert (result.returncode == 0) == (success or operation == "submit"), result.stdout

    def settled(compiled, failed):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = json.loads(stats.read_bytes())
            if value["compiled"] == compiled and value["failed"] == failed and not value["active_jobs"]:
                assert value["publication_reserved_bytes"] == 0, value
                assert value["compiler_peak_reserved_bytes"] == 0, value
                return value
            time.sleep(0.01)
        raise AssertionError("worker statistics did not settle")

    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    current = cache / (source + ".current")
    with (work / "daemon.log").open("wb") as log:
        daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            client("baseline", first, guest, True)
            baseline_stats = settled(1, 0)
            original = current.read_bytes()
            value = json.loads(original)
            preserved = {name: (cache / name).read_bytes() for name in
                         (value[role] for role in ("module", "native", "tbset"))}
            marker.touch()
            client("injected", full, guest, False)
            failed_stats = settled(1, 1)
            assert not marker.exists() and current.read_bytes() == original
            assert all((cache / name).read_bytes() == data for name, data in preserved.items())
            assert failed_stats["generation_logical_bytes"] == baseline_stats["generation_logical_bytes"]
            assert failed_stats["generation_capacity_ready"]
            time.sleep(0.02)
            client("retry", full, guest, True)
            after = settled(2, 1)
            assert after["generation_capacity_ready"] and current.read_bytes() != original
            generated = [p for p in cache.iterdir() if p.suffix in {".so", ".native", ".tbset"}]
            unique = {(p.stat().st_dev, p.stat().st_ino): p.stat().st_size for p in generated}
            assert after["generation_logical_bytes"] == sum(unique.values()), after
            deadline = time.monotonic() + 15
            while True:
                observed = json.loads(stats.read_bytes())
                assert not observed['automatic_deletion_enabled'], observed
                if observed['retirement_discovery_complete'] and observed['retirement_candidates']:
                    assert observed['retirement_publication_wakeups'], observed
                    assert not observed['retirement_due_candidates'], observed
                    assert observed['retirement_next_deadline_boottime_us'], observed
                    assert observed['retirement_next_attempt_boottime_us'] == observed['retirement_next_deadline_boottime_us'], observed
                    assert not observed['retirement_ready_candidates'] and not observed['retirement_deferred_candidates'], observed
                    break
                assert daemon.poll() is None and time.monotonic() < deadline, observed
                time.sleep(.05)
            result = subprocess.run([str(prefix / "bin/latx-x86_64"), str(guest)],
                env=dict(env, LATX_AOT="0", LATX_AOT_V2="1", LATX_AOT_V2_CACHE_DIR=str(cache),
                         LATX_AOT_V2_AUTOSTART="0", LATC_STRICT_FILE_AOT="1",
                         LATC_DISABLE_PRETRANSLATE="1"), capture_output=True, timeout=30)
            (work / "strict.log").write_bytes(result.stdout + result.stderr)
            assert result.returncode == 42
            checkpoint = cache / '.gc/retirement-scheduler.ini'
            saved = configparser.ConfigParser()
            saved.read(checkpoint)
            ages = {name: saved[name]['enqueued'] for name in saved.sections() if name != 'queue'}
            assert ages
            checkpoint_inode = checkpoint.stat().st_ino
            daemon.terminate()
            assert daemon.wait(timeout=20) == 0
            # Move grace deadlines near the present only in this stopped,
            # isolated cache. Production grace remains unchanged at 600s.
            now_us = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000
            assert now_us > 600_000_000
            for transaction in (cache / '.gc/transactions').glob('*.ini'):
                record = configparser.ConfigParser()
                record.read(transaction)
                if record['transaction']['state'] == 'RETIRED':
                    record['transaction']['retired_boottime_us'] = str(now_us - 596_000_000)
                    mode = transaction.stat().st_mode & 0o777
                    transaction.chmod(0o600)
                    try:
                        with transaction.open('w') as stream:
                            record.write(stream, space_around_delimiters=False)
                    finally:
                        transaction.chmod(mode)
            stats.unlink()
            daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 20
            while True:
                observed = json.loads(stats.read_bytes()) if stats.exists() else {}
                if observed.get('retirement_discovery_complete'):
                    assert observed['retirement_candidates'] == len(ages), observed
                    assert not observed['automatic_deletion_enabled'], observed
                    recovered = configparser.ConfigParser()
                    recovered.read(checkpoint)
                    assert ages == {name: recovered[name]['enqueued'] for name in
                                    recovered.sections() if name != 'queue'}
                    assert checkpoint.stat().st_ino == checkpoint_inode
                    assert not observed['retirement_due_candidates'], observed
                    break
                assert daemon.poll() is None and time.monotonic() < deadline, observed
                time.sleep(.05)
            deadline = time.monotonic() + 15
            while True:
                observed = json.loads(stats.read_bytes())
                assert not observed['requests'] and not observed['automatic_deletion_enabled'], observed
                if observed['retirement_timer_wakeups'] and observed['retirement_due_candidates']:
                    assert observed['retirement_discovery_complete'], observed
                    assert observed['retirement_ready_candidates'] == observed['retirement_due_candidates'], observed
                    assert not observed['retirement_deferred_candidates'], observed
                    break
                assert daemon.poll() is None and time.monotonic() < deadline, observed
                time.sleep(.05)
            updated = current.read_bytes()
            orphan = cache / ("b" * 64 + "-" + "c" * 64 + ".native")
            orphan.write_bytes(b"external generation")
            second = work / "second.elf"
            second.write_bytes(guest.read_bytes() + b"new source identity")
            second.chmod(0o700)
            second_keys = work / "second.tbset"
            subprocess.run([sys.executable, str(Path(__file__).with_name("make-tbset.py")),
                            str(second), str(second_keys)], env=env, check=True)
            client("external-change", second_keys, second, False)
            rejected = settled(0, 1)
            assert not rejected["generation_capacity_ready"]
            assert current.read_bytes() == updated and orphan.read_bytes() == b"external generation"
            assert b"capacity:" in (work / "daemon.log").read_bytes()
        finally:
            if daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
            assert daemon.wait(timeout=20) == 0
    limited = work / 'limited-cache'
    limited_socket = work / 'limited.sock'
    limited_command = command.copy()
    limited_command[limited_command.index(str(cache))] = str(limited)
    limited_command[limited_command.index(str(socket))] = str(limited_socket)
    with (work / 'limited.log').open('wb') as log:
        daemon = subprocess.Popen(limited_command + ['--max-cache-bytes', '4194304'],
                                  env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while not limited_socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            result = subprocess.run([str(latcd), '--submit', '--socket', str(limited_socket),
                                     '--tbset', str(first), str(guest)], env=env,
                                    capture_output=True, timeout=30)
            assert result.returncode == 0
            result = subprocess.run([str(latcd), '--flush-source', '--socket', str(limited_socket),
                                     str(guest)], env=env, capture_output=True, timeout=30)
            assert result.returncode != 0
            assert not list(limited.glob('*.current'))
            assert not list((limited / '.gc/tasks').glob('*.ini'))
            assert b'capacity:' in (work / 'limited.log').read_bytes()
        finally:
            daemon.terminate()
            assert daemon.wait(timeout=20) == 0
    print("generation-capacity: publication/retry/index/strict42/scheduler-restart/idle-deadline/compiler-peak-admission PASS")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: test-generation-capacity.py PREFIX X86_EXIT42 NEW_WORKDIR")
    run(*(Path(value).resolve() for value in sys.argv[1:]))
