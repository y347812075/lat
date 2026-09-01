#!/usr/bin/env python3
"""Regression test for per-application AOT coverage accounting."""

import json
import pathlib
import subprocess
import sys
import tempfile


checker = pathlib.Path(sys.argv[1]).resolve()
source = "a" * 64
runtime = (
    "latx: AOT v2 runtime stats direct_targets=0 "
    "compiler_submissions=0 compiler_submission_failures=0\n")

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    (root / "python.stderr").write_text(
        runtime + "latx: AOT v2 module stats source=%s range=0x1-0x2 "
        "module=registered aot_lookups=999 jit_fallbacks=1 "
        "registration_ns=1\n" % source)
    (root / "sqlite.stderr").write_text(
        runtime + "latx: AOT v2 module stats source=%s range=0x1-0x2 "
        "module=missing aot_lookups=0 jit_fallbacks=10 "
        "registration_ns=0\n" % source)
    (root / "redis-first.stderr").write_text(
        runtime + "latx: AOT v2 fork child switched to JIT\n" +
        "latx: AOT v2 module stats source=%s range=0x1-0x2 "
        "module=registered aot_lookups=10 jit_fallbacks=0 "
        "registration_ns=1\n" % source)

    success = subprocess.run(
        [sys.executable, checker, root, "99.9", "python"], check=False)
    assert success.returncode == 0
    python_result = json.loads(
        (root / "python-aot-coverage.json").read_text())
    assert python_result["aot_percent"] == 99.9
    assert python_result["sources"][source]["jit_fallbacks"] == 1

    failure = subprocess.run(
        [sys.executable, checker, "--require-no-fork-jit", root, "99.9",
         "sqlite", "redis"], check=False)
    assert failure.returncode == 1
    sqlite_result = json.loads(
        (root / "sqlite-aot-coverage.json").read_text())
    redis_result = json.loads(
        (root / "redis-aot-coverage.json").read_text())
    assert "coverage below requirement" in sqlite_result["failure_reasons"]
    assert "fork child switched to JIT" in redis_result["failure_reasons"]

print("test-check-aot-v2-coverage: PASS")
