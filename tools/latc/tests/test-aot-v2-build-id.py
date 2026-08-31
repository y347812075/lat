#!/usr/bin/env python3
"""Regression tests for the deterministic AOT v2 product identity."""

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts/compute-aot-v2-build-id.py"
SPEC = importlib.util.spec_from_file_location("aot_v2_build_id", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    (root / "linux-user").mkdir()
    (root / "tools/latc/aot-v2/runtime").mkdir(parents=True)
    (root / "linux-user/main.c").write_text("one\n")
    (root / "tools/latc/aot-v2/runtime/runtime.c").write_text("two\n")
    first = MODULE.compute(root)
    assert first == MODULE.compute(root)
    assert len(first) == 64

    (root / "linux-user/main.c").write_text("changed\n")
    assert MODULE.compute(root) != first
    changed = MODULE.compute(root)

    (root / "build-junk").mkdir()
    (root / "build-junk/generated.c").write_text("ignored\n")
    (root / "tools/latc/aot-v2/tests").mkdir()
    (root / "tools/latc/aot-v2/tests/fixture.c").write_text("ignored\n")
    for name in MODULE.GENERATED_SOURCE_PATHS:
        generated = root / name
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text("configure output\n")
    assert MODULE.compute(root) == changed

    header = root / "identity.h"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--header", str(header), str(root)],
        check=True,
    )
    assert f'#define LATC_BUILD_ID "{changed}"' in header.read_text()
    listed = subprocess.check_output(
        [sys.executable, str(SCRIPT), "--list", str(root)], text=True
    ).splitlines()
    assert listed == [
        "linux-user/main.c",
        "tools/latc/aot-v2/runtime/runtime.c",
    ]

print("aot-v2-build-id: PASS")
