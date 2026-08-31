#!/usr/bin/env python3
"""Verify staging runner adapters come from the canonical main LAT files."""

import subprocess
import sys
import tempfile
from pathlib import Path


def create_staging(root: Path) -> Path:
    (root / "linux-user").mkdir(parents=True)
    (root / "target/i386/latx/sbt").mkdir(parents=True)
    (root / ".latc-staging").touch()
    (root / "linux-user/meson.build").write_text("  'main.c',\n")
    (root / "target/i386/latx/sbt/meson.build").write_text(
        "  'aot.c',\n"
    )
    (root / "configure").write_text(
        '  QEMU_LDFLAGS="-lcrypto -lz $QEMU_LDFLAGS"\n'
    )
    return root


def prepare(script: Path, staging: Path, *arguments: str):
    return subprocess.run(
        [sys.executable, str(script), str(staging), *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} PREPARE_SCRIPT REPOSITORY_ROOT",
              file=sys.stderr)
        return 2
    script = Path(sys.argv[1]).resolve()
    repository = Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="latc-runner-staging-") as temp:
        staging = create_staging(Path(temp) / "source")
        completed = prepare(script, staging)
        assert completed.returncode == 0, completed.stdout
        for relative in (
            "linux-user/main.c",
            "linux-user/latc-aot-v2-runner.c",
            "accel/tcg/cpu-exec.c",
            "include/exec/fasttb.h",
            "target/i386/latx/sbt/latc_native_export.c",
        ):
            assert (staging / relative).read_bytes() == (
                repository / relative
            ).read_bytes(), relative

        without = create_staging(Path(temp) / "source-without-aot-v2")
        completed = prepare(script, without, "--without-aot-v2")
        assert completed.returncode == 0, completed.stdout
        assert (without / "linux-user/latc-aot-v2-runner.c").read_bytes() == (
            repository /
            "tools/latc/lat/linux-user/latc-aot-v2-runner-stub.c"
        ).read_bytes()

    print("test-prepare-runner-source: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
