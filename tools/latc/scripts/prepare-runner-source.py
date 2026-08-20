#!/usr/bin/env python3
"""Install latc runner adapters into a matching full LAT source tree."""

import argparse
import shutil
from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"expected text not found in {path}: {old!r}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lat_source", type=Path)
    args = parser.parse_args()
    source = args.lat_source.resolve()
    local = Path(__file__).resolve().parents[1] / "lat"
    if not (source / ".latc-staging").is_file():
        raise SystemExit(
            "refusing to modify a LAT checkout: prepare a staging copy with "
            "build-runner.sh"
        )

    for relative in (
        "include/latc-bundle-format.h",
        "accel/tcg/translate-all.c",
        "linux-user/latc-bundle-loader.c",
        "linux-user/latc-bundle-loader.h",
        "linux-user/main.c",
    ):
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local / relative, destination)

    replace_once(source / "linux-user/meson.build",
                 "  'main.c',\n", "  'main.c',\n  'latc-bundle-loader.c',\n")
    # The minimal static linux-user runner uses neither OpenSSL nor zlib.
    replace_once(source / "configure",
                 '  QEMU_LDFLAGS="-lcrypto -lz $QEMU_LDFLAGS"\n', "")


if __name__ == "__main__":
    main()
