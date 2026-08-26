#!/usr/bin/env python3
"""Install latc runner adapters into a matching full LAT source tree."""

import argparse
import json
import shutil
from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if new and new in text:
        return
    if old not in text:
        if not new:
            return
        raise SystemExit(f"expected text not found in {path}: {old!r}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lat_source", type=Path)
    parser.add_argument("--without-aot-v2", action="store_true")
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
        "include/latc-aot-v2-runner.h",
        "include/exec/fasttb.h",
        "accel/tcg/cpu-exec.c",
        "accel/tcg/translate-all.c",
        "linux-user/latc-bundle-loader.c",
        "linux-user/latc-bundle-loader.h",
        "linux-user/elfload.c",
        "linux-user/main.c",
        "linux-user/mmap.c",
        "linux-user/signal.c",
        "linux-user/syscall.c",
        "target/i386/latx/sbt/aot_recover_tb.c",
        "target/i386/latx/sbt/aot.c",
        "target/i386/latx/sbt/latc_native_export.c",
        "target/i386/latx/sbt/latc_native_export.h",
        "target/i386/latx/latx-config.c",
        "target/i386/cpu.h",
        "target/i386/latx/include/lsenv.h",
        "target/i386/latx/translator/translate.c",
    ):
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local / relative, destination)

    aot_adapter = ("latc-aot-v2-runner-stub.c" if args.without_aot_v2 else
                   "latc-aot-v2-runner.c")
    shutil.copy2(local / "linux-user" / aot_adapter,
                 source / "linux-user/latc-aot-v2-runner.c")

    native_image_header = (Path(__file__).resolve().parents[1] /
                           "native/include/lat-native-image.h")
    shutil.copy2(native_image_header, source / "lat-native-image.h")
    shutil.copy2(native_image_header, source / "include/lat-native-image.h")
    shutil.copy2(Path(__file__).resolve().parents[1] /
                 "native/include/latc-x86-syscall-abi.h",
                 source / "include/latc-x86-syscall-abi.h")
    shutil.copy2(Path(__file__).resolve().parents[1] /
                 "aot-v2/include/lat-aot-v2.h",
                 source / "include/lat-aot-v2.h")
    shutil.copy2(Path(__file__).resolve().parents[1] /
                 "aot-v2/include/latcd-protocol.h",
                 source / "include/latcd-protocol.h")
    shutil.copy2(Path(__file__).resolve().parents[1] /
                 "aot-v2/runtime/registry.h",
                 source / "include/registry.h")
    shutil.copy2(Path(__file__).resolve().parents[1] /
                 "aot-v2/runtime/module-loader.h",
                 source / "include/module-loader.h")
    for name in ("guest-elf-map.c", "guest-elf-map.h",
                 "latcd-client.c", "latcd-client.h"):
        shutil.copy2(Path(__file__).resolve().parents[1] /
                     "aot-v2/runtime" / name,
                     source / "linux-user" / name)
    manifest = json.loads((Path(__file__).resolve().parents[1] /
                           "lat-import.json").read_text())
    build_id = f"lat-{manifest['source_commit']}-x64-v3"
    (source / "include/latc-build-id.h").write_text(
        "#ifndef LATC_BUILD_ID_H\n#define LATC_BUILD_ID_H\n"
        f"#define LATC_BUILD_ID \"{build_id}\"\n#endif\n"
    )

    replace_once(source / "linux-user/meson.build",
                 "  'main.c',\n",
                 "  'main.c',\n  'latc-bundle-loader.c',\n")
    replace_once(source / "linux-user/meson.build",
                 "  'latc-bundle-loader.c',\n",
                 "  'latc-bundle-loader.c',\n"
                 "  'guest-elf-map.c',\n"
                 "  'latcd-client.c',\n"
                 "  'latc-aot-v2-runner.c',\n")
    replace_once(source / "target/i386/latx/sbt/meson.build",
                 "  'aot.c',\n", "  'aot.c',\n  'latc_native_export.c',\n")
    # The minimal static linux-user runner uses neither OpenSSL nor zlib.
    replace_once(source / "configure",
                 '  QEMU_LDFLAGS="-lcrypto -lz $QEMU_LDFLAGS"\n', "")


if __name__ == "__main__":
    main()
