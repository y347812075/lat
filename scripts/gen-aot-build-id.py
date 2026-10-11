#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import hashlib
import os
import tempfile
from pathlib import Path


SOURCE_SUFFIXES = {".c", ".h", ".inc"}


def source_files(root, directories, exclude_directories):
    paths = []
    excluded = [(root / directory).resolve() for directory in exclude_directories]
    for directory in directories:
        base = (root / directory).resolve()
        for path in base.rglob("*"):
            if (
                path.is_file()
                and path.suffix in SOURCE_SUFFIXES
                and not any(path == directory or directory in path.parents
                            for directory in excluded)
            ):
                paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def build_id(root, paths, configs):
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    for config in sorted(configs):
        digest.update(config.encode())
        digest.update(b"\0")
    return digest.hexdigest()[:20]


def write_if_changed(output, content):
    if output.exists() and output.read_text() == content:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=output.parent, prefix=output.name + ".")
    try:
        with os.fdopen(fd, "w") as temporary:
            temporary.write(content)
        os.replace(name, output)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--directory", action="append", default=[])
    parser.add_argument("--exclude-directory", action="append", default=[])
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--print-inputs", action="store_true")
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    paths = source_files(root, arguments.directory, arguments.exclude_directory)
    if arguments.print_inputs:
        for path in paths:
            print(path.relative_to(root).as_posix())
        return
    if arguments.output is None:
        parser.error("--output is required unless --print-inputs is used")

    identity = build_id(root, paths, arguments.config)
    content = f'#define LATX_AOT_BUILD_ID "{identity}"\n'
    write_if_changed(arguments.output, content)


if __name__ == "__main__":
    main()
