#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile the real Meson version and AOT identity headers in isolation.

Requires Meson, Ninja, ccache and a native C compiler. This checks build/cache
semantics; it does not execute the LoongArch translator or an AOT workload.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def version_rules():
    meson = (ROOT / "meson.build").read_text()
    start = meson.index("latx_version = get_option('latx_version')")
    return meson[start:meson.index("# The path to glib.h", start)]


class VersionBuild:
    def __init__(self, directory, debug=False, rules=None, ordinary_count=1):
        self.source = directory / "source"
        self.build = directory / "build"
        self.source.mkdir(parents=True)
        compiler = f"{shutil.which('ccache')} {shutil.which('cc')}"
        self.env = dict(os.environ, CC=compiler,
                        CCACHE_DIR=str(directory / "cache"),
                        CCACHE_COMPILERCHECK="content")
        config = directory / "ccache.conf"
        config.write_text("direct_mode = true\n")
        self.env["CCACHE_CONFIGPATH"] = str(config)
        translator_directory = self.source / "translator"
        translator_directory.mkdir()
        self.translator = translator_directory / "translator.c"
        self.translator.write_text("int translator_input(void) { return 1; }\n")
        header = '#ifndef LATX_VERSION\n#include "latx-version.h"\n#endif\n'
        (self.source / "version.c").write_text(
            header + 'const char *version(void) { return LATX_VERSION; }\n')
        (self.source / "footer.c").write_text(
            '#include "aot-version.h"\n'
            'const char *footer(void) { return AOT_VERSION; }\n'
            'const char *build_id(void) { return LATX_AOT_BUILD_ID; }\n')
        (self.source / "main.c").write_text(
            '#include <stdio.h>\nconst char *version(void);\n'
            'const char *footer(void);\nconst char *build_id(void);\n'
            'int ordinary_0(void);\n'
            'int main(void) { printf("%s\\n%s\\n%s\\n%d\\n", '
            'version(), footer(), build_id(), ordinary_0()); return 0; }\n')
        sources = ["main.c", "version.c", "footer.c"]
        for index in range(ordinary_count):
            name = f"ordinary_{index}.c"
            (self.source / name).write_text(
                '#include <stdint.h>\n#include <stdlib.h>\n'
                '#include <string.h>\n'
                '#include <stdio.h>\n#include "qemu/queue.h"\n'
                f'int ordinary_{index}(void) {{ return 42; }}\n')
            sources.append(name)
        project = ("project('lat-version-probe', 'c', "
                   "default_options: ['buildtype=release'])\n")
        project += rules if rules is not None else version_rules()
        generator = ROOT / "scripts/gen-aot-build-id.py"
        project += (
            "python = import('python').find_installation()\n"
            "aot_build_id = custom_target('aot-build-id', "
            "input: 'translator/translator.c', "
            "output: 'latx-aot-build-id.h', "
            f"command: [python, '{generator}', "
            "'--root', meson.current_source_dir(), "
            "'--directory', 'translator', "
            "'--config', 'CONFIG_LATX_AVX_OPT=n', "
            "'--output', '@OUTPUT@'])\n")
        if debug:
            project += ("add_project_arguments('-DCONFIG_LATX_DEBUG', "
                        "language: 'c')\n")
        project += "executable('probe', aot_build_id, "
        project += ", ".join(repr(name) for name in sources)
        project += (", include_directories: "
                    "[include_directories('.'), "
                    f"include_directories('{ROOT / 'include'}'), "
                    f"include_directories('{ROOT / 'target/i386/latx/include'}')])\n")
        (self.source / "meson.build").write_text(project)
        (self.source / "meson_options.txt").write_text(
            "option('latx_version', type: 'string', value: '')\n")

    def run(self, *args):
        result = subprocess.run(
            args, env=self.env, cwd=self.source, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"{args!r}\n{result.stdout}")
        return result.stdout

    def configure(self, version, reconfigure=False):
        if reconfigure:
            time.sleep(1.1)
        args = ["meson", "setup"]
        if reconfigure:
            args.append("--reconfigure")
        return self.run(*args, str(self.build), str(self.source),
                        f"-Dlatx_version={version}")

    def compile(self):
        return self.run("ninja", "-C", str(self.build), "-j2")

    def output(self):
        return self.run(str(self.build / "probe")).splitlines()

    def build_id_header(self):
        return self.build / "latx-aot-build-id.h"

    def modify_translator(self):
        time.sleep(1.1)
        self.translator.write_text("int translator_input(void) { return 2; }\n")

    def modify_ordinary(self):
        time.sleep(1.1)
        ordinary = self.source / "ordinary_0.c"
        ordinary.write_text(ordinary.read_text().replace("return 42", "return 43"))

    def clean_objects(self):
        self.run("ninja", "-C", str(self.build), "-t", "clean")

    def reset_stats(self):
        self.run("ccache", "--zero-stats")

    def stats(self):
        result = subprocess.run(
            ("ccache", "--print-stats"), env=self.env, cwd=self.source,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            return {name: int(value) for name, value in
                    (line.split() for line in result.stdout.splitlines())}
        output = self.run("ccache", "--show-stats")
        direct = re.search(r"^cache hit \(direct\)\s+(\d+)$",
                           output, re.MULTILINE)
        if direct is None:
            raise RuntimeError(f"unable to parse ccache statistics\n{output}")
        return {"direct_cache_hit": int(direct.group(1))}


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("meson", "ninja", "ccache", "cc")),
    "requires meson, ninja, ccache and cc")
class VersionCacheTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="lat-version-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_version_change_keeps_unrelated_objects_in_incremental_build(self):
        fixture = VersionBuild(self.root)
        fixture.configure("version-a")
        fixture.compile()
        fixture.configure("version-b", reconfigure=True)
        output = fixture.compile()
        self.assertNotIn("ordinary_0.c.o", output)
        self.assertNotIn("main.c.o", output)
        result = fixture.output()
        self.assertEqual(result[0], "version-b")
        self.assertRegex(result[1], r"^Version: version-b-release-[0-9a-f]{20}$")
        self.assertEqual(result[3], "42")

    def test_clean_build_direct_hits_survive_version_change(self):
        fixture = VersionBuild(self.root)
        fixture.configure("version-a")
        fixture.compile()
        fixture.configure("version-b", reconfigure=True)
        fixture.clean_objects()
        fixture.reset_stats()
        fixture.compile()
        self.assertGreaterEqual(fixture.stats()["direct_cache_hit"], 2)
        self.assertEqual(fixture.output()[0], "version-b")

    def test_debug_and_release_footer_identity_remains_versioned(self):
        for debug, suffix in ((False, "release"), (True, "debug")):
            with self.subTest(debug=debug):
                fixture = VersionBuild(self.root / suffix, debug=debug)
                fixture.configure("old-version")
                fixture.compile()
                old_footer = fixture.output()[1]
                fixture.configure("new-version", reconfigure=True)
                fixture.compile()
                new_footer = fixture.output()[1]
                self.assertRegex(
                    old_footer,
                    rf"^Version: old-version-{suffix}-[0-9a-f]{{20}}$")
                self.assertRegex(
                    new_footer,
                    rf"^Version: new-version-{suffix}-[0-9a-f]{{20}}$")
                self.assertNotEqual(old_footer, new_footer)

    def test_incremental_translator_change_updates_aot_build_id(self):
        fixture = VersionBuild(self.root)
        fixture.configure("version-a")
        fixture.compile()
        old_output = fixture.output()
        fixture.modify_translator()
        output = fixture.compile()
        new_output = fixture.output()

        self.assertNotEqual(old_output[2], new_output[2])
        self.assertNotEqual(old_output[1], new_output[1])
        self.assertNotIn("ordinary_0.c.o", output)
        self.assertNotIn("main.c.o", output)

        header = fixture.build_id_header()
        header_mtime = header.stat().st_mtime_ns
        time.sleep(0.01)
        self.assertIn("no work to do", fixture.compile())
        self.assertEqual(fixture.output(), new_output)
        self.assertEqual(header.stat().st_mtime_ns, header_mtime)

    def test_unrelated_source_change_keeps_aot_build_id(self):
        fixture = VersionBuild(self.root)
        fixture.configure("version-a")
        fixture.compile()
        old_build_id = fixture.output()[2]
        header_mtime = fixture.build_id_header().stat().st_mtime_ns
        fixture.modify_ordinary()
        output = fixture.compile()

        self.assertIn("ordinary_0.c.o", output)
        self.assertEqual(fixture.output()[2], old_build_id)
        self.assertEqual(fixture.build_id_header().stat().st_mtime_ns,
                         header_mtime)


if __name__ == "__main__":
    unittest.main()
