#!/usr/bin/env python3
"""Exercise offline object-hold commands in disposable private cache roots."""

import configparser
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid


LATCD = Path(sys.argv.pop(1)).resolve()
SOURCE = "a" * 64
NAME = SOURCE + "-" + "b" * 64 + ".native"


class ObjectHoldTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home() / "tmp",
                                                     prefix="object-hold-")
        self.root = Path(self.temporary.name)
        self.obj = self.root / NAME
        self.obj.write_bytes(b"immutable baseline")
        self.obj.chmod(0o400)
        self.hold_id = str(uuid.uuid4())

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, release=False, expected=0, **overrides):
        options = dict(cache_dir=self.root, source=SOURCE, name=NAME,
                       hold_id=self.hold_id, reason="ROLLBACK")
        options.update(overrides)
        args = [str(LATCD), "gc", "--release-object-hold" if release else "--hold-object"]
        for key, value in options.items():
            if value is not None:
                args.extend(["--" + key.replace("_", "-"), str(value)])
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def record(self, hold_id=None):
        path = self.root / ".gc/holds" / NAME / ((hold_id or self.hold_id) + ".ini")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read(path)
        return path, parser["hold"]

    def test_create_repeat_release_and_plan(self):
        before = self.obj.stat()
        self.command()
        path, value = self.record()
        self.assertEqual(value["state"], "ACTIVE")
        self.assertEqual(int(value["object_inode"]), before.st_ino)
        self.assertEqual(int(value["cache_inode"]), self.root.stat().st_ino)
        self.assertFalse(path.stat().st_mode & 0o222)
        original = path.read_bytes()
        self.command()
        self.assertEqual(path.read_bytes(), original)
        plan = subprocess.run([str(LATCD), "gc", "--plan", "--cache-dir", str(self.root)],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(plan.returncode, 0, plan.stderr + plan.stdout)
        report = json.loads(plan.stdout)
        self.assertFalse(report["delete_authorized"])
        self.assertEqual(report["explicit_hold_count"], 1)
        self.assertTrue(next(iter(report["explicit_holds"].values()))["binding_observed"])
        self.command(release=True)
        self.assertEqual(self.record()[1]["state"], "RELEASED")
        released = path.read_bytes()
        self.command(release=True)
        self.command(expected=1)
        self.assertEqual(path.read_bytes(), released)
        self.assertEqual(self.obj.read_bytes(), b"immutable baseline")
        after = self.obj.stat()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))

    def test_multiple_holders_and_exact_release(self):
        self.command()
        original = self.record()[0].read_bytes()
        self.command(release=True, expected=1, reason="MIGRATION")
        self.command(release=True, expected=1, hold_id=str(uuid.uuid4()))
        self.assertEqual(self.record()[0].read_bytes(), original)
        other = str(uuid.uuid4())
        self.command(hold_id=other, reason="MIGRATION")
        self.command(release=True)
        self.assertEqual(self.record(other)[1]["state"], "ACTIVE")
        self.command(release=True, hold_id=other, reason="MIGRATION")
        third = str(uuid.uuid4())
        self.command(hold_id=third, reason="EXTERNAL")
        self.assertEqual(self.record(third)[1]["state"], "ACTIVE")

    def test_owner_busy_preserves_record_and_owner(self):
        self.command()
        path = self.record()[0]
        original = path.read_bytes()
        owner = self.root / ".latcd.lock"
        with owner.open("rb") as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner_before = owner.read_bytes()
            result = self.command(release=True, expected=1)
            self.assertIn("already owned", result.stderr)
            self.assertEqual(owner.read_bytes(), owner_before)
        self.assertEqual(path.read_bytes(), original)

    def test_source_busy(self):
        self.command()
        original = self.record()[0].read_bytes()
        latch = self.root / ".gc/source-locks" / (SOURCE + ".lock")
        with latch.open("rb") as fd:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.command(release=True, expected=1)
        self.assertEqual(self.record()[0].read_bytes(), original)

    def test_replaced_object_cannot_release_old_hold(self):
        self.command()
        path = self.record()[0]
        original = path.read_bytes()
        self.obj.rename(self.root / "old-inode")
        self.obj.write_bytes(b"different inode")
        self.obj.chmod(0o400)
        self.command(release=True, expected=1)
        self.assertEqual(path.read_bytes(), original)

    def test_tombstone_rejects_new_hold(self):
        store = self.root / ".gc/tombstones"
        store.mkdir(mode=0o700, parents=True)
        (store / NAME).write_bytes(b"intent")
        self.command(expected=1)
        self.assertFalse((self.root / ".gc/holds" / NAME / (self.hold_id + ".ini")).exists())

    def test_unsafe_objects(self):
        for kind in ("writable", "hardlink", "symlink", "missing", "empty"):
            with self.subTest(kind=kind):
                if self.obj.exists() or self.obj.is_symlink():
                    self.obj.unlink()
                self.obj.write_bytes(b"fixture")
                self.obj.chmod(0o400)
                alias = self.root / (kind + "-alias")
                if kind == "writable":
                    self.obj.chmod(0o600)
                elif kind == "hardlink":
                    os.link(self.obj, alias)
                elif kind == "symlink":
                    self.obj.rename(alias)
                    self.obj.symlink_to(alias.name)
                elif kind == "missing":
                    self.obj.unlink()
                else:
                    self.obj.unlink()
                    self.obj.touch(mode=0o400)
                self.command(expected=1)

    def test_invalid_arguments(self):
        for options in (dict(reason="UNKNOWN"), dict(hold_id="../invalid"),
                        dict(source="b" * 64), dict(name="../" + NAME)):
            self.command(expected=1, **options)
        self.command(reason=None, expected=2)
        self.command(scope="CACHE", expected=2)
        self.command(lease_id=self.hold_id, expected=2)
        self.command(hold_object="duplicate", expected=2)
        for mode in ("--plan", "--domain-status", "--init-domain"):
            result = subprocess.run([str(LATCD), "gc", mode, "--cache-dir", str(self.root),
                                     "--hold-id", self.hold_id], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)

    def test_missing_or_shared_root_is_not_created_or_chmodded(self):
        missing = self.root / "missing"
        self.command(cache_dir=missing, expected=1)
        self.assertFalse(missing.exists())
        self.root.chmod(0o755)
        self.command(expected=1)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
        self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
