#!/usr/bin/env python3
"""Exercise the read-only planner without opening any user cache."""

import importlib.util
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


LATCD = Path(sys.argv.pop(1)).resolve()
SOURCE = "a" * 64
OTHER = "b" * 64
STEM = SOURCE + "-" + "c" * 64
SPEC = importlib.util.spec_from_file_location(
    "cache_gc", Path(__file__).resolve().parents[1] / "latcd/cache_gc.py")
GC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GC)


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home() / "tmp",
                                                    prefix="gc-plan-test-")
        self.root = Path(self.temporary.name)
        self.manifest = dict(version=2, module=STEM + ".so", native=STEM + ".native",
                             tbset=STEM + ".tbset", source_sha256=SOURCE,
                             codegen_id="d" * 64, published_sequence=7)
        for suffix in (".so", ".native", ".tbset"):
            self.put(STEM + suffix, b"fixture")
        self.write_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def put(self, name, data):
        p = self.root / name
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (p.parent, *p.parent.parents):
            parent.mkdir(mode=0o700, exist_ok=True)
            parent.chmod(0o700)
            if parent == self.root:
                break
        if p.exists():
            p.chmod(0o600)
        p.write_bytes(data)
        p.chmod(0o400)
        return p

    def write_manifest(self, raw=None):
        self.put(SOURCE + ".current", raw if raw is not None else
                 json.dumps(self.manifest).encode())

    def run_plan(self, success=True):
        before = self.snapshot()
        result = subprocess.run([str(LATCD), "gc", "--plan", "--cache-dir", str(self.root)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0 if success else 1,
                         result.stderr + "\n" + result.stdout)
        self.assertEqual(before, self.snapshot(), "planner changed cache contents")
        plan = json.loads(result.stdout)
        self.assertFalse(plan["delete_authorized"])
        self.assertFalse(plan["snapshot_atomic"])
        self.assertFalse(plan["content_validated"])
        self.assertTrue(all(not x["delete_authorized"] for x in plan["entries"]))
        return plan

    def snapshot(self):
        result = {}
        for p in self.root.rglob("*"):
            st = p.lstat()
            result[str(p.relative_to(self.root))] = (st.st_ino, st.st_size,
                st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink)
        return result

    def test_current_and_inventory(self):
        self.put(".superseded/legacy/" + STEM + ".so", b"old")
        self.put(".tmp/part.native", b"work")
        self.put(".tbsets/" + SOURCE + ".tbset", b"keys")
        self.put(".gc/notes", b"opaque lifecycle metadata")
        plan = self.run_plan()
        rows = {r["path"]: r for r in plan["entries"]}
        self.assertEqual(plan["manifest_count"], 1)
        self.assertIn("incremental_baseline", rows[STEM + ".native"]["reasons"])
        self.assertEqual(rows[".superseded/legacy/" + STEM + ".so"]["category"], "legacy_retired")
        self.assertEqual(rows[".tmp/part.native"]["category"], "temporary")
        self.assertEqual(rows[".gc/notes"]["category"], "gc_metadata")

    def test_transaction_roots_and_corruption(self):
        previous = dict(self.manifest, module=SOURCE + ".so", native=SOURCE + ".native")
        for suffix in (".so", ".native"):
            self.put(SOURCE + suffix, b"previous generation")
        path = ".gc/transactions/12345678-1234-4234-8234-123456789abc.ini"
        record = ("[transaction]\nversion=1\nsource=" + SOURCE +
                  "\nstate=RETIRED\nprevious=" +
                  base64.b64encode(json.dumps(previous).encode()).decode() +
                  "\nnext=" + base64.b64encode(json.dumps(self.manifest).encode()).decode() + "\n")
        self.put(path, record.encode())
        plan = self.run_plan()
        self.assertEqual(plan["transaction_count"], 1)
        rows = {r["path"]: r for r in plan["entries"]}
        self.assertEqual(rows[SOURCE + ".native"]["category"], "transaction_artifact")
        self.assertEqual(rows[SOURCE + ".native"]["transaction_references"][0]["state"], "RETIRED")
        self.put(path, record.replace("version=1", "version=1\nversion=2").encode())
        plan = self.run_plan(False)
        self.assertTrue(any(e["reason"] == "invalid_transaction" for e in plan["errors"]))

    def test_object_evidence_schema(self):
        name = STEM + ".native"
        st = (self.root / name).stat()
        evidence = "[objects]\ncount=3\n"
        for i, role in enumerate(("native", "module", "tbset")):
            obj = self.root / self.manifest[role]
            status = obj.stat()
            evidence += (f"[object{i}]\nname={obj.name}\ndevice={status.st_dev}" +
                         f"\ninode={status.st_ino}\nsize={status.st_size}" +
                         f"\nallocated={status.st_blocks * 512}\nsha256=" + "e" * 64 + "\n")
        path = ".gc/transactions/12345678-1234-4234-8234-123456789abc.ini"
        record = ("[transaction]\nversion=2\nsource=" + SOURCE +
                  "\nstate=RETIRED\nprevious=\nnext=" +
                  base64.b64encode(json.dumps(self.manifest).encode()).decode() +
                  "\nobjects=" + base64.b64encode(evidence.encode()).decode() +
                  "\nobjects_status=RECORDED\n")
        self.put(path, record.encode())
        plan = self.run_plan()
        self.assertEqual(plan["transactions"][path]["object_identities"][0]["inode"], st.st_ino)
        self.assertTrue(plan["transactions"][path]["binding_verified"])
        # Recorded evidence is deliberately not a claim of current content validity.
        self.assertFalse(plan["content_validated"])
        for bad in (evidence.replace("count=3", "count=7"),
                    evidence.replace(name, "../escape.native"),
                    evidence.replace("inode=", "unexpected="),
                    evidence.replace("size=" + str(st.st_size), "size=-1"),
                    evidence.replace(self.manifest["module"], name),
                    evidence.replace(self.manifest["module"], SOURCE + ".so")):
            changed = record.replace(base64.b64encode(evidence.encode()).decode(),
                                     base64.b64encode(bad.encode()).decode())
            self.put(path, changed.encode())
            self.run_plan(False)

    def test_missing_target(self):
        (self.root / (STEM + ".native")).unlink()
        plan = self.run_plan(False)
        self.assertTrue(any(e["reason"] == "missing_or_invalid_current_target" for e in plan["errors"]))

    def test_bad_manifests(self):
        variants = [b"{", b"[]", b"{\"version\":2,\"version\":2}"]
        for key, value in [("module", "../escape.so"), ("version", True),
                           ("published_sequence", -1), ("source_sha256", OTHER),
                           ("codegen_id", "oops"), ("unexpected", 1)]:
            changed = dict(self.manifest)
            changed[key] = value
            variants.append(json.dumps(changed).encode())
        variants.extend([b"x" * 4096, b"\xff", b"{" * 1000])
        for raw in variants:
            with self.subTest(raw=raw[:70]):
                self.write_manifest(raw)
                plan = self.run_plan(False)
                self.assertTrue(any(e["reason"] == "invalid_manifest" for e in plan["errors"]))

    def test_special_files_no_follow(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        self.put("outside/secret", b"not a cache file")
        (self.root / "alias").symlink_to(outside, target_is_directory=True)
        os.mkfifo(self.root / "fifo", 0o600)
        rows = {r["path"]: r for r in self.run_plan()["entries"]}
        self.assertEqual(rows["alias"]["category"], "special")
        self.assertNotIn("alias/secret", rows)
        self.assertEqual(rows["fifo"]["category"], "special")

    def test_manifest_fifo_symlink_directory(self):
        manifest = self.root / (SOURCE + ".current")
        manifest.unlink()
        os.mkfifo(manifest, 0o400)
        self.run_plan(False)
        manifest.unlink()
        manifest.symlink_to(STEM + ".so")
        self.run_plan(False)
        manifest.unlink()
        manifest.mkdir(mode=0o700)
        self.run_plan(False)

    def test_hardlink_alias_preserves_reference(self):
        alias = self.root / (OTHER + ".so")
        os.link(self.root / (STEM + ".so"), alias)
        plan = self.run_plan(False)
        row = next(r for r in plan["entries"] if r["path"] == alias.name)
        self.assertEqual(row["category"], "current_artifact")
        self.assertEqual(plan["totals"]["unique_objects"], plan["totals"]["path_count"] - 1)

    def test_shared_tbset(self):
        shared = self.manifest["tbset"]
        second = dict(self.manifest, module=SOURCE + ".so", native=SOURCE + ".native")
        for suffix in (".so", ".native"):
            self.put(SOURCE + suffix, b"second generation")
        self.manifest = second
        self.write_manifest()
        rows = {r["path"]: r for r in self.run_plan()["entries"]}
        self.assertEqual(rows[shared]["category"], "current_artifact")
        self.assertEqual(rows[STEM + ".native"]["category"], "unreferenced_artifact")

    def test_changed_after_scan(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            inventory = GC.Inventory(str(self.root))
            inventory.scan(fd)
            path = self.root / (STEM + ".native")
            path.unlink()
            self.put(STEM + ".native", b"changed fixture")
            inventory.verify(fd)
            self.assertFalse(inventory.report()["complete"])
        finally:
            os.close(fd)

    def test_reject_unknown_cli(self):
        for args in (["gc"], ["gc", "--delete"], ["gc", "--plan"]):
            result = subprocess.run([str(LATCD), *args], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
