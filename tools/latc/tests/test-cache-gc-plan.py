#!/usr/bin/env python3
"""Exercise the read-only planner without opening any user cache."""

import importlib.util
import base64
import hashlib
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
OTHER = "b" * 64
STEM = SOURCE + "-" + "c" * 64
SPEC = importlib.util.spec_from_file_location(
    "cache_gc", Path(__file__).resolve().parents[1] / "latcd/cache_gc.py")
GC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GC)
BOOT = "12345678-1234-4234-8234-123456789abc"


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

    def task(self):
        path = self.put('.tmp/input-ABC', b'compiler input')
        record_id = str(uuid.uuid4())
        record = (f'[task]\nversion=1\nid={record_id}\nstate=BOUND\nsource={SOURCE}\n'
                  f'build_id={OTHER}\nenvironment_sha256={OTHER}\n')
        for role, target in [('cache', self.root), ('temporary', path.parent),
                             ('source', path)]:
            st = target.stat()
            record += (f'[{role}]\ndevice={st.st_dev}\ninode={st.st_ino}\n'
                       f'size={st.st_size}\nmode={st.st_mode}\nuid={st.st_uid}\n'
                       f'mtime_sec={st.st_mtime_ns // 10**9}\n'
                       f'mtime_nsec={st.st_mtime_ns % 10**9}\n')
            if role == 'source':
                record += f'name={target.name}\ndirectory=temporary\n'
        record += '[output_native]\nname=native-ABC\n[output_module]\nname=module-ABC\n'
        return self.put(f'.gc/tasks/{record_id}.ini', record.encode())

    def test_task_lease_and_references(self):
        record = self.task()
        with record.open('rb') as pin:
            fcntl.flock(pin, fcntl.LOCK_SH)
            plan = self.run_plan()
            self.assertEqual(plan['task_count'], 1)
            task = next(iter(plan['tasks'].values()))
            self.assertEqual(task['lease_observation'], 'HELD_OBSERVED')
            self.assertFalse(task['completion_verified'])
            row = next(row for row in plan['entries'] if row['path'] == '.tmp/input-ABC')
            self.assertEqual(len(row['task_references']), 1)
        task = next(iter(self.run_plan()['tasks'].values()))
        self.assertEqual(task['lease_observation'], 'NO_HOLDER_OBSERVED')
        self.assertFalse(task['completion_verified'])

    def test_task_bad_schema_and_path(self):
        record = self.task()
        original = record.read_bytes()
        for bad in (original.replace(b'version=1', b'version=2'),
                    original.replace(b'name=input-ABC', b'name=../input-ABC'),
                    original + b'[unexpected]\nvalue=1\n',
                    original.replace(b'uid=', b'uid=18446744073709551616', 1)):
            self.put(str(record.relative_to(self.root)), bad)
            plan = self.run_plan(success=False)
            self.assertTrue(any(e['reason'] == 'invalid_task' for e in plan['errors']))
        self.put(str(record.relative_to(self.root)), original)
        record.chmod(0o600)
        self.run_plan(success=False)

    def test_task_changed_input_and_incomplete_write(self):
        self.task()
        self.put('.tmp/input-ABC', b'changed input size')
        plan = self.run_plan(success=False)
        self.assertTrue(any(e['reason'] == 'task_binding_changed' for e in plan['errors']))
        self.put('.gc/tasks/.write-interrupted', b'incomplete')
        plan = self.run_plan(success=False)
        self.assertTrue(any(e['reason'] == 'invalid_task' for e in plan['errors']))

    def test_task_cache_and_collected_bindings(self):
        record = self.task()
        original = record.read_bytes()
        self.put('input-ABC', b'compiler input')
        st = (self.root / 'input-ABC').stat()
        bound = original.decode().split('[source]')[0] + (
            f'[source]\nname=input-ABC\ndirectory=cache\ndevice={st.st_dev}\n'
            f'inode={st.st_ino}\nsize={st.st_size}\nmode={st.st_mode}\nuid={st.st_uid}\n'
            f'mtime_sec={st.st_mtime_ns // 10**9}\nmtime_nsec={st.st_mtime_ns % 10**9}\n'
            '[output_native]\nname=native-ABC\n[output_module]\nname=module-ABC\n')
        self.put(str(record.relative_to(self.root)), bound.encode())
        plan = self.run_plan()
        row = next(row for row in plan['entries'] if row['path'] == 'input-ABC')
        self.assertEqual(len(row['task_references']), 1)
        self.put(str(record.relative_to(self.root)),
                 bound.replace('directory=cache', 'directory=collected').encode())
        self.run_plan(success=False)

    def test_copy_task_schema_and_output_intent(self):
        record = self.task()
        original = record.read_text()
        copying = original.replace('version=1', 'version=2\nkind=COPY').replace(
            f'environment_sha256={OTHER}\n', '').replace('[source]', '[input]').replace(
            '[output_native]', '[output]')
        copying = copying.split('[output_module]')[0]
        self.put(str(record.relative_to(self.root)), copying.encode())
        plan = self.run_plan()
        task = next(iter(plan['tasks'].values()))
        self.assertEqual(task['kind'], 'COPY')
        self.assertFalse(task['completion_verified'])
        self.assertEqual(task['lease_observation'], 'NO_HOLDER_OBSERVED')
        self.put('.tmp/native-ABC', b'partial output')
        plan = self.run_plan()
        row = next(row for row in plan['entries'] if row['path'] == '.tmp/native-ABC')
        self.assertEqual(row['task_references'][0]['role'], 'output')
        for bad in (copying.replace('kind=COPY', 'kind=UNKNOWN'),
                    copying.replace('name=native-ABC', 'name=../escape'),
                    copying + '[output_module]\nname=unexpected\n'):
            self.put(str(record.relative_to(self.root)), bad.encode())
            self.run_plan(success=False)

    def test_copy_receipt_binding_and_bad_input(self):
        task = self.task()
        raw = task.read_text().replace('version=1', 'version=2\nkind=COPY').replace(
            f'environment_sha256={OTHER}\n', '').replace('[source]', '[input]').replace(
            '[output_native]', '[output]').split('[output_module]')[0]
        self.put(str(task.relative_to(self.root)), raw.encode())
        output = self.put('.tmp/native-ABC', b'complete output')
        st, root = output.stat(), task.stat()
        record = (f'[receipt]\nversion=1\ntask_id={task.stem}\ntask_device={root.st_dev}\n'
                  f'task_inode={root.st_ino}\nstate=COPIED\n[output]\nname={output.name}\n'
                  f'device={st.st_dev}\ninode={st.st_ino}\nsize={st.st_size}\nmode={st.st_mode}\n'
                  f'uid={st.st_uid}\nmtime_sec={st.st_mtime_ns // 10**9}\n'
                  f'mtime_nsec={st.st_mtime_ns % 10**9}\n'
                  f'sha256={hashlib.sha256(output.read_bytes()).hexdigest()}\n')
        receipt = self.put(f'.gc/copy-receipts/{task.name}', record.encode())
        plan = self.run_plan()
        value = next(iter(plan['copy_receipts'].values()))
        self.assertTrue(value['binding_observed'])
        self.assertFalse(value['content_validated'])
        for bad in (record.replace('state=COPIED', 'state=DONE'),
                    record.replace('name=native-ABC', 'name=../escape'),
                    record.replace(f'task_inode={root.st_ino}', 'task_inode=0'),
                    record.replace('sha256=', 'sha256=invalid')):
            self.put(str(receipt.relative_to(self.root)), bad.encode())
            self.run_plan(success=False)
        self.put(str(receipt.relative_to(self.root)), record.encode())
        receipt_stat = receipt.stat()
        handoff = (f'[handoff]\nversion=1\ntask_id={task.stem}\nstate=SNAPSHOT_OWNED\n'
                   f'task_device={root.st_dev}\ntask_inode={root.st_ino}\n'
                   f'receipt_device={receipt_stat.st_dev}\nreceipt_inode={receipt_stat.st_ino}\n')
        marker = self.put(f'.gc/copy-handoffs/{task.name}', handoff.encode())
        plan = self.run_plan()
        value = next(iter(plan['copy_handoffs'].values()))
        self.assertTrue(value['input_reference_released'])
        input_row = next(row for row in plan['entries'] if row['path'] == '.tmp/input-ABC')
        self.assertFalse(input_row['task_references'])
        for bad in (handoff.replace('SNAPSHOT_OWNED', 'DONE'),
                    handoff.replace(f'receipt_inode={receipt_stat.st_ino}', 'receipt_inode=0'),
                    handoff + 'unexpected=1\n'):
            self.put(str(marker.relative_to(self.root)), bad.encode())
            self.run_plan(success=False)
        self.put(str(marker.relative_to(self.root)), handoff.encode())
        self.put('.tmp/native-ABC', b'changed size')
        self.run_plan(success=False)
        output.unlink()
        value = next(iter(self.run_plan()['copy_receipts'].values()))
        self.assertEqual(value['output_observation'], 'MISSING')
        self.assertFalse(value['binding_observed'])
        self.assertFalse(next(iter(self.run_plan()['copy_handoffs'].values()))[
            'input_reference_released'])

    def generation(self, digit, *, tbset=None):
        stem = SOURCE + "-" + digit * 64
        manifest = dict(self.manifest, module=stem + ".so", native=stem + ".native",
                        tbset=tbset or stem + ".tbset")
        for role in ("module", "native", "tbset"):
            if not (self.root / manifest[role]).exists():
                self.put(manifest[role], (digit + role).encode())
        return manifest

    def transaction(self, previous, following, stamp=1000000, state="RETIRED", boot=BOOT):
        names = sorted({manifest[role] for manifest in (previous, following) if manifest
                        for role in ("module", "native", "tbset") if manifest[role]})
        evidence = f"[objects]\ncount={len(names)}\n"
        for i, name in enumerate(names):
            p = self.root / name
            st = p.stat()
            evidence += (f"[object{i}]\nname={name}\ndevice={st.st_dev}\ninode={st.st_ino}\n"
                         f"size={st.st_size}\nallocated={st.st_blocks * 512}\n"
                         f"sha256={hashlib.sha256(p.read_bytes()).hexdigest()}\n")
        encode = lambda data: base64.b64encode(data).decode()
        record = (f"[transaction]\nversion=2\nsource={SOURCE}\nstate={state}\n"
                  f"previous={encode(json.dumps(previous).encode()) if previous else ''}\n"
                  f"next={encode(json.dumps(following).encode())}\n"
                  f"objects={encode(evidence.encode())}\nobjects_status=RECORDED\n"
                  "binding_status=COMPLETE\n")
        if stamp is not None:
            record += f"retired_boot={boot}\nretired_boottime_us={stamp}\n"
        path = ".gc/transactions/" + str(uuid.uuid4()) + ".ini"
        self.put(path, record.encode())
        return path

    def selected(self, now=601000000, boot=BOOT):
        before = self.snapshot()
        inventory = GC.Inventory(str(self.root), clock=(boot, now))
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            inventory.scan(fd)
            inventory.verify(fd)
        finally:
            os.close(fd)
        plan = inventory.report()
        self.assertEqual(before, self.snapshot())
        self.assertFalse(plan["retirement_plan"]["full_reference_graph_verified"])
        self.assertTrue(all(not row["delete_authorized"]
                            for row in plan["retirement_plan"]["candidates"]))
        return plan, {row["name"]: row for row in plan["retirement_plan"]["candidates"]}

    def test_shared_objects_and_independent_deadlines(self):
        old = self.generation("1")
        middle = self.generation("2", tbset=old["tbset"])
        first = self.transaction(old, middle)
        self.transaction(middle, self.manifest, stamp=500000000)
        plan, rows = self.selected()
        self.assertTrue(plan["complete"])
        self.assertEqual(rows[old["module"]]["selection_status"], "due")
        self.assertEqual(rows[old["module"]]["retirement_transactions"], [first])
        self.assertEqual(rows[old["module"]]["deadline_boottime_us"], 601000000)
        self.assertEqual(rows[old["tbset"]]["selection_status"], "grace")
        self.assertEqual(rows[old["tbset"]]["deadline_boottime_us"], 1100000000)
        self.assertIn("current_reference", rows[self.manifest["native"]]["holds"])
        newer = self.generation("3")
        self.transaction(self.manifest, newer, stamp=600000000)
        self.write_manifest(json.dumps(newer).encode())
        _, changed = self.selected()
        self.assertEqual(rows[old["module"]], changed[old["module"]])
        self.assertEqual(changed[self.manifest["module"]]["selection_status"], "grace")
        _, earlier = self.selected(now=600999999)
        self.assertEqual(earlier[old["module"]]["remaining_grace_us"], 1)
        _, later = self.selected(now=1100000000)
        self.assertEqual(later[old["tbset"]]["selection_status"], "due")
        self.run_plan()

    def test_unresolved_transaction_roots_hold(self):
        old = self.generation("1")
        self.transaction(old, self.manifest)
        for state in ("PREPARED", "ABORTED", "UNKNOWN"):
            with self.subTest(state=state):
                path = self.transaction(old, self.manifest, state=state)
                _, rows = self.selected()
                self.assertEqual(rows[old["module"]]["selection_status"], "held")
                self.assertIn(state.lower() + "_transaction", rows[old["module"]]["holds"])
                (self.root / path).unlink()

    def test_retirement_clock_recovery_and_validation(self):
        old = self.generation("1")
        cases = ((None, BOOT, "missing_retirement_clock"),
                 (1000000, "22345678-1234-4234-8234-123456789abc", "reboot_recovery_required"),
                 (601000001, BOOT, "future_retirement_clock"))
        for stamp, boot, reason in cases:
            with self.subTest(reason=reason):
                path = self.transaction(old, self.manifest, stamp=stamp, boot=boot)
                plan, rows = self.selected()
                self.assertTrue(plan["complete"])
                self.assertIn(reason, rows[old["module"]]["holds"])
                self.assertIsNone(rows[old["module"]]["deadline_boottime_us"])
                (self.root / path).unlink()
        path = self.transaction(old, self.manifest)
        original = (self.root / path).read_text()
        for bad in ("-1", "18446744073709551616", "1.5", ""):
            self.put(path, original.replace("retired_boottime_us=1000000",
                                           "retired_boottime_us=" + bad).encode())
            self.run_plan(False)
        for bad in (original.replace("retired_boot=" + BOOT + "\n", ""),
                    original.replace("retired_boot=" + BOOT, "retired_boot=invalid")):
            self.put(path, bad.encode())
            self.run_plan(False)

    def test_candidate_identity_and_missing_current(self):
        old = self.generation("1")
        self.transaction(old, self.manifest)
        name = old["native"]
        p = self.root / name
        p.rename(self.root / "held-old-inode")
        self.put(name, b"replacement")
        _, rows = self.selected()
        self.assertIn("object_identity_changed", rows[name]["holds"])
        (self.root / (SOURCE + ".current")).unlink()
        _, rows = self.selected()
        self.assertIn("missing_current_root", rows[old["module"]]["holds"])

    def test_shared_current_and_conflicting_evidence(self):
        old = self.generation("1", tbset=self.manifest["tbset"])
        self.transaction(old, self.manifest)
        _, rows = self.selected()
        self.assertIn("current_reference", rows[old["tbset"]]["holds"])
        self.assertIn("no_proven_retirement", rows[old["tbset"]]["holds"])
        # Same basename with new identity must not be merged into old evidence.
        self.put(old["native"], b"changed object")
        self.transaction(old, self.manifest, stamp=500000000)
        _, rows = self.selected()
        self.assertIn("conflicting_object_evidence", rows[old["native"]]["holds"])

    def test_unproven_evidence_and_unavailable_clock(self):
        old = self.generation("1")
        path = self.transaction(old, self.manifest)
        original = (self.root / path).read_text()
        self.put(path, original.replace("objects_status=RECORDED",
                                        "objects_status=MISMATCH").encode())
        _, rows = self.selected()
        self.assertIn("unproven_object_evidence", rows[old["module"]]["holds"])
        self.put(path, original.encode())
        inventory = GC.Inventory(str(self.root), clock=False)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            inventory.scan(fd)
            inventory.verify(fd)
        finally:
            os.close(fd)
        rows = {row["name"]: row for row in inventory.report()["retirement_plan"]["candidates"]}
        self.assertIn("clock_unavailable", rows[old["module"]]["holds"])
        self.assertIsNone(rows[old["module"]]["deadline_boottime_us"])

    def test_completed_removal_receipt(self):
        old = self.generation("1")
        self.transaction(old, self.manifest)
        name = old["module"]
        st = (self.root / name).stat()
        raw = (f"[tombstone]\nversion=1\nsource={SOURCE}\nname={name}\nstate=DELETING\n"
               f"device={st.st_dev}\ninode={st.st_ino}\nsize={st.st_size}\n"
               f"allocated={st.st_blocks * 512}\n"
               f"sha256={hashlib.sha256((self.root / name).read_bytes()).hexdigest()}\n"
               "recovery_status=MISSING\ndeletion_status=UNLINKED\n")
        path = ".gc/tombstones/" + name
        self.put(path, raw.encode())
        (self.root / name).unlink()
        plan, rows = self.selected()
        self.assertTrue(plan["complete"])
        self.assertEqual(rows[name]["selection_status"], "removed")
        self.assertEqual(rows[old["native"]]["selection_status"], "due")
        self.run_plan()
        for bad in (raw.replace("deletion_status=UNLINKED\n", ""),
                    raw.replace("recovery_status=MISSING", "recovery_status=UNKNOWN"),
                    raw.replace(f"inode={st.st_ino}", "inode=0")):
            self.put(path, bad.encode())
            self.run_plan(False)
        self.put(path, raw.encode())
        self.put(name, b"replacement must survive")
        plan, rows = self.selected()
        self.assertFalse(plan["complete"])
        self.assertEqual(rows[name]["selection_status"], "held")

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

    def test_tombstone_freezes_source(self):
        self.put(".gc/tombstones/" + STEM + ".native", b"invalid intent")
        plan = self.run_plan(False)
        self.assertTrue(any(e["reason"] == "unrecovered_tombstone" for e in plan["errors"]))
        rows = {row["path"]: row for row in plan["entries"]}
        self.assertIn("invalid_source_manifest", rows[STEM + ".so"]["reasons"])

    def test_structured_tombstone(self):
        name = STEM + ".native"
        st = (self.root / name).stat()
        raw = ("[tombstone]\nversion=1\nsource=" + SOURCE + "\nname=" + name +
               "\nstate=DELETING\ndevice=" + str(st.st_dev) + "\ninode=" + str(st.st_ino) +
               "\nsize=" + str(st.st_size) + "\nallocated=" + str(st.st_blocks * 512) +
               "\nsha256=" + "f" * 64 + "\nrecovery_status=MISSING\n")
        path = ".gc/tombstones/" + name
        self.put(path, raw.encode())
        plan = self.run_plan(False)
        self.assertEqual(plan["tombstone_count"], 1)
        self.assertEqual(plan["tombstones"][path]["recovery_status"], "MISSING")
        self.put(path, (raw + "deletion_status=UNLINKED\n").encode())
        completed = self.run_plan(False)
        self.assertEqual(completed["tombstones"][path]["deletion_status"], "UNLINKED")
        for bad in (raw.replace("version=1", "version=1\nversion=1"),
                    raw.replace("source=" + SOURCE, "source=" + OTHER),
                    raw.replace("size=7", "size=-1"),
                    raw.replace("recovery_status=MISSING", "recovery_status=DELETED")):
            self.put(path, bad.encode())
            changed = self.run_plan(False)
            self.assertEqual(changed["tombstone_count"], 0)

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
