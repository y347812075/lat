#!/usr/bin/env python3
"""Read-only AOT cache inventory. A plan never authorizes deletion."""

import argparse
import base64
import configparser
import json
import os
import re
import stat
import sys
import uuid


SHA = r"[0-9a-f]{64}"
CURRENT = re.compile(rf"({SHA})\.current\Z")
GENERATED = re.compile(rf"({SHA})(?:-{SHA})?\.(so|native|tbset)\Z")
MAX_MANIFEST = 4096
MAX_ENTRIES = 100000
MAX_DEPTH = 12


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_manifest(raw, source):
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=lambda s: invalid(f"invalid constant: {s}"))
    if not isinstance(value, dict):
        raise ValueError("manifest must be an object")
    required = {"version", "module", "native", "tbset", "source_sha256",
                "codegen_id", "published_sequence"}
    optional = {"module_sha256", "native_sha256"}
    if not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("unsupported manifest fields")
    if type(value["version"]) is not int or value["version"] != 2:
        raise ValueError("unsupported manifest version")
    if value["source_sha256"] != source:
        raise ValueError("source identity differs from manifest basename")
    for key in ("codegen_id", "module_sha256", "native_sha256"):
        if key in value and (not isinstance(value[key], str) or
                             not re.fullmatch(SHA, value[key])):
            raise ValueError(f"invalid {key}")
    sequence = value["published_sequence"]
    if type(sequence) is not int or not 0 <= sequence < 2**64:
        raise ValueError("invalid published_sequence")
    for field, suffix in (("module", "so"), ("native", "native"),
                          ("tbset", "tbset")):
        name = value[field]
        if field == "tbset" and name == "":
            continue
        if not isinstance(name, str):
            raise ValueError(f"invalid {field} basename")
        match = GENERATED.fullmatch(name)
        if not match or match[1] != source or match[2] != suffix:
            raise ValueError(f"invalid {field} basename")
    return value


def invalid(message):
    raise ValueError(message)


class Inventory:
    def __init__(self, root):
        self.root = root
        self.entries = {}
        self.directories = {}
        self.manifests = {}
        self.errors = []
        self.refs = {}
        self.transaction_refs = {}
        self.transactions = {}
        self.frozen = set()
        self.freeze_all = False
        self.count = 0

    def error(self, path, reason, detail):
        self.errors.append({"path": path, "reason": reason, "detail": detail})

    def scan(self, fd, prefix="", depth=0):
        before = os.fstat(fd)
        self.directories[prefix] = identity(before)
        if before.st_uid != os.geteuid() or before.st_mode & 0o077:
            self.error(prefix or ".", "unsafe_directory", "requires private owner directory")
        if depth >= MAX_DEPTH:
            self.error(prefix, "scan_limit", "maximum directory depth")
            return
        # Stop iteration before materializing an unbounded directory listing.
        with os.scandir(fd) as iterator:
            for item in iterator:
                self.count += 1
                if self.count > MAX_ENTRIES:
                    self.error(prefix or ".", "scan_limit", "maximum entry count")
                    raise OverflowError("maximum entry count")
                name = item.name
                relative = f"{prefix}/{name}" if prefix else name
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    row = {"path": relative, "logical_bytes": st.st_size,
                           "allocated_bytes": st.st_blocks * 512,
                           "device": st.st_dev, "inode": st.st_ino,
                           "links": st.st_nlink, "_identity": identity(st),
                           "_mode": st.st_mode, "_uid": st.st_uid}
                    self.entries[relative] = row
                    if not prefix and CURRENT.fullmatch(name):
                        self.read_manifest(fd, name, st)
                    if prefix == ".gc/transactions" and not name.startswith(".write-"):
                        self.read_transaction(fd, name, st)
                    if stat.S_ISDIR(st.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                        os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            if identity(os.fstat(child)) != identity(st):
                                raise ValueError("directory changed before open")
                            self.scan(child, relative, depth + 1)
                        finally:
                            os.close(child)
                except (OSError, ValueError) as exc:
                    self.error(relative, "unreadable_or_changed", str(exc))
        if identity(os.fstat(fd)) != identity(before):
            self.error(prefix or ".", "concurrent_change", "directory changed during scan")

    def read_transaction(self, directory, name, before):
        relative = ".gc/transactions/" + name
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 65536):
                raise ValueError("unsafe retirement transaction")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 65537)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("transaction changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.sections() != ["transaction"] or parser.defaults():
                raise ValueError("invalid transaction sections")
            value = dict(parser["transaction"])
            required = {"version", "source", "state", "previous", "next"}
            optional = {"prepared_boot", "prepared_boottime_us", "retired_boot", "retired_boottime_us",
                        "objects", "objects_status"}
            if not required <= value.keys() or value.keys() - required - optional:
                raise ValueError("unsupported transaction fields")
            source, state = value["source"], value["state"]
            if (value["version"] not in {"1", "2"} or not re.fullmatch(SHA, source) or
                    state not in {"PREPARED", "RETIRED", "ABORTED", "UNKNOWN"}):
                raise ValueError("invalid transaction identity/state")
            snapshots = {}
            for role in ("previous", "next"):
                raw_manifest = base64.b64decode(value[role], validate=True)
                if not raw_manifest and role == "previous":
                    continue
                if not 0 < len(raw_manifest) < MAX_MANIFEST:
                    raise ValueError("invalid transaction snapshot size")
                snapshots[role] = parse_manifest(raw_manifest, source)
            object_rows = []
            if value["version"] == "2":
                encoded = value.get("objects")
                if encoded is None:
                    raise ValueError("missing object evidence")
                evidence = base64.b64decode(encoded, validate=True)
                if len(evidence) >= 16384:
                    raise ValueError("object evidence too large")
                if evidence:
                    objects = configparser.ConfigParser(interpolation=None, strict=True)
                    objects.read_string(evidence.decode("ascii"))
                    count = objects.getint("objects", "count")
                    if (not 0 < count <= 6 or objects.defaults() or
                            set(objects["objects"]) != {"count"} or
                            set(objects.sections()) != {"objects", *(f"object{i}" for i in range(count))}):
                        raise ValueError("invalid object table")
                    for i in range(count):
                        row = dict(objects[f"object{i}"])
                        if set(row) != {"name", "device", "inode", "size", "allocated", "sha256"}:
                            raise ValueError("invalid object fields")
                        match = GENERATED.fullmatch(row["name"])
                        if not match or match[1] != source or not re.fullmatch(SHA, row["sha256"]):
                            raise ValueError("invalid object identity")
                        for key in ("device", "inode", "size", "allocated"):
                            if not re.fullmatch(r"[0-9]+", row[key]) or int(row[key]) >= 2**64:
                                raise ValueError("invalid object number")
                            row[key] = int(row[key])
                        object_rows.append(row)
                if value.get("objects_status", "UNPROVEN") not in {"UNPROVEN", "MISMATCH", "RECORDED"}:
                    raise ValueError("invalid object evidence status")
            value["object_identities"] = object_rows
            for role, manifest in snapshots.items():
                for field in ("module", "native", "tbset"):
                    if manifest[field]:
                        self.transaction_refs.setdefault(manifest[field], []).append(
                            {"transaction": relative, "snapshot": role,
                             "role": field, "state": state})
            self.transactions[relative] = value
            if state == "UNKNOWN":
                self.frozen.add(source)
        except (OSError, ValueError, KeyError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_transaction", str(exc))

    def read_manifest(self, directory, name, before):
        source = CURRENT.fullmatch(name)[1]
        try:
            if (not stat.S_ISREG(before.st_mode) or
                    before.st_uid != os.geteuid() or before.st_nlink != 1 or
                    before.st_mode & 0o222 or not 0 < before.st_size < MAX_MANIFEST):
                raise ValueError("manifest is not a bounded immutable owned regular file")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                if identity(os.fstat(fd)) != identity(before):
                    raise ValueError("manifest changed before read")
                raw = os.read(fd, MAX_MANIFEST + 1)
                if len(raw) != before.st_size or identity(os.fstat(fd)) != identity(before):
                    raise ValueError("manifest changed during read")
                value = parse_manifest(raw, source)
            finally:
                os.close(fd)
            self.manifests[name] = value
            for field in ("module", "native", "tbset"):
                if value[field]:
                    self.refs.setdefault(value[field], []).append(
                        {"manifest": name, "role": field})
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            self.frozen.add(source)
            self.error(name, "invalid_manifest", str(exc))

    def verify(self, root_fd):
        # Reopen every parent relative to the original root without following links.
        for relative, before in [(p, r["_identity"]) for p, r in self.entries.items()]:
            parts = relative.split("/")
            fd = os.dup(root_fd)
            try:
                for component in parts[:-1]:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = child
                after = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                if identity(after) != before:
                    self.error(relative, "concurrent_change", "entry changed after scan")
            except OSError as exc:
                self.error(relative, "concurrent_change", str(exc))
            finally:
                os.close(fd)
        # Detect inserted names as well as replacements; this is diagnostic, not a lease.
        if identity(os.fstat(root_fd)) != self.directories.get(""):
            self.error(".", "concurrent_change", "root changed after scan")
        for relative, before in self.directories.items():
            if relative and (relative not in self.entries or
                             self.entries[relative]["_identity"] != before):
                self.error(relative, "concurrent_change", "directory changed before scan")

    def report(self):
        for relative in self.entries:
            if "/" not in relative and relative.endswith(".current") and not CURRENT.fullmatch(relative):
                self.freeze_all = True
                self.error(relative, "unknown_manifest_name", "cannot establish source scope")
        for target, referrers in sorted(self.refs.items()):
            row = self.entries.get(target)
            if row is None or not stat.S_ISREG(row["_mode"]):
                self.error(target, "missing_or_invalid_current_target", str(referrers))
                self.frozen.update(r["manifest"][:64] for r in referrers)
            elif (row["_uid"] != os.geteuid() or row["_mode"] & 0o222 or
                  row["links"] != 1 or not row["logical_bytes"]):
                self.error(target, "unsafe_current_target", "ownership/mode/links/size")
                self.frozen.update(r["manifest"][:64] for r in referrers)
        objects = {}
        for row in self.entries.values():
            objects.setdefault((row["device"], row["inode"]), []).append(row)
        output = []
        groups = {}
        for relative, row in sorted(self.entries.items()):
            mode = row["_mode"]
            category, reasons = "unknown", ["unrecognized_object"]
            referrers = [r for alias in objects[(row["device"], row["inode"])]
                         for r in self.refs.get(alias["path"], [])]
            if stat.S_ISDIR(mode):
                category, reasons = "directory", ["directory_metadata"]
            elif not stat.S_ISREG(mode):
                category, reasons = "special", ["non_regular_object"]
            elif relative in self.manifests:
                category, reasons = "current_manifest", ["publication_root"]
            elif referrers:
                category, reasons = "current_artifact", ["current_reference"]
                if any(r["role"] == "native" for r in referrers):
                    reasons.append("incremental_baseline")
            elif relative in self.transaction_refs:
                category, reasons = "transaction_artifact", ["persistent_transaction_hold"]
            elif relative.startswith(".superseded/"):
                category, reasons = "legacy_retired", ["legacy_reference_contract_unknown"]
            elif relative.startswith(".tmp/"):
                category, reasons = "temporary", ["worker_liveness_unknown"]
            elif relative.startswith(".tbsets/"):
                category, reasons = "collected_keys", ["accepted_request_state"]
            elif relative.startswith(".identities/"):
                category, reasons = "source_identity", ["source_identity_state"]
            elif relative.startswith(".gc/"):
                category, reasons = "gc_metadata", ["persistent_lifecycle_state"]
            elif relative.startswith(".journals/"):
                category, reasons = "journal", ["recovery_state"]
            elif relative == ".latcd.lock":
                category, reasons = "owner_lock", ["management_lock"]
            elif GENERATED.fullmatch(relative):
                category, reasons = "unreferenced_artifact", ["no_current_reference_not_liveness_proof"]
            if self.freeze_all or any(part[:64] in self.frozen for part in relative.split("/")):
                reasons.append("invalid_source_manifest")
            if self.errors:
                reasons.append("inventory_incomplete")
            if stat.S_ISREG(mode):
                reasons.append("lifecycle_and_mount_admission_unverified")
            result = {k: v for k, v in row.items() if not k.startswith("_")}
            result.update(category=category, reasons=reasons, references=referrers,
                          transaction_references=self.transaction_refs.get(relative, []),
                          delete_authorized=False)
            output.append(result)
            group = groups.setdefault(category, {"entries": 0, "logical_bytes": 0,
                                                  "allocated_bytes": 0})
            group["entries"] += 1
            group["logical_bytes"] += row["logical_bytes"]
            group["allocated_bytes"] += row["allocated_bytes"]
        unique = [aliases[0] for aliases in objects.values()]
        return {"schema_version": 1, "mode": "read_only_plan", "cache": self.root,
                "delete_authorized": False, "complete": not self.errors,
                "snapshot_atomic": False, "content_validated": False,
                "liveness_verified": False, "manifest_count": len(self.manifests),
                "transaction_count": len(self.transactions),
                "transactions": self.transactions,
                "totals": {"path_count": len(output), "unique_objects": len(unique),
                           "logical_bytes": sum(r["logical_bytes"] for r in unique),
                           "allocated_bytes": sum(r["allocated_bytes"] for r in unique)},
                "categories_path_totals": groups, "entries": output,
                "errors": self.errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", required=True)
    parser.add_argument("--cache-dir", required=True)
    args = parser.parse_args()
    root = os.path.abspath(args.cache_dir)
    inventory = Inventory(root)
    try:
        # Root ancestors may contain user-managed aliases; the cache root itself may not.
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            inventory.scan(fd)
            inventory.verify(fd)
            if identity(os.stat(root, follow_symlinks=False)) != inventory.directories.get(""):
                inventory.error(".", "concurrent_change", "cache root replaced")
        finally:
            os.close(fd)
    except (OSError, OverflowError) as exc:
        inventory.error(".", "scan_failed", str(exc))
    report = inventory.report()
    json.dump(report, sys.stdout, ensure_ascii=True, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
