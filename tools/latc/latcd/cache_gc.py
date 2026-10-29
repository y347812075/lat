#!/usr/bin/env python3
"""Read-only AOT cache inventory. A plan never authorizes deletion."""

import argparse
import base64
import configparser
import fcntl
import json
import os
import re
import stat
import sys
import time
import uuid


SHA = r"[0-9a-f]{64}"
CURRENT = re.compile(rf"({SHA})\.current\Z")
GENERATED = re.compile(rf"({SHA})(?:-{SHA})?\.(so|native|tbset)\Z")
MAX_MANIFEST = 4096
MAX_ENTRIES = 100000
MAX_DEPTH = 12
DEFAULT_GRACE_US = 600 * 1000000


def boot_clock():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
            boot = stream.read(128).strip()
        if str(uuid.UUID(boot)) != boot:
            return None
        return boot, time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000
    except (OSError, ValueError):
        return None


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
    def __init__(self, root, *, clock=None, grace_us=DEFAULT_GRACE_US):
        self.root = root
        self.entries = {}
        self.directories = {}
        self.manifests = {}
        self.domain = None
        self.retirement_handoff = None
        self.domain_binding_observed = False
        self.errors = []
        self.refs = {}
        self.transaction_refs = {}
        self.transactions = {}
        self.snapshots = {}
        self.tombstones = {}
        self.tasks = {}
        self.task_refs = {}
        self.copy_receipts = {}
        self.copy_handoffs = {}
        self.copy_releases = {}
        self.compiler_releases = {}
        self.compiler_output_releases = {}
        self.compiler_budgets = {}
        self.explicit_holds = {}
        self.hold_refs = {}
        self.mount_leases = {}
        self.frozen = set()
        self.freeze_all = False
        self.count = 0
        self.clock = boot_clock() if clock is None else clock
        self.grace_us = grace_us

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
                    if prefix == ".gc/holds" and (not GENERATED.fullmatch(name) or not stat.S_ISDIR(st.st_mode)):
                        self.freeze_all = True
                        self.error(relative, "invalid_explicit_hold_directory", "expected object hold directory")
                    if not prefix and CURRENT.fullmatch(name):
                        self.read_manifest(fd, name, st)
                    if prefix == ".gc" and name == "domain.ini":
                        self.read_domain(fd, st)
                    if prefix == ".gc" and name == "retirement-handoff.ini":
                        self.read_retirement_handoff(fd, st)
                    if prefix in (".gc/transactions", ".gc/tombstones"):
                        if name.startswith(".write-"):
                            self.freeze_all = True
                            self.error(relative, "incomplete_lifecycle_record",
                                       "unresolved temporary record")
                        elif prefix == ".gc/transactions":
                            self.read_transaction(fd, name, st)
                        else:
                            self.read_tombstone(fd, name, st)
                    if prefix == ".gc/tasks":
                        self.read_task(fd, name, st)
                    if prefix == ".gc/compiler-budgets":
                        self.read_compiler_budget(fd, name, st)
                    if prefix.startswith(".gc/holds/"):
                        self.read_explicit_hold(fd, prefix, name, st)
                    if prefix == ".gc/mount-leases":
                        if name.startswith(".write-"):
                            self.freeze_all = True
                            self.error(relative, "invalid_mount_lease", "partial named record")
                        else:
                            self.read_mount_lease(fd, name, st)
                    if prefix == ".gc/copy-receipts":
                        self.read_copy_receipt(fd, name, st)
                    if prefix == ".gc/copy-handoffs":
                        self.read_copy_handoff(fd, name, st)
                    if prefix == ".gc/copy-releases":
                        self.read_copy_handoff(fd, name, st, releasing=True)
                    if prefix == ".gc/compiler-releases":
                        self.read_copy_handoff(fd, name, st, releasing=True, compiler=True)
                    if prefix == ".gc/compiler-output-releases":
                        self.read_copy_handoff(fd, name, st, releasing=True, compiler=True, outputs=True)
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

    def read_explicit_hold(self, directory, prefix, name, before):
        relative = prefix + "/" + name
        try:
            obj = prefix.removeprefix(".gc/holds/")
            if (not GENERATED.fullmatch(obj) or not name.endswith(".ini") or
                    str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or not 0 < before.st_size <= 4096):
                raise ValueError("unsafe explicit hold")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("hold changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["hold"]:
                raise ValueError("invalid hold sections")
            value = dict(parser["hold"])
            numbers = {"cache_device", "cache_inode", "object_device", "object_inode"}
            if (set(value) != numbers | {"version", "id", "name", "reason", "state"} or
                    value["version"] != "1" or value["id"] != name[:-4] or value["name"] != obj or
                    value["reason"] not in {"ROLLBACK", "MIGRATION", "EXTERNAL"} or
                    value["state"] not in {"ACTIVE", "RELEASED"}):
                raise ValueError("invalid hold fields")
            for key in numbers:
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid hold integer")
                value[key] = int(value[key])
            self.explicit_holds[relative] = dict(value, binding_observed=False)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_explicit_hold", str(exc))

    def read_retirement_handoff(self, directory, before):
        relative = ".gc/retirement-handoff.ini"
        self.retirement_handoff = {"status": "invalid", "requires_rescan": True}
        try:
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 4096):
                raise ValueError("unsafe retirement handoff")
            fd = os.open("retirement-handoff.ini", os.O_RDONLY | os.O_CLOEXEC |
                         os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("retirement handoff changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["handoff"]:
                raise ValueError("invalid retirement handoff sections")
            value = dict(parser["handoff"])
            numbers = {"cache_device", "cache_inode", "recorded_boottime_us", "grace_us",
                       "known_candidates", "known_deferred"}
            optional = {"next_attempt_hint_boottime_us"}
            fields = numbers | {"version", "boot", "reason", "state", "discovery_complete",
                                "unattended_gc_guaranteed", "automatic_deletion_enabled"}
            if (not fields <= value.keys() or value.keys() - fields - optional or
                    value["version"] != "1" or str(uuid.UUID(value["boot"])) != value["boot"] or
                    value["reason"] not in ("IDLE", "STOP") or value["state"] != "PENDING_RESCAN" or
                    value["discovery_complete"] not in ("true", "false") or
                    value["unattended_gc_guaranteed"] != "false" or
                    value["automatic_deletion_enabled"] != "false"):
                raise ValueError("invalid retirement handoff fields")
            for key in numbers | (optional & value.keys()):
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid retirement handoff integer")
                value[key] = int(value[key])
            value["discovery_complete"] = value["discovery_complete"] == "true"
            hint = value.get("next_attempt_hint_boottime_us", 0)
            if (value["known_deferred"] > value["known_candidates"] or
                    (not value["discovery_complete"] and hint) or
                    (hint and hint < value["recorded_boottime_us"])):
                raise ValueError("inconsistent retirement handoff")
            self.retirement_handoff = dict(value, status="valid", requires_rescan=True)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.error(relative, "invalid_retirement_handoff", str(exc))

    def read_domain(self, directory, before):
        relative = ".gc/domain.ini"
        try:
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 4096):
                raise ValueError("unsafe cache domain")
            fd = os.open("domain.ini", os.O_RDONLY | os.O_CLOEXEC |
                         os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("cache domain changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["domain"]:
                raise ValueError("invalid cache domain sections")
            value = dict(parser["domain"])
            numbers = {"cache_device", "cache_inode", "lock_device", "lock_inode",
                       "created_boottime_us"}
            if (set(value) != numbers | {"version", "id", "created_boot"} or
                    value["version"] != "1" or
                    str(uuid.UUID(value["id"])) != value["id"] or
                    str(uuid.UUID(value["created_boot"])) != value["created_boot"]):
                raise ValueError("invalid cache domain fields")
            for key in numbers:
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid cache domain integer")
                value[key] = int(value[key])
            self.domain = value
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_cache_domain", str(exc))

    def read_compiler_budget(self, directory, name, before):
        relative = ".gc/compiler-budgets/" + name
        self.compiler_budgets[relative] = {"valid": False, "binding_observed": False}
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 4096):
                raise ValueError("unsafe compiler budget")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("compiler budget changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["budget"]:
                raise ValueError("invalid compiler budget sections")
            value = dict(parser["budget"])
            numbers = {"task_device", "task_inode", "cache_device", "cache_inode", "bytes"}
            if (set(value) != numbers | {"version", "task_id"} or
                    value["version"] != "1" or value["task_id"] != name[:-4]):
                raise ValueError("invalid compiler budget fields")
            for key in numbers:
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid compiler budget integer")
                value[key] = int(value[key])
            if not value["bytes"]:
                raise ValueError("compiler budget must be positive")
            self.compiler_budgets[relative] = dict(value, valid=True, binding_observed=False)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_compiler_budget", str(exc))

    def read_mount_lease(self, directory, name, before):
        relative = ".gc/mount-leases/" + name
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 4096):
                raise ValueError("unsafe mount lease")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("mount lease changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["mount"]:
                raise ValueError("invalid mount lease sections")
            value = dict(parser["mount"])
            numbers = {"cache_device", "cache_inode", "object_device", "object_inode"}
            if (set(value) != numbers | {"version", "id", "scope", "state", "source", "name"} or
                    value["version"] != "1" or value["id"] != name[:-4] or
                    value["scope"] not in {"CACHE", "SOURCE", "OBJECT"} or
                    value["state"] not in {"ACTIVE", "RELEASED"}):
                raise ValueError("invalid mount lease fields")
            for key in numbers:
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid mount lease integer")
                value[key] = int(value[key])
            cache = self.directories.get("")
            if not cache or cache[:2] != (value["cache_device"], value["cache_inode"]):
                raise ValueError("mount lease cache binding changed")
            if value["scope"] == "CACHE":
                valid_scope = value["source"] == value["name"] == "" and \
                    value["object_device"] == value["object_inode"] == 0
            elif value["scope"] == "SOURCE":
                valid_scope = bool(re.fullmatch(SHA, value["source"])) and \
                    value["name"] == "" and value["object_device"] == value["object_inode"] == 0
            else:
                valid_scope = bool(re.fullmatch(SHA, value["source"])) and \
                    bool(GENERATED.fullmatch(value["name"])) and \
                    GENERATED.fullmatch(value["name"])[1] == value["source"] and \
                    value["object_device"] and value["object_inode"]
            if not valid_scope:
                raise ValueError("invalid mount lease scope")
            self.mount_leases[relative] = dict(value, binding_observed=False)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_mount_lease", str(exc))

    def compiler_budget_report(self):
        bound_bytes = outstanding_bytes = unknown_tasks = 0
        for relative, budget in self.compiler_budgets.items():
            if not budget["valid"]:
                continue
            task_path = ".gc/tasks/" + budget["task_id"] + ".ini"
            task, row = self.tasks.get(task_path), self.entries.get(task_path)
            cache = self.directories.get("")
            if (not task or task["version"] != "1" or not row or not cache or
                    (row["device"], row["inode"]) != (budget["task_device"], budget["task_inode"]) or
                    cache[:2] != (budget["cache_device"], budget["cache_inode"])):
                self.freeze_all = True
                self.error(relative, "compiler_budget_binding_changed", task_path)
                continue
            budget["binding_observed"] = True
            bound_bytes += budget["bytes"]
            if not task.get("compiler_outputs_released"):
                outstanding_bytes += budget["bytes"]
        for relative, task in self.tasks.items():
            if task["version"] != "1":
                task["compiler_budget_status"] = "NOT_APPLICABLE"
                continue
            path = ".gc/compiler-budgets/" + relative.rsplit("/", 1)[1]
            budget = self.compiler_budgets.get(path)
            if budget is None:
                task["compiler_budget_status"] = "MISSING"
            elif not budget["binding_observed"]:
                task["compiler_budget_status"] = "INVALID"
            else:
                task["compiler_budget_status"] = "BOUND"
                task["compiler_peak_budget_bytes"] = budget["bytes"]
            if task["compiler_budget_status"] != "BOUND":
                unknown_tasks += 1
        return {"bound_peak_bytes": bound_bytes,
                "without_output_release_observed_bytes": outstanding_bytes,
                "unknown_compiler_task_count": unknown_tasks,
                "invalid_or_unbound_record_count": sum(not b["binding_observed"]
                                                        for b in self.compiler_budgets.values()),
                "daemon_reservation_verified": False,
                "physical_usage": False}

    def read_copy_handoff(self, directory, name, before, releasing=False, compiler=False, outputs=False):
        relative = (".gc/compiler-output-releases/" if outputs else ".gc/compiler-releases/" if compiler else
                    ".gc/copy-releases/" if releasing else ".gc/copy-handoffs/") + name
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 4096):
                raise ValueError("unsafe copy handoff")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 4097)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("copy handoff changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["handoff"]:
                raise ValueError("invalid copy handoff sections")
            value = dict(parser["handoff"])
            numbers = {"task_device", "task_inode"}
            if not releasing:
                numbers |= {"receipt_device", "receipt_inode"}
            if (set(value) != numbers | {"version", "task_id", "state"} or
                    value["version"] != "1" or value["task_id"] != name[:-4] or
                    value["state"] != ("OUTPUTS_RELEASED" if outputs else "INPUTS_RELEASED" if compiler else
                                       "RELEASED" if releasing else "SNAPSHOT_OWNED")):
                raise ValueError("invalid copy handoff fields")
            for key in numbers:
                if not re.fullmatch(r"[0-9]+", value[key]) or int(value[key]) >= 2**64:
                    raise ValueError("invalid copy handoff integer")
                value[key] = int(value[key])
            target = (self.compiler_output_releases if outputs else self.compiler_releases if compiler else
                      self.copy_releases if releasing else self.copy_handoffs)
            target[relative] = dict(value, binding_observed=False,
                                                input_reference_released=False)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_copy_handoff", str(exc))

    def read_copy_receipt(self, directory, name, before):
        relative = ".gc/copy-receipts/" + name
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 65536):
                raise ValueError("unsafe copy receipt")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 65537)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("copy receipt changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.defaults() or parser.sections() != ["receipt", "output"]:
                raise ValueError("invalid copy receipt sections")
            value, obj = dict(parser["receipt"]), dict(parser["output"])
            if (set(value) != {"version", "task_id", "task_device", "task_inode", "state"} or
                    value["version"] != "1" or value["task_id"] != name[:-4] or
                    value["state"] != "COPIED" or set(obj) != {"name", "device", "inode",
                    "size", "mode", "uid", "mtime_sec", "mtime_nsec", "sha256"} or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", obj["name"]) or
                    not re.fullmatch(SHA, obj["sha256"])):
                raise ValueError("invalid copy receipt fields")
            for fields, keys in ((value, {"task_device", "task_inode"}),
                                 (obj, set(obj) - {"name", "sha256"})):
                for key in keys:
                    if not re.fullmatch(r"-?[0-9]+" if key == "mtime_sec" else r"[0-9]+", fields[key]):
                        raise ValueError("invalid copy receipt integer")
                    fields[key] = int(fields[key])
                    low, high = (-2**63, 2**63) if key == "mtime_sec" else (0, 2**64)
                    if not low <= fields[key] < high:
                        raise ValueError("copy receipt integer out of range")
            if (obj["uid"] != os.geteuid() or not stat.S_ISREG(obj["mode"]) or
                    obj["mode"] & 0o222 or not obj["size"] or obj["mtime_nsec"] >= 10**9):
                raise ValueError("unsafe copy output binding")
            self.copy_receipts[relative] = dict(value, output=obj, binding_observed=False,
                                                content_validated=False)
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_copy_receipt", str(exc))

    def read_task(self, directory, name, before):
        relative = ".gc/tasks/" + name
        try:
            if (not name.endswith(".ini") or str(uuid.UUID(name[:-4])) != name[:-4] or
                    not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                    before.st_nlink != 1 or before.st_mode & 0o222 or
                    not 0 < before.st_size <= 65536):
                raise ValueError("unsafe or incomplete task record")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 65537)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("task record changed during read")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    observation = "NO_HOLDER_OBSERVED"
                except BlockingIOError:
                    observation = "HELD_OBSERVED"
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            copying = parser.get("task", "version", fallback="") == "2"
            inputs = {"input"} if copying else {"source", "tbset", "base_native", "base_module"}
            outputs = {"output"} if copying else {"output_native", "output_module"}
            required = {"task", "cache", "temporary", "input" if copying else "source"} | outputs
            if (parser.defaults() or not required <= set(parser.sections()) or
                    set(parser.sections()) - required - inputs - {"collected"}):
                raise ValueError("invalid task sections")
            value = dict(parser["task"])
            if (set(value) != {"version", "id", "state", "source", "build_id",
                               "kind" if copying else "environment_sha256"} or
                    value["version"] != ("2" if copying else "1") or
                    (copying and value["kind"] != "COPY") or
                    value["id"] != name[:-4] or value["state"] != "BOUND" or
                    any(not re.fullmatch(SHA, value[k]) for k in
                        (("source", "build_id") if copying else
                         ("source", "build_id", "environment_sha256")))):
                raise ValueError("invalid task identity/state")
            objects = {}
            numbers = {"device", "inode", "size", "mode", "uid", "mtime_sec", "mtime_nsec"}
            for role in set(parser.sections()) - {"task"}:
                obj = dict(parser[role])
                fields = {"name"} if role in outputs else numbers
                if role in inputs:
                    fields = fields | {"name", "directory"}
                    if obj.get("directory") not in {"temporary", "cache", "collected"}:
                        raise ValueError("invalid task input directory")
                    if obj["directory"] == "collected" and "collected" not in parser:
                        raise ValueError("missing task input directory binding")
                if set(obj) != fields:
                    raise ValueError("invalid task object fields")
                if "name" in obj and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", obj["name"])):
                    raise ValueError("invalid task basename")
                for field in fields - {"name", "directory"}:
                    pattern = r"-?[0-9]+" if field == "mtime_sec" else r"[0-9]+"
                    if not re.fullmatch(pattern, obj[field]):
                        raise ValueError("invalid task integer")
                    obj[field] = int(obj[field])
                    low, high = (-2**63, 2**63) if field == "mtime_sec" else (0, 2**64)
                    if not low <= obj[field] < high:
                        raise ValueError("task integer out of range")
                if role not in outputs:
                    directory_role = role in {"cache", "temporary", "collected"}
                    if (obj["mtime_nsec"] >= 10**9 or obj["uid"] != os.geteuid() or
                            not (stat.S_ISDIR(obj["mode"]) if directory_role else
                                 stat.S_ISREG(obj["mode"])) or
                            obj["mode"] & (0o077 if directory_role else 0o022)):
                        raise ValueError("unsafe task object binding")
                objects[role] = obj
            self.tasks[relative] = dict(value, lease_observation=observation,
                                        objects=objects, completion_verified=False)
            for role, obj in objects.items():
                if "name" in obj:
                    target = {"cache": "", "temporary": ".tmp/", "collected": ".tbsets/"}[
                        obj.get("directory", "temporary")] + obj["name"]
                    self.task_refs.setdefault(target, []).append(
                        {"task": relative, "role": role, "lease_observation": observation})
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.freeze_all = True
            self.error(relative, "invalid_task", str(exc))

    def read_tombstone(self, directory, name, before):
        relative = ".gc/tombstones/" + name
        try:
            match = GENERATED.fullmatch(name)
            if (not match or not stat.S_ISREG(before.st_mode) or
                    before.st_uid != os.geteuid() or before.st_nlink != 1 or
                    before.st_mode & 0o222 or not 0 < before.st_size <= 65536):
                raise ValueError("unsafe tombstone")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory)
            try:
                raw = os.read(fd, 65537)
                if identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size:
                    raise ValueError("tombstone changed during read")
            finally:
                os.close(fd)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("ascii"))
            if parser.sections() != ["tombstone"] or parser.defaults():
                raise ValueError("invalid tombstone sections")
            value = dict(parser["tombstone"])
            required = {"version", "source", "name", "state", "device", "inode",
                        "size", "allocated", "sha256"}
            if not required <= value.keys() or value.keys() - required - {"recovery_status", "deletion_status"}:
                raise ValueError("invalid tombstone fields")
            if (value["version"] != "1" or value["source"] != match[1] or
                    value["name"] != name or value["state"] != "DELETING" or
                    not re.fullmatch(SHA, value["sha256"]) or
                    value.get("recovery_status", "MATCHED") not in
                    {"MATCHED", "MISSING", "UNKNOWN", "BUSY"}):
                raise ValueError("invalid tombstone identity/state")
            if value.get("deletion_status", "UNLINKED") != "UNLINKED":
                raise ValueError("invalid tombstone deletion status")
            for field in ("device", "inode", "size", "allocated"):
                if not re.fullmatch(r"[0-9]+", value[field]) or int(value[field]) >= 2**64:
                    raise ValueError("invalid tombstone integer")
                value[field] = int(value[field])
            if not value["size"]:
                raise ValueError("empty tombstone object")
            self.tombstones[relative] = value
        except (OSError, ValueError, UnicodeError, configparser.Error) as exc:
            self.error(relative, "invalid_tombstone", str(exc))

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
                        "objects", "objects_status", "binding_status", "retirement_clock_reason"}
            if not required <= value.keys() or value.keys() - required - optional:
                raise ValueError("unsupported transaction fields")
            if ("retirement_clock_reason" in value and
                    value["retirement_clock_reason"] not in {"BOOT_CHANGED", "CLOCK_MISSING"}):
                raise ValueError("invalid retirement clock reason")
            source, state = value["source"], value["state"]
            if (value["version"] not in {"1", "2"} or not re.fullmatch(SHA, source) or
                    state not in {"PREPARED", "RETIRED", "ABORTED", "UNKNOWN"}):
                raise ValueError("invalid transaction identity/state")
            for prefix in ("prepared", "retired"):
                boot_key, time_key = prefix + "_boot", prefix + "_boottime_us"
                if (boot_key in value) != (time_key in value):
                    raise ValueError("incomplete transaction clock")
                if boot_key in value:
                    if (str(uuid.UUID(value[boot_key])) != value[boot_key] or
                            not re.fullmatch(r"[0-9]+", value[time_key]) or
                            int(value[time_key]) >= 2**64):
                        raise ValueError("invalid transaction clock")
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
            expected = {}
            for manifest in snapshots.values():
                for role in ("module", "native", "tbset"):
                    name = manifest[role]
                    if not name:
                        continue
                    digest = manifest.get(role + "_sha256", "")
                    prior = expected.get(name, "")
                    if prior and digest and prior != digest:
                        raise ValueError("conflicting snapshot digests")
                    expected[name] = prior or digest
            observed = {}
            for row in object_rows:
                name = row["name"]
                if (name not in expected or
                        (expected[name] and expected[name] != row["sha256"]) or
                        (name in observed and observed[name] != row)):
                    raise ValueError("object evidence differs from manifest references")
                observed[name] = row
            if object_rows and observed.keys() != expected.keys():
                raise ValueError("object evidence does not cover manifest references")
            value["binding_verified"] = bool(object_rows)
            if value.get("binding_status", "UNPROVEN") not in {"COMPLETE", "UNPROVEN"}:
                raise ValueError("invalid binding status")
            if value.get("binding_status") == "COMPLETE" and not object_rows:
                raise ValueError("complete binding has no object evidence")
            for role, manifest in snapshots.items():
                for field in ("module", "native", "tbset"):
                    if manifest[field]:
                        self.transaction_refs.setdefault(manifest[field], []).append(
                            {"transaction": relative, "snapshot": role,
                             "role": field, "state": state})
            self.transactions[relative] = value
            self.snapshots[relative] = snapshots
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

    def completed_removal(self, name):
        marker = self.tombstones.get(".gc/tombstones/" + name)
        if (not marker or marker.get("deletion_status") != "UNLINKED" or
                marker.get("recovery_status") != "MISSING" or name in self.entries or
                name in self.refs or name in self.task_refs or name in self.hold_refs or
                self.freeze_all or marker["source"] in self.frozen or self.errors or
                marker["source"] + ".current" not in self.manifests):
            return False
        for lease in self.mount_leases.values():
            if lease["state"] == "ACTIVE" and lease["binding_observed"] and (
                    lease["scope"] == "CACHE" or
                    (lease["scope"] == "SOURCE" and lease["source"] == marker["source"]) or
                    (lease["scope"] == "OBJECT" and lease["source"] == marker["source"] and
                     lease["name"] == name)):
                return False
        references = self.transaction_refs.get(name, [])
        if not references:
            return False
        fields = ("name", "device", "inode", "size", "allocated", "sha256")
        for reference in references:
            record = self.transactions[reference["transaction"]]
            matching = [obj for obj in record["object_identities"] if obj["name"] == name]
            if (reference["snapshot"] == "next" or record["state"] != "RETIRED" or
                    not record["binding_verified"] or
                    record.get("objects_status") != "RECORDED" or not matching or
                    any(any(obj[field] != marker[field] for field in fields) for obj in matching)):
                return False
        return True

    def retirement_plan(self, objects):
        """Select diagnostic deadlines, not live-safe deletion candidates."""
        output = []
        for name, references in sorted(self.transaction_refs.items()):
            row = self.entries.get(name)
            source = GENERATED.fullmatch(name)[1]
            if self.completed_removal(name):
                output.append({"name": name, "source": source, "selection_status": "removed",
                               "holds": [], "retirement_transactions": [], "current_references": [],
                               "deadline_boottime_us": None, "remaining_grace_us": None,
                               "delete_authorized": False})
                continue
            holds, events, evidence = set(), [], []
            for reference in references:
                path = reference["transaction"]
                transaction = self.transactions[path]
                state = transaction["state"]
                snapshots = self.snapshots[path]
                if state != "RETIRED":
                    holds.add(state.lower() + "_transaction")
                if not row and reference["snapshot"] == "next":
                    holds.add("missing_transaction_next_reference")
                # Sharing a filename into the next generation does not retire it.
                next_names = {snapshots["next"][role] for role in ("module", "native", "tbset")}
                if (state == "RETIRED" and reference["snapshot"] == "previous" and
                        name not in next_names):
                    events.append(path)
                matching = [obj for obj in transaction["object_identities"] if obj["name"] == name]
                if (not transaction["binding_verified"] or
                        transaction.get("objects_status") != "RECORDED" or not matching):
                    holds.add("unproven_object_evidence")
                evidence.extend(matching)
            events = sorted(set(events))
            aliases = objects.get((row["device"], row["inode"]), []) if row else []
            current = [ref for alias in aliases for ref in self.refs.get(alias["path"], [])]
            if current:
                holds.add("current_reference")
            if name in self.task_refs or any(self.task_refs.get(alias["path"]) for alias in aliases):
                holds.add("persistent_task_reference")
            if any(self.hold_refs.get(alias["path"]) for alias in aliases) or name in self.hold_refs:
                holds.add("explicit_retention_reference")
            for lease in self.mount_leases.values():
                if lease["state"] != "ACTIVE" or not lease["binding_observed"]:
                    continue
                if (lease["scope"] == "CACHE" or
                        (lease["scope"] == "SOURCE" and lease["source"] == source) or
                        (lease["scope"] == "OBJECT" and lease["source"] == source and
                         lease["name"] == name)):
                    holds.add("mount_lease_reference")
            if source + ".current" not in self.manifests:
                holds.add("missing_current_root")
            if self.freeze_all or source in self.frozen or self.errors:
                holds.add("inventory_or_source_unknown")
            if not events:
                holds.add("no_proven_retirement")
            if (not row or not stat.S_ISREG(row["_mode"]) or row["_uid"] != os.geteuid() or
                    row["_mode"] & 0o222 or row["links"] != 1 or not row["logical_bytes"]):
                holds.add("missing_or_unsafe_object")
            if evidence and any(obj != evidence[0] for obj in evidence):
                holds.add("conflicting_object_evidence")
            if row and any((obj["device"], obj["inode"], obj["size"], obj["allocated"]) !=
                           (row["device"], row["inode"], row["logical_bytes"], row["allocated_bytes"])
                           for obj in evidence):
                holds.add("object_identity_changed")
            deadlines = []
            for path in events:
                transaction = self.transactions[path]
                boot, stamp = transaction.get("retired_boot"), transaction.get("retired_boottime_us")
                if not self.clock:
                    holds.add("clock_unavailable")
                elif boot is None or stamp is None:
                    holds.add("missing_retirement_clock")
                elif boot != self.clock[0]:
                    holds.add("reboot_recovery_required")
                elif int(stamp) > self.clock[1]:
                    holds.add("future_retirement_clock")
                else:
                    deadlines.append(int(stamp) + self.grace_us)
            deadline = max(deadlines) if events and len(deadlines) == len(events) else None
            remaining = max(0, deadline - self.clock[1]) if deadline is not None else None
            status = "held" if holds else "grace" if remaining else "due"
            output.append({"name": name, "source": source, "selection_status": status,
                           "holds": sorted(holds), "retirement_transactions": events,
                           "current_references": current, "deadline_boottime_us": deadline,
                           "remaining_grace_us": remaining, "delete_authorized": False})
        return output

    def report(self):
        domain_marker = self.entries.get(".gc/domain.ini")
        domain_lock = self.entries.get(".gc/domain.lock")
        cache = self.directories.get("")
        handoff = self.retirement_handoff
        if handoff and handoff["status"] == "valid":
            handoff["binding_observed"] = bool(cache and cache[:2] ==
                (handoff["cache_device"], handoff["cache_inode"]))
            if not handoff["binding_observed"]:
                handoff["status"] = "wrong_cache"
                self.error(".gc/retirement-handoff.ini", "retirement_handoff_binding_changed",
                           "record does not bind this cache")
            elif not self.clock:
                handoff["status"] = "clock_unavailable"
            elif handoff["boot"] != self.clock[0]:
                handoff["status"] = "previous_boot"
            elif handoff["recorded_boottime_us"] > self.clock[1]:
                handoff["status"] = "future_record"
                self.error(".gc/retirement-handoff.ini", "invalid_retirement_handoff_clock",
                           "recorded time is in the future")
            elif not handoff["discovery_complete"]:
                handoff["status"] = "incomplete_discovery"
        if domain_marker or domain_lock:
            lock_valid = bool(domain_lock and stat.S_ISREG(domain_lock["_mode"]) and
                domain_lock["_uid"] == os.geteuid() and domain_lock["links"] == 1 and
                not domain_lock["_mode"] & 0o077 and domain_lock["logical_bytes"] == 0)
            self.domain_binding_observed = bool(self.domain and lock_valid and cache and
                cache[:2] == (self.domain["cache_device"], self.domain["cache_inode"]) and
                (domain_lock["device"], domain_lock["inode"]) ==
                (self.domain["lock_device"], self.domain["lock_inode"]))
            if not self.domain_binding_observed:
                self.freeze_all = True
                self.error(".gc/domain.ini", "cache_domain_binding_changed",
                           "marker and lock must both exist and bind this cache")
        for relative, lease in self.mount_leases.items():
            cache = self.directories.get("")
            cache_matched = bool(cache and cache[:2] ==
                                 (lease["cache_device"], lease["cache_inode"]))
            row = self.entries.get(lease["name"]) if lease["scope"] == "OBJECT" else None
            object_matched = lease["scope"] != "OBJECT" or bool(
                row and (row["device"], row["inode"]) ==
                (lease["object_device"], lease["object_inode"]))
            lease["binding_observed"] = cache_matched and object_matched
            if not cache_matched or (not object_matched and
                    (lease["state"] == "ACTIVE" or row is not None)):
                self.freeze_all = True
                self.error(relative, "mount_lease_binding_changed", lease["scope"])
        for relative, hold in self.explicit_holds.items():
            cache = self.directories.get("")
            row = self.entries.get(hold["name"])
            matched = (cache and cache[:2] == (hold["cache_device"], hold["cache_inode"]) and
                       row and (row["device"], row["inode"]) == (hold["object_device"], hold["object_inode"]))
            hold["binding_observed"] = bool(matched)
            if hold["state"] == "ACTIVE" or (row is not None and not matched):
                self.hold_refs.setdefault(hold["name"], []).append(relative)
                if not matched:
                    self.freeze_all = True
                    self.error(relative, "explicit_hold_binding_changed", hold["name"])
        compiler_inputs = {"source", "tbset", "base_native", "base_module"}
        for relative, release in self.compiler_releases.items():
            task_path = ".gc/tasks/" + release["task_id"] + ".ini"
            task, row = self.tasks.get(task_path), self.entries.get(task_path)
            if (not task or task["version"] != "1" or not row or
                    (row["device"], row["inode"]) != (release["task_device"], release["task_inode"])):
                self.freeze_all = True
                self.error(relative, "compiler_release_binding_changed", task_path)
                continue
            release["binding_observed"] = True
            if task["lease_observation"] != "NO_HOLDER_OBSERVED":
                continue
            task["compiler_inputs_released"] = True
            release["input_reference_released"] = True
            for target, refs in self.task_refs.items():
                self.task_refs[target] = [ref for ref in refs if not
                    (ref["task"] == task_path and ref["role"] in compiler_inputs)]
        for relative, release in self.compiler_output_releases.items():
            task_path = ".gc/tasks/" + release["task_id"] + ".ini"
            task, row = self.tasks.get(task_path), self.entries.get(task_path)
            if (not task or task["version"] != "1" or not row or
                    (row["device"], row["inode"]) != (release["task_device"], release["task_inode"])):
                self.freeze_all = True
                self.error(relative, "compiler_output_release_binding_changed", task_path)
                continue
            release["binding_observed"] = True
            if (not task.get("compiler_inputs_released") or
                    any(".tmp/" + task["objects"][role]["name"] in self.entries
                        for role in ("output_native", "output_module"))):
                continue
            task["compiler_outputs_released"] = True
            release["output_reference_released"] = True
            for target, refs in self.task_refs.items():
                self.task_refs[target] = [ref for ref in refs if not
                    (ref["task"] == task_path and ref["role"].startswith("output_"))]
        for relative, release in self.copy_releases.items():
            task_path = ".gc/tasks/" + release["task_id"] + ".ini"
            task, row = self.tasks.get(task_path), self.entries.get(task_path)
            if (not task or task.get("kind") != "COPY" or not row or
                    (row["device"], row["inode"]) != (release["task_device"], release["task_inode"])):
                self.freeze_all = True
                self.error(relative, "copy_release_binding_changed", task_path)
                continue
            release["binding_observed"] = True
            output = ".tmp/" + task["objects"]["output"]["name"]
            if output in self.entries or task["lease_observation"] != "NO_HOLDER_OBSERVED":
                continue
            task["copy_released"] = True
            task["input_reference_released"] = True
            release["input_reference_released"] = True
            for target, refs in self.task_refs.items():
                self.task_refs[target] = [ref for ref in refs if ref["task"] != task_path]
        for relative, receipt in self.copy_receipts.items():
            task_path = ".gc/tasks/" + receipt["task_id"] + ".ini"
            task, row = self.tasks.get(task_path), self.entries.get(task_path)
            obj = receipt["output"]
            if (not task or task.get("kind") != "COPY" or not row or
                    (row["device"], row["inode"]) != (receipt["task_device"], receipt["task_inode"]) or
                    task["objects"]["output"]["name"] != obj["name"]):
                self.freeze_all = True
                self.error(relative, "copy_receipt_task_changed", task_path)
                continue
            output = self.entries.get(".tmp/" + obj["name"])
            receipt["output_observation"] = "MISSING" if output is None else "CHANGED"
            if output is not None:
                observed = output["_identity"]
                matched = (observed[0], observed[1], observed[2], observed[3], observed[4],
                           observed[5], observed[6]) == (obj["device"], obj["inode"], obj["mode"],
                    obj["uid"], 1, obj["size"], obj["mtime_sec"] * 10**9 + obj["mtime_nsec"])
                if matched:
                    receipt["binding_observed"] = True
                    receipt["output_observation"] = "MATCHED"
                else:
                    self.freeze_all = True
                    self.error(relative, "copy_receipt_output_changed", obj["name"])
            task["copy_receipt"] = relative
        for relative, handoff in self.copy_handoffs.items():
            name = handoff["task_id"] + ".ini"
            task_path, receipt_path = ".gc/tasks/" + name, ".gc/copy-receipts/" + name
            task, receipt = self.tasks.get(task_path), self.copy_receipts.get(receipt_path)
            rows = [self.entries.get(path) for path in (task_path, receipt_path)]
            matched = task and task.get("kind") == "COPY" and receipt and all(rows)
            if matched:
                matched = all((row["device"], row["inode"]) ==
                    (handoff[prefix + "_device"], handoff[prefix + "_inode"])
                    for row, prefix in zip(rows, ("task", "receipt")))
            if not matched:
                self.freeze_all = True
                self.error(relative, "copy_handoff_binding_changed", task_path)
                continue
            handoff["binding_observed"] = True
            # Missing/changed snapshots cannot justify releasing a root in a plan.
            if not receipt["binding_observed"]:
                continue
            handoff["input_reference_released"] = True
            task["input_reference_released"] = True
            task["copy_handoff"] = relative
            for target, refs in self.task_refs.items():
                self.task_refs[target] = [ref for ref in refs if not
                    (ref["task"] == task_path and ref["role"] == "input")]
        for relative, task in self.tasks.items():
            for role, obj in task["objects"].items():
                directories = {"cache": "", "temporary": ".tmp", "collected": ".tbsets"}
                path = (directories[role] if role in directories else
                        (directories[obj.get("directory", "temporary")] + "/").lstrip("/") + obj["name"])
                if role in directories:
                    observed = self.directories.get(path)
                    matched = observed and (observed[0], observed[1], observed[2], observed[3]) == (
                        obj["device"], obj["inode"], obj["mode"], obj["uid"])
                elif role == "output" or role.startswith("output_"):
                    continue  # Intent only: never claim an output inode is reserved.
                elif role == "input" and task.get("input_reference_released"):
                    continue
                elif role in compiler_inputs and task.get("compiler_inputs_released"):
                    continue
                else:
                    row = self.entries.get(path)
                    if row is None:
                        if task["lease_observation"] == "HELD_OBSERVED":
                            self.error(relative, "task_input_missing", path)
                        continue  # A retained historical root may outlive normal cleanup.
                    observed = row["_identity"]
                    matched = (observed[0], observed[1], observed[2], observed[3],
                               observed[5], observed[6]) == (obj["device"], obj["inode"],
                        obj["mode"], obj["uid"], obj["size"], obj["mtime_sec"] * 10**9 + obj["mtime_nsec"])
                if not matched:
                    self.freeze_all = True
                    self.error(relative, "task_binding_changed", path or ".")
        compiler_budget_summary = self.compiler_budget_report()
        for relative in self.entries:
            if (relative.startswith(".gc/tombstones/") and
                    not relative.removeprefix(".gc/tombstones/").startswith(".write-")):
                name = relative.removeprefix(".gc/tombstones/")
                if self.completed_removal(name):
                    continue
                match = GENERATED.fullmatch(name)
                if match:
                    self.frozen.add(match[1])
                else:
                    self.freeze_all = True
                self.error(relative, "unrecovered_tombstone",
                           "persistent deletion intent requires controlled recovery")
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
        cache_mounts, source_mounts, object_mounts = [], {}, {}
        for path, lease in self.mount_leases.items():
            if lease["state"] != "ACTIVE" or not lease["binding_observed"]:
                continue
            if lease["scope"] == "CACHE":
                cache_mounts.append(path)
            elif lease["scope"] == "SOURCE":
                source_mounts.setdefault(lease["source"], []).append(path)
            else:
                object_mounts.setdefault(lease["name"], []).append(path)
        output = []
        groups = {}
        for relative, row in sorted(self.entries.items()):
            mode = row["_mode"]
            category, reasons = "unknown", ["unrecognized_object"]
            referrers = [r for alias in objects[(row["device"], row["inode"])]
                         for r in self.refs.get(alias["path"], [])]
            aliases = objects[(row["device"], row["inode"])]
            transactions = [r for alias in aliases for r in self.transaction_refs.get(alias["path"], [])]
            tasks = [r for alias in aliases for r in self.task_refs.get(alias["path"], [])]
            holds = [r for alias in aliases for r in self.hold_refs.get(alias["path"], [])]
            generated = GENERATED.fullmatch(relative)
            mounts = (cache_mounts + source_mounts.get(generated[1], []) +
                      [path for alias in aliases for path in object_mounts.get(alias["path"], [])]
                      if generated else [])
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
            elif transactions:
                category, reasons = "transaction_artifact", ["persistent_transaction_hold"]
            elif generated and (holds or tasks or mounts):
                category, reasons = "retained_artifact", []
            elif relative.startswith(".superseded/"):
                category, reasons = "legacy_retired", ["legacy_reference_contract_unknown"]
            elif relative.startswith(".tmp/"):
                category, reasons = "temporary", ["worker_liveness_unknown"]
                if tasks:
                    reasons.append("persistent_task_reference")
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
            if holds:
                reasons.append("explicit_retention_reference")
            if tasks and "persistent_task_reference" not in reasons:
                reasons.append("persistent_task_reference")
            if mounts:
                reasons.append("mount_lease_reference")
            if self.freeze_all or any(part[:64] in self.frozen for part in relative.split("/")):
                reasons.append("invalid_source_manifest")
            if self.errors:
                reasons.append("inventory_incomplete")
            if stat.S_ISREG(mode):
                reasons.append("lifecycle_and_mount_admission_unverified")
            result = {k: v for k, v in row.items() if not k.startswith("_")}
            result.update(category=category, reasons=reasons, references=referrers,
                          transaction_references=transactions, task_references=tasks,
                          explicit_hold_references=holds, mount_lease_references=mounts,
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
                "cache_domain": ({"status": "managed", "id": self.domain["id"],
                                  "binding_observed": self.domain_binding_observed}
                                 if self.domain and self.domain_binding_observed else
                                 {"status": "legacy"} if not domain_marker and not domain_lock else
                                 {"status": "unknown", "binding_observed": False}),
                "transaction_count": len(self.transactions),
                "task_count": len(self.tasks), "tasks": self.tasks,
                "copy_receipt_count": len(self.copy_receipts), "copy_receipts": self.copy_receipts,
                "copy_handoff_count": len(self.copy_handoffs), "copy_handoffs": self.copy_handoffs,
                "copy_release_count": len(self.copy_releases), "copy_releases": self.copy_releases,
                "compiler_release_count": len(self.compiler_releases), "compiler_releases": self.compiler_releases,
                "compiler_output_release_count": len(self.compiler_output_releases),
                "compiler_output_releases": self.compiler_output_releases,
                "compiler_budget_count": len(self.compiler_budgets),
                "compiler_budgets": self.compiler_budgets,
                "compiler_budget_summary": compiler_budget_summary,
                "explicit_hold_count": len(self.explicit_holds),
                "explicit_holds": self.explicit_holds,
                "mount_lease_count": len(self.mount_leases),
                "mount_leases": self.mount_leases,
                "transactions": self.transactions,
                "retirement_plan": {"grace_us": self.grace_us,
                                    "exit_handoff": handoff,
                                    "clock": ({"boot_id": self.clock[0], "boottime_us": self.clock[1]}
                                              if self.clock else None),
                                    "full_reference_graph_verified": False,
                                    "candidates": self.retirement_plan(objects)},
                "tombstone_count": len(self.tombstones), "tombstones": self.tombstones,
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
