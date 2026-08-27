#!/usr/bin/env python3
"""Run a focused, strict M4 versus AOT v2 SPEC train comparison."""

import argparse
import json
import os
import platform
import shlex
from pathlib import Path

from specint import replace_run_link, run_spec, sample_summary
from specint import selected_programs, sha256, strict_aot_v2_env_lines


def quote(value):
    return shlex.quote(str(value))


def write_wrapper(path, lines):
    path.write_text("#!/bin/sh\nset -eu\n" + "\n".join(lines) + "\n")
    path.chmod(0o755)


def save(path, report):
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--m4-dir", required=True, type=Path)
    parser.add_argument("--aot-v2-dir", required=True, type=Path)
    parser.add_argument("--module-dir", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--spec-root", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--guest-dir", default="specbin/x64_gcc12_2_0")
    parser.add_argument("--benchmark", action="append", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--cpu", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--disable-aslr", action="store_true")
    args = parser.parse_args()

    for name in ("m4_dir", "aot_v2_dir", "module_dir", "runtime_dir",
                 "spec_root", "workdir"):
        setattr(args, name, getattr(args, name).resolve())
    if not args.runtime_dir.is_dir():
        raise SystemExit("missing AOT v2 runtime directory: %s" %
                         args.runtime_dir)
    guest_dir = (args.spec_root / args.guest_dir).resolve()
    programs = selected_programs(args.benchmark)
    modes = ("m4", "aot_v2")
    wrappers = args.workdir / "wrappers"
    logs = args.workdir / "logs"
    raws = args.workdir / "raws"
    for path in (args.workdir, wrappers, logs, raws):
        path.mkdir(parents=True, exist_ok=True)
    mode_dirs = {mode: wrappers / mode for mode in modes}
    for path in mode_dirs.values():
        path.mkdir(exist_ok=True)

    command_prefix = "taskset -c %d" % args.cpu
    if args.disable_aslr:
        command_prefix += " setarch %s -R" % quote(platform.machine())
    inputs = {}
    for benchmark, filename, _strict in programs:
        guest = guest_dir / filename
        m4 = args.m4_dir / filename
        aot_v2 = args.aot_v2_dir / filename
        module = args.module_dir / (filename + ".so")
        for path in (guest, m4, aot_v2, module):
            if not path.is_file():
                raise SystemExit("missing %s input: %s" % (benchmark, path))
        write_wrapper(mode_dirs["m4"] / filename, [
            "exec %s %s \"$@\"" % (command_prefix, quote(m4)),
        ])
        write_wrapper(mode_dirs["aot_v2"] / filename,
                      strict_aot_v2_env_lines(
                          args.runtime_dir, module, guest) + [
            "exec %s %s \"$@\"" % (command_prefix, quote(aot_v2)),
        ])
        inputs[benchmark] = {
            "guest": sha256(guest), "m4": sha256(m4),
            "aot_v2": sha256(aot_v2), "module": sha256(module),
        }

    report = {
        "suite": "SPECint2000", "input": "train",
        "host": platform.node(), "kernel": platform.release(),
        "machine": platform.machine(), "cpu": args.cpu,
        "rounds": args.rounds, "strict_aot_v2": True,
        "aslr_disabled": args.disable_aslr,
        "inputs": inputs,
        "samples": {benchmark: {mode: [] for mode in modes}
                    for benchmark, _filename, _strict in programs},
        "results": {},
    }
    report_path = args.workdir / "report.json"
    run_link = args.spec_root / "specbin" / "run"
    old_target = Path(os.readlink(run_link))
    if not old_target.is_absolute():
        old_target = (run_link.parent / old_target).resolve()

    try:
        for benchmark, _filename, _strict in programs:
            for index in range(1, args.rounds + 1):
                order = modes if index % 2 else tuple(reversed(modes))
                for mode in order:
                    replace_run_link(args.spec_root, mode_dirs[mode])
                    log = logs / ("%s-%s-%02d.log" %
                                  (benchmark, mode, index))
                    value, raw, valid = run_spec(
                        args.spec_root, "train", benchmark, os.environ.copy(),
                        log, timeout=args.timeout)
                    if not valid:
                        raise RuntimeError("invalid SPEC result: %s %s" %
                                           (benchmark, mode))
                    destination = raws / ("%s-%s-%02d.raw" %
                                          (benchmark, mode, index))
                    destination.write_bytes(raw.read_bytes())
                    report["samples"][benchmark][mode].append(value)
                    save(report_path, report)
                    print("%s %s %02d %.6f" %
                          (benchmark, mode, index, value), flush=True)
    finally:
        replace_run_link(args.spec_root, old_target)

    for benchmark, _filename, _strict in programs:
        result = {
            mode: sample_summary(report["samples"][benchmark][mode])
            for mode in modes
        }
        result["aot_v2_vs_m4"] = (result["m4"]["median"] /
                                    result["aot_v2"]["median"])
        report["results"][benchmark] = result
    save(report_path, report)
    print(json.dumps({
        "report": str(report_path),
        "aot_v2_vs_m4": {
            benchmark: result["aot_v2_vs_m4"]
            for benchmark, result in report["results"].items()
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
