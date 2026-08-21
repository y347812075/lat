#!/usr/bin/env python3
"""Compare direct LATC ELF, LAT AOT/TU, and native LoongArch SPEC train."""

import argparse
import json
import os
import platform
import shlex
import shutil
from pathlib import Path

from specint import (geometric_mean, replace_run_link, run_spec,
                     sample_summary, selected_programs, sha256)


def quote(value):
    return shlex.quote(str(value))


def wrapper(path, lines):
    path.write_text("#!/bin/sh\nset -eu\n" + "\n".join(lines) + "\n")
    path.chmod(0o755)


def save(report, workdir):
    (workdir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--latc-dir", required=True, type=Path)
    parser.add_argument("--native-dir", required=True, type=Path)
    parser.add_argument("--spec-root", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--guest-dir", default="specbin/x64_gcc12_2_0")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--lat-cache", choices=("warm", "cold"),
                        default="warm")
    parser.add_argument("--benchmark", action="append", default=[])
    args = parser.parse_args()

    args.runner = args.runner.resolve()
    args.latc_dir = args.latc_dir.resolve()
    args.native_dir = args.native_dir.resolve()
    args.spec_root = args.spec_root.resolve()
    args.workdir = args.workdir.resolve()
    guest_dir = (args.spec_root / args.guest_dir).resolve()
    programs = selected_programs(args.benchmark)
    modes = ("latc", "lat_aot", "native")
    args.workdir.mkdir(parents=True, exist_ok=True)
    wrappers = args.workdir / "wrappers"
    logs = args.workdir / "logs"
    raws = args.workdir / "raws"
    homes = args.workdir / "homes"
    for directory in (wrappers, logs, raws, homes):
        directory.mkdir(exist_ok=True)
    mode_dirs = {mode: wrappers / mode for mode in modes}
    for directory in mode_dirs.values():
        directory.mkdir(exist_ok=True)

    for benchmark, filename, _strict in programs:
        guest = guest_dir / filename
        latc = args.latc_dir / filename
        native = args.native_dir / filename
        for path in (guest, latc, native):
            if not path.is_file():
                raise SystemExit("missing %s input: %s" % (benchmark, path))
        home = homes / benchmark
        home.mkdir(exist_ok=True)
        wrapper(mode_dirs["latc"] / filename, [
            "exec taskset -c %d %s \"$@\"" % (args.cpu, quote(latc)),
        ])
        wrapper(mode_dirs["lat_aot"] / filename, [
            "export HOME=%s" % quote(home),
            "export LATX_AOT=1",
            "export LATX_TU=1",
            "exec taskset -c %d %s %s \"$@\"" %
            (args.cpu, quote(args.runner), quote(guest)),
        ])
        wrapper(mode_dirs["native"] / filename, [
            "exec taskset -c %d %s \"$@\"" % (args.cpu, quote(native)),
        ])

    report = {
        "suite": "SPECint2000", "input": "train",
        "host": platform.node(), "kernel": platform.release(),
        "machine": platform.machine(), "cpu": args.cpu,
        "rounds": args.rounds, "lat_cache": args.lat_cache,
        "runner": str(args.runner), "runner_sha256": sha256(args.runner),
        "latc_dir": str(args.latc_dir), "native_dir": str(args.native_dir),
        "samples": {benchmark: {mode: [] for mode in modes}
                    for benchmark, _filename, _strict in programs},
        "results": {},
    }
    run_link = args.spec_root / "specbin" / "run"
    old_target = Path(os.readlink(run_link))
    if not old_target.is_absolute():
        old_target = (run_link.parent / old_target).resolve()
    env = os.environ.copy()

    def measure(benchmark, mode, index, warmup=False):
        replace_run_link(args.spec_root, mode_dirs[mode])
        suffix = "warmup" if warmup else "%02d" % index
        log = logs / (benchmark + "-" + mode + "-" + suffix + ".log")
        run_env = env.copy()
        if mode == "lat_aot" and args.lat_cache == "cold":
            shutil.rmtree(homes / benchmark / ".cache" / "latx",
                          ignore_errors=True)
        value, raw, valid = run_spec(args.spec_root, "train", benchmark,
                                     run_env, log, timeout=args.timeout)
        if not valid:
            raise RuntimeError("invalid SPEC result: %s %s" %
                               (benchmark, mode))
        (raws / (benchmark + "-" + mode + "-" + suffix + ".raw")).write_bytes(
            raw.read_bytes())
        if not warmup:
            report["samples"][benchmark][mode].append(value)
            save(report, args.workdir)
        print("%s %s %s %.6f" %
              (benchmark, mode, suffix, value), flush=True)

    try:
        for benchmark, _filename, _strict in programs:
            for mode in modes:
                measure(benchmark, mode, 0, warmup=True)
            for index in range(1, args.rounds + 1):
                order = modes[index % len(modes):] + modes[:index % len(modes)]
                for mode in order:
                    measure(benchmark, mode, index)
    finally:
        replace_run_link(args.spec_root, old_target)

    latc_vs_lat = []
    latc_vs_native = []
    for benchmark, _filename, _strict in programs:
        result = {mode: sample_summary(report["samples"][benchmark][mode])
                  for mode in modes}
        result["latc_vs_lat"] = (result["lat_aot"]["median"] /
                                 result["latc"]["median"])
        result["latc_vs_native"] = (result["native"]["median"] /
                                    result["latc"]["median"])
        report["results"][benchmark] = result
        latc_vs_lat.append(result["latc_vs_lat"])
        latc_vs_native.append(result["latc_vs_native"])
    report["geomean_latc_vs_lat"] = geometric_mean(latc_vs_lat)
    report["geomean_latc_vs_native"] = geometric_mean(latc_vs_native)
    save(report, args.workdir)
    print(json.dumps({
        "report": str(args.workdir / "report.json"),
        "geomean_latc_vs_lat": report["geomean_latc_vs_lat"],
        "geomean_latc_vs_native": report["geomean_latc_vs_native"],
    }))


if __name__ == "__main__":
    main()
