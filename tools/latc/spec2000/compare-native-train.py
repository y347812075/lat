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


def save_markdown(report, workdir):
    lines = [
        "# SPECint2000 train performance baseline",
        "",
        "Runtime is the median of %d measured rounds. Efficiency is "
        "native runtime/runtime; higher is faster." % report["rounds"],
        "",
        "Host: `%s`; kernel: `%s`; CPU: `%s`; LAT cache: `%s`; "
        "ASLR disabled: `%s`." %
        (report["host"], report["kernel"], report["cpu"],
         report["lat_cache"], str(report["aslr_disabled"]).lower()),
        "",
        "| Benchmark | LATC runtime (s) | LATC efficiency | "
        "LAT AOT runtime (s) | LAT AOT efficiency | "
        "LA native runtime (s) | LA native efficiency |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for benchmark, result in report["results"].items():
        lines.append(
            "| %s | %.6f | %.2f%% | %.6f | %.2f%% | %.6f | %.2f%% |" %
            (benchmark, result["latc"]["median"],
             result["translation_efficiency_percent"]["latc"],
             result["lat_aot"]["median"],
             result["translation_efficiency_percent"]["lat_aot"],
             result["native"]["median"],
             result["translation_efficiency_percent"]["native"]))
    geomean = report["geomean_translation_efficiency_percent"]
    lines.extend([
        "| **Geometric mean** | - | **%.2f%%** | - | **%.2f%%** | "
        "- | **%.2f%%** |" %
        (geomean["latc"], geomean["lat_aot"], geomean["native"]),
        "",
    ])
    (workdir / "baseline.md").write_text("\n".join(lines))


def aot_cache_files(home):
    cache = home / ".cache" / "latx"
    return sorted(path for path in cache.glob("*.aot2")
                  if path.stat().st_size > 0)


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
    parser.add_argument("--disable-aslr", action="store_true")
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

    command_prefix = "taskset -c %d" % args.cpu
    if args.disable_aslr:
        command_prefix += " setarch %s -R" % quote(platform.machine())

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
            "exec %s %s \"$@\"" % (command_prefix, quote(latc)),
        ])
        wrapper(mode_dirs["lat_aot"] / filename, [
            "export HOME=%s" % quote(home),
            "export LATX_AOT=1",
            "export LATX_TU=1",
            "exec %s %s %s \"$@\"" %
            (command_prefix, quote(args.runner), quote(guest)),
        ])
        wrapper(mode_dirs["native"] / filename, [
            "exec %s %s \"$@\"" % (command_prefix, quote(native)),
        ])

    report = {
        "suite": "SPECint2000", "input": "train",
        "host": platform.node(), "kernel": platform.release(),
        "machine": platform.machine(), "cpu": args.cpu,
        "aslr_disabled": args.disable_aslr,
        "rounds": args.rounds, "lat_cache": args.lat_cache,
        "runner": str(args.runner), "runner_sha256": sha256(args.runner),
        "latc_dir": str(args.latc_dir), "native_dir": str(args.native_dir),
        "aot_cache": {},
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
        return value

    try:
        for benchmark, _filename, _strict in programs:
            measure(benchmark, "latc", 0, warmup=True)
            measure(benchmark, "native", 0, warmup=True)
            if args.lat_cache == "warm":
                home = homes / benchmark
                files = []
                generation_runs = 0
                while generation_runs < 3 and not files:
                    generation_runs += 1
                    measure(benchmark, "lat_aot", generation_runs,
                            warmup=True)
                    files = aot_cache_files(home)
                if not files:
                    raise RuntimeError(
                        "%s did not create a non-empty AOT cache in %s" %
                        (benchmark, home / ".cache" / "latx"))
                measure(benchmark, "lat_aot", generation_runs + 1,
                        warmup=True)
                files = aot_cache_files(home)
                report["aot_cache"][benchmark] = {
                    "generation_runs": generation_runs,
                    "hot_verification_runs": 1,
                    "files": [{"name": path.name,
                               "size": path.stat().st_size}
                              for path in files],
                }
                save(report, args.workdir)
            else:
                measure(benchmark, "lat_aot", 0, warmup=True)
            for index in range(1, args.rounds + 1):
                order = modes[index % len(modes):] + modes[:index % len(modes)]
                for mode in order:
                    measure(benchmark, mode, index)
    finally:
        replace_run_link(args.spec_root, old_target)

    latc_vs_lat = []
    latc_vs_native = []
    translation_efficiency_percent = {mode: [] for mode in modes}
    for benchmark, _filename, _strict in programs:
        result = {mode: sample_summary(report["samples"][benchmark][mode])
                  for mode in modes}
        result["latc_vs_lat"] = (result["lat_aot"]["median"] /
                                 result["latc"]["median"])
        result["latc_vs_native"] = (result["native"]["median"] /
                                    result["latc"]["median"])
        native_runtime = result["native"]["median"]
        result["translation_efficiency_percent"] = {
            mode: native_runtime / result[mode]["median"] * 100.0
            for mode in modes
        }
        report["results"][benchmark] = result
        latc_vs_lat.append(result["latc_vs_lat"])
        latc_vs_native.append(result["latc_vs_native"])
        for mode in modes:
            translation_efficiency_percent[mode].append(
                result["translation_efficiency_percent"][mode])
    report["geomean_latc_vs_lat"] = geometric_mean(latc_vs_lat)
    report["geomean_latc_vs_native"] = geometric_mean(latc_vs_native)
    report["geomean_translation_efficiency_percent"] = {
        mode: geometric_mean(translation_efficiency_percent[mode])
        for mode in modes
    }
    save(report, args.workdir)
    save_markdown(report, args.workdir)
    print(json.dumps({
        "report": str(args.workdir / "report.json"),
        "baseline": str(args.workdir / "baseline.md"),
        "geomean_latc_vs_lat": report["geomean_latc_vs_lat"],
        "geomean_latc_vs_native": report["geomean_latc_vs_native"],
        "geomean_translation_efficiency_percent":
            report["geomean_translation_efficiency_percent"],
    }))


if __name__ == "__main__":
    main()
