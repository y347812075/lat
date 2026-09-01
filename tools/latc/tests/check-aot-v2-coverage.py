#!/usr/bin/env python3
"""Check file-backed AOT coverage for complex-application stderr logs."""

import argparse
import json
import pathlib
import re


parser = argparse.ArgumentParser()
parser.add_argument("phase_root", type=pathlib.Path)
parser.add_argument("required_percent", type=float)
parser.add_argument("applications", nargs="+")
parser.add_argument("--require-no-fork-jit", action="store_true")
args = parser.parse_args()

module_pattern = re.compile(
    r"source=([0-9a-f]{64}).*module=(\w+) "
    r"aot_lookups=(\d+) jit_fallbacks=(\d+)")
runtime_pattern = re.compile(
    r"AOT v2 runtime stats .*compiler_submissions=(\d+) "
    r"compiler_submission_failures=(\d+)")
failed = []

for application in args.applications:
    paths = sorted(args.phase_root.rglob(f"{application}*.stderr"))
    aot = fallback = submissions = submission_failures = 0
    states = {}
    sources = {}
    fork_jit = 0
    for path in paths:
        text = path.read_text(errors="replace")
        fork_jit += text.count("AOT v2 fork child switched to JIT")
        for source, state, hits, misses in module_pattern.findall(text):
            aot += int(hits)
            fallback += int(misses)
            states[state] = states.get(state, 0) + 1
            source_result = sources.setdefault(source, {
                "aot_lookups": 0,
                "jit_fallbacks": 0,
                "states": {},
            })
            source_result["aot_lookups"] += int(hits)
            source_result["jit_fallbacks"] += int(misses)
            source_result["states"][state] = \
                source_result["states"].get(state, 0) + 1
        for submitted, compiler_failed in runtime_pattern.findall(text):
            submissions += int(submitted)
            submission_failures += int(compiler_failed)
    total = aot + fallback
    percent = 100.0 * aot / total if total else 0.0
    result = {
        "aot_lookups": aot,
        "aot_percent": percent,
        "application": application,
        "compiler_submission_failures": submission_failures,
        "compiler_submissions": submissions,
        "fork_child_jit": fork_jit,
        "jit_fallbacks": fallback,
        "module_states": states,
        "required_percent": args.required_percent,
        "sources": sources,
        "stderr_files": [str(path.relative_to(args.phase_root))
                         for path in paths],
    }
    output = args.phase_root / f"{application}-aot-coverage.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("%s AOT coverage: %.6f%% (%d/%d) submissions=%d fork_jit=%d" %
          (application, percent, aot, total, submissions, fork_jit))
    reasons = []
    if not paths or not total:
        reasons.append("no module statistics")
    if percent < args.required_percent:
        reasons.append("coverage below requirement")
    if submissions or submission_failures:
        reasons.append("warm run submitted compiler work")
    if args.require_no_fork_jit and fork_jit:
        reasons.append("fork child switched to JIT")
    if reasons:
        result["failure_reasons"] = reasons
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        failed.append(application)

if failed:
    raise SystemExit("AOT coverage failed: " + ", ".join(failed))
