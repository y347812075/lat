#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 LATC RUNNER RUNTIME_DIR X86_STATIC_GUEST WORK_DIR" >&2
    exit 2
fi
latc=$1
runner=$2
runtime=$3
guest=$4
work=$5
mkdir "$work"
export TMPDIR="$work"
export LD_LIBRARY_PATH="$runtime${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LATC_TBSET_SELECTION=exact-static
# Deliberately enable expansion inputs: exact selection must still ignore them.
export LATC_TBSET_CLOSURE_LIMIT=20000 LATC_TBSET_EXPAND_FUNCTIONS=1
unset LATC_NATIVE_BASE LATC_NATIVE_OUTPUT
"$latc" emit-static-tbset "$guest" -o "$work/requested.tbset"
"$latc" split-tbset "$work/requested.tbset" "$work/left.tbset" "$work/right.tbset"
for part in left right whole; do
    input=$work/$part.tbset
    if [ "$part" = whole ]; then input=$work/requested.tbset; fi
    LATC_NATIVE_OUTPUT="$work/$part.native" "$latc" compile-module "$guest" \
        -o "$work/$part.so" --runner "$runner" --runtime-dir "$runtime" \
        --tbset "$input" --static-tbset
    "$latc" emit-module-tbset "$work/$part.so" -o "$work/$part.actual"
done
"$latc" merge-native "$work/left.native" "$work/right.native" -o "$work/merged.native"
script_dir=$(CDPATH= cd -- "$(dirname "$0")/../scripts" && pwd)
"$script_dir/link-aot-v2-module.sh" "$latc" "$work/merged.native" \
    "$runtime" "$work/merged.so"
"$latc" emit-module-tbset "$work/merged.so" -o "$work/merged.actual"
LATC_TBSET_SELECTION=bounded LATC_NATIVE_OUTPUT="$work/planned.native" \
    "$latc" compile-module "$guest" -o "$work/planned.so" --runner "$runner" \
    --runtime-dir "$runtime" --tbset "$work/requested.tbset" --static-tbset
"$latc" emit-module-tbset "$work/planned.so" -o "$work/planned.actual"
"$latc" validate-module-replacement "$work/whole.so" "$work/planned.so"
LATC_TBSET_SELECTION=bounded "$latc" plan-tbset "$guest" "$work/requested.tbset" \
    "$work/audit-plan" --static --batch-size 257 --work-budget 7
"$latc" validate-tbplan-module "$guest" "$work/audit-plan" "$work/planned.so"
if "$latc" validate-tbplan-module "$guest" "$work/audit-plan" "$work/left.so" \
    >"$work/rejected-plan.stdout" 2>"$work/rejected-plan.stderr"; then
    echo "incomplete module unexpectedly covered full discovery plan" >&2
    exit 1
fi
python3 - "$work" <<'PY'
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
header = struct.Struct('<8sII32sQQ')
record = struct.Struct('<QII')
def read(name):
    data = (root / name).read_bytes()
    magic, version, size, digest, count, _ = header.unpack_from(data)
    assert (magic, version, size) == (b'LATTBKS\0', 1, 64)
    keys = list(record.iter_unpack(data[size:]))
    assert len(keys) == count
    return digest, set(keys)

source, required = read('requested.tbset')
for part in ('left', 'right'):
    digest, requested = read(part + '.tbset')
    actual_digest, actual = read(part + '.actual')
    assert source == digest == actual_digest
    assert actual == requested, (part, requested - actual, actual - requested)
for name in ('whole.actual', 'merged.actual'):
    digest, actual = read(name)
    assert source == digest and actual == required, (name, required - actual, actual - required)
print('exact-batch keys=', len(required))
PY
LATX_AOT=0 LATX_AOT_V2=1 LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_MODULE="$work/merged.so" LATX_AOT_V2_SOURCE="$guest" \
LATC_STRICT_FILE_AOT=1 LATC_DISABLE_PRETRANSLATE=1 \
    "$runner" "$guest" >"$work/stdout" 2>"$work/stderr"
LATX_AOT=0 LATX_AOT_V2=1 LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_MODULE="$work/planned.so" LATX_AOT_V2_SOURCE="$guest" \
LATC_STRICT_FILE_AOT=1 LATC_DISABLE_PRETRANSLATE=1 \
    "$runner" "$guest" >"$work/planned.stdout" 2>"$work/planned.stderr"
printf 'test-aot-v2-exact-batches: PASS\n'
