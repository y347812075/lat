#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 LATC RUNNER RUNTIME_DIR X86_GUEST NATIVE_IMAGE WORKDIR" >&2
    exit 2
fi

latc=$1
runner=$2
runtime_dir=$3
guest=$4
native_image=$5
work=$6
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
rm -rf "$work"
mkdir -p "$work"

"$script_dir/../scripts/link-aot-v2-module.sh" \
  "$latc" "$native_image" "$runtime_dir" "$work/module.so"
"$latc" compile "$guest" -o "$work/runner" --runner "$runner" >/dev/null

LD_LIBRARY_PATH="$runtime_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
LATX_AOT_V2_MODULE="$work/module.so" \
LATX_AOT_V2_SOURCE="$guest" \
LATX_AOT_V2_STRICT=1 \
LATX_AOT_V2_REPORT=1 \
LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 \
LATC_STATS_OUT="$work/stats.json" \
  "$work/runner" >"$work/stdout" 2>"$work/stderr"

printf 'Hello, LATC!\n' >"$work/expected"
cmp "$work/expected" "$work/stdout"
grep -q 'AOT v2 registered module with 2 TBs' "$work/stderr"
grep -q '"runtime_tb_gen_attempts":0' "$work/stats.json"
grep -q '"runtime_tb_gen_calls":0' "$work/stats.json"
grep -q '"pretranslation_disabled":true' "$work/stats.json"
readelf -lW "$work/module.so" | \
  awk '/ LOAD / && $0 ~ /W/ && $0 ~ /E/ { bad=1 } END { exit bad }'
readelf -dW "$work/module.so" | \
  grep -q 'Shared library: \[liblat-aot-runtime.so.2\]'
echo "test-aot-v2-runner: PASS"
