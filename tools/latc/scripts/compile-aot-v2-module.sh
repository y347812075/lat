#!/bin/sh
set -eu

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
    echo "usage: $0 LATC STATIC_RUNNER X86_GUEST RUNTIME_DIRECTORY OUTPUT [TBSET]" >&2
    exit 2
fi

latc=$1
runner=$2
guest=$3
runtime_dir=$4
output=$5
tbset=${6:-}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
case "$output" in /*) ;; *) output="$(pwd)/$output";; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-aot-v2-compile.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

shards=${LATC_AOT_COMPILE_SHARDS:-1}
case "$shards" in
    1|2|3|4|5|6|7|8) ;;
    *) echo "latc: LATC_AOT_COMPILE_SHARDS must be 1..8" >&2; exit 2 ;;
esac
if [ "$shards" -gt 1 ] && [ -n "$tbset" ]; then
    tbset_size=$(wc -c <"$tbset")
    tbset_keys=$(((tbset_size - 64) / 16))
    min_keys=${LATC_AOT_COMPILE_MIN_KEYS:-32768}
    if [ "$tbset_keys" -lt "$min_keys" ]; then shards=1; fi
fi

if [ "$shards" -gt 1 ] && [ -z "$tbset" ]; then
    echo "latc: parallel module compilation requires a TB set" >&2
    exit 2
fi

if [ "$shards" -gt 1 ]; then
    pids=""
    fragments=""
    index=0
    while [ "$index" -lt "$shards" ]; do
        fragment="$work/module.$index.latnative"
        fragments="$fragments $fragment"
        LATC_TBSET_SHARD_INDEX=$index LATC_TBSET_SHARD_COUNT=$shards \
            "$script_dir/compile-native-image.sh" --module \
            "$latc" "$runner" "$guest" "$fragment" "$tbset" >/dev/null &
        pids="$pids $!"
        index=$((index + 1))
    done
    failed=0
    for pid in $pids; do
        if ! wait "$pid"; then failed=1; fi
    done
    if [ "$failed" -ne 0 ]; then exit 1; fi
    # Fragment names are generated under mktemp and contain no shell spaces.
    # shellcheck disable=SC2086
    "$latc" merge-native "$work/module.latnative" $fragments
elif [ -n "$tbset" ]; then
    "$script_dir/compile-native-image.sh" --module \
        "$latc" "$runner" "$guest" \
        "$work/module.latnative" "$tbset" >/dev/null
else
    "$script_dir/compile-native-image.sh" --module \
        "$latc" "$runner" "$guest" \
        "$work/module.latnative" >/dev/null
fi
"$script_dir/link-aot-v2-module.sh" "$latc" "$work/module.latnative" \
    "$runtime_dir" "$output"
"$latc" inspect-module --json "$output"
