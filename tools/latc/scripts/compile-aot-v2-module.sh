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

if [ -n "$tbset" ]; then
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
