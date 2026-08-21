#!/bin/sh
set -eu

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 LATC STATIC_RUNNER X86_GUEST OUTPUT [PROFILE]" >&2
    exit 2
fi

latc=$1
runner=$2
guest=$3
output=$4
profile=${5:-}

case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-native.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

if [ -n "$profile" ]; then
    LATC_NATIVE_IMAGE_OUT="$output" \
        "$(dirname "$0")/compile-aot.sh" "$latc" "$runner" "$guest" \
        "$work/compatibility-bundle" "$profile" >/dev/null
else
    LATC_NATIVE_IMAGE_OUT="$output" \
        "$(dirname "$0")/compile-aot.sh" "$latc" "$runner" "$guest" \
        "$work/compatibility-bundle" >/dev/null
fi

if [ ! -s "$output" ]; then
    echo "latc: LAT did not export a native image" >&2
    exit 1
fi
"$latc" mark-native-x86 "$output"
"$latc" inspect-native --json "$output"
