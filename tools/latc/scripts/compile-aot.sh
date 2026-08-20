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
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-aot.XXXXXX")
guest_hash=$(sha256sum "$guest" | awk '{print $1}')
guest_prefix=$(printf '%s' "$guest_hash" | cut -c1-16)
named_guest="${TMPDIR:-/tmp}/latc-${guest_prefix}-x86-guest"

cleanup()
{
    rm -rf "$work"
    rm -f "$named_guest"
}
trap cleanup EXIT HUP INT TERM

if [ -n "$profile" ]; then
    "$latc" compile "$guest" -o "$work/stage1.la64" --runner "$runner" \
        --profile "$profile" >/dev/null
else
    "$latc" compile "$guest" -o "$work/stage1.la64" --runner "$runner" \
        >/dev/null
fi
HOME="$work/home" LATX_AOT=1 LATC_EMIT_AOT=1 \
    LATC_NAMED_GUEST="$named_guest" "$work/stage1.la64"
aot=$(find "$work/home/.cache/latx" -type f -name 'v2-*.aot2' \
    -size +0c -print -quit)
if [ -z "$aot" ]; then
    echo "latc: LAT did not produce an AOT file" >&2
    exit 1
fi

if [ -n "$profile" ]; then
    "$latc" compile "$guest" -o "$output" --runner "$runner" \
        --profile "$profile" --aot "$aot"
else
    "$latc" compile "$guest" -o "$output" --runner "$runner" --aot "$aot"
fi
"$latc" inspect --json "$output"
