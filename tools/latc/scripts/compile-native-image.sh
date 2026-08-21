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

supplements="$work/supplements.profile"
if [ -n "$profile" ]; then
    cp "$profile" "$supplements"
else
    : >"$supplements"
fi

round=1
while [ "$round" -le 20 ]; do
    missing="$work/missing-$round.profile"
    rm -f "$output" "$missing"
    if LATC_NATIVE_IMAGE_OUT="$output" LATC_NATIVE_MISSING_OUT="$missing" \
        "$(dirname "$0")/compile-aot.sh" "$latc" "$runner" "$guest" \
        "$work/compatibility-bundle" "$supplements" >/dev/null; then
        break
    fi
    if [ ! -s "$missing" ]; then
        echo "latc: native compilation failed without static missing targets" >&2
        exit 1
    fi
    cat "$supplements" "$missing" | \
        awk '{ count[$1] += $2 } END { for (pc in count) print pc, count[pc] }' | \
        sort -k1,1 >"$work/supplements-next.profile"
    mv "$work/supplements-next.profile" "$supplements"
    echo "latc: static supplement round $round added $(wc -l <"$missing") targets" >&2
    round=$((round + 1))
done

if [ ! -s "$output" ]; then
    echo "latc: static supplement rounds exhausted" >&2
    exit 1
fi
"$latc" mark-native-x86 "$output"
"$latc" inspect-native --json "$output"
