#!/bin/sh
set -eu

module=0
if [ "${1:-}" = "--module" ]; then
    module=1
    shift
fi
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 [--module] LATC RUNNER X86_GUEST OUTPUT [TBSET]" >&2
    exit 2
fi

latc=$1
runner=$2
guest=$3
output=$4
tbset=${5:-}

case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-native.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

supplements="$work/supplements.tbset"
if [ -n "$tbset" ]; then
    cp "$tbset" "$supplements"
else
    printf 'LATC_TBSET_V1 %s\n' "$(sha256sum "$guest" | awk '{print $1}')" >"$supplements"
fi

round=1
max_rounds=${LATC_NATIVE_MAX_ROUNDS:-64}
best_missing=2147483647
stagnant_rounds=0
while [ "$round" -le "$max_rounds" ]; do
    missing="$work/missing-$round.tbset"
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
    missing_count=$(wc -l <"$missing")
    if [ "$missing_count" -lt "$best_missing" ]; then
        best_missing=$missing_count
        stagnant_rounds=0
    else
        stagnant_rounds=$((stagnant_rounds + 1))
    fi
    if [ "$stagnant_rounds" -ge 3 ]; then
        echo "latc: static missing target count stopped improving" >&2
        break
    fi
    repeated=0
    for seen in "$work"/missing-*.tbset; do
        if [ "$seen" != "$missing" ] && cmp -s "$seen" "$missing"; then
            repeated=1
            break
        fi
    done
    if [ "$repeated" -eq 1 ]; then
        echo "latc: static missing targets entered a cycle" >&2
        break
    fi
    head -n 1 "$supplements" >"$work/supplements-next.tbset"
    {
        tail -n +2 "$supplements"
        python3 - "$guest" "$missing" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as source:
    elf = source.read(64)
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", elf, 54)
    source.seek(phoff)
    headers = source.read(phentsize * phnum)
bases = [struct.unpack_from("<Q", headers, offset + 16)[0]
         for offset in range(0, len(headers), phentsize)
         if struct.unpack_from("<I", headers, offset)[0] == 1]
base = min(bases)
for line in open(sys.argv[2]):
    pc, _ = line.split()
    print(hex(int(pc, 0) - base), "0x1")
PY
    } | sort -u -k1,1 -k2,2 >>"$work/supplements-next.tbset"
    mv "$work/supplements-next.tbset" "$supplements"
    echo "latc: static supplement round $round added $(wc -l <"$missing") targets" >&2
    round=$((round + 1))
done

if [ ! -s "$output" ] && [ "$module" -eq 1 ]; then
    rm -f "$output"
    LATC_NATIVE_IMAGE_OUT="$output" LATC_NATIVE_ALLOW_MISSING=1 \
        "$(dirname "$0")/compile-aot.sh" "$latc" "$runner" "$guest" \
        "$work/compatibility-bundle" "$supplements" >/dev/null || true
fi
if [ ! -s "$output" ]; then
    echo "latc: static supplement rounds exhausted" >&2
    exit 1
fi
if [ "$module" -eq 0 ]; then
    "$latc" mark-native-x86 "$output"
fi
"$latc" inspect-native --json "$output"
