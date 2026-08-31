#!/bin/sh
set -eu

module=0
if [ "${1:-}" = "--module" ]; then
    module=1
    shift
fi
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 [--module] LATC RUNNER X86_GUEST OUTPUT [PROFILE]" >&2
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
max_rounds=${LATC_NATIVE_MAX_ROUNDS:-20}
while [ "$round" -le "$max_rounds" ]; do
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
    if head -n 1 "$supplements" | grep -q '^LATC_PROFILE_V2 '; then
        head -n 1 "$supplements" >"$work/supplements-next.profile"
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
    pc, count = line.split()
    print(hex(int(pc, 0) - base), "0x1", count)
PY
        } | awk '{ key=$1 " " $2; count[key]+=$3 }
                  END { for (key in count) print key, count[key] }' | \
            sort -k1,1 -k2,2 >>"$work/supplements-next.profile"
    else
        cat "$supplements" "$missing" | \
            awk '{ count[$1] += $2 }
                  END { for (pc in count) print pc, count[pc] }' | \
            sort -k1,1 >"$work/supplements-next.profile"
    fi
    mv "$work/supplements-next.profile" "$supplements"
    echo "latc: static supplement round $round added $(wc -l <"$missing") targets" >&2
    round=$((round + 1))
done

if [ ! -s "$output" ]; then
    echo "latc: static supplement rounds exhausted" >&2
    exit 1
fi
if [ "$module" -eq 0 ]; then
    "$latc" mark-native-x86 "$output"
fi
"$latc" inspect-native --json "$output"
