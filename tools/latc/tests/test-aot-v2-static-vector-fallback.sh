#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then
    echo "usage: $0 LATC RUNNER RUNTIME GUEST WORKDIR" >&2
    exit 2
fi
latc=$1 runner=$2 runtime=$3 guest=$4 work=$5
if [ "$guest" = - ]; then
    guest=${LATC_STATIC_VECTOR_GUEST:-}
    if [ -z "$guest" ]; then
        echo 'SKIP: LATC_STATIC_VECTOR_GUEST is not set'
        exit 77
    fi
fi
scripts=$(CDPATH= cd -- "$(dirname "$0")/../scripts" && pwd)
mkdir -p "$work"
for threads in 1 4; do
    native=$work/module-$threads.native
    LATC_AOT_THREADS=$threads "$scripts/compile-native-image.sh" --module \
      "$latc" "$runner" "$guest" "$native" >"$work/compile-$threads.log" 2>&1
    grep -q 'reason=build-disabled-avx512' "$work/compile-$threads.log"
    if grep -q 'unsupported static instruction' "$work/compile-$threads.log"; then
        echo 'disabled static candidate reached native translation' >&2
        exit 1
    fi
    python3 - "$native" "$guest" <<'PY'
from pathlib import Path
import struct
import subprocess
import sys

data = Path(sys.argv[1]).read_bytes()
offset, count = struct.unpack_from('<QQ', data, 72)
keys = {struct.unpack_from('<Q', data, offset + i * 56)[0]
        for i in range(count)}
symbols = {}
output = subprocess.check_output(['nm', '-n', sys.argv[2]], text=True)
for line in output.splitlines():
    fields = line.split()
    if len(fields) == 3:
        symbols[fields[2]] = int(fields[0], 16)
for name in ('_start', 'supported_value', 'unsupported_caller'):
    assert symbols[name] in keys, (name, keys)
for name in ('unsupported_zmm', 'unsupported_opmask', 'unsupported_extended'):
    assert symbols[name] not in keys, (name, keys)
PY
    "$scripts/link-aot-v2-module.sh" "$latc" "$native" "$runtime" \
      "$work/module-$threads.so"
    cache=$work/cache-$threads
    mkdir -p "$cache"
    source=$(sha256sum "$guest" | awk '{print $1}')
    cp "$work/module-$threads.so" "$cache/$source.so"
    rm -f "$cache/$source.current"
    printf '{"version":2,"module":"%s.so"}\n' "$source" \
      >"$cache/$source.current"
    chmod 444 "$cache/$source.current"
    status=0
    env LD_LIBRARY_PATH="$runtime" LATX_AOT=0 LATX_AOT_V2=1 \
      LATX_AOT_V2_CACHE_DIR="$cache" LATX_AOT_V2_AUTOSTART=0 \
      LATX_AOT_V2_REPORT=1 LATC_STRICT_FILE_AOT=1 \
      timeout -k 2s 15s "$runner" "$guest" \
      >"$work/run-$threads.out" 2>"$work/run-$threads.err" || status=$?
    test "$status" -eq 42
    grep -Eq 'module=registered aot_lookups=[1-9][0-9]* jit_fallbacks=0' \
      "$work/run-$threads.err"
done
python3 "$(dirname "$0")/make-symbol-tbset.py" "$guest" \
    'unsupported_(zmm|opmask|extended)' "$work/explicit.tbset"
if "$scripts/compile-native-image.sh" --static-tbset "$latc" "$runner" "$guest" \
    "$work/strict.native" "$work/explicit.tbset" >"$work/strict.log" 2>&1; then
    echo 'strict native compilation accepted an unsupported vector TB' >&2
    exit 1
fi
grep -q 'unsupported static instruction' "$work/strict.log"
test ! -e "$work/strict.native"
echo 'test-aot-v2-static-vector-fallback: PASS'
