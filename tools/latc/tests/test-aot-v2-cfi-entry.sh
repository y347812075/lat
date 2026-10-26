#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 PREFIX ROOTFS X86_CFI_GUEST WORK" >&2
    exit 2
fi
prefix=$1
rootfs=$2
guest=$3
work=$4
mkdir "$work"
chmod 700 "$work"
export TMPDIR="$work" LATCD_COMPILE_TMPDIR="$work"
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$prefix/bin/latcd" --serve --socket "$work/latcd.sock" \
    --cache-dir "$work/cache" --latc "$prefix/bin/latc" \
    --runner "$prefix/bin/latx-x86_64" --runtime-dir "$prefix/lib" \
    --x86-rootfs "$rootfs" --workers 1 --stats "$work/stats.json" \
    >"$work/daemon.stdout" 2>"$work/daemon.stderr" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null || true; wait "$daemon" || true' EXIT HUP INT TERM
attempt=0
while [ ! -S "$work/latcd.sock" ]; do
    kill -0 "$daemon"
    attempt=$((attempt + 1))
    test "$attempt" -lt 500
    sleep 0.01
done
"$prefix/bin/latcd" --precompile --socket "$work/latcd.sock" \
    --x86-rootfs "$rootfs" --latc "$prefix/bin/latc" --jobs 1 "$guest" \
    >"$work/precompile.stdout" 2>"$work/precompile.stderr"
kill -TERM "$daemon"
wait "$daemon"
trap - EXIT HUP INT TERM
LATX_AOT=0 LATX_AOT_V2=1 LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_CACHE_DIR="$work/cache" LATC_STRICT_FILE_AOT=1 \
LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
    "$prefix/bin/latx-x86_64" -L "$rootfs" "$rootfs$guest" \
    >"$work/guest.stdout" 2>"$work/guest.stderr"
python3 - "$work" <<'PY'
import json
from pathlib import Path
import re
import sys

work = Path(sys.argv[1])
stats = json.loads((work/'stats.json').read_text())
assert stats['failed'] == 0 and stats['compiled'] > 0, stats
text = (work/'guest.stderr').read_text()
assert 'module=registered' in text
for field in ('file_dispatch_misses', 'compiler_submissions',
              'compiler_submission_failures', 'jit_fallbacks'):
    values = re.findall(rf'\b{field}=(\d+)', text)
    assert values and all(int(value) == 0 for value in values), (field, values)
assert sum(map(int, re.findall(r'\baot_lookups=(\d+)', text))) > 0
assert not re.search(r'(?i)reject|strict.*miss', text)
PY
printf 'test-aot-v2-cfi-entry: PASS\n'
