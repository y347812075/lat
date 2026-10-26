#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -lt 6 ] || [ "$#" -gt 7 ]; then
    echo "usage: $0 LATC LATCD RUNNER RUNTIME_DIR GUEST WORKDIR [nested|shared]" >&2
    exit 2
fi
latc=$1
latcd=$2
runner=$3
runtime_dir=$4
guest=$5
work=$6
mode=${7:-nested}
case "$mode" in nested|shared) ;; *) exit 2 ;; esac
mkdir -m 700 "$work"
mkdir "$work/cache" "$work/empty-root" "$work/home"
export HOME="$work/home" LATX_AOT=0 LATX_AOT_V2=1
export LATX_AOT_V2_AUTOSTART=0 LATX_AOT_V2_REPORT=1
export LATC_DISABLE_PRETRANSLATE=1
export LATX_AOT_V2_CACHE_DIR="$work/cache"
export LATX_AOT_V2_LATCD_SOCKET="$work/socket"
"$latcd" --serve --socket "$work/socket" --cache-dir "$work/cache" \
    --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
    --workers 1 --idle-seconds 0 \
    >"$work/daemon.stdout" 2>"$work/daemon.stderr" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true' EXIT
for ((i=0; i<500; i++)); do
    test ! -S "$work/socket" || break
    kill -0 "$daemon"
    sleep 0.01
done
timeout -k 2s 60s "$runner" "$guest" "$work/empty-root" "$mode" \
    >"$work/learn.stdout" 2>"$work/learn.stderr"
grep -qx SANDBOX_CHANNEL_OK "$work/learn.stdout"
"$latcd" --flush-all --socket "$work/socket" >"$work/flush.stdout" 2>"$work/flush.stderr"
kill -TERM "$daemon"
wait "$daemon"
trap - EXIT
env LATC_STRICT_FILE_AOT=1 timeout -k 2s 60s "$runner" "$guest" "$work/empty-root" "$mode" \
    >"$work/strict.stdout" 2>"$work/strict.stderr"
grep -qx SANDBOX_CHANNEL_OK "$work/strict.stdout"
python3 - "$work" <<'PY'
import re
import sys
from pathlib import Path

work = Path(sys.argv[1])
learn = (work / 'learn.stderr').read_text()
assert 'TB set submitted' in learn
assert not re.search(r'channel unavailable|submission failed', learn)
failures = re.findall(r'\bcompiler_submission_failures=(\d+)', learn)
assert failures and all(int(value) == 0 for value in failures), failures
strict = (work / 'strict.stderr').read_text()
for field in ('jit_fallbacks', 'file_dispatch_misses', 'compiler_submissions',
              'compiler_submission_failures'):
    values = re.findall(rf'\b{field}=(\d+)', strict)
    assert values and all(int(value) == 0 for value in values), (field, values)
assert sum(map(int, re.findall(r'\baot_lookups=(\d+)', strict))) > 0
assert not re.search(r'(?i)reject|strict.*miss', strict)
PY
echo "test-aot-v2-sandbox-channel: PASS ($mode, shared FS, chroot, learned cache strict replay)"
