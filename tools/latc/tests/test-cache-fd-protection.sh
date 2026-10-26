#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 LATCD LATC RUNNER RUNTIME_DIR X86_GUEST WORKDIR" >&2
    exit 2
fi

latcd=$1
latc=$2
runner=$3
runtime_dir=$4
guest=$5
work=$6
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
rm -rf "$work"
mkdir -m 700 -p "$work"

socket=$work/latcd.sock
cache=$work/cache
"$latcd" --once --socket "$socket" --cache-dir "$cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  >"$work/daemon.stdout" 2>"$work/daemon.stderr" &
daemon_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$daemon_pid" 2>/dev/null; do
  n=$((n + 1))
  test "$n" -lt 500
  sleep 0.01
done
test -S "$socket"

tbset=$work/guest.tbset
python3 "$script_dir/make-tbset.py" "$guest" "$tbset"
timeout 60 "$latcd" --submit --socket "$socket" --tbset "$tbset" "$guest" \
  >"$work/submit.client"
wait "$daemon_pid"

source_sha=$(sha256sum "$guest" | cut -d ' ' -f 1)
module=$(python3 - "$cache/$source_sha.current" "$cache" <<'PY'
import json
import pathlib
import sys

manifest = json.load(open(sys.argv[1]))
print(pathlib.Path(sys.argv[2]) / manifest["module"])
PY
)
test -f "$module"

LD_LIBRARY_PATH="$runtime_dir" \
LATX_AOT=0 \
LATX_AOT_V2_CACHE_DIR="$cache" \
LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_STRICT=1 \
LATX_AOT_V2_REPORT=1 \
LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 \
  timeout 60 "$runner" "$guest" >"$work/guest.stdout" \
  2>"$work/guest.stderr" &
runner_pid=$!
n=0
while ! grep -q '^CLOSED$' "$work/guest.stdout" 2>/dev/null; do
  kill -0 "$runner_pid"
  n=$((n + 1))
  test "$n" -lt 3000
  sleep 0.01
done
grep -q 'module=registered' "$work/guest.stderr"
if flock -n "$module" -c true; then
  echo "guest close/flock loop released the AOT module lifetime lease" >&2
  kill -TERM "$runner_pid" 2>/dev/null || true
  wait "$runner_pid" 2>/dev/null || true
  exit 1
fi
kill -TERM "$runner_pid" 2>/dev/null || true
wait "$runner_pid" 2>/dev/null || true
flock -n "$module" -c true

echo 'test-cache-fd-protection: PASS'
