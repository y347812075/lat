#!/bin/sh
set -eu

if [ "$#" -ne 8 ]; then
    echo "usage: $0 LATCD LATC RUNNER RUNTIME_DIR ROOTFS STATIC_GUEST DYNAMIC_GUEST WORKDIR" >&2
    exit 2
fi

latcd=$1
latc=$2
runner=$3
runtime_dir=$4
rootfs=$5
static_guest=$6
dynamic_guest=$7
work=$8
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
rm -rf "$work"
mkdir -m 700 -p "$work"
daemon_pid=

cleanup()
{
    if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

start_daemon()
{
    phase=$1
    compiler=$2
    mkdir -m 700 "$phase"
    socket=$phase/latcd.sock
    cache=$phase/cache
    stats=$phase/stats.json
    "$latcd" --serve --socket "$socket" --cache-dir "$cache" \
      --latc "$compiler" --runner "$runner" --runtime-dir "$runtime_dir" \
      --x86-rootfs "$rootfs" --stats "$stats" \
      >"$phase/daemon.stdout" 2>"$phase/daemon.stderr" &
    daemon_pid=$!
    n=0
    while [ ! -S "$socket" ] && kill -0 "$daemon_pid" 2>/dev/null; do
        n=$((n + 1))
        [ "$n" -lt 500 ] || break
        sleep 0.01
    done
    [ -S "$socket" ]
}

stop_daemon()
{
    kill -TERM "$daemon_pid"
    wait "$daemon_pid"
    daemon_pid=
}

wait_stats()
{
    expression=$1
    n=0
    while :; do
        if [ -f "$stats" ] && \
           python3 - "$stats" "$expression" 2>/dev/null <<'PY'
import json
import sys
s = json.load(open(sys.argv[1]))
assert eval(sys.argv[2], {"__builtins__": {}}, {"s": s})
PY
        then
            return
        fi
        n=$((n + 1))
        [ "$n" -lt 1200 ] || return 1
        sleep 0.05
    done
}

mkdir -m 700 "$work/no-daemon-cache"
LD_LIBRARY_PATH="$runtime_dir" \
LATX_AOT_V2_CACHE_DIR="$work/no-daemon-cache" \
LATX_AOT_V2_LATCD_SOCKET="$work/missing.sock" \
LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
  timeout 60 "$runner" "$static_guest" >"$work/no-daemon.stdout" \
  2>"$work/no-daemon.stderr"
test "$(cat "$work/no-daemon.stdout")" = "Hello, LATC!"
grep -q 'compiler_submissions=0 compiler_submission_failures=1' \
  "$work/no-daemon.stderr"

start_daemon "$work/static-cold" "$script_dir/fake-latc-slow.sh"
start=$(date +%s%N)
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_REPORT=1 \
LATC_DISABLE_PRETRANSLATE=1 timeout 60 "$runner" "$static_guest" \
  >"$phase/guest.stdout" 2>"$phase/guest.stderr"
end=$(date +%s%N)
elapsed_ms=$(((end - start) / 1000000))
test "$(cat "$phase/guest.stdout")" = "Hello, LATC!"
test "$elapsed_ms" -lt 900
grep -q 'compiler_submissions=1 compiler_submission_failures=0' \
  "$phase/guest.stderr"
grep -q 'module=missing' "$phase/guest.stderr"
wait_stats 's["compiled"] == 1 and s["active_jobs"] == 0'
stop_daemon

start_daemon "$work/dynamic" "$latc"
start=$(date +%s%N)
LD_LIBRARY_PATH="$runtime_dir" LATC_TEST_ENV=works LATX_AOT=0 \
LATX_AOT_V2_CACHE_DIR="$cache" LATX_AOT_V2_LATCD_SOCKET="$socket" \
LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
  timeout 60 "$runner" -L "$rootfs" "$dynamic_guest" alpha beta \
  >"$phase/cold.stdout" 2>"$phase/cold.stderr"
end=$(date +%s%N)
dynamic_ms=$(((end - start) / 1000000))
test "$(cat "$phase/cold.stdout")" = "Hello from glibc!"
grep -q 'compiler_submissions=3 compiler_submission_failures=0' \
  "$phase/cold.stderr"
test "$(grep -c 'compiler submitted.*priority=200' "$phase/cold.stderr")" -eq 2
test "$(grep -c 'compiler submitted.*priority=100' "$phase/cold.stderr")" -eq 1
test "$(grep -c 'discovered ELF.*module=missing' "$phase/cold.stderr")" -ge 3
wait_stats 's["compiled"] == 3 and s["failed"] == 0 and s["active_jobs"] == 0'
test "$(find "$cache" -maxdepth 1 -name '*.so' | wc -l)" -eq 3
test "$(find "$cache" -maxdepth 1 -name '*.current' | wc -l)" -eq 3
test -z "$(find "$cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"
stop_daemon

LD_LIBRARY_PATH="$runtime_dir" LATC_TEST_ENV=works LATX_AOT=0 \
LATX_AOT_V2_CACHE_DIR="$cache" LATX_AOT_V2_LATCD_SOCKET="$work/missing.sock" \
LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 timeout 60 "$runner" -L "$rootfs" \
  "$dynamic_guest" alpha beta >"$phase/warm.stdout" \
  2>"$phase/warm.stderr"
test "$(cat "$phase/warm.stdout")" = "Hello from glibc!"
test "$(grep -c 'discovered ELF.*module=registered' "$phase/warm.stderr")" -ge 3
test "$(grep -Ec 'module=registered aot_lookups=[1-9][0-9]*' \
  "$phase/warm.stderr")" -ge 3
grep -Eq 'direct_targets=[1-9][0-9]* compat_tb_allocations=0 compiler_submissions=0' \
  "$phase/warm.stderr"

printf 'test-latcd-runner: PASS static_cold_ms=%s dynamic_cold_ms=%s\n' \
  "$elapsed_ms" "$dynamic_ms"
