#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 INSTALL_PREFIX X86_ROOTFS X86_GUEST WORKDIR TIMEOUT FIXTURE_DIR" >&2
    exit 2
fi
prefix=$1
rootfs=$2
guest=$3
work=$4
run_timeout=$5
fixtures=$6
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

rm -rf "$work"
mkdir -m 700 "$work" "$work/cache" "$work/home"
socket=$work/socket
daemon_pid=
cleanup()
{
    if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

LD_LIBRARY_PATH="$prefix/lib" "$prefix/bin/latcd" --serve \
    --socket "$socket" --cache-dir "$work/cache" \
    --latc "$prefix/bin/latc" --runner "$prefix/bin/latx-x86_64" \
    --runtime-dir "$prefix/lib" --workers 1 --idle-seconds 0 --flush-only \
    >"$work/daemon.log" 2>&1 &
daemon_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$daemon_pid" 2>/dev/null; do
    n=$((n + 1))
    test "$n" -lt 500
    sleep 0.01
done
test -S "$socket"

source_sha=$(sha256sum "$guest" | awk '{print $1}')
python3 "$script_dir/make-symbol-tbset.py" "$guest" '^fork_hot_value$' \
    "$work/fork.tbset"
LD_LIBRARY_PATH="$prefix/lib" LAT_LD_PREFIX="$rootfs" \
    "$prefix/libexec/latc/scripts/compile-aot-v2-module.sh" \
    "$prefix/bin/latc" "$prefix/bin/latx-x86_64" "$guest" "$prefix/lib" \
    "$work/fork.so" "$work/fork.tbset" >"$work/compile.stdout"
cp "$work/fork.so" "$work/cache/$source_sha.so"
printf '{"version":2,"module":"%s.so"}\n' "$source_sha" \
    >"$work/cache/$source_sha.current"
chmod 444 "$work/cache/$source_sha.current"

env HOME="$work/home" LD_LIBRARY_PATH="$prefix/lib" LATX_AOT=0 \
    LATX_AOT_V2_CACHE_DIR="$work/cache" LATX_AOT_V2_REPORT=1 \
    LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_KEY_JOURNAL=1 \
    LATX_AOT_V2_AUTOSTART=0 LATC_DISABLE_PRETRANSLATE=1 \
    timeout -k 2s "$run_timeout" "$prefix/bin/latx-x86_64" -L "$rootfs" \
    "$guest" >"$work/run.stdout" 2>"$work/run.stderr"

grep -q '^FORK_OK parent_aot_child_aot=1 ' "$work/run.stdout"
grep -q '^FORK_CHILD_AOT_OK$' "$work/run.stdout"
grep -q '^latx: AOT v2 fork child retained AOT$' "$work/run.stderr"
test "$(grep -c 'fork child switched to JIT' "$work/run.stderr" || true)" -eq 0

kill -TERM "$daemon_pid"
wait "$daemon_pid"
daemon_pid=
echo "test-aot-v2-journal-fork: PASS"
