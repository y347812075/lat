#!/bin/sh
set -eu
umask 022
if [ "$#" -ne 6 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: $0 LATCD FIXTURE LATC RUNNER RUNTIME STATIC_LAUNCHER" >&2
    exit 2
fi
daemon=$1 fixture=$2 compiler=$3 runner=$4 runtime=$5 launcher=$6
work=/opt/latcd-managed-retirement-test
test ! -e "$work"
mkdir -m 755 "$work" "$work/tools" "$work/runtime" "$work/caches"
mount -t tmpfs tmpfs "$work/caches"
chmod 755 "$work/caches"
cp "$daemon" "$work/tools/latcd"
cp "$fixture" "$work/tools/fixture"
cp "$compiler" "$work/tools/latc"
cp "$runner" "$work/tools/runner"
cp "$launcher" "$work/tools/launcher"
cp "$runtime" "$work/runtime/liblat-aot-runtime.so.2"
chmod 755 "$work/tools/latcd" "$work/tools/fixture" "$work/tools/latc" \
    "$work/tools/runner" "$work/tools/launcher" "$work/runtime/liblat-aot-runtime.so.2"
pid=
pin_pid=
cleanup() {
    if [ -n "$pin_pid" ]; then kill "$pin_pid" 2>/dev/null || :; wait "$pin_pid" 2>/dev/null || :; fi
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
}
trap cleanup EXIT HUP INT TERM
source=0000000000000000000000000000000000000000000000000000000000000007
setup_scenario() {
    name=$1
    dir=$work/caches/$name
    mkdir -m 755 "$dir"
    mkdir -m 700 "$dir/cache" "$dir/admin"
    mkdir -m 755 "$dir/broker"
    chown 1234:1234 "$dir/cache" "$dir/admin" "$dir/broker"
    printf '%s\n' "{\"service_uid\":\"1234\",\"client_uid\":\"1235\",\"cache\":\"$dir/cache\",\"admin\":\"$dir/admin\",\"broker\":\"$dir/broker\",\"compiler\":\"$work/tools/latc\",\"runner\":\"$work/tools/runner\",\"runtime\":\"$work/runtime\",\"worker_bwrap\":\"$work/tools/launcher\",\"worker_bootstrap\":\"$work/tools/launcher\",\"automatic_retirement\":true}" > "$work/config-$name"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        "$work/tools/latcd" gc --init-domain --cache-dir "$dir/cache"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        "$work/tools/fixture" --aged-timer-fixture "$dir/cache"
    test -f "$dir/cache/$source.so"
    test -f "$dir/cache/$source-$source.so"
}
hold_old_files() {
    dir=$1
    ready=$dir/admin/pin-ready
    release=$dir/admin/pin-release
    rm -f "$ready" "$release"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        python3 - "$dir/cache/$source.so" "$dir/cache/$source.native" \
        "$dir/cache/$source.tbset" "$ready" "$release" <<'PY' &
import fcntl, pathlib, sys, time
files = [open(path, 'rb') for path in sys.argv[1:4]]
for file in files:
    fcntl.flock(file, fcntl.LOCK_SH)
pathlib.Path(sys.argv[4]).touch()
release = pathlib.Path(sys.argv[5])
while not release.exists():
    time.sleep(0.05)
PY
    pin_pid=$!
    n=0
    while [ ! -f "$ready" ]; do
        kill -0 "$pin_pid"; n=$((n + 1)); [ "$n" -lt 200 ] || exit 1; sleep .05
    done
}
start_daemon() {
    name=$1
    dir=$work/caches/$name
    rm -f "$dir/admin/admin.sock" "$dir/broker/broker.sock"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        "$work/tools/latcd" --managed-config "$work/config-$name" >"$dir/daemon.out" 2>"$dir/daemon.err" &
    pid=$!
    n=0
    while [ ! -S "$dir/broker/broker.sock" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/daemon.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 400 ] || { cat "$dir/daemon.err" >&2; exit 1; }; sleep .05
    done
    grep -q 'automatic retirement enabled for managed domain' "$dir/daemon.err"
}
wait_busy() {
    dir=$1
    n=0
    while ! grep -q 'test page busy retry=' "$dir/daemon.err"; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/daemon.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 600 ] || { cat "$dir/daemon.err" >&2; exit 1; }; sleep .1
    done
    test -f "$dir/cache/$source.so"
}
wait_deleted() {
    dir=$1
    n=0
    while [ -e "$dir/cache/$source.so" ] || [ -e "$dir/cache/$source.native" ] || [ -e "$dir/cache/$source.tbset" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/daemon.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 1200 ] || { cat "$dir/daemon.err" >&2; exit 1; }; sleep .1
    done
    test -f "$dir/cache/$source-$source.so"
    test -f "$dir/cache/$source-$source.native"
    test -f "$dir/cache/$source-$source.tbset"
    test -f "$dir/cache/$source.current"
}
setup_scenario unreferenced
start_daemon unreferenced
wait_deleted "$work/caches/unreferenced"
kill -TERM "$pid"
wait "$pid"
pid=
setup_scenario release
hold_old_files "$work/caches/release"
start_daemon release
wait_busy "$work/caches/release"
touch "$work/caches/release/admin/pin-release"
wait "$pin_pid"
pin_pid=
wait_deleted "$work/caches/release"
kill -TERM "$pid"
wait "$pid"
pid=
setup_scenario restart
hold_old_files "$work/caches/restart"
start_daemon restart
wait_busy "$work/caches/restart"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || :
pid=
touch "$work/caches/restart/admin/pin-release"
wait "$pin_pid"
pin_pid=
start_daemon restart
wait_deleted "$work/caches/restart"
kill -TERM "$pid"
wait "$pid"
pid=
echo 'test-managed-retirement: PASS unreferenced/release/restart'
