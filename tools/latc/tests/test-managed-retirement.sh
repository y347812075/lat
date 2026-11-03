#!/bin/sh
set -eu
umask 022
if [ "$#" -ne 8 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: $0 LATCD FIXTURE LATC RUNNER RUNTIME STATIC_LAUNCHER X86_GUEST LATC_HELPER_ROOT" >&2
    exit 2
fi
daemon=$1 fixture=$2 compiler=$3 runner=$4 runtime=$5 launcher=$6 guest=$7 helper=$8
work=/opt/latcd-managed-retirement-test
test ! -e "$work"
mkdir -m 755 "$work" "$work/tools" "$work/runtime" "$work/caches"
mount -t tmpfs -o size=1g tmpfs "$work/caches"
chmod 755 "$work/caches"
cp "$daemon" "$work/tools/latcd"
cp "$fixture" "$work/tools/fixture"
cp "$compiler" "$work/tools/latc"
cp "$runner" "$work/tools/runner"
cp "$launcher" "$work/tools/launcher"
cp "$runtime" "$work/runtime/liblat-aot-runtime.so.2"
cp "$guest" "$work/tools/guest"
cp "$helper/tests/tb_key_set.py" "$work/tools/tb_key_set.py"
mkdir -p /usr/libexec/latc/scripts /usr/libexec/latc/aot-v2/include /usr/libexec/latc/aot-v2/compiler
cp "$helper"/scripts/compile-aot-v2-module.sh "$helper"/scripts/compile-native-image.sh \
    "$helper"/scripts/compile-aot.sh "$helper"/scripts/link-aot-v2-module.sh \
    /usr/libexec/latc/scripts/
cp "$helper/aot-v2/include/lat-aot-v2.h" /usr/libexec/latc/aot-v2/include/
cp "$helper/aot-v2/compiler/module.map" /usr/libexec/latc/aot-v2/compiler/
chmod 755 /usr/libexec/latc/scripts/*.sh "$work/tools/latcd" "$work/tools/fixture" \
    "$work/tools/latc" "$work/tools/runner" "$work/tools/launcher" \
    "$work/runtime/liblat-aot-runtime.so.2"
chmod 644 /usr/libexec/latc/aot-v2/include/lat-aot-v2.h \
    /usr/libexec/latc/aot-v2/compiler/module.map "$work/tools/guest" "$work/tools/tb_key_set.py"
pid=
pin_pid=
cleanup() {
    if [ -n "$pin_pid" ]; then kill "$pin_pid" 2>/dev/null || :; wait "$pin_pid" 2>/dev/null || :; fi
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
}
trap cleanup EXIT HUP INT TERM
fixture_source=0000000000000000000000000000000000000000000000000000000000000007
setup_scenario() {
    name=$1
    dir=$work/caches/$name
    mkdir -m 755 "$dir"
    mkdir -m 700 "$dir/cache" "$dir/admin"
    mkdir -m 755 "$dir/broker"
    chown 1234:1234 "$dir/cache" "$dir/admin" "$dir/broker"
    printf '%s\n' "{\"service_uid\":\"1234\",\"client_uid\":\"1235\",\"cache\":\"$dir/cache\",\"admin\":\"$dir/admin\",\"broker\":\"$dir/broker\",\"compiler\":\"$work/tools/latc\",\"runner\":\"$work/tools/runner\",\"runtime\":\"$work/runtime\",\"worker_bwrap\":\"$work/tools/launcher\",\"worker_bootstrap\":\"$work/tools/launcher\",\"automatic_retirement\":true,\"retirement_grace_us\":1000000}" > "$work/config-$name"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        "$work/tools/latcd" gc --init-domain --cache-dir "$dir/cache"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        "$work/tools/fixture" --aged-timer-fixture "$dir/cache"
    test -f "$dir/cache/$fixture_source.so"
    test -f "$dir/cache/$fixture_source-$fixture_source.so"
}
hold_old_files() {
    dir=$1
    ready=$dir/admin/pin-ready
    release=$dir/admin/pin-release
    rm -f "$ready" "$release"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        python3 - "$dir/cache/$fixture_source.so" "$dir/cache/$fixture_source.native" \
        "$dir/cache/$fixture_source.tbset" "$ready" "$release" <<'PY' &
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
    test -f "$dir/cache/$fixture_source.so"
}
wait_deleted() {
    dir=$1
    n=0
    while [ -e "$dir/cache/$fixture_source.so" ] || [ -e "$dir/cache/$fixture_source.native" ] || [ -e "$dir/cache/$fixture_source.tbset" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/daemon.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 1200 ] || { cat "$dir/daemon.err" >&2; exit 1; }; sleep .1
    done
    test -f "$dir/cache/$fixture_source-$fixture_source.so"
    test -f "$dir/cache/$fixture_source-$fixture_source.native"
    test -f "$dir/cache/$fixture_source-$fixture_source.tbset"
    test -f "$dir/cache/$fixture_source.current"
}
wait_paths_deleted() {
    dir=$1
    shift
    n=0
    while :; do
        remaining=0
        for name in "$@"; do
            [ ! -e "$dir/cache/$name" ] || remaining=1
        done
        [ "$remaining" -eq 0 ] && break
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/daemon.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 1200 ] || { cat "$dir/daemon.err" >&2; exit 1; }; sleep .1
    done
}
setup_published() {
    name=published
    dir=$work/caches/$name
    mkdir -m 755 "$dir"
    mkdir -m 700 "$dir/cache" "$dir/admin"
    mkdir -m 755 "$dir/broker"
    chown 1234:1234 "$dir/cache" "$dir/admin" "$dir/broker"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        "$work/tools/latcd" gc --init-domain --cache-dir "$dir/cache"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        "$work/tools/latc" emit-static-tbset "$work/tools/guest" -o "$dir/admin/first.tbset"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        LATCD_COMPILE_TMPDIR="$dir/admin" \
        "$work/tools/latcd" --serve --socket "$dir/admin/ordinary.sock" \
        --cache-dir "$dir/cache" --latc "$work/tools/latc" --runner "$work/tools/runner" \
        --runtime-dir "$work/runtime" --workers 1 --flush-only --idle-seconds 1 \
        >"$dir/ordinary.out" 2>"$dir/ordinary.err" &
    pid=$!
    n=0
    while [ ! -S "$dir/admin/ordinary.sock" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$dir/ordinary.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 500 ] || { cat "$dir/ordinary.err" >&2; exit 1; }; sleep .05
    done
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        "$work/tools/latcd" --submit --socket "$dir/admin/ordinary.sock" \
        --tbset "$dir/admin/first.tbset" "$work/tools/guest" >"$dir/admin/first.submit"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        "$work/tools/latcd" --flush-source --socket "$dir/admin/ordinary.sock" \
        "$work/tools/guest" >"$dir/admin/first.flush"
    grep -q '^status=0$' "$dir/admin/first.flush"
    published_source=$(sha256sum "$work/tools/guest" | cut -d' ' -f1)
    cp "$dir/cache/$published_source.current" "$dir/admin/old.json"
    PYTHONPATH="$work/tools" python3 - "$dir/admin/second.tbset" "$work/tools/guest" <<'PY'
from pathlib import Path
import sys
from tb_key_set import write_key_set
import struct
guest = Path(sys.argv[2])
data = guest.read_bytes()
entry, phoff = struct.unpack_from("<QQ", data, 24)
entsize, count = struct.unpack_from("<HH", data, 54)
base = min(struct.unpack_from("<Q", data, phoff + i * entsize + 16)[0]
           for i in range(count)
           if struct.unpack_from("<I", data, phoff + i * entsize)[0] == 1)
write_key_set(guest, Path(sys.argv[1]), [(entry + 0x13 - base, 3)])
PY
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        "$work/tools/latcd" --submit --socket "$dir/admin/ordinary.sock" \
        --tbset "$dir/admin/second.tbset" "$work/tools/guest" >"$dir/admin/second.submit"
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LD_LIBRARY_PATH="$work/runtime" \
        "$work/tools/latcd" --flush-source --socket "$dir/admin/ordinary.sock" \
        "$work/tools/guest" >"$dir/admin/second.flush"
    grep -q '^status=0$' "$dir/admin/second.flush"
    cp "$dir/cache/$published_source.current" "$dir/admin/new.json"
    cmp -s "$dir/admin/old.json" "$dir/admin/new.json" && exit 1
    kill -TERM "$pid"
    wait "$pid"
    pid=
    printf '%s\n' "{\"service_uid\":\"1234\",\"client_uid\":\"1235\",\"cache\":\"$dir/cache\",\"admin\":\"$dir/admin\",\"broker\":\"$dir/broker\",\"compiler\":\"$work/tools/latc\",\"runner\":\"$work/tools/runner\",\"runtime\":\"$work/runtime\",\"worker_bwrap\":\"$work/tools/launcher\",\"worker_bootstrap\":\"$work/tools/launcher\",\"automatic_retirement\":true,\"retirement_grace_us\":1000000}" > "$work/config-$name"
}
setup_published
start_daemon published
dir=$work/caches/published
old_module=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$dir/admin/old.json")
old_native=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["native"])' "$dir/admin/old.json")
old_tbset=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tbset"])' "$dir/admin/old.json")
wait_paths_deleted "$dir" "$old_module" "$old_native" "$old_tbset"
cmp "$dir/admin/new.json" "$dir/cache/$published_source.current"
python3 - "$dir/cache" "$dir/admin/new.json" <<'PY'
import json, pathlib, sys
root, manifest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
new = json.loads(manifest.read_text())
assert all((root / new[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
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
echo 'test-managed-retirement: PASS published/release/restart'
