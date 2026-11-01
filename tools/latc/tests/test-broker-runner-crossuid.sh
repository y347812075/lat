#!/bin/sh
set -eu
# Run as root inside a disposable container with /input and /runner mounts.
work=/opt/latcd-broker-runner-test
test "$(id -u)" = 0 && test ! -e "$work"
mkdir -m 755 "$work" "$work/tools" "$work/runtime" "$work/broker" "$work/home"
mkdir -m 700 "$work/cache" "$work/admin"
chown 1234:1234 "$work/cache" "$work/admin" "$work/broker"
chown 1235:1235 "$work/home"
cp /input/build/tests/test-cache-retirement "$work/tools/latc"
cp /input/build/tests/test-cache-retirement "$work/tools/runner"
cp /input/build/tests/test-cache-retirement "$work/tools/bootstrap"
cp /bwrap "$work/tools/bwrap"
cp /input/build/tests/gc-timer-runtime/liblat-aot-runtime.so.2 "$work/runtime/"
chmod 755 "$work/tools/"* "$work/runtime/"*
printf '%s\n' '{"service_uid":"1234","client_uid":"1235","cache":"/opt/latcd-broker-runner-test/cache","admin":"/opt/latcd-broker-runner-test/admin","broker":"/opt/latcd-broker-runner-test/broker","compiler":"/opt/latcd-broker-runner-test/tools/latc","runner":"/opt/latcd-broker-runner-test/tools/runner","runtime":"/opt/latcd-broker-runner-test/runtime","worker_bwrap":"/opt/latcd-broker-runner-test/tools/bwrap","worker_bootstrap":"/opt/latcd-broker-runner-test/tools/bootstrap"}' > "$work/config"
pid=
cleanup() { if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; }
trap cleanup EXIT HUP INT TERM
setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /input/build/tests/latcd-gc-timer \
    --managed-config "$work/config" >"$work/daemon.log" 2>&1 &
pid=$!
n=0
while [ ! -S "$work/broker/broker.sock" ]; do
    kill -0 "$pid" 2>/dev/null || { cat "$work/daemon.log" >&2; exit 1; }
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
status=0
setpriv --no-new-privs --reuid=1235 --regid=1235 --clear-groups \
    env HOME="$work/home" LD_LIBRARY_PATH=/runner LATX_AOT=0 LATX_AOT_V2=1 \
    LATX_AOT_V2_KEY_JOURNAL=1 LATX_AOT_V2_JOURNAL_BROKER="$work/broker/broker.sock" \
    LATX_AOT_V2_JOURNAL_BROKER_UID=1234 LATX_AOT_V2_AUTOSTART=0 \
    LATC_DISABLE_PRETRANSLATE=1 timeout 30 /runner/latx-x86_64 \
    /input/build/tests/x86-exit42 >"$work/run.out" 2>"$work/run.err" || status=$?
[ "$status" -eq 42 ] || { cat "$work/run.err" >&2; exit 1; }
set -- "$work"/cache/.journals/*
[ "$#" -eq 1 ] && [ -f "$1/registration" ] && [ -f "$1/source" ] && [ -f "$1/keys" ]
python3 - "$1/keys" <<'PY'
import struct
import sys

with open(sys.argv[1], 'rb') as journal:
    header = journal.read(192)
    assert len(header) == 192
    capacity, slot_size = struct.unpack_from('<QI', header, 16)
    assert capacity == 65536 and slot_size == 32
    slots = journal.read()
    assert len(slots) == capacity * slot_size
    committed = [struct.unpack_from('<QQQQ', slots, offset)
                 for offset in range(0, len(slots), slot_size)
                 if struct.unpack_from('<Q', slots, offset)[0] == 3]
    assert committed and all(flags == 3 and reserved == 0
                             for _, _, flags, reserved in committed)
PY
echo 'test-broker-runner-crossuid: PASS'
