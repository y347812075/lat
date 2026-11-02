#!/bin/sh
set -eu
daemon=$1 prefix=$2 guest=$3 work=$4
: "${LATCD_TEST_SERVICE_DELEGATION:?}" "${LATCD_TEST_BOOTSTRAP:?}" \
  "${LATCD_TEST_BWRAP:?}" "${LATCD_TEST_WORKER_CLOSURE:?}"
mkdir -m 700 "$work" "$work/cache" "$work/broker" "$work/home"
export LATCD_TEST_REAL_COMPILE=1 LATCD_TEST_JOURNAL_REPLAY=1
export LATCD_TEST_BROKER_DIRECTORY="$work/broker"
"$daemon" --serve --socket "$work/admin.sock" --cache-dir "$work/cache" \
    --latc "$prefix/bin/latc" --runner "$prefix/bin/latx-x86_64" \
    --runtime-dir "$prefix/lib" --workers 1 --idle-seconds 0 > "$work/daemon.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :' EXIT HUP INT TERM
n=0
while [ ! -S "$work/broker/broker.sock" ]; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep .05
done
status=0
env HOME="$work/home" LD_LIBRARY_PATH="$prefix/lib" LATX_AOT=0 LATX_AOT_V2=1 \
    LATX_AOT_V2_KEY_JOURNAL=1 LATX_AOT_V2_JOURNAL_BROKER="$work/broker/broker.sock" \
    LATX_AOT_V2_JOURNAL_BROKER_UID="$(id -u)" LATX_AOT_V2_AUTOSTART=0 \
    timeout 30 "$prefix/bin/latx-x86_64" "$guest" > "$work/run.out" 2> "$work/run.err" || status=$?
[ "$status" -eq 42 ] || { cat "$work/run.err" >&2; exit 1; }
n=0
while ! grep -qs 'latcd: test journal replay succeeded task=' "$work/daemon.log"; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 600 ] || { cat "$work/daemon.log" >&2; exit 1; }; sleep .1
done
id=$(sed -n 's/^latcd: test journal replay succeeded task=//p' "$work/daemon.log" | head -1)
grep -qx 'state=REPLAY_DISCARDED' "$work/cache/.gc/managed-task-state/$id.ini"
grep -qx 'kind=MANAGED_REPLAY' "$work/cache/.gc/tasks/$id.ini"
grep -qx 'version=4' "$work/cache/.gc/tasks/$id.ini"
test -z "$(find "$work/cache" -maxdepth 1 -name '*.so' -print -quit)"
echo 'test-managed-journal-replay-integration: PASS'
