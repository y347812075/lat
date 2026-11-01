#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 TEST_DAEMON TEST_TOOL RUNTIME RUNNER X86_GUEST" >&2
    exit 2
fi
daemon=$1 tool=$2 runtime=$3 runner=$4 guest=$5
work=$(mktemp -d "${TMPDIR:-$HOME/tmp}/latcd-broker-runner.XXXXXX")
pid=
cleanup() {
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    if ! findmnt -rn -o TARGET | grep -F "$work" >/dev/null &&
       ! lsof +D "$work" >/dev/null 2>&1; then rm -rf "$work"; else
        echo "retained busy test directory: $work" >&2
    fi
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$work/cache" "$work/broker" "$work/home"
LATCD_TEST_BROKER_DIRECTORY="$work/broker" "$daemon" --serve \
    --socket "$work/admin.sock" --cache-dir "$work/cache" --latc "$tool" \
    --runner "$tool" --runtime-dir "$runtime" --workers 1 --idle-seconds 0 \
    --flush-only >"$work/daemon.log" 2>&1 &
pid=$!
n=0
while [ ! -S "$work/broker/broker.sock" ]; do
    kill -0 "$pid" 2>/dev/null || { cat "$work/daemon.log" >&2; exit 1; }
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
run_guest() {
    env HOME="$work/home" LATX_AOT=0 LATX_AOT_V2=1 LATX_AOT_V2_KEY_JOURNAL=1 \
        LATX_AOT_V2_JOURNAL_BROKER="$work/broker/broker.sock" \
        LATX_AOT_V2_JOURNAL_BROKER_UID="$1" LATX_AOT_V2_AUTOSTART=0 \
        LATC_DISABLE_PRETRANSLATE=1 timeout 30 "$runner" "$guest" \
        >"$work/run.out" 2>"$work/run.err"
}
status=0
run_guest "$(id -u)" || status=$?
[ "$status" -eq 42 ] || { cat "$work/run.err" >&2; exit 1; }
set -- "$work"/cache/.journals/*
[ "$#" -eq 1 ] && [ -f "$1/registration" ] && [ -f "$1/source" ] && [ -f "$1/keys" ]
status=0
run_guest "$(( $(id -u) + 1 ))" || status=$?
[ "$status" -eq 125 ] && grep -q 'peer UID does not match' "$work/run.err"
echo 'test-aot-v2-broker-runner: PASS'
