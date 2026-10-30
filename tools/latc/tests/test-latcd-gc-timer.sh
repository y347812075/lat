#!/bin/sh
set -eu
test_daemon=$1
daemon=$2
compiler=$3
fixture=$4
work=$5
runtime=$6
cache=$work/cache
socket=$work/latcd.sock
stats=$work/stats.json
mkdir -m 700 "$cache"
pid=
cleanup() {
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
}
trap cleanup EXIT
start() {
    "$test_daemon" --serve --socket "$socket" --cache-dir "$cache" \
        --latc "$compiler" --runner "$daemon" --runtime-dir "$runtime" \
        --stats "$stats" --workers 1 >"$work/server.out" 2>"$work/server.err" &
    pid=$!
    n=0
    while [ ! -S "$socket" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$work/server.err" >&2; return 1; fi
        n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
}
stop() { kill -TERM "$pid"; wait "$pid"; pid=; }
wait_stats() {
    n=0
    while ! python3 - "$stats" "$1" <<'PY' 2>/dev/null
import json, sys
with open(sys.argv[1]) as f:
    s = json.load(f)
assert eval(sys.argv[2], {"__builtins__": {}}, {"s": s})
PY
    do
        kill -0 "$pid"
        n=$((n + 1)); if [ "$n" -ge 300 ]; then
            cat "$stats" "$work/server.err" >&2; return 1
        fi
        sleep 0.05
    done
}
start
stop
"$fixture" --timer-fixture "$cache"
start
wait_stats 's["retirement_discovery_complete"] and s["retirement_candidates"] >= 3 and s["retirement_next_attempt_boottime_us"] > 0'
wait_stats 's["retirement_timer_wakeups"] >= 1 and s["retirement_due_candidates"] >= 3 and not s["automatic_deletion_enabled"]'
old=$cache/$(printf '%064x' 7)
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
stop
rm -f "$stats"
start
wait_stats 's["retirement_discovery_complete"] and s["retirement_due_candidates"] >= 3 and not s["automatic_deletion_enabled"]'
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
stop
