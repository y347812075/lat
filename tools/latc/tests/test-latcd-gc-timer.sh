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
cache=$work/crash-cache
socket=$work/crash.sock
stats=$work/crash-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_RETIREMENT_IO=crash:consumption-unlinked start
n=0
while kill -0 "$pid" 2>/dev/null; do
    n=$((n + 1)); if [ "$n" -ge 300 ]; then cat "$work/server.err" >&2; exit 1; fi
    sleep 0.05
done
if wait "$pid"; then echo 'expected consumption crash' >&2; exit 1; fi
pid=
rm -f "$socket"
old=$cache/$(printf '%064x' 7)
test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
LATCD_TEST_RECOVER_PAGE=1 start
grep -q 'latcd: test recovered page consumed' "$work/server.err"
python3 - "$cache" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); source = f'{7:064x}'
m = json.loads((root / (source + '.current')).read_text())
assert all((root / m[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
stop
cache=$work/cache
socket=$work/latcd.sock
stats=$work/stats.json
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
rm -f "$stats"
LATCD_TEST_STAGE_PAGE=1 start
n=0
while ! grep -q 'latcd: test page staged' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null; then cat "$work/server.err" >&2; exit 1; fi
    n=$((n + 1)); if [ "$n" -ge 300 ]; then cat "$work/server.err" >&2; exit 1; fi
    sleep 0.05
done
test -f "$cache/.gc/retirement-page.ini"
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
stop
if "$test_daemon" --serve --socket "$socket" --cache-dir "$cache" \
    --latc "$compiler" --runner "$daemon" --runtime-dir "$runtime" \
    --stats "$stats" --workers 1 >"$work/restart.out" 2>"$work/restart.err"; then
    echo 'daemon accepted unresolved first page' >&2; exit 1
fi
grep -q 'retirement page budget recovery unavailable or checkpoint unsafe' "$work/restart.err"
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
LATCD_TEST_RECOVER_PAGE=1 start
grep -q 'latcd: test recovered page consumed' "$work/server.err"
test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
stop
cache=$work/consume-cache
socket=$work/consume.sock
stats=$work/consume-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 start
n=0
while ! grep -q 'latcd: test page consumed' "$work/server.err"; do
    if grep -q 'latcd: test page .* failed' "$work/server.err" || ! kill -0 "$pid" 2>/dev/null; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); if [ "$n" -ge 300 ]; then cat "$work/server.err" >&2; exit 1; fi
    sleep 0.05
done
old=$cache/$(printf '%064x' 7)
test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
python3 - "$cache" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
source = f'{7:064x}'
manifest = json.loads((root / (source + '.current')).read_text())
assert all((root / manifest[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
stop
