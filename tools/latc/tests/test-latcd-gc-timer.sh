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
pin_pid=
cleanup() {
    if [ -n "$pin_pid" ]; then kill "$pin_pid" 2>/dev/null || :; wait "$pin_pid" 2>/dev/null || :; fi
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
test_daemon_saved=$test_daemon
test_daemon=$(dirname "$test_daemon")/../latcd/latcd
cache=$work/production-invalid-cache
socket=$work/production-invalid.sock
stats=$work/production-invalid-stats.json
mkdir -m 700 "$cache"
start
wait_stats 's["retirement_discovery_complete"]'
"$fixture" --timer-fixture "$cache"
printf 'invalid\n' > "$cache/.gc/transactions/invalid"
n=0
while ! grep -q 'retirement discovery stopped:' "$work/server.err"; do
    kill -0 "$pid"
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
sleep 6
test "$(grep -c 'retirement discovery stopped:' "$work/server.err")" -eq 1
old=$cache/$(printf '%064x' 7)
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
stop
test_daemon=$test_daemon_saved
for fault in unlinked unlink-synced; do
    cache=$work/object-$fault-cache
    socket=$work/object-$fault.sock
    stats=$work/object-$fault-stats.json
    mkdir -m 700 "$cache"
    start
    stop
    "$fixture" --timer-fixture "$cache"
    LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_RETIREMENT_IO=crash:$fault start
    n=0
    while kill -0 "$pid" 2>/dev/null; do
        n=$((n + 1)); if [ "$n" -ge 300 ]; then cat "$work/server.err" >&2; exit 1; fi
        sleep 0.05
    done
    if wait "$pid"; then echo "expected $fault crash" >&2; exit 1; fi
    pid=
    rm -f "$socket"
    LATCD_TEST_RECOVER_PAGE=1 start
    grep -q 'latcd: test recovered page consumed' "$work/server.err"
    old=$cache/$(printf '%064x' 7)
    test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
    python3 - "$cache" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); source = f'{7:064x}'
m = json.loads((root / (source + '.current')).read_text())
assert all((root / m[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
    stop
done
cache=$work/partial-done-cache
socket=$work/partial-done.sock
stats=$work/partial-done-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_CRASH_AFTER_PAGE_DONE=1 start
n=0
while kill -0 "$pid" 2>/dev/null; do
    n=$((n + 1)); if [ "$n" -ge 300 ]; then cat "$work/server.err" >&2; exit 1; fi
    sleep 0.05
done
if wait "$pid"; then echo 'expected partial DONE crash' >&2; exit 1; fi
pid=
rm -f "$socket"
old=$cache/$(printf '%064x' 7)
remaining=0
for suffix in so native tbset; do
    if [ -e "$old.$suffix" ]; then remaining=$((remaining + 1)); fi
done
test "$remaining" -eq 2
LATCD_TEST_RECOVER_PAGE=1 start
grep -q 'latcd: test recovered page consumed' "$work/server.err"
test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
python3 - "$cache" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); source = f'{7:064x}'
m = json.loads((root / (source + '.current')).read_text())
assert all((root / m[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
stop
cache=$work/deferred-guard-cache
socket=$work/deferred-guard.sock
stats=$work/deferred-guard-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_DEFER_PAGE=1 start
n=0
while ! grep -q 'latcd: test page deferred' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'latcd: test defer .*failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 300 ]; sleep 0.05
done
stop
scheduler=$cache/.gc/retirement-scheduler.ini
before=$(sha256sum "$scheduler")
LATCD_TEST_RECOVER_PAGE=1 start
grep -q 'test recovered page waiting; automatic retry unavailable' "$work/server.err"
test -f "$cache/.gc/retirement-page.ini"
old=$cache/$(printf '%064x' 7)
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
stop
test "$before" = "$(sha256sum "$scheduler")"
cache=$work/hash-stop-cache
socket=$work/hash-stop.sock
stats=$work/hash-stop-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    LATCD_TEST_SMALL_HASH_BUDGET=1 LATCD_TEST_STOP_ON_HASH_YIELD=1 start
wait "$pid"; pid=
grep -q 'test retirement hash yielded' "$work/server.err"
grep -q 'test retirement cancellation persisted' "$work/server.err"
old=$cache/$(printf '%064x' 7)
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
python3 - "$cache/.gc/retirement-scheduler.ini" <<'PY'
import configparser, sys
c = configparser.ConfigParser(); assert c.read(sys.argv[1])
assert any(c.getint(s, 'busy_count') >= 1 and c.getint(s, 'retry_at') > 0
           for s in c.sections() if s != 'queue')
PY
cache=$work/busy-fair-cache
socket=$work/busy-fair.sock
stats=$work/busy-fair-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
old=$cache/$(printf '%064x' 7)
python3 - "$old.native" "$work/fair-pin-ready" <<'PY' &
import fcntl, pathlib, signal, sys
f = open(sys.argv[1], 'rb'); fcntl.flock(f, fcntl.LOCK_SH)
pathlib.Path(sys.argv[2]).touch(); signal.pause()
PY
pin_pid=$!
n=0
while [ ! -f "$work/fair-pin-ready" ]; do
    kill -0 "$pin_pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    LATCD_TEST_SMALL_HASH_BUDGET=1 start
n=0
while ! grep -q 'test page busy retry=' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.05
done
n=0
while [ -e "$old.so" ] || [ -e "$old.tbset" ]; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.05
done
test -f "$old.native"
grep -q 'test retirement hash yielded' "$work/server.err"
kill "$pin_pid"; wait "$pin_pid" 2>/dev/null || :; pin_pid=
stop
cache=$work/busy-timer-cache
socket=$work/busy-timer.sock
stats=$work/busy-timer-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
old=$cache/$(printf '%064x' 7)
python3 - "$old" "$work/pins-ready" <<'PY' &
import fcntl, pathlib, signal, sys
files = [open(sys.argv[1] + suffix, 'rb') for suffix in ('.so', '.native', '.tbset')]
for f in files: fcntl.flock(f, fcntl.LOCK_SH)
pathlib.Path(sys.argv[2]).touch()
signal.pause()
PY
pin_pid=$!
n=0
while [ ! -f "$work/pins-ready" ]; do
    kill -0 "$pin_pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    LATCD_TEST_CRASH_BEFORE_BUSY_PAGE=1 start
n=0
while kill -0 "$pid" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.05
done
if wait "$pid"; then echo 'expected busy handoff crash' >&2; exit 1; fi
pid=
rm -f "$socket"
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
test ! -e "$cache/.gc/tombstones/$(printf '%064x' 7).so"
test ! -e "$cache/.gc/tombstones/$(printf '%064x' 7).native"
test ! -e "$cache/.gc/tombstones/$(printf '%064x' 7).tbset"
LATCD_TEST_RECOVER_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 start
# Keep the pins across a second attempt and inspect the persisted scheduler,
# rather than assuming that two BUSY log lines refer to the same object.
n=0
while ! python3 - "$cache/.gc/retirement-scheduler.ini" "$work/repeated-retry" <<'PY' 2>/dev/null
import configparser, pathlib, sys
c = configparser.ConfigParser()
c.read(sys.argv[1])
items = [(s, c.getint(s, 'retry_at')) for s in c.sections()
         if s != 'queue' and c.getint(s, 'busy_count') >= 2]
assert items
pathlib.Path(sys.argv[2]).write_text('%s %d\n' % items[0])
PY
do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 2800 ]; sleep 0.1
done
n=0
while ! grep -q 'test page busy retry=' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.05
done
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
kill -KILL "$pid"; wait "$pid" 2>/dev/null || :; pid=
rm -f "$socket"
LATCD_TEST_RECOVER_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 start
grep -q 'test recovered page waiting' "$work/server.err"
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
python3 - "$cache/.gc/retirement-scheduler.ini" "$work/repeated-retry" <<'PY'
import configparser, pathlib, sys
name, retry = pathlib.Path(sys.argv[2]).read_text().split()
c = configparser.ConfigParser(); c.read(sys.argv[1])
assert c.getint(name, 'busy_count') >= 2
assert c.getint(name, 'retry_at') == int(retry)
PY
kill "$pin_pid"; wait "$pin_pid" 2>/dev/null || :; pin_pid=
python3 - "$cache" "$work/repeated-retry" <<'PY'
import pathlib, sys, time
name, retry = pathlib.Path(sys.argv[2]).read_text().split()
retry = int(retry) / 1_000_000
remaining = retry - time.clock_gettime(time.CLOCK_BOOTTIME)
assert remaining > 2
time.sleep(remaining - 1)
assert time.clock_gettime(time.CLOCK_BOOTTIME) < retry
assert (pathlib.Path(sys.argv[1]) / name).is_file()
PY
n=0
while ! grep -q 'test waiting page consumed' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then
        cat "$work/server.err" >&2; exit 1
    fi
    n=$((n + 1)); [ "$n" -lt 1600 ]; sleep 0.1
done
grep -q 'test waiting timer woke' "$work/server.err"
grep -q 'test retirement witness yielded' "$work/server.err"
test "$(grep -c 'test consumption recovery step=' "$work/server.err")" -ge 2
test ! -e "$old.so" && test ! -e "$old.native" && test ! -e "$old.tbset"
python3 - "$cache" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); source = f'{7:064x}'
m = json.loads((root / (source + '.current')).read_text())
assert all((root / m[key]).is_file() for key in ('module', 'native', 'tbset'))
PY
stop
cache=$work/busy-checkpoint-error-cache
socket=$work/busy-checkpoint-error.sock
stats=$work/busy-checkpoint-error-stats.json
mkdir -m 700 "$cache"
start
stop
"$fixture" --timer-fixture "$cache"
old=$cache/$(printf '%064x' 7)
python3 - "$old" "$work/error-pins-ready" <<'PY' &
import fcntl, pathlib, signal, sys
files = [open(sys.argv[1] + suffix, 'rb') for suffix in ('.so', '.native', '.tbset')]
for f in files: fcntl.flock(f, fcntl.LOCK_SH)
pathlib.Path(sys.argv[2]).touch()
signal.pause()
PY
pin_pid=$!
n=0
while [ ! -f "$work/error-pins-ready" ]; do
    kill -0 "$pin_pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    LATCD_TEST_RETIREMENT_IO=error:completion-clock start
n=0
while ! grep -q 'test waiting page failed' "$work/server.err"; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.05
done
! grep -q 'test page busy retry=' "$work/server.err"
test -f "$old.so" && test -f "$old.native" && test -f "$old.tbset"
test -f "$cache/.gc/retirement-page.ini"
kill "$pin_pid"; wait "$pin_pid" 2>/dev/null || :; pin_pid=
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
