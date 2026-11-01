#!/bin/sh
set -eu
test_daemon=$1
latcd=$2
latc=$3
runner=$4
runtime=$5
guest=$6
work=$7
mode=${8:-pin}
case "$mode" in pin|pin-restart|unreferenced|capture|capture-restart|broker-copy) ;; *) exit 2 ;; esac
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -m 700 "$work" "$work/cache" "$work/broker"
cache=$work/cache
socket=$work/latcd.sock
pid=
pin_pid=
broker_pid=
closure_replaced=0
cleanup() {
    if [ -n "$pin_pid" ]; then kill "$pin_pid" 2>/dev/null || :; wait "$pin_pid" 2>/dev/null || :; fi
    if [ -n "$broker_pid" ]; then kill "$broker_pid" 2>/dev/null || :; wait "$broker_pid" 2>/dev/null || :; fi
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    if [ "$closure_replaced" = 1 ]; then
        python3 - "$LATCD_TEST_WORKER_CLOSURE" <<'PY'
import json, os, sys
targets = {'/usr/libexec/latc/scripts/compile-aot-v2-module.sh', '/usr/bin/gcc',
           '/usr/lib64/ld-linux-loongarch-lp64d.so.1'}
for item in json.load(open(sys.argv[1]))['files']:
    if item['destination'] not in targets: continue
    saved = item['source'] + '.latcd-test-saved'
    if os.path.exists(saved): os.replace(saved, item['source'])
PY
    fi
}
trap cleanup EXIT
unset LATCD_TEST_BROKER_DIRECTORY
if [ "$mode" = pin ] || [ "$mode" = broker-copy ]; then export LATCD_TEST_BROKER_DIRECTORY="$work/broker"; fi
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    "$test_daemon" --serve --socket "$socket" --cache-dir "$cache" --latc "$latc" \
    --runner "$runner" --runtime-dir "$runtime" --stats "$work/stats.json" \
    --workers 1 --flush-only --idle-seconds "${LATCD_TEST_IDLE_SECONDS:-0}" >"$work/server.out" 2>"$work/server.err" &
pid=$!
n=0
while [ ! -S "$socket" ]; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 500 ]; sleep 0.05
done
if [ "${LATCD_TEST_REPLACE_CLOSURE:-0}" = 1 ]; then
    : "${LATCD_TEST_WORKER_CLOSURE:?closure manifest required}"
    closure_replaced=1
    python3 - "$LATCD_TEST_WORKER_CLOSURE" <<'PY'
import json, os, sys
targets = {'/usr/libexec/latc/scripts/compile-aot-v2-module.sh', '/usr/bin/gcc',
           '/usr/lib64/ld-linux-loongarch-lp64d.so.1'}
items = [i for i in json.load(open(sys.argv[1]))['files'] if i['destination'] in targets]
assert {i['destination'] for i in items} == targets
for item in items:
    path = item['source']; saved = path + '.latcd-test-saved'
    assert not os.path.lexists(saved)
    os.rename(path, saved)
    with open(path, 'xb') as replacement: replacement.write(b'invalid replacement\n')
PY
fi
if [ "${LATCD_TEST_REPLACE_LAUNCHER:-0}" = 1 ]; then
    mv "$LATCD_TEST_BWRAP" "$LATCD_TEST_BWRAP.saved"
    mv "$LATCD_TEST_BOOTSTRAP" "$LATCD_TEST_BOOTSTRAP.saved"
    printf invalid > "$LATCD_TEST_BWRAP"
    printf invalid > "$LATCD_TEST_BOOTSTRAP"
fi
if [ "${LATCD_TEST_REPLACE_TOOLS:-0}" = 1 ]; then
    for file in "$latc" "$runner" "$runtime/liblat-aot-runtime.so.2"; do
        mv "$file" "$file.saved"
        printf invalid > "$file"
    done
fi
python3 "$script_dir/make-tbset.py" "$guest" "$work/initial.tbset"
"$latcd" --submit --socket "$socket" --tbset "$work/initial.tbset" "$guest" >"$work/initial-submit"
"$latcd" --flush-source --socket "$socket" "$guest" >"$work/initial-flush"
grep -q '^status=0$' "$work/initial-flush"
if [ "${LATCD_TEST_REPLACE_LAUNCHER:-0}" = 1 ]; then
    mv -f "$LATCD_TEST_BWRAP.saved" "$LATCD_TEST_BWRAP"
    mv -f "$LATCD_TEST_BOOTSTRAP.saved" "$LATCD_TEST_BOOTSTRAP"
fi
if [ "${LATCD_TEST_REPLACE_TOOLS:-0}" = 1 ]; then
    for file in "$latc" "$runner" "$runtime/liblat-aot-runtime.so.2"; do
        mv -f "$file.saved" "$file"
    done
fi
if [ "$mode" = pin ]; then
    python3 "$script_dir/test-broker-publication.py" "$work/broker/broker.sock" "$cache" "$guest"
    broker_client=$(dirname "$latcd")/latcd-broker-export
    "$broker_client" --socket "$work/broker/broker.sock" --service-uid "$(id -u)" --output "$work/export-old.so" "$guest"
    if "$broker_client" --socket "$work/broker/broker.sock" --service-uid "$(id -u)" --output "$work/export-old.so" "$guest"; then exit 1; fi
    if "$broker_client" --socket "$work/broker/broker.sock" --service-uid 4294967294 --output "$work/invalid.so" "$guest"; then exit 1; fi
    test ! -e "$work/invalid.so"
fi
if [ "$mode" = broker-copy ]; then
    python3 "$script_dir/test-broker-publication.py" "$work/broker/broker.sock" "$cache" "$guest" \
        "$work/broker-ready" "$work/broker-release" >"$work/broker.out" 2>"$work/broker.err" &
    broker_pid=$!
    n=0
    while [ ! -f "$work/broker-ready" ]; do
        kill -0 "$broker_pid" || { cat "$work/broker.err" >&2; exit 1; }
        n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
fi
python3 - "$cache" "$guest" "$work" "$script_dir" <<'PY'
import hashlib, json, pathlib, struct, sys
cache, guest, work = map(pathlib.Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set, write_key_set
source = hashlib.sha256(guest.read_bytes()).hexdigest()
m = json.loads((cache / (source + '.current')).read_text())
(work / 'old.json').write_text(json.dumps(m))
data = guest.read_bytes()
entry, phoff = struct.unpack_from('<QQ', data, 24)
entsize, count = struct.unpack_from('<HH', data, 54)
base = min(struct.unpack_from('<Q', data, phoff + i * entsize + 16)[0]
           for i in range(count) if struct.unpack_from('<I', data, phoff + i * entsize)[0] == 1)
_, _, old = read_key_set(cache / m['tbset'])
delta = (entry + 14 - base, 3)
assert delta not in old
write_key_set(guest, work / 'delta.tbset', [delta])
PY
if [ "$mode" = capture ] || [ "$mode" = capture-restart ]; then
    LD_LIBRARY_PATH="$runtime" LATX_AOT_V2_CACHE_DIR="$cache" LATX_AOT_V2_LATCD_SOCKET="$socket" \
        LATX_AOT_V2_STRICT=1 LATC_DISABLE_PRETRANSLATE=1 LATC_STRICT_AOT=1 \
        LATX_AOT_V2_TEST_CAPTURE_READY="$work/capture-ready" \
        LATX_AOT_V2_TEST_CAPTURE_RELEASE="$work/capture-release" \
        "$runner" "$guest" >"$work/capture.out" 2>"$work/capture.err" &
    pin_pid=$!
    n=0
    while [ ! -f "$work/capture-ready" ]; do
        kill -0 "$pin_pid" || { cat "$work/capture.err" >&2; exit 1; }
        n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
    python3 - "$cache" "$work/old.json" <<'PY'
import fcntl, json, pathlib, sys
cache = pathlib.Path(sys.argv[1]); old = json.loads(pathlib.Path(sys.argv[2]).read_text())
with (cache / old['module']).open('rb') as module:
    try:
        fcntl.flock(module, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise AssertionError('runner did not pin the old module')
PY
elif [ "$mode" != unreferenced ] && [ "$mode" != broker-copy ]; then
python3 - "$cache" "$work/old.json" "$work/pins-ready" <<'PY' &
import fcntl, json, pathlib, signal, sys
cache = pathlib.Path(sys.argv[1]); m = json.loads(pathlib.Path(sys.argv[2]).read_text())
files = [open(cache / m[k], 'rb') for k in ('module', 'native', 'tbset')]
for f in files: fcntl.flock(f, fcntl.LOCK_SH)
pathlib.Path(sys.argv[3]).touch()
signal.pause()
PY
pin_pid=$!
n=0
while [ ! -f "$work/pins-ready" ]; do kill -0 "$pin_pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05; done
fi
"$latcd" --submit --socket "$socket" --tbset "$work/delta.tbset" "$guest" >"$work/delta-submit"
"$latcd" --flush-source --socket "$socket" "$guest" >"$work/delta-flush"
grep -q '^status=0$' "$work/delta-flush"
if [ "${LATCD_TEST_REQUIRE_INCREMENTAL:-0}" = 1 ]; then
    grep -q '^latcd: test incremental module validated$' "$work/server.err"
fi
if [ "$closure_replaced" = 1 ]; then
    python3 - "$LATCD_TEST_WORKER_CLOSURE" <<'PY'
import json, os, sys
targets = {'/usr/libexec/latc/scripts/compile-aot-v2-module.sh', '/usr/bin/gcc',
           '/usr/lib64/ld-linux-loongarch-lp64d.so.1'}
for item in json.load(open(sys.argv[1]))['files']:
    if item['destination'] not in targets: continue
    saved = item['source'] + '.latcd-test-saved'
    if os.path.exists(saved): os.replace(saved, item['source'])
PY
    closure_replaced=0
fi
if [ "${LATCD_TEST_IDLE_SECONDS:-0}" != 0 ]; then
    sleep 2
    kill -0 "$pid"
fi
python3 - "$cache" "$guest" "$work" "$script_dir" <<'PY'
import hashlib, json, pathlib, sys
cache, guest, work = map(pathlib.Path, sys.argv[1:4]); sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set
source = hashlib.sha256(guest.read_bytes()).hexdigest()
old = json.loads((work / 'old.json').read_text())
new = json.loads((cache / (source + '.current')).read_text())
assert old['module'] != new['module'] and old['native'] != new['native']
_, _, a = read_key_set(cache / old['tbset']); _, _, b = read_key_set(cache / new['tbset'])
_, _, delta = read_key_set(work / 'delta.tbset')
assert set(a) | set(delta) <= set(b)
retired = set(old[k] for k in ('module', 'native', 'tbset')) - set(new[k] for k in ('module', 'native', 'tbset'))
assert retired
(work / 'new.json').write_text(json.dumps(new))
(work / 'retired.json').write_text(json.dumps(sorted(retired)))
PY
if [ "$mode" = unreferenced ] || [ "$mode" = broker-copy ]; then
python3 - "$cache" "$work/old.json" "$work/retired.json" <<'PY'
import base64, configparser, json, pathlib, sys, time
cache = pathlib.Path(sys.argv[1]); old = json.loads(pathlib.Path(sys.argv[2]).read_text())
retired = json.loads(pathlib.Path(sys.argv[3]).read_text())
matches = []
for path in (cache / '.gc/transactions').glob('*.ini'):
    c = configparser.ConfigParser(); c.read(path)
    t = c['transaction']
    if t.get('previous') and json.loads(base64.b64decode(t['previous'])) == old:
        matches.append(int(t['retired_boottime_us']) / 1_000_000)
assert len(matches) == 1
deadline = matches[0] + 3
remaining = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
assert remaining > 0.5
time.sleep(remaining - 0.25)
assert time.clock_gettime(time.CLOCK_BOOTTIME) < deadline
assert all((cache / name).is_file() for name in retired)
PY
fi
if [ "$mode" != unreferenced ] && [ "$mode" != broker-copy ]; then
n=0
while ! grep -q 'test page busy retry=' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then cat "$work/server.err" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 600 ]; sleep 0.05
done
python3 - "$cache" "$work/retired.json" "$work/old.json" "$mode" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); names = json.loads(pathlib.Path(sys.argv[2]).read_text())
if sys.argv[4] in ('capture', 'capture-restart'):
    old = json.loads(pathlib.Path(sys.argv[3]).read_text())
    assert old['module'] in names and (root / old['module']).is_file()
else:
    assert all((root / name).is_file() for name in names)
PY
if [ "$mode" = pin-restart ] || [ "$mode" = capture-restart ]; then
    kill -KILL "$pid"; wait "$pid" 2>/dev/null || :; pid=
    rm -f "$socket"
    LATCD_TEST_RECOVER_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
        "$test_daemon" --serve --socket "$socket" --cache-dir "$cache" --latc "$latc" \
        --runner "$runner" --runtime-dir "$runtime" --stats "$work/stats.json" \
        --workers 1 --flush-only --idle-seconds "${LATCD_TEST_IDLE_SECONDS:-0}" >"$work/restart.out" 2>"$work/restart.err" &
    pid=$!
    n=0
    while [ ! -S "$socket" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$work/restart.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 500 ]; sleep 0.05
    done
    grep -q 'test recovered page waiting' "$work/restart.err"
    cp "$work/restart.err" "$work/restart-startup.err"
    python3 - "$cache" "$guest" "$work" "$mode" <<'PY'
import hashlib, json, pathlib, sys
cache, guest, work = map(pathlib.Path, sys.argv[1:4])
retired = json.loads((work / 'retired.json').read_text())
current = json.loads((work / 'new.json').read_text())
source = hashlib.sha256(guest.read_bytes()).hexdigest()
if sys.argv[4] == 'capture-restart':
    old = json.loads((work / 'old.json').read_text())
    assert old['module'] in retired and (cache / old['module']).is_file()
else:
    assert all((cache / name).is_file() for name in retired)
assert json.loads((cache / (source + '.current')).read_text()) == current
assert all((cache / current[k]).is_file() for k in ('module', 'native', 'tbset'))
PY
    log=$work/restart.err
else
    log=$work/server.err
fi
if [ "$mode" = capture ] || [ "$mode" = capture-restart ]; then
    touch "$work/capture-release"
    set +e
    wait "$pin_pid"
    capture_status=$?
    set -e
    pin_pid=
    test "$capture_status" -eq 42
else
    kill "$pin_pid"; wait "$pin_pid" 2>/dev/null || :; pin_pid=
fi
else
    log=$work/server.err
fi
n=0
while ! grep -q 'test waiting page consumed' "$log"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$log"; then cat "$log" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 1000 ]; sleep 0.1
done
if [ "$mode" != unreferenced ] && [ "$mode" != broker-copy ]; then
    grep -q 'test waiting timer woke' "$log"
else
    python3 - "$work/stats.json" <<'PY'
import json, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 5
while True:
    if json.loads(path.read_text())['retirement_timer_wakeups'] > 0:
        break
    if time.monotonic() >= deadline:
        raise AssertionError('retirement timer wakeup not reflected in statistics')
    time.sleep(0.05)
PY
fi
if [ "$mode" = pin ]; then
    python3 "$script_dir/test-broker-publication.py" "$work/broker/broker.sock" "$cache" "$guest"
    "$broker_client" --socket "$work/broker/broker.sock" --service-uid "$(id -u)" --output "$work/export-new.so" "$guest"
    python3 - "$work" <<'PY'
import hashlib, json, pathlib, sys
work = pathlib.Path(sys.argv[1])
for generation in ('old', 'new'):
    manifest = json.loads((work / (generation + '.json')).read_text())
    assert hashlib.sha256((work / ('export-' + generation + '.so')).read_bytes()).hexdigest() == manifest['module_sha256']
PY
fi
python3 - "$cache" "$guest" "$work" <<'PY'
import hashlib, json, pathlib, sys
cache, guest, work = map(pathlib.Path, sys.argv[1:])
names = json.loads((work / 'retired.json').read_text())
assert all(not (cache / name).exists() for name in names)
source = hashlib.sha256(guest.read_bytes()).hexdigest()
new = json.loads((work / 'new.json').read_text())
assert json.loads((cache / (source + '.current')).read_text()) == new
assert all((cache / new[k]).is_file() for k in ('module', 'native', 'tbset'))
PY
if [ "$mode" = broker-copy ]; then
    touch "$work/broker-release"
    wait "$broker_pid" || { cat "$work/broker.err" >&2; exit 1; }
    broker_pid=
fi
module=$(python3 - "$cache" "$guest" <<'PY'
import hashlib, json, pathlib, sys
root, guest = map(pathlib.Path, sys.argv[1:])
print(json.loads((root / (hashlib.sha256(guest.read_bytes()).hexdigest() + '.current')).read_text())['module'])
PY
)
"$latc" emit-module-tbset "$cache/$module" -o "$work/actual.tbset"
python3 - "$work" "$script_dir" <<'PY'
import pathlib, sys
work = pathlib.Path(sys.argv[1]); sys.path.insert(0, sys.argv[2])
from tb_key_set import read_key_set
_, _, a = read_key_set(work / 'initial.tbset'); _, _, b = read_key_set(work / 'delta.tbset')
_, _, actual = read_key_set(work / 'actual.tbset')
assert set(a) | set(b) <= set(actual)
PY
set +e
LD_LIBRARY_PATH="$runtime" LATX_AOT_V2_CACHE_DIR="$cache" LATX_AOT_V2_LATCD_SOCKET="$socket" \
    LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 LATC_STRICT_AOT=1 \
    LATC_STATS_OUT="$work/strict-stats.json" "$runner" "$guest" >"$work/strict.out" 2>"$work/strict.err"
strict_status=$?
set -e
test "$strict_status" -eq 42
python3 - "$work/strict-stats.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s['runtime_file_tb_gen_calls'] == 0 and s['runtime_file_tb_gen_attempts'] == 0
PY
python3 - "$guest" "$work/third.tbset" "$script_dir" <<'PY'
import pathlib, struct, sys
guest, output = map(pathlib.Path, sys.argv[1:3]); sys.path.insert(0, sys.argv[3])
from tb_key_set import write_key_set
data = guest.read_bytes(); entry, phoff = struct.unpack_from('<QQ', data, 24)
entsize, count = struct.unpack_from('<HH', data, 54)
base = min(struct.unpack_from('<Q', data, phoff + i * entsize + 16)[0]
           for i in range(count) if struct.unpack_from('<I', data, phoff + i * entsize)[0] == 1)
write_key_set(guest, output, [(entry + 28 - base, 3)])
PY
"$latcd" --submit --socket "$socket" --tbset "$work/third.tbset" "$guest" >"$work/third-submit"
"$latcd" --flush-source --socket "$socket" "$guest" >"$work/third-flush"
grep -q '^status=0$' "$work/third-flush"
python3 - "$cache" "$guest" "$work" "$script_dir" <<'PY'
import hashlib, json, pathlib, sys
cache, guest, work = map(pathlib.Path, sys.argv[1:4]); sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set
source = hashlib.sha256(guest.read_bytes()).hexdigest()
old = json.loads((work / 'new.json').read_text())
new = json.loads((cache / (source + '.current')).read_text())
assert old['module'] != new['module'] and old['native'] != new['native']
(work / 'third.json').write_text(json.dumps(new))
_, _, a = read_key_set(work / 'initial.tbset'); _, _, b = read_key_set(work / 'delta.tbset')
_, _, c = read_key_set(work / 'third.tbset'); _, _, result = read_key_set(cache / new['tbset'])
assert set(a) | set(b) | set(c) <= set(result)
assert all((cache / new[k]).is_file() for k in ('module', 'native', 'tbset'))
PY
n=0
while [ "$(grep -c 'test waiting page consumed' "$log" || :)" -lt 2 ]; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$log"; then cat "$log" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 1000 ]; sleep 0.1
done
python3 - "$cache" "$work/new.json" "$work/third.json" "$guest" <<'PY'
import hashlib, json, pathlib, sys
cache = pathlib.Path(sys.argv[1]); old = json.loads(pathlib.Path(sys.argv[2]).read_text())
third = json.loads(pathlib.Path(sys.argv[3]).read_text())
source = hashlib.sha256(pathlib.Path(sys.argv[4]).read_bytes()).hexdigest()
assert all(not (cache / old[k]).exists() for k in ('module', 'native', 'tbset'))
assert json.loads((cache / (source + '.current')).read_text()) == third
assert all((cache / third[k]).is_file() for k in ('module', 'native', 'tbset'))
PY
if [ "${LATCD_TEST_IDLE_SECONDS:-0}" != 0 ]; then
    n=0
    while kill -0 "$pid" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 400 ]; sleep 0.1
    done
    wait "$pid"; pid=
    grep -q 'retirement exit handoff persisted (IDLE)' "$log"
else
    kill -TERM "$pid"; wait "$pid"; pid=
fi
