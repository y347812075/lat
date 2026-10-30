#!/bin/sh
set -eu
test_daemon=$1
latcd=$2
latc=$3
runner=$4
runtime=$5
guest=$6
work=$7
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -m 700 "$work" "$work/cache"
cache=$work/cache
socket=$work/latcd.sock
pid=
pin_pid=
cleanup() {
    if [ -n "$pin_pid" ]; then kill "$pin_pid" 2>/dev/null || :; wait "$pin_pid" 2>/dev/null || :; fi
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
}
trap cleanup EXIT
LATCD_TEST_STAGE_PAGE=1 LATCD_TEST_CONSUME_PAGE=1 LATCD_TEST_WAITING_DRIVER=1 \
    "$test_daemon" --serve --socket "$socket" --cache-dir "$cache" --latc "$latc" \
    --runner "$runner" --runtime-dir "$runtime" --stats "$work/stats.json" \
    --workers 1 --flush-only --idle-seconds 0 >"$work/server.out" 2>"$work/server.err" &
pid=$!
n=0
while [ ! -S "$socket" ]; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 500 ]; sleep 0.05
done
python3 "$script_dir/make-tbset.py" "$guest" "$work/initial.tbset"
"$latcd" --submit --socket "$socket" --tbset "$work/initial.tbset" "$guest" >"$work/initial-submit"
"$latcd" --flush-source --socket "$socket" "$guest" >"$work/initial-flush"
grep -q '^status=0$' "$work/initial-flush"
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
"$latcd" --submit --socket "$socket" --tbset "$work/delta.tbset" "$guest" >"$work/delta-submit"
"$latcd" --flush-source --socket "$socket" "$guest" >"$work/delta-flush"
grep -q '^status=0$' "$work/delta-flush"
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
n=0
while ! grep -q 'test page busy retry=' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then cat "$work/server.err" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 600 ]; sleep 0.05
done
python3 - "$cache" "$work/retired.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); names = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert all((root / name).is_file() for name in names)
PY
kill "$pin_pid"; wait "$pin_pid" 2>/dev/null || :; pin_pid=
n=0
while ! grep -q 'test waiting page consumed' "$work/server.err"; do
    if ! kill -0 "$pid" 2>/dev/null || grep -q 'test waiting page failed' "$work/server.err"; then cat "$work/server.err" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 1000 ]; sleep 0.1
done
grep -q 'test waiting timer woke' "$work/server.err"
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
_, _, a = read_key_set(work / 'initial.tbset'); _, _, b = read_key_set(work / 'delta.tbset')
_, _, c = read_key_set(work / 'third.tbset'); _, _, result = read_key_set(cache / new['tbset'])
assert set(a) | set(b) | set(c) <= set(result)
assert all((cache / new[k]).is_file() for k in ('module', 'native', 'tbset'))
PY
kill -TERM "$pid"; wait "$pid"; pid=
