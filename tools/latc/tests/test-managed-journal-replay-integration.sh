#!/bin/sh
set -eu
daemon=$1 prefix=$2 guest=$3 work=$4 scanner=$5
: "${LATCD_TEST_SERVICE_DELEGATION:?}" "${LATCD_TEST_BOOTSTRAP:?}" \
  "${LATCD_TEST_BWRAP:?}" "${LATCD_TEST_WORKER_CLOSURE:?}"
mkdir -m 700 "$work" "$work/cache" "$work/broker" "$work/home"
mkdir -m 700 "$work/cache/.tmp"
LD_LIBRARY_PATH="$prefix/lib" LATX_AOT_V2=1 "$prefix/bin/latx-x86_64" \
    --latc-translation-config-native --latc-translation-config-out "$work/config" \
    "$guest" > "$work/config.json"
"$prefix/bin/latc" emit-static-tbset "$guest" -o "$work/base.tbset"
PYTHONPATH="$(dirname "$0")" python3 - "$work/base.tbset" <<'PY'
import sys
from pathlib import Path
from tb_key_set import read_key_set, write_key_set_digest
path = Path(sys.argv[1])
digest, _, keys = read_key_set(path)
assert len(keys) > 1
write_key_set_digest(digest, path, [keys[-1]])
PY
LD_LIBRARY_PATH="$prefix/lib" LATC_TRANSLATION_CONFIG_FROM="$work/config" \
    "$prefix/libexec/latc/scripts/compile-native-image.sh" --config-replay \
    "$prefix/bin/latc" "$prefix/bin/latx-x86_64" "$guest" \
    "$work/cache/.tmp/base.native" "$work/base.tbset"
chmod 400 "$work/cache/.tmp/base.native"
export LATCD_TEST_REAL_COMPILE=1 LATCD_TEST_JOURNAL_REPLAY=1
export LATCD_TEST_JOURNAL_REPLAY_BASE="$work/cache/.tmp/base.native"
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
if [ -n "${LATCD_TEST_REPLAY_CRASH_PREPARED:-}${LATCD_TEST_REPLAY_CRASH_LINKED:-}${LATCD_TEST_REPLAY_CRASH_HANDOFF:-}${LATCD_TEST_REPLAY_CRASH_UNLINKED:-}" ]; then
    n=0
    while kill -0 "$pid" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 600 ] || exit 1; sleep .1
    done
    wait "$pid" 2>/dev/null || :
    state=$(find "$work/cache/.gc/managed-task-state" -name '*.ini' -type f)
    grep -qx 'state=REPLAY_ADOPTED' "$state"
    id=$(basename "$state" .ini)
    test -s "$work/cache/.gc/journal-inputs/$id.receipt"
    [ "$("$scanner" --task-status "$work/cache" .tmp/base.native)" = 1 ]
    if [ -n "${LATCD_TEST_REPLAY_CRASH_HANDOFF:-}" ]; then
        receipt="$work/cache/.gc/journal-inputs/$id.receipt"
        mv "$receipt" "$work/original.receipt"
        printf 'invalid receipt\n' > "$receipt"
        chmod 400 "$receipt"
        if "$daemon" --test-managed-adoption-recovery "$work/cache" "$id" > "$work/receipt-reject.log" 2>&1; then
            echo 'replacement receipt accepted by recovery' >&2; exit 1
        fi
        grep -qx 'state=REPLAY_ADOPTED' "$state"
        test -f "$work/cache/.tmp/base.native"
        rm "$receipt"
        mv "$work/original.receipt" "$receipt"
    fi
    if [ -n "${LATCD_TEST_REPLAY_CRASH_UNLINKED:-}" ]; then
        test -z "$(find "$work/cache/.tmp" -name 'replay-native-*' -print -quit)"
    fi
    if [ -n "${LATCD_TEST_REPLAY_REPLACE:-}" ]; then
        output=$(find "$work/cache/.tmp" -name 'replay-native-*' -type f)
        [ -n "$output" ]
        mv "$output" "$work/original.native"
        printf 'replacement\n' > "$output"
        if "$daemon" --test-managed-adoption-recovery "$work/cache" "$id" > "$work/reject.log" 2>&1; then
            echo 'replacement accepted by recovery' >&2; exit 1
        fi
        test -f "$work/cache/.tmp/base.native"
        grep -qx replacement "$output"
        rm "$output"
        mv "$work/original.native" "$output"
    fi
    unset LATCD_TEST_REPLAY_CRASH_PREPARED LATCD_TEST_REPLAY_CRASH_LINKED LATCD_TEST_REPLAY_CRASH_HANDOFF LATCD_TEST_REPLAY_CRASH_UNLINKED
    "$daemon" --serve --socket "$work/admin.sock" --cache-dir "$work/cache" \
        --latc "$prefix/bin/latc" --runner "$prefix/bin/latx-x86_64" \
        --runtime-dir "$prefix/lib" --workers 1 --idle-seconds 0 > "$work/restart.log" 2>&1 &
    pid=$!
    n=0
    while ! grep -qs '^state=OUTPUTS_REMOVED$' "$state"; do
        kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 600 ] || { cat "$work/restart.log" >&2; exit 1; }; sleep .1
    done
    n=0
    while ! grep -qs '^latcd: test journal replay succeeded task=' "$work/restart.log"; do
        kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 600 ] || { cat "$work/restart.log" >&2; exit 1; }; sleep .1
    done
    retried=$(sed -n 's/^latcd: test journal replay succeeded task=//p' "$work/restart.log" | head -1)
    [ -n "$retried" ] && [ "$retried" != "$id" ]
    test ! -e "$work/cache/.gc/journal-inputs/$id.receipt"
    test ! -e "$work/cache/.gc/journal-inputs/$retried.receipt"
    grep -qx 'state=OUTPUTS_REMOVED' "$work/cache/.gc/managed-task-state/$retried.ini"
    test -f "$work/cache/.tmp/base.native"
    test -z "$(find "$work/cache/.tmp" -name 'replay-native-*' -print -quit)"
    kill "$pid"
    wait "$pid" || :
    [ "$("$scanner" --task-status "$work/cache" .tmp/base.native)" = 0 ]
    "$daemon" --test-managed-adoption-recovery "$work/cache" "$id" > "$work/recover-again.log" 2>&1
    grep -qx 'state=OUTPUTS_REMOVED' "$state"
    echo 'test-managed-journal-replay-integration: crash recovery PASS'
    exit 0
fi
n=0
while ! grep -qs 'latcd: test journal replay succeeded task=' "$work/daemon.log"; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 600 ] || { cat "$work/daemon.log" >&2; exit 1; }; sleep .1
done
id=$(sed -n 's/^latcd: test journal replay succeeded task=//p' "$work/daemon.log" | head -1)
grep -qx 'state=OUTPUTS_REMOVED' "$work/cache/.gc/managed-task-state/$id.ini"
grep -qx 'kind=MANAGED_REPLAY' "$work/cache/.gc/tasks/$id.ini"
grep -qx 'version=5' "$work/cache/.gc/tasks/$id.ini"
grep -qx 'name=base.native' "$work/cache/.gc/tasks/$id.ini"
PYTHONPATH="$(dirname "$0")" python3 - "$work/base.tbset" "$work/cache/.journals" <<'PY'
import sys
from pathlib import Path
from tb_key_set import read_key_set
base = set(read_key_set(Path(sys.argv[1]))[2])
receipts = list(Path(sys.argv[2]).glob('*/received.tbset'))
assert len(receipts) == 1
requested = set(read_key_set(receipts[0])[2])
assert requested and requested - base
PY
receipt=$(find "$work/cache/.journals" -name received.tbset -type f)
if "$prefix/bin/latc" validate-replay-native "$work/cache/.tmp/base.native" \
    "$work/config" "$receipt" > "$work/base-validation.out" 2>&1; then
    echo 'baseline already covers journal requests' >&2
    exit 1
fi
grep -q 'missing requested TB' "$work/base-validation.out"
test -z "$(find "$work/cache" -maxdepth 1 -name '*.so' -print -quit)"
echo 'test-managed-journal-replay-integration: PASS'
