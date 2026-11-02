#!/bin/sh
set -eu
if [ "$#" -ne 6 ]; then
    echo "usage: $0 DAEMON TOOL RUNTIME RUNNER GUEST CONSUMER" >&2
    exit 2
fi
daemon=$1 tool=$2 runtime=$3 runner=$4 guest=$5 consumer=$6
work=$(mktemp -d "${TMPDIR:-$HOME/tmp}/broker-load.XXXXXX")
pid=
cleanup() {
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    if ! findmnt -rn -o TARGET | grep -F "$work" >/dev/null &&
       ! lsof +D "$work" >/dev/null 2>&1; then rm -rf "$work"; else
        echo "retained busy test directory: $work" >&2
    fi
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$work/cache" "$work/broker"
LATX_AOT_V2=1 "$runner" --latc-translation-config-native \
    --latc-translation-config-out "$work/config" "$guest" >"$work/config.json"
source=$(python3 tests/prepare-broker-load-fixture.py "${BROKER_LOAD_FIXTURE:-build/aot-v2/fixture-config.so}" \
    "$guest" "$work/config" "$($daemon --build-id)" "$work/cache")
mkdir -m 700 "$work/cache/.gc" "$work/cache/.gc/source-locks"
(umask 077; : >"$work/cache/.gc/source-locks/$source.lock")
LATCD_TEST_BROKER_DIRECTORY="$work/broker" LATCD_TEST_BROKER_LOAD=1 "$daemon" --serve \
    --socket "$work/admin.sock" --cache-dir "$work/cache" --latc "$tool" \
    --runner "$tool" --runtime-dir "$runtime" --workers 1 --idle-seconds 0 \
    --flush-only >"$work/daemon.log" 2>&1 &
pid=$!
n=0
while [ ! -S "$work/broker/broker.sock" ]; do
    kill -0 "$pid" 2>/dev/null || { cat "$work/daemon.log" >&2; exit 1; }
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
if [ -n "${BROKER_LOAD_TEST_RUNNER:-}" ]; then
    set +e
    LATX_AOT_V2=1 LATX_AOT_V2_TEST_BROKER_LOAD=1 LATX_AOT_V2_KEY_JOURNAL=1 \
        LATX_AOT_V2_JOURNAL_BROKER="$work/broker/broker.sock" \
        LATX_AOT_V2_JOURNAL_BROKER_UID="$(id -u)" LATX_AOT_V2_TRACE_LOAD=1 \
        LATX_AOT_V2_CACHE_DIR="$work/cache" \
        "$BROKER_LOAD_TEST_RUNNER" "$guest" >"$work/runner.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 42 ] || ! grep -q 'module loaded path=test-broker-load' "$work/runner.log" ||
       ! grep -q 'test broker registry lookup succeeded' "$work/runner.log"; then
        cat "$work/runner.log" >&2
        echo "broker runner integration failed: exit=$rc" >&2
        exit 1
    fi
fi
cp "$work/config" "$work/wrong-config"
python3 - "$work/wrong-config" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[64] ^= 1
p.write_bytes(data)
PY
"$consumer" "$work/broker/broker.sock" "$guest" "$work/wrong-config" - reject
"$consumer" "$work/broker/broker.sock" "$guest" "$work/config" "$work/cache/$source.so"
