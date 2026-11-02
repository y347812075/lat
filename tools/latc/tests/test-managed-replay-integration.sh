#!/bin/sh
set -eu
# Run in a fresh delegated systemd scope with the worker closure configured.
daemon=$1
prefix=$2
guest=$3
tbset=$4
root=$5
: "${LATCD_TEST_BOOTSTRAP:?}" "${LATCD_TEST_BWRAP:?}" "${LATCD_TEST_WORKER_CLOSURE:?}"
: "${LATCD_TEST_DELEGATION:?}"
mkdir -m 700 "$root" "$root/.tmp"
cp "$guest" "$root/.tmp/input"
cp "$tbset" "$root/.tmp/tbset"
chmod 600 "$root/.tmp/input" "$root/.tmp/tbset"
LD_LIBRARY_PATH="$prefix/lib" LATX_AOT_V2=1 "$prefix/bin/latx-x86_64" \
    --latc-translation-config-native --latc-translation-config-out "$root/.tmp/config" \
    "$root/.tmp/input" > "$root/config.json"
export LATCD_TEST_REPLAY_CONFIG="$root/.tmp/config"
export LATCD_TEST_INPUT_TBSET="$root/.tmp/tbset"
export LATCD_TEST_COMPILER="$prefix/bin/latc" LATCD_TEST_RUNNER="$prefix/bin/latx-x86_64"
export LATCD_TEST_RUNTIME_DIR="$prefix/lib" LATCD_TEST_REAL_COMPILE=1
sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' sh "$LATCD_TEST_DELEGATION" \
    "$daemon" --test-managed-compiler "$root" "$LATCD_TEST_DELEGATION" > "$root/id"
id=$(cat "$root/id")
grep -qx 'state=REPLAY_DISCARDED' "$root/.gc/managed-task-state/$id.ini"
test ! -e "$root/.tmp/output-native"
test ! -e "$root/.tmp/output-module"
echo 'test-managed-replay-integration: PASS'
