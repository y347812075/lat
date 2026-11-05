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
retire_root=$root-retire
mkdir -m 700 "$retire_root" "$retire_root/.tmp"
cp "$guest" "$retire_root/.tmp/input"
cp "$tbset" "$retire_root/.tmp/tbset"
chmod 600 "$retire_root/.tmp/input" "$retire_root/.tmp/tbset"
LD_LIBRARY_PATH="$prefix/lib" LATX_AOT_V2=1 "$prefix/bin/latx-x86_64" \
    --latc-translation-config-native --latc-translation-config-out "$retire_root/.tmp/config" \
    "$retire_root/.tmp/input" > "$retire_root/config.json"
export LATCD_TEST_REPLAY_CONFIG="$retire_root/.tmp/config"
export LATCD_TEST_INPUT_TBSET="$retire_root/.tmp/tbset"
export LATCD_TEST_COMPILER="$prefix/bin/latc" LATCD_TEST_RUNNER="$prefix/bin/latx-x86_64"
export LATCD_TEST_RUNTIME_DIR="$prefix/lib" LATCD_TEST_REAL_COMPILE=1
LATCD_TEST_RETIRE_COMPILER_TASK=1 \
    sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' \
    sh "$LATCD_TEST_DELEGATION" "$daemon" --test-managed-compiler "$retire_root" \
    "$LATCD_TEST_DELEGATION" > "$retire_root/id"
retire_task=$(cat "$retire_root/id")
grep -qx 'state=REPLAY_DISCARDED' \
    "$retire_root/.gc/managed-task-state/$retire_task.ini"
test ! -e "$retire_root/.tmp/output-native"
test ! -e "$retire_root/.tmp/output-module"
rm -rf "$retire_root"
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
if [ "${LATCD_TEST_REPLAY_EXTRA_MODULE:-0}" = 1 ]; then
    if sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' sh "$LATCD_TEST_DELEGATION" \
        "$daemon" --test-managed-compiler "$root" "$LATCD_TEST_DELEGATION" > "$root/id" 2> "$root/error"; then
        echo 'unexpected replay module accepted' >&2
        exit 1
    fi
    grep -q 'unexpected replay module output' "$root/error"
    test ! -e "$root/.tmp/output-native"
    test ! -e "$root/.tmp/output-module"
    echo 'test-managed-replay-integration: extra module rejected'
    exit 0
fi
sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' sh "$LATCD_TEST_DELEGATION" \
    "$daemon" --test-managed-compiler "$root" "$LATCD_TEST_DELEGATION" > "$root/id"
id=$(cat "$root/id")
grep -qx 'state=REPLAY_DISCARDED' "$root/.gc/managed-task-state/$id.ini"
test ! -e "$root/.tmp/output-native"
test ! -e "$root/.tmp/output-module"
echo 'test-managed-replay-integration: PASS'
