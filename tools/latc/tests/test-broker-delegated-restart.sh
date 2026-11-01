#!/bin/sh
set -eu
# Run inside a delegated user scope with a disposable work directory under ~/tmp.
daemon=$1
compiler=$2
runner=$3
runtime=$4
bootstrap=$5
launcher=$6
work=$7
scope=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir "$scope/supervisor"
printf '%s\n' "$$" > "$scope/supervisor/cgroup.procs"
printf '%s\n' '+memory +pids' > "$scope/cgroup.subtree_control"
mkdir "$scope/worker"
mkdir -m 700 "$work/cache" "$work/broker"
export LATCD_TEST_SERVICE_DELEGATION="$scope/worker" LATCD_TEST_REAL_COMPILE=1
export LATCD_TEST_BOOTSTRAP="$bootstrap" LATCD_TEST_BWRAP="$launcher"
export LATCD_TEST_BROKER_DIRECTORY="$work/broker" LD_LIBRARY_PATH="$runtime"
pid= task=
cleanup() {
    [ -z "$task" ] || kill "$task" 2>/dev/null || :
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || :
    [ -z "$task" ] || wait "$task" 2>/dev/null || :
    [ -z "$pid" ] || wait "$pid" 2>/dev/null || :
}
trap cleanup EXIT HUP INT TERM
start() {
    "$daemon" --serve --socket "$work/admin.sock" --cache-dir "$work/cache" \
        --latc "$compiler" --runner "$runner" --runtime-dir "$runtime" \
        --workers 1 --idle-seconds 0 >"$work/$1.log" 2>&1 &
    pid=$!
}
wait_broker() {
    n=0
    while ! python3 - "$work/broker/broker.sock" <<'PY'
import socket, sys
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(.2); s.connect(sys.argv[1])
except OSError:
    sys.exit(1)
PY
    do
        kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep .05
    done
}
start first
wait_broker
grep -qx "$pid" "$scope/worker/manager/cgroup.procs"
mkdir "$scope/worker/preserved"
sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; exec sleep 120' sh "$scope/worker/preserved" &
task=$!
n=0
while ! grep -qx "$task" "$scope/worker/preserved/cgroup.procs"; do
    kill -0 "$task"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep .05
done
kill -KILL "$pid"; wait "$pid" 2>/dev/null || :; pid=
grep -q '^populated 1$' "$scope/worker/preserved/cgroup.events"
start second
wait_broker
grep -qx "$pid" "$scope/worker/manager/cgroup.procs"
kill -0 "$task"
grep -q '^populated 1$' "$scope/worker/preserved/cgroup.events"
kill -TERM "$pid"; wait "$pid"; pid=
kill "$task"; wait "$task" 2>/dev/null || :; task=
rmdir "$scope/worker/preserved" "$scope/worker/manager" "$scope/worker"
echo 'test-broker-delegated-restart: PASS'
