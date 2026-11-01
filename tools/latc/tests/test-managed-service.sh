#!/bin/sh
set -eu
umask 022

# Run only in a disposable container with an empty /opt/latcd-managed-test.
if [ "$#" -ne 5 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: $0 LATCD LATC RUNNER RUNTIME STATIC_LAUNCHER (root in disposable container)" >&2
    exit 2
fi
daemon=$1
compiler=$2
runner=$3
runtime=$4
static_launcher=$5
work=/opt/latcd-managed-test
test ! -e "$work"
mkdir -m 755 "$work" "$work/tools" "$work/runtime"
mkdir -m 700 "$work/cache" "$work/admin"
mkdir -m 755 "$work/broker"
chown 1234:1234 "$work/cache" "$work/admin" "$work/broker"
cp "$compiler" "$work/tools/latc"
cp "$runner" "$work/tools/runner"
cp "$static_launcher" "$work/tools/bwrap"
cp "$compiler" "$work/tools/bootstrap"
cp "$runtime" "$work/runtime/liblat-aot-runtime.so.2"
chmod 755 "$work/tools/latc" "$work/tools/runner"
chmod 755 "$work/tools/bwrap" "$work/tools/bootstrap"
chmod 755 "$work/runtime/liblat-aot-runtime.so.2"
printf '%s\n' '{"service_uid":"1234","client_uid":"1235","cache":"/opt/latcd-managed-test/cache","admin":"/opt/latcd-managed-test/admin","broker":"/opt/latcd-managed-test/broker","compiler":"/opt/latcd-managed-test/tools/latc","runner":"/opt/latcd-managed-test/tools/runner","runtime":"/opt/latcd-managed-test/runtime","worker_bwrap":"/opt/latcd-managed-test/tools/bwrap","worker_bootstrap":"/opt/latcd-managed-test/tools/bootstrap"}' > "$work/config"
pid=
task_pid=
cleanup() {
    if [ -n "$task_pid" ]; then kill -KILL "$task_pid" 2>/dev/null || :; wait "$task_pid" 2>/dev/null || :; fi
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
}
trap cleanup EXIT HUP INT TERM
run_service() {
    setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/config"
}
expect_rejected() {
    if run_service >"$work/reject.out" 2>"$work/reject.err"; then
        echo 'unsafe configuration accepted' >&2; exit 1
    fi
    grep -q 'managed configuration rejected' "$work/reject.err"
    test ! -e "$work/admin/admin.sock"
    test ! -e "$work/broker/broker.sock"
}
chmod 777 "$work/tools/latc"
expect_rejected
chmod 755 "$work/tools/latc"
chmod 777 "$work/tools/bootstrap"
expect_rejected
chmod 755 "$work/tools/bootstrap"
cp "$compiler" "$work/tools/bwrap.dynamic"
mv "$work/tools/bwrap" "$work/tools/bwrap.static"
mv "$work/tools/bwrap.dynamic" "$work/tools/bwrap"
expect_rejected
mv "$work/tools/bwrap.static" "$work/tools/bwrap"
sed 's|,"worker_bootstrap":"/opt/latcd-managed-test/tools/bootstrap"||' "$work/config" > "$work/incomplete-config"
if setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/incomplete-config" \
    >"$work/incomplete.out" 2>"$work/incomplete.err"; then
    echo 'incomplete launcher accepted' >&2; exit 1
fi
grep -q 'managed configuration rejected' "$work/incomplete.err"
sed 's|}$|,"worker_closure":"/opt/latcd-managed-test/missing-closure"}|' "$work/config" > "$work/missing-closure-config"
if setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/missing-closure-config" \
    >"$work/closure.out" 2>"$work/closure.err"; then
    echo 'missing worker closure accepted' >&2; exit 1
fi
grep -q 'managed worker closure rejected' "$work/closure.err"
test ! -e "$work/admin/admin.sock"
test ! -e "$work/broker/broker.sock"
chmod 777 "$work/broker"
expect_rejected
chmod 755 "$work/broker"
sed 's|}$|,"worker_cgroup":"/opt/latcd-managed-test/cache"}|' "$work/config" > "$work/invalid-cgroup-config"
if setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/invalid-cgroup-config" \
    >"$work/cgroup.out" 2>"$work/cgroup.err"; then
    echo 'ordinary directory accepted as worker cgroup' >&2; exit 1
fi
grep -q 'worker delegation rejected' "$work/cgroup.err"
test ! -e "$work/admin/admin.sock"
test ! -e "$work/broker/broker.sock"
if setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C LATCD_COMPILE_TMPDIR=/tmp \
    "$daemon" --managed-config "$work/config" >"$work/env.out" 2>"$work/env.err"; then
    echo 'unsafe environment accepted' >&2; exit 1
fi
grep -q 'managed configuration rejected' "$work/env.err"
test ! -e "$work/admin/admin.sock"
test ! -e "$work/broker/broker.sock"
setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/config" \
    >"$work/stdout" 2>"$work/stderr" &
pid=$!
n=0
while [ ! -S "$work/broker/broker.sock" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then cat "$work/stderr" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
test -S "$work/admin/admin.sock"
if setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/invalid-cgroup-config" \
    >"$work/second.out" 2>"$work/second.err"; then
    echo 'second cache owner accepted' >&2; exit 1
fi
if grep -q 'worker delegation rejected' "$work/second.err"; then
    echo 'worker delegation touched before acquiring cache ownership' >&2; exit 1
fi
# Managed services must remain available to process retirement deadlines even
# when no clients send requests; their lifetime is controlled externally.
sleep 2
kill -0 "$pid"
test -S "$work/admin/admin.sock"
test -S "$work/broker/broker.sock"
# An unauthenticated request must fail closed both while recovery encounters an
# unrecognized task and after the obstruction is removed.
setpriv --reuid=1234 --regid=1234 --clear-groups \
    sh -c 'printf invalid > "$1/.gc/tasks/not-a-task"' sh "$work/cache"
n=0
while ! grep -q 'cannot scan compiler task roots' "$work/stderr"; do
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
submit_probe() {
    setpriv --reuid=1234 --regid=1234 --clear-groups \
        "$daemon" --submit --socket "$work/admin/admin.sock" \
        --tbset /etc/hosts /etc/hosts >"$work/probe.out" 2>"$work/probe.err" || :
}
submit_probe
grep -q 'managed compilation requires an authenticated translation configuration' "$work/probe.out"
rm "$work/cache/.gc/tasks/not-a-task"
n=0
while :; do
    submit_probe
    if grep -q 'managed compilation requires an authenticated translation configuration' "$work/probe.out"; then break; fi
    kill -0 "$pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
setpriv --reuid=1236 --regid=1236 --clear-groups python3 - "$work/broker/broker.sock" <<'PY'
import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
    s.connect(sys.argv[1])
    s.settimeout(3)
    assert s.recv(1) == b''
PY
if setpriv --reuid=1235 --regid=1235 --clear-groups ls "$work/cache" >/dev/null 2>&1 ||
   setpriv --reuid=1235 --regid=1235 --clear-groups ls "$work/admin" >/dev/null 2>&1; then
    echo 'client can access private directory' >&2; exit 1
fi
broker_missing_probe() {
    setpriv --reuid=1235 --regid=1235 --clear-groups python3 - "$work/broker/broker.sock" <<'PY'
import array, fcntl, hashlib, os, socket, struct, sys

data = b'managed broker absent source'
digest = hashlib.sha256(data).digest()
fd = os.memfd_create('source', os.MFD_ALLOW_SEALING)
try:
    os.write(fd, data)
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(10)
        s.connect(sys.argv[1])
        assert struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] == 1234
        request = struct.pack('=IIQ32s', 2, 0, len(data), digest)
        assert s.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]) == len(request)
        packet, ancillary, flags, _ = s.recvmsg(88, socket.CMSG_SPACE(4))
        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        assert not ancillary
        version, status, purpose, authorized, size, source_hash, module_hash = struct.unpack('=IIIIQ32s32s', packet)
        assert (version, status, purpose, authorized, size) == (2, 1, 1, 0, 0)
        assert source_hash == bytes(32) and module_hash == bytes(32)
finally:
    os.close(fd)
PY
}
broker_missing_probe
kill -KILL "$pid"
wait "$pid" 2>/dev/null || :
pid=
setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/config" \
    >"$work/restart-basic.out" 2>"$work/restart-basic.err" &
pid=$!
n=0
while ! setpriv --reuid=1236 --regid=1236 --clear-groups python3 - "$work/broker/broker.sock" <<'PY'
import socket, sys
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(1); s.connect(sys.argv[1]); assert s.recv(1) == b''
except (OSError, AssertionError):
    sys.exit(1)
PY
do
    if ! kill -0 "$pid" 2>/dev/null; then cat "$work/restart-basic.err" >&2; exit 1; fi
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
submit_probe
grep -q '^status=' "$work/probe.out"
broker_missing_probe
kill -TERM "$pid"
wait "$pid"
pid=
test ! -e "$work/admin/admin.sock"
test ! -e "$work/broker/broker.sock"
if [ "${LATCD_TEST_REAL_DELEGATION:-0}" = 1 ]; then
    scope=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
    mkdir "$scope/supervisor"
    printf '%s\n' "$$" > "$scope/supervisor/cgroup.procs"
    printf '%s\n' '+memory +pids' > "$scope/cgroup.subtree_control"
    mkdir "$scope/worker"
    chown 1234:1234 "$scope/worker" "$scope/worker/cgroup.procs" \
        "$scope/worker/cgroup.subtree_control"
    sed "s|}$|,\"worker_cgroup\":\"$scope/worker\"}|" "$work/config" > "$work/delegated-config"
    # The trusted supervisor places the process before it drops privileges.
    sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' sh "$scope/worker" \
        setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/delegated-config" \
        >"$work/delegated.out" 2>"$work/delegated.err" &
    pid=$!
    n=0
    while [ ! -S "$work/broker/broker.sock" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$work/delegated.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
    grep -q 'worker delegation initialized; compiler disabled' "$work/delegated.err"
    grep -qx "$pid" "$scope/worker/manager/cgroup.procs"
    mkdir "$scope/worker/preserved-task"
    sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; exec sleep 120' sh "$scope/worker/preserved-task" &
    task_pid=$!
    n=0
    while ! grep -qx "$task_pid" "$scope/worker/preserved-task/cgroup.procs"; do
        kill -0 "$task_pid"; n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
    kill -KILL "$pid"
    wait "$pid" 2>/dev/null || :
    pid=
    test "$(awk '$1 == "populated" {print $2}' "$scope/worker/preserved-task/cgroup.events")" = 1
    sh -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' sh "$scope/worker/manager" \
        setpriv --no-new-privs --reuid=1234 --regid=1234 --clear-groups \
        env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$daemon" --managed-config "$work/delegated-config" \
        >"$work/restarted.out" 2>"$work/restarted.err" &
    pid=$!
    n=0
    while ! setpriv --reuid=1236 --regid=1236 --clear-groups python3 - "$work/broker/broker.sock" <<'PY'
import socket, sys
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(1); s.connect(sys.argv[1]); assert s.recv(1) == b''
except (OSError, AssertionError):
    sys.exit(1)
PY
    do
        if ! kill -0 "$pid" 2>/dev/null; then cat "$work/restarted.err" >&2; exit 1; fi
        n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
    done
    grep -q 'worker delegation initialized; compiler disabled' "$work/restarted.err"
    grep -qx "$pid" "$scope/worker/manager/cgroup.procs"
    test -d "$scope/worker/preserved-task"
    kill -0 "$task_pid"
    test "$(awk '$1 == "populated" {print $2}' "$scope/worker/preserved-task/cgroup.events")" = 1
    kill -TERM "$pid"
    wait "$pid"
    pid=
    kill "$task_pid"
    wait "$task_pid" 2>/dev/null || :
    task_pid=
    rmdir "$scope/worker/preserved-task"
    rmdir "$scope/worker/manager" "$scope/worker"
fi
touch "$work/broker/broker.sock"
chown 1234:1234 "$work/broker/broker.sock"
if run_service >"$work/failure.out" 2>"$work/failure.err"; then exit 1; fi
grep -q 'broker startup failed' "$work/failure.err"
test -f "$work/broker/broker.sock"
test ! -e "$work/admin/admin.sock"
echo 'test-managed-service: PASS'
