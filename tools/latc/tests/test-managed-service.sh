#!/bin/sh
set -eu

# Run only in a disposable container with an empty /opt/latcd-managed-test.
if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: $0 LATCD FIXTURE RUNTIME (root in disposable container)" >&2
    exit 2
fi
daemon=$1
fixture=$2
runtime=$3
work=/opt/latcd-managed-test
test ! -e "$work"
mkdir -m 755 "$work" "$work/tools" "$work/runtime"
mkdir -m 700 "$work/cache" "$work/admin"
mkdir -m 755 "$work/broker"
chown 1234:1234 "$work/cache" "$work/admin" "$work/broker"
cp "$fixture" "$work/tools/latc"
cp "$fixture" "$work/tools/runner"
cp "$runtime" "$work/runtime/liblat-aot-runtime.so.2"
chmod 755 "$work/tools/latc" "$work/tools/runner"
printf '%s\n' '{"service_uid":"1234","client_uid":"1235","cache":"/opt/latcd-managed-test/cache","admin":"/opt/latcd-managed-test/admin","broker":"/opt/latcd-managed-test/broker","compiler":"/opt/latcd-managed-test/tools/latc","runner":"/opt/latcd-managed-test/tools/runner","runtime":"/opt/latcd-managed-test/runtime"}' > "$work/config"
pid=
cleanup() {
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
kill -TERM "$pid"
wait "$pid"
pid=
test ! -e "$work/admin/admin.sock"
test ! -e "$work/broker/broker.sock"
touch "$work/broker/broker.sock"
chown 1234:1234 "$work/broker/broker.sock"
if run_service >"$work/failure.out" 2>"$work/failure.err"; then exit 1; fi
grep -q 'broker startup failed' "$work/failure.err"
test -f "$work/broker/broker.sock"
test ! -e "$work/admin/admin.sock"
echo 'test-managed-service: PASS'
