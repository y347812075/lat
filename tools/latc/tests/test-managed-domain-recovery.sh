#!/bin/sh
set -eu
# Run in a disposable container with a writable delegated cgroup and /work.
binary=$1
scope=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir "$scope/supervisor"
printf '%s\n' "$$" > "$scope/supervisor/cgroup.procs"
printf '%s\n' '+memory +pids' > "$scope/cgroup.subtree_control"
mkdir "$scope/worker" /work/cache /work/cache/.tmp
chmod 700 /work/cache /work/cache/.tmp
printf input > /work/cache/.tmp/input
mkfifo /work/gate
exec 3<>/work/gate
LATCD_TEST_DELEGATION="$scope/worker" sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker" "$binary" --test-managed-task /work/cache </work/gate >/work/id 2>/work/first.err &
pid=$!
n=0
while [ ! -s /work/id ]; do
    kill -0 "$pid" || { cat /work/first.err >&2; exit 1; }
    n=$((n + 1)); [ "$n" -lt 200 ]; sleep 0.05
done
id=$(cat /work/id)
state=/work/cache/.gc/managed-task-state/$id.ini
grep -qx 'state=EXEC_AUTHORIZED' "$state"
test "$(awk '$1 == "populated" {print $2}' "$scope/worker/$id/cgroup.events")" = 1
kill -KILL "$pid"
wait "$pid" 2>/dev/null || :
cp "$state" /work/original-state
sed -i 's/^boot=.*/boot=00000000-0000-0000-0000-000000000000/' "$state"
if LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/cache "$scope/worker"; then
    echo 'mismatched boot accepted during recovery' >&2; exit 1
fi
grep -qx 'state=EXEC_AUTHORIZED' "$state"
test "$(awk '$1 == "populated" {print $2}' "$scope/worker/$id/cgroup.events")" = 1
cp /work/original-state "$state"
LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/cache "$scope/worker"
grep -qx 'state=CANCELLED_DOMAIN_EMPTY' "$state"
test "$(awk '$1 == "populated" {print $2}' "$scope/worker/$id/cgroup.events")" = 0
test -f "/work/cache/.gc/tasks/$id.ini"
test -f "/work/cache/.gc/compiler-budgets/$id.ini"
test ! -e "/work/cache/.gc/compiler-releases/$id.ini"
printf invalid > /work/cache/.gc/tasks/not-a-task
if LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/cache "$scope/worker"; then
    echo 'unknown task record accepted during recovery' >&2; exit 1
fi
rm /work/cache/.gc/tasks/not-a-task
bad_task=/work/cache/.gc/tasks/00000000-0000-0000-0000-000000000000.ini
printf '[task]\nversion=1\n' > "$bad_task"
chmod 400 "$bad_task"
if LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/cache "$scope/worker"; then
    echo 'malformed legacy task record accepted during recovery' >&2; exit 1
fi
rm "$bad_task"
rmdir "$scope/worker/$id" "$scope/worker/manager" "$scope/worker"
mkdir "$scope/worker" /work/unbound-cache /work/unbound-cache/.tmp
chmod 700 /work/unbound-cache /work/unbound-cache/.tmp
printf input > /work/unbound-cache/.tmp/input
if LATCD_TEST_KILL_AFTER_DOMAIN_CREATE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker" "$binary" --test-managed-compiler /work/unbound-cache "$scope/worker"; then
    echo 'expected crash after domain creation' >&2; exit 1
fi
state=$(find /work/unbound-cache/.gc/managed-task-state -name '*.ini')
grep -qx 'state=DELEGATION_BOUND' "$state"
grep -qx "boot=$(cat /proc/sys/kernel/random/boot_id)" "$state"
grep -qx "delegation_device=$(stat -c %d "$scope/worker")" "$state"
grep -qx "delegation_inode=$(stat -c %i "$scope/worker")" "$state"
id=$(basename "$state" .ini)
test -d "$scope/worker/$id"
cp "$state" /work/unbound-original-state
sed -i 's/^boot=.*/boot=00000000-0000-0000-0000-000000000000/' "$state"
if LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/unbound-cache "$scope/worker"; then
    echo 'unbound domain with mismatched boot accepted' >&2; exit 1
fi
grep -qx 'state=DELEGATION_BOUND' "$state"
cp /work/unbound-original-state "$state"
LATCD_TEST_RECOVERY_BUDGET=1 LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/unbound-cache "$scope/worker"
grep -qx 'state=PREEXEC_CANCELLED' "$state"
test -d "$scope/worker/$id"
LATCD_TEST_RECOVERY_BUDGET=1 LATCD_TEST_RECOVERY_ONCE=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/unbound-cache "$scope/worker"
grep -qx 'state=PREEXEC_CANCELLED' "$state"
test -f "/work/unbound-cache/.gc/compiler-budgets/$id.ini"
test ! -e "/work/unbound-cache/.gc/compiler-releases/$id.ini"
rmdir "$scope/worker/$id" "$scope/worker/manager" "$scope/worker"
mkdir "$scope/worker" /work/compile-cache /work/compile-cache/.tmp
chmod 700 /work/compile-cache /work/compile-cache/.tmp
printf input > /work/compile-cache/.tmp/input
if LATCD_TEST_DOMAIN_DESCENDANT=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker" "$binary" --test-managed-compiler /work/compile-cache "$scope/worker"; then
    echo 'worker with surviving descendant returned success' >&2; exit 1
fi
state=$(find /work/compile-cache/.gc/managed-task-state -name '*.ini')
id=$(basename "$state" .ini)
grep -qx 'state=CANCELLED_DOMAIN_EMPTY' "$state"
test "$(awk '$1 == "populated" {print $2}' "$scope/worker/$id/cgroup.events")" = 0
test -f "/work/compile-cache/.gc/compiler-budgets/$id.ini"
test ! -e "/work/compile-cache/.gc/compiler-releases/$id.ini"
rmdir "$scope/worker/$id" "$scope/worker/manager" "$scope/worker"
mkdir "$scope/worker" /work/success-cache /work/success-cache/.tmp
chmod 700 /work/success-cache /work/success-cache/.tmp
printf input > /work/success-cache/.tmp/input
sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker" "$binary" --test-managed-compiler /work/success-cache "$scope/worker" >/work/success-id
id=$(cat /work/success-id)
grep -qx 'state=DOMAIN_EMPTY' "/work/success-cache/.gc/managed-task-state/$id.ini"
rmdir "$scope/worker/$id" "$scope/worker/manager" "$scope/worker"
mkdir "$scope/worker" /work/crash-cache /work/crash-cache/.tmp
chmod 700 /work/crash-cache /work/crash-cache/.tmp
printf input > /work/crash-cache/.tmp/input
if LATCD_TEST_KILL_BEFORE_AUTH=1 sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker" "$binary" --test-managed-compiler /work/crash-cache "$scope/worker"; then
    echo 'expected pre-authorization crash' >&2; exit 1
fi
state=$(find /work/crash-cache/.gc/managed-task-state -name '*.ini')
grep -qx 'state=DOMAIN_BOUND' "$state"
id=$(basename "$state" .ini)
sh -c '
    printf "%s\n" "$$" > "$1/cgroup.procs"; shift
    exec "$@"
' sh "$scope/worker/manager" "$binary" --test-managed-recovery /work/crash-cache "$scope/worker"
grep -qx 'state=CANCELLED_DOMAIN_EMPTY' "$state"
test "$(awk '$1 == "populated" {print $2}' "$scope/worker/$id/cgroup.events")" = 0
rmdir "$scope/worker/$id" "$scope/worker/manager" "$scope/worker"
echo 'test-managed-domain-recovery: PASS'
