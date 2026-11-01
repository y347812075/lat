#!/bin/sh
set -eu
# Run inside a delegated user scope, with a disposable cache under ~/tmp.
binary=$1
work=$2
scope=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir "$scope/supervisor"
printf '%s\n' "$$" > "$scope/supervisor/cgroup.procs"
printf '%s\n' '+memory +pids' > "$scope/cgroup.subtree_control"
mkdir "$scope/worker" "$work/cache" "$work/cache/.tmp"
chmod 700 "$work/cache" "$work/cache/.tmp"
for name in input tbset configuration; do printf '%s' "$name" > "$work/cache/.tmp/$name"; done
if LATCD_TEST_JOURNAL_RECORD=1 LATCD_TEST_MANAGED_AFTER_PREPARE=1 \
    "$binary" --test-managed-task "$work/cache"; then
    echo 'expected PREPARED crash' >&2; exit 1
fi
state=$(find "$work/cache/.gc/managed-task-state" -name '*.ini')
grep -qx 'state=PREPARED' "$state"
for attempt in 1 2; do
    target=$scope/worker
    if [ "$attempt" = 2 ]; then target=$scope/worker/manager; fi
    LATCD_TEST_RECOVERY_BUDGET=1 LATCD_TEST_RECOVERY_ONCE=1 sh -c '
        printf "%s\n" "$$" > "$1/cgroup.procs"; shift
        exec "$@"
    ' sh "$target" "$binary" --test-managed-recovery "$work/cache" "$scope/worker"
    grep -qx 'state=PREEXEC_CANCELLED' "$state"
done
rmdir "$scope/worker/manager" "$scope/worker"
