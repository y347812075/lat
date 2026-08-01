#!/bin/sh
set -eu

emulator=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
source_file=$2
pidfd_runner=$3
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

if ! command -v unshare >/dev/null 2>&1 ||
   ! unshare -Urm true 2>/dev/null; then
    echo "SKIP: unprivileged user and mount namespaces are unavailable"
    exit 77
fi

compile_guest()
{
    output=$1
    shift
    "$clang" --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
        -Wl,--build-id=none "$@" "$source_file" -o "$output"
}

run_invalid_fd_case()
{
    guest="$workdir/setns-invalid-fd"

    compile_guest "$guest" -DSETNS_FLAGS=0 -DSETNS_FD=-1 \
        -DEXPECT_SETNS_ERRNO=9
    LATX_AOT=0 LATX_KZT=0 "$emulator" "$guest"
    echo "PASS: invalid namespace fd returned EBADF"
}

run_pidfd_case()
{
    guest="$workdir/setns-ipc-pidfd"

    if ! command -v python3 >/dev/null 2>&1 ||
       ! python3 -c 'import os; fd = os.pidfd_open(os.getpid()); os.close(fd)';
    then
        echo "SKIP: pidfd support is unavailable"
        return
    fi

    compile_guest "$guest" -DSETNS_FLAGS=134217728 -DSETNS_ONLY=1
    unshare -Ur sh -eu -c '
        emulator=$1
        guest=$2
        pidfd_runner=$3

        unshare -i sh -c "exec sleep 300" &
        holder=$!
        current_ipc=$(readlink /proc/self/ns/ipc)
        namespace_ready=false
        attempts=0
        while [ "$attempts" -lt 100 ]; do
            if [ -r "/proc/$holder/ns/ipc" ] &&
               [ "$(readlink "/proc/$holder/ns/ipc")" != "$current_ipc" ]; then
                namespace_ready=true
                break
            fi
            attempts=$((attempts + 1))
            sleep 0.01
        done
        if [ "$namespace_ready" != true ]; then
            kill "$holder" 2>/dev/null || true
            wait "$holder" 2>/dev/null || true
            echo "FAIL: pidfd IPC namespace holder did not start" >&2
            exit 30
        fi

        set +e
        "$pidfd_runner" "$holder" "$emulator" "$guest"
        ret=$?
        set -e
        kill "$holder" 2>/dev/null || true
        wait "$holder" 2>/dev/null || true
        if [ "$ret" -ne 0 ]; then
            echo "FAIL: pidfd setns guest exited with status $ret" >&2
            exit "$ret"
        fi
        echo "PASS: pidfd joined the IPC namespace"
    ' sh "$emulator" "$guest" "$pidfd_runner"
}

if command -v clang-19 >/dev/null 2>&1; then
    clang=clang-19
elif command -v clang >/dev/null 2>&1; then
    clang=clang
else
    echo "SKIP: clang is required to build the x86_64 guest"
    exit 77
fi

run_case()
{
    setns_flags=$1
    case_name=$2
    guest="$workdir/setns-ipc-mqueue-$case_name"
    mkdir "$workdir/$case_name"

    compile_guest "$guest" -DSETNS_FLAGS="$setns_flags"

    unshare -Urm sh -eu -c '
        emulator=$1
        guest=$2
        case_name=$3
        workdir=$4
        cd "$workdir"
        mkdir mqueue
        mount --make-rprivate /
        trap "umount mqueue 2>/dev/null || true" EXIT HUP INT TERM

        unshare -i sh -c "exec sleep 300" &
        holder=$!
        current_ipc=$(readlink /proc/self/ns/ipc)
        namespace_ready=false
        attempts=0
        while [ "$attempts" -lt 100 ]; do
            if [ -r "/proc/$holder/ns/ipc" ] &&
               [ "$(readlink "/proc/$holder/ns/ipc")" != "$current_ipc" ]; then
                namespace_ready=true
                break
            fi
            attempts=$((attempts + 1))
            sleep 0.01
        done
        if [ "$namespace_ready" != true ]; then
            kill "$holder" 2>/dev/null || true
            wait "$holder" 2>/dev/null || true
            echo "FAIL: IPC namespace holder did not start" >&2
            exit 30
        fi

        exec 9<"/proc/$holder/ns/ipc"
        kill "$holder"
        wait "$holder" 2>/dev/null || true

        LATX_AOT=1 LATX_KZT=0 "$emulator" "$guest" &
        emulator_pid=$!
        exec 9<&-
        wait "$emulator_pid" || {
            ret=$?
            echo "FAIL: $case_name guest exited with status $ret" >&2
            exit "$ret"
        }

        if touch mqueue/MQ2 2>/dev/null; then
            echo "FAIL: $case_name left the IPC namespace alive" >&2
            exit 40
        fi
        echo "PASS: $case_name released the IPC namespace"
    ' sh "$emulator" "$guest" "$case_name" "$workdir/$case_name"
}

run_invalid_fd_case
run_pidfd_case
run_case 134217728 explicit-CLONE_NEWIPC
run_case 0 inferred-from-fd
