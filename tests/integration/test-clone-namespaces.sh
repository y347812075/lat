#!/bin/sh
set -eu

emulator=$1
source_file=$2
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

if ! command -v unshare >/dev/null 2>&1 || ! unshare -Ur true 2>/dev/null; then
    echo "SKIP: unprivileged user namespaces are unavailable"
    exit 77
fi

if command -v clang-19 >/dev/null 2>&1; then
    clang=clang-19
elif command -v clang >/dev/null 2>&1; then
    clang=clang
else
    echo "SKIP: clang is required to build the x86_64 guest"
    exit 77
fi

"$clang" --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
    -Wl,--build-id=none "$source_file" -o "$workdir/clone-namespaces"

set +e
LATX_AOT=0 LATX_KZT=0 "$emulator" "$workdir/clone-namespaces"
ret=$?
set -e

case $ret in
0)
    echo "PASS: clone created distinct mount, IPC, and UTS namespaces"
    ;;
10)
    echo "FAIL: parent namespace stat failed" >&2
    ;;
20)
    echo "FAIL: combined namespace clone failed" >&2
    ;;
30)
    echo "FAIL: child namespace stat failed" >&2
    ;;
31)
    echo "FAIL: mount namespace was not created" >&2
    ;;
32)
    echo "FAIL: IPC namespace was not created" >&2
    ;;
33)
    echo "FAIL: UTS namespace was not created" >&2
    ;;
40)
    echo "FAIL: wait4 failed" >&2
    ;;
41)
    echo "FAIL: namespace child was killed by a signal" >&2
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
