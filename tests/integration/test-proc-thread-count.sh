#!/bin/sh
set -eu

emulator=$1
source_file=$2
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

if command -v clang-19 >/dev/null 2>&1; then
    clang=clang-19
elif command -v clang >/dev/null 2>&1; then
    clang=clang
else
    echo "SKIP: clang is required to build the x86_64 guest"
    exit 77
fi

"$clang" --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
    -Wl,--build-id=none "$source_file" -o "$workdir/proc-thread-count"

set +e
LATX_AOT=0 LATX_KZT=0 "$emulator" "$workdir/proc-thread-count"
ret=$?
set -e

case $ret in
0)
    echo "PASS: procfs reports only guest threads after helper startup"
    ;;
10)
    echo "FAIL: guest thread clone failed" >&2
    ;;
11)
    echo "FAIL: live guest thread count was not two" >&2
    ;;
12)
    echo "FAIL: stopped guest thread remained visible in /proc/self/stat" >&2
    ;;
13)
    echo "FAIL: stat(/proc/self/task) did not report one guest thread" >&2
    ;;
14)
    echo "FAIL: fstatat(/proc/self/task) did not report one guest thread" >&2
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
