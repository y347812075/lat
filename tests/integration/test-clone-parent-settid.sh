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
    -Wl,--build-id=none "$source_file" -o "$workdir/clone-parent-settid"

set +e
LATX_AOT=0 LATX_KZT=0 "$emulator" "$workdir/clone-parent-settid"
ret=$?
set -e

case $ret in
0)
    echo "PASS: fork-like clone wrote parent and child TID values"
    ;;
10)
    echo "FAIL: clone failed" >&2
    ;;
11)
    echo "FAIL: parent did not observe the child TID" >&2
    ;;
12)
    echo "FAIL: wait4 failed" >&2
    ;;
13)
    echo "FAIL: child exited abnormally" >&2
    ;;
14)
    echo "FAIL: child did not observe its TID" >&2
    ;;
15)
    echo "FAIL: invalid parent TID pointer did not return EFAULT" >&2
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
