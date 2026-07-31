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
    -Wl,--build-id=none "$source_file" -o "$workdir/rcu-thread-visibility"

set +e
LATX_AOT=0 LATX_KZT=0 "$emulator" "$workdir/rcu-thread-visibility"
ret=$?
set -e

case $ret in
0)
    echo "PASS: no internal LATX thread is visible through getpgid"
    ;;
10)
    echo "FAIL: an internal LATX thread is visible through getpgid" >&2
    ;;
11)
    echo "FAIL: process-group setup failed" >&2
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
