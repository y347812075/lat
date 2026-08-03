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
    -Wl,--build-id=none "$source_file" -o "$workdir/seccomp-errno-restart"

set +e
timeout 10s env LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$workdir/seccomp-errno-restart"
ret=$?
set -e

case $ret in
0) echo "PASS: seccomp errno 512 was returned without restarting" ;;
10) echo "FAIL: PR_SET_NO_NEW_PRIVS failed" >&2 ;;
11) echo "FAIL: seccomp filter installation failed" >&2 ;;
12) echo "FAIL: seccomp errno 512 was not returned to the guest" >&2 ;;
124) echo "FAIL: seccomp errno 512 restarted the syscall" >&2 ;;
*) echo "FAIL: unexpected guest exit status $ret" >&2 ;;
esac

exit "$ret"
