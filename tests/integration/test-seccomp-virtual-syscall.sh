#!/bin/sh
set -eu

emulator=$1
source_file=$2
target=${3:-x86_64}
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

"$clang" --target="$target-linux-gnu" -fuse-ld=lld -nostdlib -static \
    -Wl,--build-id=none "$source_file" -o "$workdir/seccomp-virtual-syscall"

set +e
timeout 10s env LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$workdir/seccomp-virtual-syscall"
ret=$?
set -e

case $ret in
0) echo "PASS: guest syscall 600 follows native seccomp semantics" ;;
10) echo "FAIL: unfiltered syscall 600 did not return ENOSYS" >&2 ;;
11) echo "FAIL: PR_SET_NO_NEW_PRIVS failed" >&2 ;;
12) echo "FAIL: seccomp filter installation failed" >&2 ;;
13) echo "FAIL: seccomp did not filter guest syscall 600" >&2 ;;
14) echo "FAIL: readable guest string bypassed syscall 600 filter" >&2 ;;
15) echo "FAIL: copied loader marker bypassed syscall 600 filter" >&2 ;;
124) echo "FAIL: guest syscall 600 test timed out" >&2 ;;
*) echo "FAIL: unexpected guest exit status $ret" >&2 ;;
esac

exit "$ret"
