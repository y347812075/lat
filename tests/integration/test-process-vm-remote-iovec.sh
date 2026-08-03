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
    -Wl,--build-id=none "$source_file" -o "$workdir/process-vm-remote-iovec"

set +e
timeout 10s env LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$workdir/process-vm-remote-iovec"
ret=$?
set -e

case $ret in
0) echo "PASS: process_vm remote mappings and guest page boundaries work" ;;
10) echo "FAIL: pipe failed" >&2 ;;
11) echo "FAIL: clone failed" >&2 ;;
12) echo "FAIL: parent did not receive the remote address" >&2 ;;
13) echo "FAIL: process_vm_readv could not read the remote mapping" >&2 ;;
14) echo "FAIL: process_vm_writev could not write the remote mapping" >&2 ;;
15) echo "FAIL: parent could not wake the child" >&2 ;;
16) echo "FAIL: wait4 failed" >&2 ;;
17) echo "FAIL: child exited abnormally" >&2 ;;
18) echo "FAIL: protected-range mmap failed" >&2 ;;
19) echo "FAIL: protected-range mprotect failed" >&2 ;;
20) echo "FAIL: child mmap failed" >&2 ;;
21) echo "FAIL: child could not publish the remote address" >&2 ;;
22) echo "FAIL: child synchronization failed" >&2 ;;
23) echo "FAIL: child did not observe the remote write" >&2 ;;
24) echo "FAIL: remote write crossed the guest page boundary" >&2 ;;
25) echo "FAIL: remote write accepted a protected guest page" >&2 ;;
124) echo "FAIL: process_vm remote iovec test timed out" >&2 ;;
*) echo "FAIL: unexpected guest exit status $ret" >&2 ;;
esac

exit "$ret"
