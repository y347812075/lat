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
    -Wl,--build-id=none "$source_file" -o "$workdir/seccomp-ptrace-trace"

set +e
timeout 10s env LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$workdir/seccomp-ptrace-trace"
ret=$?
set -e

case $ret in
0) echo "PASS: seccomp trace event and register rewrite completed" ;;
10) echo "FAIL: clone failed" >&2 ;;
11|12) echo "FAIL: initial ptrace stop failed" >&2 ;;
13) echo "FAIL: PTRACE_SETOPTIONS failed" >&2 ;;
14) echo "FAIL: PTRACE_CONT failed" >&2 ;;
15|16) echo "FAIL: seccomp trace wait status was incorrect" >&2 ;;
17) echo "FAIL: PTRACE_GETEVENTMSG failed" >&2 ;;
18) echo "FAIL: PTRACE_GETREGS failed" >&2 ;;
19) echo "FAIL: PTRACE_SETREGS failed" >&2 ;;
20|21) echo "FAIL: traced child did not exit successfully" >&2 ;;
30) echo "FAIL: child PTRACE_TRACEME failed" >&2 ;;
31) echo "FAIL: child PR_SET_NO_NEW_PRIVS failed" >&2 ;;
32) echo "FAIL: child seccomp filter installation failed" >&2 ;;
33) echo "FAIL: child did not receive the rewritten result" >&2 ;;
124) echo "FAIL: seccomp ptrace trace test timed out" >&2 ;;
*) echo "FAIL: unexpected guest exit status $ret" >&2 ;;
esac

exit "$ret"
