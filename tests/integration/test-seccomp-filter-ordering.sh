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
    -Wl,--build-id=none "$source_file" \
    -o "$workdir/seccomp-filter-ordering"

set +e
LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$workdir/seccomp-filter-ordering"
ret=$?
set -e

case $ret in
0)
    echo "PASS: seccomp filter validation follows Linux ordering"
    ;;
10)
    echo "FAIL: invalid seccomp flags did not return EINVAL" >&2
    ;;
11)
    echo "FAIL: prctl null program before NNP did not return EFAULT" >&2
    ;;
12)
    echo "FAIL: seccomp null program before NNP did not return EFAULT" >&2
    ;;
13)
    echo "FAIL: TSYNC null program before NNP did not return EFAULT" >&2
    ;;
14)
    echo "FAIL: zero-length program before NNP did not return EINVAL" >&2
    ;;
15)
    echo "FAIL: null filter before NNP did not return EACCES" >&2
    ;;
16)
    echo "FAIL: invalid filter before NNP did not return EACCES" >&2
    ;;
17)
    echo "FAIL: PR_SET_NO_NEW_PRIVS failed" >&2
    ;;
18)
    echo "FAIL: prctl null program after NNP did not return EFAULT" >&2
    ;;
19)
    echo "FAIL: seccomp null program after NNP did not return EFAULT" >&2
    ;;
20)
    echo "FAIL: null filter after NNP did not return EINVAL" >&2
    ;;
21)
    echo "FAIL: invalid filter after NNP did not return EINVAL" >&2
    ;;
22)
    echo "FAIL: TSYNC filter installation failed" >&2
    ;;
23)
    echo "FAIL: PR_GET_SECCOMP did not report filter mode" >&2
    ;;
24)
    echo "FAIL: prctl filter installation failed" >&2
    ;;
25)
    echo "FAIL: bad filter pointer before NNP did not return EACCES" >&2
    ;;
26)
    echo "FAIL: bad filter pointer after NNP did not return EFAULT" >&2
    ;;
77)
    echo "SKIP: no_new_privs was already enabled"
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
