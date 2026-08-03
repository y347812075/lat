#!/bin/sh
set -eu

emulator=$(readlink -f "$1")
source_file=$(readlink -f "$2")
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
    -Wl,--build-id=none "$source_file" -o "$workdir/guest-fatal-signal-status"

set +e
(
    cd "$workdir"
    ulimit -c 0
    LATX_AOT=0 LATX_KZT=0 "$emulator" ./guest-fatal-signal-status
)
ret=$?
set -e

case $ret in
0)
    echo "PASS: guest fatal signals preserved parent-visible wait status"
    ;;
11|12|13)
    echo "FAIL: SIGSEGV case failed at stage $((ret - 10))" >&2
    ;;
21|22|23)
    echo "FAIL: SIGSYS case failed at stage $((ret - 20))" >&2
    ;;
31|32|33)
    echo "FAIL: SIGABRT case failed at stage $((ret - 30))" >&2
    ;;
41|42|43)
    echo "FAIL: re-raised SIGSEGV case failed at stage $((ret - 40))" >&2
    ;;
*)
    echo "FAIL: unexpected guest exit status $ret" >&2
    ;;
esac

exit "$ret"
