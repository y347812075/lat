#!/bin/sh
set -eu
emulator=$1
source_file=$2
arch=$3
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM
if [ -n "${LATX_CLOSE_PROGRESS_GUEST_DIR:-}" ]; then
    guest=$LATX_CLOSE_PROGRESS_GUEST_DIR/close-linger-progress-$arch
else
    cc=${X86_64_CC:-x86_64-linux-gnu-gcc}
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "SKIP: x86 compiler or prebuilt close-progress guests required"
        exit 77
    fi
    case $arch in
    x86_64) bits=-m64 ;;
    i386) bits=-m32 ;;
    *) exit 1 ;;
    esac
    guest=$workdir/close-linger-progress
    "$cc" "$bits" -O2 -Wall -Wextra -Werror -static -pthread \
        "$source_file" -o "$guest"
fi
for operation in close dup2 dup3; do
    for observer in none fstat fork both; do
        if ! timeout -s KILL 15 env LATX_AOT=0 LATX_KZT=0 \
            "$emulator" "$guest" "$operation" "$observer"; then
            echo "FAIL: $arch $operation/$observer close progress" >&2
            exit 1
        fi
    done
done
if ! timeout -s KILL 15 env LATX_AOT=0 LATX_KZT=0 \
    "$emulator" "$guest" close reuse; then
    echo "FAIL: $arch close progress after descriptor reuse" >&2
    exit 1
fi
echo "PASS: $arch peer close progresses with waiting identity queries and fork"
