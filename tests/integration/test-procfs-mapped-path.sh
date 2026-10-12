#!/bin/sh
set -eu

emulator=$1
source_file=$2
arch=$3
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

if ! command -v unshare >/dev/null 2>&1 || ! unshare -Ur true 2>/dev/null; then
    echo "SKIP: unprivileged user namespaces are unavailable"
    exit 77
fi

if [ -n "${LATX_MAPPED_PATH_GUEST_DIR:-}" ]; then
    guest=$LATX_MAPPED_PATH_GUEST_DIR/procfs-mapped-path-$arch
else
    cc=${X86_64_CC:-x86_64-linux-gnu-gcc}
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "SKIP: x86 Linux compiler or prebuilt mapped-path guests required"
        exit 77
    fi
    case $arch in
    x86_64) bits=-m64 ;;
    i386) bits=-m32 ;;
    *) exit 1 ;;
    esac
    guest=$workdir/procfs-mapped-path
    "$cc" "$bits" -O2 -Wall -Wextra -Werror -static -pthread \
        "$source_file" -o "$guest"
fi

for mode in fstatat statx; do
  for memory in mapped guard; do
    if ! unshare -Ur timeout -s KILL 30 env LATX_AOT=0 LATX_KZT=0 \
        "$emulator" "$guest" "$mode" "$memory"; then
        echo "FAIL: $arch $mode $memory pathname snapshot" >&2
        exit 1
    fi
  done
done
echo "PASS: $arch mapped and guarded pathname snapshots"
