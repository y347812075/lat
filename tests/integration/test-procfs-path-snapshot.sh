#!/bin/sh
set -eu

emulator=$1
source_file=$2
arch=$3
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

if [ -n "${LATX_PATH_SNAPSHOT_GUEST_DIR:-}" ]; then
    guest=$LATX_PATH_SNAPSHOT_GUEST_DIR/procfs-path-snapshot-$arch
else
    cc=${X86_64_CC:-x86_64-linux-gnu-gcc}
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "SKIP: x86 Linux compiler or prebuilt snapshot guests required"
        exit 77
    fi
    case $arch in
    x86_64) bits=-m64 ;;
    i386) bits=-m32 ;;
    *) exit 1 ;;
    esac
    guest=$workdir/procfs-path-snapshot
    "$cc" "$bits" -O2 -Wall -Wextra -Werror -static -pthread \
        "$source_file" -o "$guest"
fi

for mode in fstatat statx; do
    if ! LATX_AOT=0 LATX_KZT=0 timeout -s KILL 30 \
        "$emulator" "$guest" "$mode"; then
        echo "FAIL: $arch $mode pathname snapshot" >&2
        exit 1
    fi
done
echo "PASS: $arch stat-family pathname snapshots"
