#!/bin/sh
set -eu

emulator=$1
source_file=$2
arch=$3
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

host_cc=${HOST_CC:-cc}
if ! command -v "$host_cc" >/dev/null 2>&1; then
    echo "SKIP: native C compiler is required for the scheduling hook"
    exit 77
fi
if [ -n "${LATX_FSTAT_PROVIDER_GUEST_DIR:-}" ]; then
    guest=$LATX_FSTAT_PROVIDER_GUEST_DIR/procfs-fstat-provider-race-$arch
else
    cc=${X86_64_CC:-x86_64-linux-gnu-gcc}
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "SKIP: x86 compiler or prebuilt provider-race guests required"
        exit 77
    fi
    case $arch in
    x86_64) bits=-m64 ;;
    i386) bits=-m32 ;;
    *) exit 1 ;;
    esac
    guest=$workdir/provider-race
    "$cc" "$bits" -O2 -Wall -Wextra -Werror -static -pthread \
        "$source_file" -o "$guest"
fi
"$host_cc" -O2 -Wall -Wextra -Werror -shared -fPIC -pthread -DHOST_HOOK \
    "$source_file" -o "$workdir/provider-hook.so" -ldl
for mode in temporary source-rebind; do
    control=$workdir/$mode
    dd if=/dev/zero of="$control" bs=4096 count=1 2>/dev/null
    set +e
    timeout -s KILL 15 env TMPDIR=/tmp LATX_AOT=0 LATX_KZT=0 \
        LATX_FSTAT_PROVIDER_CONTROL="$control" \
        LD_PRELOAD="$workdir/provider-hook.so" \
        "$emulator" "$guest" "$control" "$mode"
    status=$?
    set -e
    if [ "$status" -eq 77 ]; then
        exit 77
    elif [ "$status" -ne 0 ]; then
        echo "FAIL: $arch fstat provider $mode" >&2
        exit 1
    fi
done
echo "PASS: $arch fstat provider preserves source and temporary fd identity"
