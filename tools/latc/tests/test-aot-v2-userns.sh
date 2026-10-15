#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 RUNNER WORKDIR" >&2
    exit 2
fi
runner=$1
work=$2
exec_guest=${LATC_USERNS_EXEC_GUEST:-}
nested_guest=${LATC_USERNS_NESTED_GUEST:-}
if ! unshare -Ur true 2>/dev/null; then
    echo "SKIP: unprivileged user namespaces unavailable"
    exit 77
fi
mkdir -p "$work/cache" "$work/home"
sources=$(CDPATH= cd -- "$(dirname "$0")/../../../tests/integration" && pwd)
if [ -z "$exec_guest" ] || [ -z "$nested_guest" ]; then
    if command -v clang-19 >/dev/null 2>&1; then
        clang=clang-19
    elif command -v clang >/dev/null 2>&1; then
        clang=clang
    else
        echo "SKIP: clang is required to build x86 namespace fixtures"
        exit 77
    fi
fi
if [ -z "$exec_guest" ]; then
    exec_guest=$work/cef-userns-exec
    "$clang" --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
        -Wl,--build-id=none "$sources/cef-userns-exec.S" -o "$exec_guest"
fi
if [ -z "$nested_guest" ]; then
    nested_guest=$work/cef-userns-nested
    "$clang" --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
        -Wl,--build-id=none "$sources/cef-userns-nested.S" -o "$nested_guest"
fi
test -f "$exec_guest" -a -f "$nested_guest"
for mode in 0 1; do
    for name in exec nested; do
        guest=$exec_guest
        if [ "$name" = nested ]; then
            guest=$nested_guest
        fi
        env SBX_USER_NS=1 LATX_AOT=0 LATX_AOT_V2="$mode" \
            HOME="$work/home" LATX_AOT_V2_AUTOSTART=0 \
            LATX_AOT_V2_CACHE_DIR="$work/cache" \
            LATX_AOT_V2_LATCD_SOCKET="$work/unavailable.sock" \
            timeout -k 2s 30s "$runner" "$guest" \
            >"$work/$name-$mode.stdout" 2>"$work/$name-$mode.stderr"
    done
done
echo "test-aot-v2-userns: PASS (JIT/AOT exec and nested namespaces)"
