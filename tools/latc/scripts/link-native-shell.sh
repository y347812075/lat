#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 IMAGE OUTPUT" >&2
    exit 2
fi

image=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
case "$2" in
    /*) output=$2 ;;
    *) output=$(pwd)/$2 ;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
cc=${LATC_LA64_CC:-loongarch64-unknown-linux-gnu-gcc}
objcopy=${LATC_LA64_OBJCOPY:-loongarch64-unknown-linux-gnu-objcopy}
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-link.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

cp "$image" "$work/image.bin"
(
    cd "$work"
    "$objcopy" -I binary -O elf64-loongarch -B loongarch64 \
        --rename-section .data=.latc.image,alloc,load,readonly,data,contents \
        --redefine-sym _binary_image_bin_start=latc_embedded_image_start \
        --redefine-sym _binary_image_bin_end=latc_embedded_image_end \
        --redefine-sym _binary_image_bin_size=latc_embedded_image_size \
        image.bin image.o
)

"$cc" -O2 -g -fPIE -pie -Wall -Wextra -Werror -std=c11 \
    -I"$root/native/include" -I"$root/native/format" \
    -I"$root/native/runtime" \
    "$root/native/runtime/main.c" "$root/native/runtime/guest-loader.c" \
    "$root/native/runtime/relocate.c" \
    "$root/native/runtime/runtime-symbols.c" \
    "$root/native/runtime/dispatch.c" \
    "$root/native/format/native-image.c" \
    "$work/image.o" -o "$work/program"
chmod 0755 "$work/program"
mv "$work/program" "$output"
