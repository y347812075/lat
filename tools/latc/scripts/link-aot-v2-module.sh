#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 LATC NATIVE_IMAGE RUNTIME_DIRECTORY OUTPUT" >&2
    exit 2
fi

latc=$1
native_image=$2
runtime_dir=$3
output=$4
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
include_dir=$(dirname "$script_dir")/aot-v2/include
case "$runtime_dir" in /*) ;; *) runtime_dir="$(pwd)/$runtime_dir";; esac
case "$output" in /*) ;; *) output="$(pwd)/$output";; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-aot-v2-link.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$latc" emit-aot-v2 "$native_image" "$work" >/dev/null
(
    cd "$work"
    "${CC:-cc}" -I"$include_dir" -O2 -fPIC -c -o module-meta.o module.c
    "${CC:-cc}" -I"$include_dir" -fPIC -c -o module-text.o module.S
    "${CC:-cc}" -shared -nostdlib \
      -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
      -Wl,--unique=.text.lat.tu -Wl,--unique=.rodata.lat.tb \
      -Wl,--unique=.rodata.lat.guest \
      -Wl,--unique=.data.rel.ro.lat.module \
      -Wl,--version-script="$script_dir/../aot-v2/tests/module.map" \
      -Wl,--build-id=sha1 -L"$runtime_dir" -Wl,--no-as-needed \
      -l:liblat-aot-runtime.so.2 -o "$output" module-meta.o module-text.o
)
