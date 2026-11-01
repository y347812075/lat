#!/bin/sh
set -eu

# Build a pinned upstream archive without downloading or installing anything.
if [ "$#" -ne 2 ]; then
    echo "usage: $0 UPSTREAM_ARCHIVE OUTPUT_BINARY" >&2
    exit 2
fi
archive=$1
output=$2
expected=552cec9c79bb85c8ecd25ae3e55efca9af03390c17d829885ee45722dedada4f
test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = "$expected"
case "$output" in /*) ;; *) echo 'output must be absolute' >&2; exit 2 ;; esac
test ! -e "$output"
mkdir -p "$HOME/tmp"
work=$(mktemp -d "$HOME/tmp/latcd-bwrap-build.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/source"
tar -xzf "$archive" --strip-components=1 -C "$work/source"
patch -d "$work/source" -p1 <<'PATCH_END'
--- a/meson.build
+++ b/meson.build
@@ -68,6 +68,7 @@
-libcap_dep = dependency('libcap', required : true)
+libcap_dep = dependency('libcap', required : true, static : true)
 
 selinux_dep = dependency(
   'libselinux',
+  static : true,
   version : '>=2.1.9',
   # if disabled, Meson will behave as though libselinux was not found
PATCH_END
TMPDIR="$HOME/tmp" meson setup "$work/build" "$work/source" \
    -Dselinux=enabled -Dman=disabled -Dbash_completion=disabled \
    -Dzsh_completion=disabled -Dtests=false -Ddefault_library=static \
    -Dc_link_args=-static
TMPDIR="$HOME/tmp" ninja -C "$work/build"
grep -q '^#define HAVE_SELINUX 1$' "$work/build/config.h"
readelf -h "$work/build/bwrap" | grep -Eq 'Type:[[:space:]]+EXEC '
readelf -h "$work/build/bwrap" | grep -Eq 'Machine:[[:space:]]+LoongArch'
if readelf -l "$work/build/bwrap" | grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]'; then
    echo 'launcher has a dynamic loader or dynamic segment' >&2
    exit 1
fi
install -m 0755 "$work/build/bwrap" "$output"
sha256sum "$output"
