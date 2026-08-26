#!/bin/sh
set -eu

if [ "$#" -ne 8 ]; then
    echo "usage: $0 LATC RUNNER RUNTIME_DIR ROOTFS MAIN PLUGIN WORKDIR TIMEOUT" >&2
    exit 2
fi

latc=$1
runner=$2
runtime_dir=$3
rootfs=$4
guest=$5
plugin=$6
work=$7
run_timeout=$8
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
rm -rf "$work"
mkdir -p "$work/empty-cache" "$work/hot-cache"

interp=$(readlink -f "$rootfs/lib64/ld-linux-x86-64.so.2")
libc=$(readlink -f "$rootfs/lib/x86_64-linux-gnu/libc.so.6")
test -f "$interp" -a -f "$libc"
cp "$plugin" /tmp/latc-m3-dlopen-plugin.so
trap 'rm -f /tmp/latc-m3-dlopen-plugin.so' EXIT HUP INT TERM

compile_module()
{
    source=$1
    output=$2
    profile=${3:-}
    if [ -n "$profile" ]; then
        set -- "$profile"
    else
        set --
    fi
    LD_LIBRARY_PATH="$runtime_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    LAT_LD_PREFIX="$rootfs" \
      "$script_dir/../scripts/compile-aot-v2-module.sh" \
      "$latc" "$runner" "$source" "$runtime_dir" "$output" "$@" >/dev/null
    sha=$(sha256sum "$source" | awk '{print $1}')
    cp "$output" "$work/hot-cache/$sha.so"
}

plugin_pc=$(nm -D "$plugin" | awk '$3 == "latc_plugin_apply" { print "0x" $1; exit }')
test -n "$plugin_pc"
printf '%s 1\n' "$plugin_pc" >"$work/plugin.profile"
compile_module "$plugin" "$work/plugin.so" "$work/plugin.profile"
compile_module "$guest" "$work/main.so"
compile_module "$interp" "$work/interp.so"
compile_module "$libc" "$work/libc.so"

run_guest()
{
    cache=$1
    output=$2
    error=$3
    shift 3
    env LD_LIBRARY_PATH="$runtime_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      LATX_AOT=0 LATX_AOT_V2_CACHE_DIR="$cache" \
      LATX_AOT_V2_REPORT=1 \
      "$@" timeout -k 2s "$run_timeout" "$runner" -L "$rootfs" \
      "$guest" >"$output" 2>"$error"
}

printf 'dlopen loads=100 result=40 moved=1\n' >"$work/expected"
run_guest "$work/empty-cache" "$work/cold.out" "$work/cold.err"
cmp "$work/expected" "$work/cold.out"
test "$(grep -c 'discovered ELF.*module=missing' "$work/cold.err")" -eq 103

run_guest "$work/hot-cache" "$work/hot.out" "$work/hot.err"
cmp "$work/expected" "$work/hot.out"
test "$(grep -c 'discovered ELF.*module=registered' "$work/hot.err")" -eq 103
test "$(grep -Ec 'module=(registered|inactive) aot_lookups=[1-9][0-9]*' \
  "$work/hot.err")" -eq 103
plugin_sha=$(sha256sum "$plugin" | awk '{print $1}')
grep -Eq "module stats source=$plugin_sha .*module=inactive aot_lookups=[1-9]" \
  "$work/hot.err"
test "$(grep -Ec "module stats source=$plugin_sha .*module=inactive" \
  "$work/hot.err")" -eq 100
test "$(grep -c 'AOT v2 deactivated range=' "$work/hot.err")" -eq 100
grep -Eq 'direct_targets=[1-9][0-9]* compat_tb_allocations=0' "$work/hot.err"

run_guest "$work/hot-cache" "$work/no-aslr.out" "$work/no-aslr.err" \
  setarch "$(uname -m)" -R
cmp "$work/hot.out" "$work/no-aslr.out"
grep -Eq "module stats source=$plugin_sha .*module=inactive aot_lookups=[1-9]" \
  "$work/no-aslr.err"
test "$(grep -Ec "module stats source=$plugin_sha .*module=inactive" \
  "$work/no-aslr.err")" -eq 100
grep -Eq 'direct_targets=[1-9][0-9]* compat_tb_allocations=0' \
  "$work/no-aslr.err"

echo "test-aot-v2-dlopen-runner: PASS"
