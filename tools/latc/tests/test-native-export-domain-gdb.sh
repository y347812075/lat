#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 LATC RUNNER RUNTIME_DIR GUEST TBSET WORKDIR" >&2
    exit 2
fi
latc=$1
runner=$2
runtime=$3
guest=$4
tbset=$5
work=$6
mkdir -m 700 "$work"
mkdir -m 700 "$work/home"

LD_LIBRARY_PATH="$runtime" LATX_AOT_V2=1 "$runner" \
    --latc-translation-config-native --latc-translation-config-out \
    "$work/config" "$guest" >"$work/config.log" 2>&1
"$latc" compile "$guest" -o "$work/bundle" --runner "$runner" \
    --tbset "$tbset" --tbset-ignore-outside-exec >"$work/compile.log" 2>&1

printf '%s\n' 'set pagination off' 'break aot_generate' 'run' 'finish' \
    'set {long}&imm_skip_pc = 1' 'continue' > "$work/inject.gdb"
HOME="$work/home" TMPDIR="$work" LD_LIBRARY_PATH="$runtime" \
    LATX_AOT=1 LATX_AOT_V2=0 LATX_AOT_V2_AUTOSTART=0 LATC_EMIT_AOT=1 \
    LATC_NAMED_GUEST="$work/x86-guest" LATC_NATIVE_IMAGE_OUT="$work/output.native" \
    LATC_TRANSLATION_CONFIG_FROM="$work/config" \
    gdb -q -batch -x "$work/inject.gdb" --args "$work/bundle" \
    >"$work/gdb.log" 2>&1
grep -q 'native replay changed during export' "$work/gdb.log"
grep -q 'exited with code 01' "$work/gdb.log"
test ! -e "$work/output.native"
echo 'test-native-export-domain-gdb: PASS'
