#!/bin/sh
set -eu

script=$1
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-one-pass-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

printf guest >"$work/guest"
python3 "$script_dir/tb_key_set.py" "$work/guest" \
    "$work/input.tbset" 0x1000:0x1

cat >"$work/stage1" <<'EOF'
#!/bin/sh
printf 'run\n' >>"$FAKE_RUN_COUNT"
{
    printf '0x401000 0x1\n'
    printf '0x402000 0x3\n'
} >"$LATC_NATIVE_MISSING_OUT"
exit 1
EOF
chmod +x "$work/stage1"

cat >"$work/latc" <<'EOF'
#!/bin/sh
if [ "$1" = compile ]; then
    shift
    while [ "$#" -gt 0 ]; do
        if [ "$1" = -o ]; then
            cp "$FAKE_STAGE1" "$2"
            chmod +x "$2"
            exit 0
        fi
        shift
    done
fi
exit 2
EOF
chmod +x "$work/latc"

set +e
FAKE_STAGE1="$work/stage1" FAKE_RUN_COUNT="$work/run-count" \
    "$script" "$work/latc" "$work/runner" "$work/guest" \
    "$work/output" "$work/input.tbset" >"$work/stdout" 2>"$work/stderr"
status=$?
set -e

test "$status" -ne 0
test "$(wc -l <"$work/run-count")" -eq 1
grep -q '0x401000 0x1' "$work/stderr"
grep -q '0x402000 0x3' "$work/stderr"
! grep -q 'supplement round' "$work/stderr"
printf 'test-compile-native-one-pass: PASS\n'
