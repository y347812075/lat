#!/bin/sh
set -eu

script=$1
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-native-direct-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

printf guest >"$work/guest"
cat >"$work/stage1" <<'EOF'
#!/bin/sh
printf native-image >"$LATC_NATIVE_IMAGE_OUT"
EOF
chmod +x "$work/stage1"

cat >"$work/latc" <<'EOF'
#!/bin/sh
test "$1" = compile
printf 'compile\n' >>"$FAKE_COMPILE_COUNT"
shift
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then
        cp "$FAKE_STAGE1" "$2"
        chmod +x "$2"
        exit 0
    fi
    shift
done
exit 2
EOF
chmod +x "$work/latc"

FAKE_STAGE1="$work/stage1" FAKE_COMPILE_COUNT="$work/compile-count" \
    LATC_NATIVE_IMAGE_OUT="$work/native-image" \
    "$script" "$work/latc" "$work/runner" "$work/guest" \
    "$work/unused-bundle"

test "$(cat "$work/native-image")" = native-image
test "$(wc -l <"$work/compile-count")" -eq 1
test ! -e "$work/unused-bundle"
printf 'test-compile-aot-native-direct: PASS\n'
