#!/bin/sh
set -eu

latc=$1
guest=$2
bundle=$3
source_sha=$(sha256sum "$guest" | awk '{print $1}')
tbset="$bundle.input.tbset"
{
    printf 'LATC_TBSET_V1 %s\n' "$source_sha"
    printf '0x1000 0x1\n'
    printf '0x1001 0x1\n'
} >"$tbset"

message=$("$latc" compile "$guest" -o "$bundle" --runner "$guest" \
    --tbset "$tbset" 2>&1)
case "$message" in
    *"TB set matched=0 added=2 ignored=0"*) ;;
    *) echo "unexpected TB set result: $message" >&2; exit 1 ;;
esac

outside="$bundle.outside.tbset"
{
    printf 'LATC_TBSET_V1 %s\n' "$source_sha"
    printf '0x5508004504 0x1\n'
} >"$outside"
if "$latc" compile "$guest" -o "$bundle.outside" --runner "$guest" \
    --tbset "$outside" >/dev/null 2>&1; then
    echo "outside TB set address was accepted without opt-in" >&2
    exit 1
fi
message=$("$latc" compile "$guest" -o "$bundle.outside" --runner "$guest" \
    --tbset "$outside" --tbset-ignore-outside-exec 2>&1)
case "$message" in
    *"TB set matched=0 added=0 ignored=1"*) ;;
    *) echo "unexpected ignored TB set result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["selected_tbs"] == 2, data'

parallel="$bundle.parallel.tbset"
{
    printf 'LATC_TBSET_V1 %s\n' "$source_sha"
    printf '0x1000 0x1\n'
    printf '0x1000 0x3\n'
} >"$parallel"
message=$("$latc" compile "$guest" -o "$bundle.parallel" --runner "$guest" \
    --tbset "$parallel" 2>&1)
case "$message" in
    *"TB set matched=0 added=2 ignored=0"*) ;;
    *) echo "unexpected parallel TB set result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle.parallel" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["selected_tbs"] == 2, data'

wrong="$bundle.wrong-source.tbset"
{
    printf 'LATC_TBSET_V1 %064d\n' 0
    printf '0x1000 0x1\n'
} >"$wrong"
if "$latc" compile "$guest" -o "$bundle.wrong-source" --runner "$guest" \
    --tbset "$wrong" >/dev/null 2>&1; then
    echo "TB set with wrong source digest was accepted" >&2
    exit 1
fi
headerless="$bundle.headerless.tbset"
printf '0x1000 0x1 1\n' >"$headerless"
if "$latc" compile "$guest" -o "$bundle.headerless" --runner "$guest" \
    --tbset "$headerless" >/dev/null 2>&1; then
    echo "headerless three-column input was accepted" >&2
    exit 1
fi
echo "test-tbset: PASS"
