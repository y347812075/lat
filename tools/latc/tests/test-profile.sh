#!/bin/sh
set -eu

latc=$1
guest=$2
profile=$3
bundle=$4

message=$("$latc" compile "$guest" -o "$bundle" --runner "$guest" \
    --profile "$profile" 2>&1)
case "$message" in
    *"profile matched=1 added=1 ignored=0"*) ;;
    *) echo "unexpected profile result: $message" >&2; exit 1 ;;
esac

outside="$bundle.outside.profile"
printf '0x5508004504 1\n' >"$outside"
if "$latc" compile "$guest" -o "$bundle.outside" --runner "$guest" \
    --profile "$outside" >/dev/null 2>&1; then
    echo "outside profile address was accepted without opt-in" >&2
    exit 1
fi
message=$("$latc" compile "$guest" -o "$bundle.outside" --runner "$guest" \
    --profile "$outside" --profile-ignore-outside-exec 2>&1)
case "$message" in
    *"profile matched=0 added=0 ignored=1"*) ;;
    *) echo "unexpected ignored profile result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["profiled_tbs"] == 2, data'

source_sha=$(sha256sum "$guest" | awk '{print $1}')
v2="$bundle.v2.profile"
{
    printf 'LATC_PROFILE_V2 %s\n' "$source_sha"
    printf '0x401000 0x1 100\n'
    printf '0x401000 0x3 25\n'
} >"$v2"
message=$("$latc" compile "$guest" -o "$bundle.v2" --runner "$guest" \
    --profile "$v2" 2>&1)
case "$message" in
    *"profile matched=1 added=1 ignored=0"*) ;;
    *) echo "unexpected v2 profile result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle.v2" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["profiled_tbs"] == 2, data'

wrong="$bundle.wrong-source.profile"
{
    printf 'LATC_PROFILE_V2 %064d\n' 0
    printf '0x401000 0x1 1\n'
} >"$wrong"
if "$latc" compile "$guest" -o "$bundle.wrong-source" --runner "$guest" \
    --profile "$wrong" >/dev/null 2>&1; then
    echo "v2 profile with wrong source digest was accepted" >&2
    exit 1
fi
echo "test-profile: PASS"
