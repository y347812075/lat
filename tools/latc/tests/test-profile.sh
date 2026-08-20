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
echo "test-profile: PASS"
