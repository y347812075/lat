#!/bin/sh
set -eu

latc=$1
guest=$2
profile=$3
bundle=$4

message=$("$latc" compile "$guest" -o "$bundle" --runner "$guest" \
    --profile "$profile" 2>&1)
case "$message" in
    *"profile matched=1 added=1"*) ;;
    *) echo "unexpected profile result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["profiled_tbs"] == 2, data'
echo "test-profile: PASS"
