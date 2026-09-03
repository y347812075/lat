#!/bin/sh
set -eu

latc=$1
guest=$2
bundle=$3
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
tbset="$bundle.input.tbset"
python3 "$script_dir/tb_key_set.py" "$guest" "$tbset" 0x1000:0x1 0x1001:0x1

message=$("$latc" compile "$guest" -o "$bundle" --runner "$guest" \
    --tbset "$tbset" 2>&1)
case "$message" in
    *"TB set matched=1 added=1 ignored=0"*) ;;
    *) echo "unexpected TB set result: $message" >&2; exit 1 ;;
esac

outside="$bundle.outside.tbset"
python3 "$script_dir/tb_key_set.py" "$guest" "$outside" 0x5508004504:0x1
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
python3 "$script_dir/tb_key_set.py" "$guest" "$parallel" 0x1000:0x1 0x1000:0x3
message=$("$latc" compile "$guest" -o "$bundle.parallel" --runner "$guest" \
    --tbset "$parallel" 2>&1)
case "$message" in
    *"TB set matched=1 added=1 ignored=0"*) ;;
    *) echo "unexpected parallel TB set result: $message" >&2; exit 1 ;;
esac
"$latc" inspect --json "$bundle.parallel" | python3 -c \
    'import json,sys; data=json.load(sys.stdin); assert data["selected_tbs"] == 2, data'

wrong="$bundle.wrong-source.tbset"
python3 "$script_dir/tb_key_set.py" "$guest" "$wrong" 0x1000:0x1
python3 - "$wrong" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
d = bytearray(p.read_bytes())
d[16:48] = bytes(32)
p.write_bytes(d)
PY
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
