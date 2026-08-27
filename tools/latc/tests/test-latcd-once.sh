#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 LATCD LATC RUNNER RUNTIME_DIR X86_GUEST WORKDIR" >&2
    exit 2
fi

latcd=$1
latc=$2
runner=$3
runtime_dir=$4
guest=$5
work=$6
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
rm -rf "$work"
mkdir -m 700 -p "$work"

start_once()
{
    socket=$1
    cache=$2
    compiler=$3
    shift 3
    "$latcd" --once --socket "$socket" --cache-dir "$cache" \
      --latc "$compiler" --runner "$runner" --runtime-dir "$runtime_dir" \
      "$@" \
      >"$socket.stdout" 2>"$socket.stderr" &
    server_pid=$!
    n=0
    while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
        n=$((n + 1))
        [ "$n" -lt 500 ] || break
        sleep 0.01
    done
    [ -S "$socket" ]
}

failure_cache=$work/failure-cache
start_once "$work/failure.sock" "$failure_cache" /bin/false
if "$latcd" --submit --socket "$work/failure.sock" "$guest" \
     >"$work/failure.client" 2>&1; then
    echo "latcd accepted compiler failure" >&2
    exit 1
fi
if wait "$server_pid"; then
    echo "latcd server accepted compiler failure" >&2
    exit 1
fi
grep -q '^status=3$' "$work/failure.client"
test -z "$(find "$failure_cache" -maxdepth 1 -type f -name '*.so' -print -quit)"
test -z "$(find "$failure_cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

bad_cache=$work/bad-cache
start_once "$work/bad.sock" "$bad_cache" /bin/false
if "$latcd" --submit --socket "$work/bad.sock" /etc/hosts \
     >"$work/bad.client" 2>&1; then
    echo "latcd accepted non-ELF source" >&2
    exit 1
fi
if wait "$server_pid"; then
    echo "latcd server accepted non-ELF source" >&2
    exit 1
fi
grep -q '^status=2$' "$work/bad.client"
test -z "$(find "$bad_cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

writable_cache=$work/writable-cache
start_once "$work/writable.sock" "$writable_cache" /bin/false
python3 - "$work/writable.sock" "$guest" <<'PY'
import array
import os
import socket
import struct
import sys

connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
connection.connect(sys.argv[1])
source = os.open(sys.argv[2], os.O_RDWR)
request = struct.pack("=IHHIIQ", 0x4c415444, 1, 24, 100, 0, 42)
connection.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                               array.array("i", [source]))])
response = connection.recv(248)
assert len(response) == 248
assert struct.unpack_from("=i", response, 8)[0] == 2
os.close(source)
connection.close()
PY
if wait "$server_pid"; then
    echo "latcd server accepted writable source FD" >&2
    exit 1
fi
test -z "$(find "$writable_cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

invalid_cache=$work/invalid-cache
start_once "$work/invalid.sock" "$invalid_cache" \
  "$script_dir/fake-latc-invalid-module.sh"
if "$latcd" --submit --socket "$work/invalid.sock" "$guest" \
     >"$work/invalid.client" 2>&1; then
    echo "latcd accepted invalid compiler output" >&2
    exit 1
fi
if wait "$server_pid"; then
    echo "latcd server accepted invalid compiler output" >&2
    exit 1
fi
grep -q '^status=4$' "$work/invalid.client"
test -z "$(find "$invalid_cache" -maxdepth 1 -type f -name '*.so' -print -quit)"
test -z "$(find "$invalid_cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

cache=$work/cache
mkdir -m 700 "$cache"
source_sha=$(sha256sum "$guest" | cut -d ' ' -f 1)
cp /bin/true "$cache/$source_sha.so"
bad_module_sha=$(sha256sum "$cache/$source_sha.so" | cut -d ' ' -f 1)
start_once "$work/publish.sock" "$cache" "$latc"
timeout 60 "$latcd" --submit --socket "$work/publish.sock" "$guest" \
  >"$work/publish.client"
wait "$server_pid"

module=$cache/$source_sha.so
test -f "$module"
test "$(stat -c %a "$module")" = 444
test "$(sha256sum "$module" | cut -d ' ' -f 1)" != "$bad_module_sha"
"$latc" inspect-module --json "$module" >"$work/module.json"
python3 - "$work/module.json" "$source_sha" <<'PY'
import json
import sys

module = json.load(open(sys.argv[1]))
assert module["source_sha256"] == sys.argv[2]
assert module["tbs"] > 0
PY
test -z "$(find "$cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

LD_LIBRARY_PATH="$runtime_dir" \
LATX_AOT_V2_CACHE_DIR="$cache" \
LATX_AOT_V2_STRICT=1 \
LATX_AOT_V2_REPORT=1 \
LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 \
  timeout 60 "$runner" "$guest" >"$work/guest.stdout" \
  2>"$work/guest.stderr"
grep -q 'module=registered' "$work/guest.stderr"
grep -Eq 'aot_lookups=[1-9][0-9]* jit_fallbacks=0' "$work/guest.stderr"
grep -q 'compat_tb_allocations=0' "$work/guest.stderr"

start_once "$work/hit.sock" "$cache" /bin/false
"$latcd" --submit --socket "$work/hit.sock" "$guest" >"$work/hit.client"
wait "$server_pid"
grep -q 'cache hit:' "$work/hit.client"
test -z "$(find "$cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

chmod 0644 "$module"
start_once "$work/writable-module.sock" "$cache" /bin/false
if "$latcd" --submit --socket "$work/writable-module.sock" "$guest" \
     >"$work/writable-module.client" 2>&1; then
    echo "latcd accepted externally writable cached module" >&2
    exit 1
fi
if wait "$server_pid"; then
    echo "latcd treated externally writable cached module as a hit" >&2
    exit 1
fi
grep -q '^status=3$' "$work/writable-module.client"
chmod 0444 "$module"

eviction_cache=$work/eviction-cache
mkdir -m 700 "$eviction_cache"
cp "$module" "$eviction_cache/$source_sha.so"
chmod 0444 "$eviction_cache/$source_sha.so"
touch -t 200001010000 "$eviction_cache/$source_sha.so"
cp "$guest" "$work/eviction-input.elf"
printf x >>"$work/eviction-input.elf"
eviction_sha=$(sha256sum "$work/eviction-input.elf" | cut -d ' ' -f 1)
cache_limit=$(( $(stat -c %s "$module") + 4096 ))
start_once "$work/eviction.sock" "$eviction_cache" "$latc" \
  --max-cache-bytes "$cache_limit"
timeout 60 "$latcd" --submit --socket "$work/eviction.sock" \
  "$work/eviction-input.elf" >"$work/eviction.client"
wait "$server_pid"
test -f "$eviction_cache/$eviction_sha.so"
test ! -e "$eviction_cache/$source_sha.so"
test ! -e "$eviction_cache/$source_sha.current"

echo "test-latcd-once: PASS source=$source_sha"
