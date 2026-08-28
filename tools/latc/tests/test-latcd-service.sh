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

start_service()
{
    name=$1
    compiler=$2
    shift 2
    phase=$work/$name
    mkdir -m 700 "$phase"
    socket=$phase/latcd.sock
    cache=$phase/cache
    stats=$phase/stats.json
    "$latcd" --serve --socket "$socket" --cache-dir "$cache" \
      --latc "$compiler" --runner "$runner" --runtime-dir "$runtime_dir" \
      --stats "$stats" "$@" >"$phase/server.stdout" \
      2>"$phase/server.stderr" &
    server_pid=$!
    n=0
    while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
        n=$((n + 1))
        [ "$n" -lt 500 ] || break
        sleep 0.01
    done
    [ -S "$socket" ]
}

wait_stats()
{
    expression=$1
    n=0
    while :; do
        if [ -f "$stats" ] && \
           python3 - "$stats" "$expression" 2>/dev/null <<'PY'
import json
import sys
stats = json.load(open(sys.argv[1]))
assert eval(sys.argv[2], {"__builtins__": {}}, {"s": stats})
PY
        then
            return
        fi
        n=$((n + 1))
        [ "$n" -lt 1200 ] || {
            echo "timed out waiting for stats: $expression" >&2
            cat "$stats" 2>/dev/null || true
            return 1
        }
        sleep 0.05
    done
}

stop_service()
{
    kill -TERM "$server_pid"
    wait "$server_pid"
}

start_service concurrent "$latc"
cp "$guest" "$work/same-bytes.elf"
client_pids=
n=1
while [ "$n" -le 20 ]; do
    if [ $((n % 2)) -eq 0 ]; then source=$work/same-bytes.elf; else source=$guest; fi
    "$latcd" --submit --socket "$socket" "$source" \
      >"$phase/client.$n" 2>&1 &
    client_pids="$client_pids $!"
    n=$((n + 1))
done
for client_pid in $client_pids; do wait "$client_pid"; done
wait_stats 's["compiled"] == 1 and s["active_jobs"] == 0'
python3 - "$stats" <<'PY'
import json
import sys
s = json.load(open(sys.argv[1]))
assert s["requests"] == 20, s
assert s["queued"] == 1, s
assert s["compiled"] == 1 and s["failed"] == 0, s
assert s["deduplicated"] + s["cache_hits"] == 19, s
PY
stop_service

start_service workers "$script_dir/fake-latc-slow.sh" --workers 2
cp "$guest" "$work/workers-a.elf"
cp "$guest" "$work/workers-b.elf"
printf a >>"$work/workers-a.elf"
printf b >>"$work/workers-b.elf"
"$latcd" --submit --socket "$socket" "$work/workers-a.elf" \
  >"$phase/a.client" &
worker_client_a=$!
"$latcd" --submit --socket "$socket" "$work/workers-b.elf" \
  >"$phase/b.client" &
worker_client_b=$!
wait "$worker_client_a"
wait "$worker_client_b"
wait_stats 's["active_jobs"] == 2 and s["queue_depth"] == 0 and s["workers"] == 2'
wait_stats 's["compiled"] == 2 and s["active_jobs"] == 0'
stop_service

start_service same-source-workers "$script_dir/fake-latc-slow.sh" --workers 2
python3 - "$socket" "$guest" <<'PY'
import array
import hashlib
import os
import socket
import struct
import sys
import tempfile

socket_path, source_path = sys.argv[1:]
source_sha = hashlib.sha256(open(source_path, "rb").read()).hexdigest()
with open(source_path, "rb") as source:
    source.seek(24)
    entry = struct.unpack("<Q", source.read(8))[0]
    source.seek(32)
    phoff = struct.unpack("<Q", source.read(8))[0]
    source.seek(54)
    phentsize, phnum = struct.unpack("<HH", source.read(4))
    load_vaddrs = []
    for index in range(phnum):
        source.seek(phoff + index * phentsize)
        phdr = source.read(phentsize)
        if struct.unpack_from("<I", phdr)[0] == 1:  # PT_LOAD
            load_vaddrs.append(struct.unpack_from("<Q", phdr, 16)[0])
    assert load_vaddrs and entry >= min(load_vaddrs)
    entry_rva = entry - min(load_vaddrs)

for request_id, count in ((101, 1), (102, 2)):
    profile = tempfile.NamedTemporaryFile(mode="w", delete=False)
    try:
        profile.write("LATC_PROFILE_V2 %s\n" % source_sha)
        profile.write("0x%x 0x1 %d\n" % (entry_rva, count))
        profile.close()
        source_fd = os.open(source_path, os.O_RDONLY)
        profile_fd = os.open(profile.name, os.O_RDONLY)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection.connect(socket_path)
        request = struct.pack("=IHHIIQ", 0x4c415444, 1, 24,
                              100, 1, request_id)
        connection.sendmsg(
            [request],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
              array.array("i", [source_fd, profile_fd]))])
        response = connection.recv(248)
        assert len(response) == 248
        assert struct.unpack_from("=i", response, 8)[0] == 0
        connection.close()
        os.close(source_fd)
        os.close(profile_fd)
    finally:
        try:
            os.unlink(profile.name)
        except FileNotFoundError:
            pass
PY
wait_stats 's["active_jobs"] == 2 and s["queue_depth"] == 1 and s["running_sources"] == 1'
wait_stats 's["compiled"] == 2 and s["active_jobs"] == 0 and s["running_sources"] == 0'
python3 - "$cache" "$guest" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

cache = Path(sys.argv[1])
source = Path(sys.argv[2])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
with source.open("rb") as elf:
    elf.seek(24)
    entry = struct.unpack("<Q", elf.read(8))[0]
    elf.seek(32)
    phoff = struct.unpack("<Q", elf.read(8))[0]
    elf.seek(54)
    phentsize, phnum = struct.unpack("<HH", elf.read(4))
    load_vaddrs = []
    for index in range(phnum):
        elf.seek(phoff + index * phentsize)
        phdr = elf.read(phentsize)
        if struct.unpack_from("<I", phdr)[0] == 1:
            load_vaddrs.append(struct.unpack_from("<Q", phdr, 16)[0])
entry_rva = entry - min(load_vaddrs)
profile = cache / ".profiles" / f"{source_sha}.profile"
contents = profile.read_text()
assert contents.splitlines() == [
    f"LATC_PROFILE_V2 {source_sha}",
    f"0x{entry_rva:x} 0x1 3",
], contents
profile_sha = hashlib.sha256(contents.encode()).hexdigest()
module_name = f"{source_sha}-{profile_sha}.so"
assert (cache / module_name).is_file(), module_name
current = json.loads((cache / f"{source_sha}.current").read_text())
assert current["module"] == module_name, current
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 2
PY
stop_service

start_service negative /bin/false --negative-ms 500
python3 - "$socket" <<'PY'
import socket
import struct
import sys
import time

connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
connection.connect(sys.argv[1])
time.sleep(1.2)
response = connection.recv(248)
assert len(response) == 248
assert struct.unpack_from("=i", response, 8)[0] == 1
connection.close()
PY
"$latcd" --submit --socket "$socket" "$guest" >"$phase/first.client"
wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
if "$latcd" --submit --socket "$socket" "$guest" \
     >"$phase/second.client" 2>&1; then
    echo "negative cache accepted immediate retry" >&2
    exit 1
fi
grep -q '^status=7$' "$phase/second.client"
wait_stats 's["negative_hits"] == 1'
stop_service

start_service cpu-limit "$script_dir/fake-latc-cpu.sh" --cpu-seconds 1
"$latcd" --submit --socket "$socket" "$guest" >"$phase/client"
wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
grep -q 'compiler terminated by signal' "$phase/server.stderr" || true
stop_service

cp "$guest" "$work/a.elf"
cp "$guest" "$work/b.elf"
cp "$guest" "$work/c.elf"
cp "$guest" "$work/d.elf"
printf a >>"$work/a.elf"
printf b >>"$work/b.elf"
printf c >>"$work/c.elf"
printf d >>"$work/d.elf"
start_service priority "$script_dir/fake-latc-slow.sh" --max-jobs 2
"$latcd" --submit --socket "$socket" --priority 0 "$work/a.elf" \
  >"$phase/a.client"
wait_stats 's["active_jobs"] == 1 and s["queue_depth"] == 0'
"$latcd" --submit --socket "$socket" --priority 1 "$work/b.elf" \
  >"$phase/b.client"
"$latcd" --submit --socket "$socket" --priority 200 "$work/c.elf" \
  >"$phase/c.client"
wait_stats 's["queue_depth"] == 2'
if "$latcd" --submit --socket "$socket" --priority 1 "$work/d.elf" \
     >"$phase/d.client" 2>&1; then
    echo "full compiler queue accepted another request" >&2
    exit 1
fi
grep -q '^status=6$' "$phase/d.client"
wait_stats 's["compiled"] == 3 and s["active_jobs"] == 0'
b_sha=$(sha256sum "$work/b.elf" | cut -d ' ' -f 1)
c_sha=$(sha256sum "$work/c.elf" | cut -d ' ' -f 1)
python3 - "$cache/$b_sha.so" "$cache/$c_sha.so" <<'PY'
import os
import sys
assert os.stat(sys.argv[2]).st_mtime_ns < os.stat(sys.argv[1]).st_mtime_ns
PY
wait_stats 's["queue_full"] == 1 and s["compiled"] == 3'
stop_service

source_size=$(wc -c <"$work/b.elf")
start_service shutdown "$script_dir/fake-latc-cpu.sh" --cpu-seconds 60 \
  --max-jobs 10 --max-queue-bytes "$source_size"
"$latcd" --submit --socket "$socket" "$work/a.elf" >"$phase/a.client"
wait_stats 's["active_jobs"] == 1 and s["queue_depth"] == 0'
"$latcd" --submit --socket "$socket" "$work/b.elf" >"$phase/b.client"
wait_stats 's["queue_depth"] == 1 and s["queue_bytes"] > 0'
if "$latcd" --submit --socket "$socket" "$work/c.elf" \
     >"$phase/c.client" 2>&1; then
    echo "byte-limited compiler queue accepted another request" >&2
    exit 1
fi
grep -q '^status=6$' "$phase/c.client"
start=$(date +%s)
stop_service
elapsed=$(($(date +%s) - start))
[ "$elapsed" -lt 5 ]
grep -q '"queue_full":1' "$stats"
test -z "$(find "$cache/.tmp" -mindepth 1 -maxdepth 1 -print -quit)"

echo "test-latcd-service: PASS"
