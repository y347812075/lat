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
export LATC_FAKE_REAL=$latc
rm -rf "$work"
mkdir -m 700 -p "$work"

cleanup_service()
{
    for pid in "${server_pid:-}" "${owner_pid:-}" "${normal_pid:-}" "${kill_pid:-}" \
               "${legacy_reader_1:-}" "${legacy_reader_2:-}"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [ -n "${direct_hidden:-}" ] && [ -e "$direct_hidden" ]; then
        mv "$direct_hidden" "$direct_current"
    fi
}
trap cleanup_service EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
      --stats "$stats" --workers 1 "$@" >"$phase/server.stdout" \
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
    server_pid=
}

submit_source()
{
    submit_socket=$1
    submit_source_path=$2
    submit_output=$3
    shift 3
    submit_tbset=$(mktemp "$work/submit.XXXXXX.tbset")
    python3 "$script_dir/make-tbset.py" "$submit_source_path" "$submit_tbset"
    if "$latcd" --submit --socket "$submit_socket" --tbset "$submit_tbset" \
         "$@" "$submit_source_path" >"$submit_output"; then
        rm -f "$submit_tbset"
        return 0
    else
        submit_status=$?
        rm -f "$submit_tbset"
        return "$submit_status"
    fi
}

page_phase=$work/unsafe-retirement-page
mkdir -m 700 "$page_phase" "$page_phase/cache" "$page_phase/cache/.gc"
printf 'invalid checkpoint\n' > "$page_phase/cache/.gc/retirement-page.ini"
chmod 400 "$page_phase/cache/.gc/retirement-page.ini"
page_hash=$(sha256sum "$page_phase/cache/.gc/retirement-page.ini")
if "$latcd" --serve --socket "$page_phase/latcd.sock" --cache-dir "$page_phase/cache" \
     --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
     >"$page_phase/stdout" 2>"$page_phase/stderr"; then
    echo "latcd accepted an unsafe retirement checkpoint" >&2
    exit 1
fi
grep -q 'retirement page budget recovery unavailable or checkpoint unsafe' "$page_phase/stderr"
test ! -e "$page_phase/latcd.sock"
test "$page_hash" = "$(sha256sum "$page_phase/cache/.gc/retirement-page.ini")"
for page_kind in inflight pending legacy; do
    page_phase=$work/retirement-page-$page_kind
    mkdir -m 700 "$page_phase" "$page_phase/cache" "$page_phase/cache/.gc"
    python3 - "$page_phase/cache" "$page_kind" <<'PY'
import os
import sys

root, kind = sys.argv[1:]
st = os.stat(root)
boot = open('/proc/sys/kernel/random/boot_id', encoding='ascii').read().strip()
name = '0' * 63 + '1.so'
version = 2 if kind == 'legacy' else 5
lines = ['[page]', f'version={version}', f'cache_device={st.st_dev}',
         f'cache_inode={st.st_ino}', 'grace_us=100', f'boot={boot}',
         'round_cutoff=1']
if version == 5:
    lines += ['committed_cursor=']
lines += [f'cursor={"" if kind == "legacy" else name}', 'sequence=1',
          f'count={0 if kind == "legacy" else 1}']
if version == 5:
    lines += [f'pending={1 if kind == "pending" else 0}', '[entry0]',
              f'name={name}', 'deadline=2', 'enqueued=1', 'last_attempt=0',
              'retry_at=0', 'busy_count=0', f'result={1 if kind == "pending" else 0}']
path = os.path.join(root, '.gc', 'retirement-page.ini')
with open(path, 'w', encoding='ascii') as record:
    record.write('\n'.join(lines) + '\n')
os.chmod(path, 0o400)
PY
    page_hash=$(sha256sum "$page_phase/cache/.gc/retirement-page.ini")
    if "$latcd" --serve --socket "$page_phase/latcd.sock" --cache-dir "$page_phase/cache" \
         --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
         >"$page_phase/stdout" 2>"$page_phase/stderr"; then
        echo "latcd accepted $page_kind retirement checkpoint" >&2
        exit 1
    fi
    grep -q 'retirement page budget recovery unavailable or checkpoint unsafe' "$page_phase/stderr"
    test ! -e "$page_phase/latcd.sock"
    test "$page_hash" = "$(sha256sum "$page_phase/cache/.gc/retirement-page.ini")"
done

page_phase=$work/partial-retirement-record
mkdir -m 700 "$page_phase" "$page_phase/cache" "$page_phase/cache/.gc"
printf 'interrupted checkpoint\n' > "$page_phase/cache/.gc/.write-interrupted"
chmod 400 "$page_phase/cache/.gc/.write-interrupted"
page_hash=$(sha256sum "$page_phase/cache/.gc/.write-interrupted")
if "$latcd" --serve --socket "$page_phase/latcd.sock" --cache-dir "$page_phase/cache" \
     --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
     >"$page_phase/stdout" 2>"$page_phase/stderr"; then
    echo "latcd accepted an interrupted metadata record" >&2
    exit 1
fi
grep -q 'retirement page budget recovery unavailable or checkpoint unsafe' "$page_phase/stderr"
test ! -e "$page_phase/latcd.sock"
test "$page_hash" = "$(sha256sum "$page_phase/cache/.gc/.write-interrupted")"

for record_store in transactions tombstones retirement-schedule; do
    phase=$work/partial-$record_store
    mkdir -m 700 "$phase" "$phase/cache" "$phase/cache/.gc" "$phase/cache/.gc/$record_store"
    printf 'interrupted lifecycle record\n' > "$phase/cache/.gc/$record_store/.write-interrupted"
    chmod 400 "$phase/cache/.gc/$record_store/.write-interrupted"
    record_hash=$(sha256sum "$phase/cache/.gc/$record_store/.write-interrupted")
    if "$latcd" --serve --socket "$phase/latcd.sock" --cache-dir "$phase/cache" \
         --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
         >"$phase/stdout" 2>"$phase/stderr"; then
        echo "latcd accepted interrupted $record_store record" >&2
        exit 1
    fi
    grep -q 'incomplete or unsafe retirement startup records' "$phase/stderr"
    test ! -e "$phase/latcd.sock"
    test "$record_hash" = "$(sha256sum "$phase/cache/.gc/$record_store/.write-interrupted")"
done

owner_cache=$work/cache-owner
owner_phase=$work/cache-owner-primary
mkdir -m 700 "$owner_phase"
owner_socket=$owner_phase/latcd.sock
owner_stats=$owner_phase/stats.json
"$latcd" --serve --socket "$owner_socket" --cache-dir "$owner_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$owner_stats" >"$owner_phase/server.stdout" \
  2>"$owner_phase/server.stderr" &
owner_pid=$!
n=0
while [ ! -S "$owner_socket" ] && kill -0 "$owner_pid" 2>/dev/null; do
    n=$((n + 1))
    [ "$n" -lt 500 ] || break
    sleep 0.01
done
[ -S "$owner_socket" ]
test "$(stat -c %a "$owner_cache/.latcd.lock")" = 600
grep -q "^pid=$owner_pid$" "$owner_cache/.latcd.lock"

second_phase=$work/cache-owner-second
mkdir -m 700 "$second_phase"
if "$latcd" --serve --socket "$second_phase/latcd.sock" \
     --cache-dir "$owner_cache" --latc "$latc" --runner "$runner" \
     --runtime-dir "$runtime_dir" >"$second_phase/server.stdout" \
     2>"$second_phase/server.stderr"; then
    echo "second latcd acquired an owned cache" >&2
    exit 1
fi
grep -q 'cache is already owned by another latcd' \
  "$second_phase/server.stderr"
test ! -e "$second_phase/latcd.sock"
test -z "$(find "$owner_cache" -maxdepth 1 -type f \
  \( -name '*.so' -o -name '*.current' \) -print -quit)"

kill -TERM "$owner_pid"
wait "$owner_pid"
owner_pid=
normal_phase=$work/cache-owner-normal-recovery
mkdir -m 700 "$normal_phase"
normal_socket=$normal_phase/latcd.sock
"$latcd" --serve --socket "$normal_socket" --cache-dir "$owner_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  >"$normal_phase/server.stdout" 2>"$normal_phase/server.stderr" &
normal_pid=$!
n=0
while [ ! -S "$normal_socket" ] && kill -0 "$normal_pid" 2>/dev/null; do
    n=$((n + 1))
    [ "$n" -lt 500 ] || break
    sleep 0.01
done
[ -S "$normal_socket" ]
kill -KILL "$normal_pid"
wait "$normal_pid" 2>/dev/null || true
normal_pid=

kill_phase=$work/cache-owner-kill-recovery
mkdir -m 700 "$kill_phase"
kill_socket=$kill_phase/latcd.sock
kill_stats=$kill_phase/stats.json
"$latcd" --serve --socket "$kill_socket" --cache-dir "$owner_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$kill_stats" >"$kill_phase/server.stdout" \
  2>"$kill_phase/server.stderr" &
kill_pid=$!
n=0
while [ ! -S "$kill_socket" ] && kill -0 "$kill_pid" 2>/dev/null; do
    n=$((n + 1))
    [ "$n" -lt 500 ] || break
    sleep 0.01
done
[ -S "$kill_socket" ]
submit_source "$kill_socket" "$guest" "$kill_phase/client"
stats=$kill_stats
wait_stats 's["compiled"] == 1 and s["active_jobs"] == 0 and s["cache_owner_pid"] > 0'
find "$owner_cache" -maxdepth 1 -type f \
  \( -name '*.so' -o -name '*.current' \) -print0 | sort -z | \
  xargs -0 sha256sum >"$kill_phase/cache.before"
test "$(wc -l <"$kill_phase/cache.before")" -ge 2
data_second=$work/cache-owner-second-with-data
mkdir -m 700 "$data_second"
if "$latcd" --serve --socket "$data_second/latcd.sock" \
     --cache-dir "$owner_cache" --latc "$latc" --runner "$runner" \
     --runtime-dir "$runtime_dir" >"$data_second/server.stdout" \
     2>"$data_second/server.stderr"; then
    echo "second latcd acquired an owned populated cache" >&2
    exit 1
fi
grep -q 'cache is already owned by another latcd' \
  "$data_second/server.stderr"
find "$owner_cache" -maxdepth 1 -type f \
  \( -name '*.so' -o -name '*.current' \) -print0 | sort -z | \
  xargs -0 sha256sum >"$kill_phase/cache.after"
cmp "$kill_phase/cache.before" "$kill_phase/cache.after"
kill -TERM "$kill_pid"
wait "$kill_pid"
kill_pid=

start_service concurrent "$latc"
wait_stats 's["requests"] == 0 and s["compiled"] == 0 and s["failed"] == 0 and s["active_jobs"] == 0 and s["queue_depth"] == 0'
cp "$guest" "$work/same-bytes.elf"
client_pids=
n=1
while [ "$n" -le 20 ]; do
    if [ $((n % 2)) -eq 0 ]; then source=$work/same-bytes.elf; else source=$guest; fi
    submit_source "$socket" "$source" "$phase/client.$n" 2>&1 &
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
"$latcd" --flush-all --socket "$socket" >"$phase/flush-all.client"
grep -q '^status=0$' "$phase/flush-all.client"
python3 - "$phase/flush-all.client" <<'PY'
import sys
values = dict(line.rstrip().split("=", 1)
              for line in open(sys.argv[1]) if "=" in line)
assert int(values["accepted_sequence"]) > 0, values
assert values["accepted_sequence"] == values["published_sequence"], values
PY
stop_service

start_service flush-only "$latc" --flush-only
submit_source "$socket" "$guest" "$phase/client"
sleep 0.2
python3 - "$stats" <<'PY'
import json
import sys
s = json.load(open(sys.argv[1]))
assert s["compiled"] == 0, s
assert s["queue_depth"] == 1 and s["active_jobs"] == 1, s
PY
"$latcd" --flush-all --socket "$socket" >"$phase/flush-all.client"
grep -q '^status=0$' "$phase/flush-all.client"
wait_stats 's["compiled"] == 1 and s["active_jobs"] == 0'
stop_service

start_service workers "$script_dir/fake-latc-slow.sh" --workers 2
cp "$guest" "$work/workers-a.elf"
cp "$guest" "$work/workers-b.elf"
printf a >>"$work/workers-a.elf"
printf b >>"$work/workers-b.elf"
submit_source "$socket" "$work/workers-a.elf" "$phase/a.client" &
worker_client_a=$!
submit_source "$socket" "$work/workers-b.elf" "$phase/b.client" &
worker_client_b=$!
wait "$worker_client_a"
wait "$worker_client_b"
wait_stats 's["active_jobs"] == 2 and s["queue_depth"] == 0 and s["workers"] == 2'
"$latcd" --flush-all --socket "$socket" >"$phase/flush-all.client"
grep -q '^status=0$' "$phase/flush-all.client"
python3 - "$phase/flush-all.client" <<'PY'
import sys
values = dict(line.rstrip().split("=", 1) for line in open(sys.argv[1]) if "=" in line)
assert int(values["published_sequence"]) >= int(values["accepted_sequence"]), values
PY
wait_stats 's["compiled"] == 2 and s["active_jobs"] == 0'
stop_service

start_service same-source-workers "$script_dir/fake-latc-slow.sh" --workers 2
python3 - "$socket" "$guest" "$script_dir" <<'PY'
import array
import hashlib
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile

socket_path, source_path, script_dir = sys.argv[1:]
sys.path.insert(0, script_dir)
from tb_key_set import write_key_set
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

for request_id, flags in ((101, 3), (102, 3)):
    if request_id == 102:
        import time
        time.sleep(0.2)
    tbset = tempfile.NamedTemporaryFile(delete=False)
    try:
        tbset.close()
        write_key_set(Path(source_path), Path(tbset.name),
                      [(entry_rva, flags)])
        source_fd = os.open(source_path, os.O_RDONLY)
        tbset_fd = os.open(tbset.name, os.O_RDONLY)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection.connect(socket_path)
        request = struct.pack("=IHHIIQQ", 0x4c415444, 2, 32,
                              1, 100, request_id, request_id)
        connection.sendmsg(
            [request],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
              array.array("i", [source_fd, tbset_fd]))])
        response = connection.recv(264)
        assert len(response) == 264
        assert struct.unpack_from("=i", response, 8)[0] == 0
        connection.close()
        os.close(source_fd)
        os.close(tbset_fd)
    finally:
        try:
            os.unlink(tbset.name)
        except FileNotFoundError:
            pass
PY
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/flush-source.client"
grep -q '^status=0$' "$phase/flush-source.client"
python3 - "$phase/flush-source.client" <<'PY'
import sys
values = dict(line.rstrip().split("=", 1) for line in open(sys.argv[1]) if "=" in line)
assert int(values["accepted_sequence"]) > 0, values
assert values["accepted_sequence"] == values["published_sequence"], values
PY
wait_stats 's["compiled"] == 1 and s["active_jobs"] == 0 and s["running_sources"] == 0'
python3 - "$cache" "$guest" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

cache = Path(sys.argv[1])
source = Path(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from tb_key_set import read_key_set
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
tbset = cache / ".tbsets" / f"{source_sha}.tbset"
digest, sequence, records = read_key_set(tbset)
assert digest.hex() == source_sha, digest.hex()
assert records == [(entry_rva, 3)], records
assert sequence >= 1, sequence
assert not (cache / f"{source_sha}.so").exists()
current = json.loads((cache / f"{source_sha}.current").read_text())
assert current["version"] == 2, current
assert (cache / current["module"]).is_file(), current
assert (cache / current["native"]).is_file(), current
assert (cache / current["tbset"]).is_file(), current
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.native"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.tbset"))) == 1
(cache.parent / "initial-generation.json").write_text(json.dumps({
    current[role]: hashlib.sha256((cache / current[role]).read_bytes()).hexdigest()
    for role in ("module", "native", "tbset")}))
stats = json.loads((cache.parent / "stats.json").read_text())
assert stats["requests"] == 2, stats
assert stats["queued"] == 1 and stats["deduplicated"] == 1, stats
assert stats["compiled"] == 1 and stats["failed"] == 0, stats
PY
set +e
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_STRICT=1 \
LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 LATC_STRICT_AOT=1 \
LATC_STATS_OUT="$phase/single-module.stats.json" \
  "$runner" "$guest" >"$phase/single-module.stdout" \
  2>"$phase/single-module.stderr"
strict_status=$?
set -e
test "$strict_status" -eq 42
python3 - "$phase/single-module.stats.json" <<'PY'
import json
import sys
stats = json.load(open(sys.argv[1]))
assert stats["runtime_file_tb_gen_calls"] == 0, stats
assert stats["runtime_file_tb_gen_attempts"] == 0, stats
PY
python3 - "$socket" "$guest" "$script_dir" <<'PY'
import array
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile

socket_path, source_path, script_dir = sys.argv[1:]
sys.path.insert(0, script_dir)
from tb_key_set import write_key_set
with open(source_path, "rb") as source:
    source.seek(24)
    entry = struct.unpack("<Q", source.read(8))[0]
    source.seek(32)
    phoff = struct.unpack("<Q", source.read(8))[0]
    source.seek(54)
    phentsize, phnum = struct.unpack("<HH", source.read(4))
    bases = []
    for index in range(phnum):
        source.seek(phoff + index * phentsize)
        phdr = source.read(phentsize)
        if struct.unpack_from("<I", phdr)[0] == 1:
            bases.append(struct.unpack_from("<Q", phdr, 16)[0])
entry_rva = entry - min(bases)
with tempfile.NamedTemporaryFile() as tbset:
    write_key_set(Path(source_path), Path(tbset.name), [(entry_rva + 5, 3)])
    source_fd = os.open(source_path, os.O_RDONLY)
    tbset_fd = os.open(tbset.name, os.O_RDONLY)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.connect(socket_path)
    request = struct.pack("=IHHIIQQ", 0x4c415444, 2, 32, 1, 100, 103, 103)
    connection.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array("i", [source_fd, tbset_fd]))])
    response = connection.recv(264)
    assert len(response) == 264
    assert struct.unpack_from("=i", response, 8)[0] == 0
    connection.close()
    os.close(source_fd)
    os.close(tbset_fd)
PY
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/compact-flush.client"
grep -q '^status=0$' "$phase/compact-flush.client"
wait_stats 's["compiled"] == 2 and s["active_jobs"] == 0'
python3 - "$cache" "$guest" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

cache, source = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from tb_key_set import read_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
with source.open("rb") as elf:
    elf.seek(24)
    entry = struct.unpack("<Q", elf.read(8))[0]
    elf.seek(32)
    phoff = struct.unpack("<Q", elf.read(8))[0]
    elf.seek(54)
    phentsize, phnum = struct.unpack("<HH", elf.read(4))
    bases = []
    for index in range(phnum):
        elf.seek(phoff + index * phentsize)
        phdr = elf.read(phentsize)
        if struct.unpack_from("<I", phdr)[0] == 1:
            bases.append(struct.unpack_from("<Q", phdr, 16)[0])
entry_rva = entry - min(bases)
current = json.loads((cache / f"{source_sha}.current").read_text())
_, sequence, records = read_key_set(cache / current["tbset"])
assert sequence >= 2, sequence
assert records == [(entry_rva, 3), (entry_rva + 5, 3)], records
assert current["version"] == 2, current
assert (cache / current["native"]).is_file(), current
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 2
assert len(list(cache.glob(f"{source_sha}-*.native"))) == 2
assert len(list(cache.glob(f"{source_sha}-*.tbset"))) == 2
old = json.loads((cache.parent / "initial-generation.json").read_text())
assert all(hashlib.sha256((cache / name).read_bytes()).hexdigest() == digest
           for name, digest in old.items()), old
PY
set +e
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_STRICT=1 \
LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 LATC_STRICT_AOT=1 \
LATC_STATS_OUT="$phase/incremented.stats.json" \
  "$runner" "$guest" >"$phase/incremented.stdout" \
  2>"$phase/incremented.stderr"
strict_status=$?
set -e
test "$strict_status" -eq 42
python3 - "$phase/incremented.stats.json" <<'PY'
import json
import sys
stats = json.load(open(sys.argv[1]))
assert stats["runtime_file_tb_gen_calls"] == 0, stats
assert stats["runtime_file_tb_gen_attempts"] == 0, stats
PY
stop_service

native_aware_counter=$work/native-aware-compiler.count
native_aware_compiler=$work/native-aware-latc
printf '%s\n' '#!/bin/sh' 'set -eu' \
  "if [ \"\${1:-}\" = build-id ]; then exec $latc \"\$@\"; fi" \
  "printf 'compile\\n' >>$native_aware_counter" \
  "exec $latc \"\$@\"" >"$native_aware_compiler"
chmod 755 "$native_aware_compiler"
start_service native-aware "$native_aware_compiler" --flush-only
submit_source "$socket" "$guest" "$phase/initial.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/initial-flush.client"
test "$(wc -l <"$native_aware_counter")" -eq 1
python3 - "$cache" "$guest" "$phase/initial-generation.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, output = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
output.write_text(json.dumps({name: manifest[name]
                              for name in ("module", "native")},
                             sort_keys=True))
(cache.parent / "initial-files.json").write_text(json.dumps({
    manifest[role]: hashlib.sha256((cache / manifest[role]).read_bytes()).hexdigest()
    for role in ("module", "native", "tbset")}))
PY
python3 - "$cache" "$guest" "$phase/covered.tbset" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

cache, source, output = map(Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set, write_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
_, _, records = read_key_set(cache / manifest["tbset"])
assert len(records) == 1
module = (cache / manifest["module"]).read_bytes()
section_offset = struct.unpack_from("<Q", module, 40)[0]
section_size, section_count, names_index = struct.unpack_from("<HHH", module, 58)
sections = [struct.unpack_from("<IIQQQQIIQQ", module,
                               section_offset + index * section_size)
            for index in range(section_count)]
names = sections[names_index]
name_data = module[names[4]:names[4] + names[5]]
tb_section = next(section for section in sections
                  if name_data[section[0]:].split(b"\0", 1)[0] ==
                     b".rodata.lat.tb")
tb_data = module[tb_section[4]:tb_section[4] + tb_section[5]]
module_keys = [(rva, flags) for rva, _, _, flags in
               struct.iter_unpack("<QQII", tb_data)]
covered = next(key for key in module_keys if key not in records)
write_key_set(source, output, [covered])
PY
"$latcd" --submit --socket "$socket" --tbset "$phase/covered.tbset" \
  "$guest" >"$phase/covered.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/covered-flush.client"
grep -q '^status=0$' "$phase/covered-flush.client"
test "$(wc -l <"$native_aware_counter")" -eq 1
python3 - "$cache" "$guest" "$phase/initial-generation.json" \
  "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, initial = map(Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
assert {name: manifest[name] for name in ("module", "native")} == \
       json.loads(initial.read_text())
_, _, records = read_key_set(cache / manifest["tbset"])
assert len(records) == 2, records
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.native"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.tbset"))) == 2
old = json.loads((cache.parent / "initial-files.json").read_text())
assert all(hashlib.sha256((cache / name).read_bytes()).hexdigest() == digest
           for name, digest in old.items()), old
PY
stop_service

retained_marker=$work/retained-coverage.marker
retained_compiler=$work/retained-coverage-latc
retained_trace=$work/retained-coverage.trace
printf '%s\n' '#!/bin/sh' 'set -eu' \
  "if [ \"\${1:-}\" = build-id ]; then exec $latc \"\$@\"; fi" \
  "if [ -e $retained_marker ]; then" \
  "  if [ -n \"\${LATC_NATIVE_BASE:-}\" ]; then" \
  "    printf 'incremental-failure\\n' >>$retained_trace" \
  '    exit 1' \
  '  fi' \
  "  printf 'full-rebuild\\n' >>$retained_trace" \
  '  export LATC_TBSET_CLOSURE_LIMIT=0 LATC_TBSET_SELECTION=bounded' \
  'fi' \
  "exec $latc \"\$@\"" >"$retained_compiler"
chmod 755 "$retained_compiler"
start_service retained-coverage "$retained_compiler" --flush-only
submit_source "$socket" "$guest" "$phase/initial.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/initial-flush.client"
retained_sha=$(sha256sum "$guest" | cut -d ' ' -f 1)
retained_old_module=$(python3 - "$cache/$retained_sha.current" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["module"])
PY
)
"$latc" emit-module-tbset "$cache/$retained_old_module" \
  -o "$phase/old-actual.tbset"
python3 - "$cache" "$guest" "$phase" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, phase = map(Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set, write_key_set
sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{sha}.current").read_text())
_, _, observed = read_key_set(cache / manifest["tbset"])
_, _, actual = read_key_set(phase / "old-actual.tbset")
assert set(actual) - set(observed), (actual, observed)
delta = (observed[0][0] + 5, 3)
assert delta not in actual, (delta, actual)
write_key_set(source, phase / "delta.tbset", [delta])
PY
touch "$retained_marker"
"$latcd" --submit --socket "$socket" --tbset "$phase/delta.tbset" \
  "$guest" >"$phase/delta.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/rebuilt-flush.client"
grep -q '^status=0$' "$phase/rebuilt-flush.client"
test "$(sed -n '1p' "$retained_trace")" = incremental-failure
test "$(sed -n '2p' "$retained_trace")" = full-rebuild
test "$(wc -l <"$retained_trace")" -eq 2
retained_new_module=$(python3 - "$cache/$retained_sha.current" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["module"])
PY
)
"$latc" emit-module-tbset "$cache/$retained_new_module" \
  -o "$phase/new-actual.tbset"
python3 - "$phase" "$script_dir" <<'PY'
from pathlib import Path
import sys

phase = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from tb_key_set import read_key_set
_, _, old = read_key_set(phase / "old-actual.tbset")
_, _, delta = read_key_set(phase / "delta.tbset")
_, _, new = read_key_set(phase / "new-actual.tbset")
assert set(old) | set(delta) <= set(new), (old, delta, new)
PY
stop_service

atomic_marker=$work/atomic-before-manifest.fail
export LATCD_TEST_FAIL_BEFORE_MANIFEST=$atomic_marker
start_service atomic "$latc" --flush-only --negative-ms 10
submit_source "$socket" "$guest" "$phase/initial.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/initial-flush.client"
grep -q '^status=0$' "$phase/initial-flush.client"
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, output = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
state = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
         for path in paths}
output.write_text(json.dumps(state, sort_keys=True))
PY
python3 - "$cache" "$guest" "$phase/delta.tbset" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, output = map(Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set, write_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
_, _, records = read_key_set(cache / manifest["tbset"])
assert records
write_key_set(source, output, [(records[0][0] + 5, 3)])
PY
"$latcd" --submit --socket "$socket" --tbset "$phase/delta.tbset" \
  "$guest" >"$phase/delta.client"
touch "$atomic_marker"
set +e
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/failed-flush.client"
atomic_status=$?
set -e
test "$atomic_status" -ne 0
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, snapshot = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
expected = json.loads(snapshot.read_text())
actual = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
          for path in paths}
assert actual == expected, (actual, expected)
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.native"))) == 1
assert len(list(cache.glob(f"{source_sha}-*.tbset"))) == 1
PY
sleep 0.05
"$latcd" --submit --socket "$socket" --tbset "$phase/delta.tbset" \
  "$guest" >"$phase/retry.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/retry-flush.client"
grep -q '^status=0$' "$phase/retry-flush.client"
python3 - "$cache" "$guest" "$script_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source = map(Path, sys.argv[1:3])
sys.path.insert(0, sys.argv[3])
from tb_key_set import read_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
_, _, records = read_key_set(cache / manifest["tbset"])
assert {flags for _, flags in records} == {3}, records
assert len(list(cache.glob(f"{source_sha}-*.so"))) == 2
assert len(list(cache.glob(f"{source_sha}-*.native"))) == 2
assert len(list(cache.glob(f"{source_sha}-*.tbset"))) == 2
old = json.loads((cache.parent / "published.json").read_text())
assert all(hashlib.sha256((cache / name).read_bytes()).hexdigest() == digest
           for name, digest in old.items() if not name.endswith(".current")), old
PY
stop_service
unset LATCD_TEST_FAIL_BEFORE_MANIFEST

start_service negative "$script_dir/fake-latc-fail.sh" --negative-ms 500
python3 - "$socket" <<'PY'
import socket
import struct
import sys
import time

connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
connection.connect(sys.argv[1])
time.sleep(1.2)
response = connection.recv(264)
assert len(response) == 264
assert struct.unpack_from("=i", response, 8)[0] == 1
connection.close()
PY
submit_source "$socket" "$guest" "$phase/first.client"
wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
if submit_source "$socket" "$guest" "$phase/second.client" 2>&1; then
    echo "negative cache accepted immediate retry" >&2
    exit 1
fi
grep -q '^status=7$' "$phase/second.client"
wait_stats 's["negative_hits"] == 1'
stop_service

start_service cpu-limit "$script_dir/fake-latc-cpu.sh" --cpu-seconds 1
submit_source "$socket" "$guest" "$phase/client"
wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
grep -q 'compiler terminated by signal' "$phase/server.stderr" || true
stop_service

cpu_hard=$(ulimit -Ht)
if [ "$cpu_hard" = "unlimited" ]; then
    cpu_expected=1200
else
    cpu_expected=$cpu_hard
    [ "$cpu_expected" -lt 1200 ] || cpu_expected=1200
fi
start_service cpu-default "$script_dir/fake-latc-cpu-report.sh"
submit_source "$socket" "$guest" "$phase/client"
wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
grep -q "^FAKE_CPU_SOFT=$cpu_expected$" "$phase/server.stderr"
stop_service

if [ "$cpu_hard" = "unlimited" ] || [ "$cpu_hard" -ge 60 ]; then
    (
        ulimit -t 60
        start_service cpu-clamped "$script_dir/fake-latc-cpu-report.sh"
        submit_source "$socket" "$guest" "$phase/client"
        wait_stats 's["failed"] == 1 and s["active_jobs"] == 0'
        grep -q '^FAKE_CPU_SOFT=60$' "$phase/server.stderr"
        grep -q 'CPU limit 1200 exceeds inherited hard limit 60' \
            "$phase/server.stderr"
        stop_service
    )
fi

cp "$guest" "$work/a.elf"
cp "$guest" "$work/b.elf"
cp "$guest" "$work/c.elf"
cp "$guest" "$work/d.elf"
printf a >>"$work/a.elf"
printf b >>"$work/b.elf"
printf c >>"$work/c.elf"
printf d >>"$work/d.elf"
start_service priority "$script_dir/fake-latc-slow.sh" --max-jobs 2
submit_source "$socket" "$work/a.elf" "$phase/a.client" --priority 0
wait_stats 's["active_jobs"] == 1 and s["queue_depth"] == 0'
submit_source "$socket" "$work/b.elf" "$phase/b.client" --priority 1
submit_source "$socket" "$work/c.elf" "$phase/c.client" --priority 200
wait_stats 's["queue_depth"] == 2'
if submit_source "$socket" "$work/d.elf" "$phase/d.client" --priority 1 \
     2>&1; then
    echo "full compiler queue accepted another request" >&2
    exit 1
fi
grep -q '^status=6$' "$phase/d.client"
wait_stats 's["compiled"] == 3 and s["active_jobs"] == 0'
b_sha=$(sha256sum "$work/b.elf" | cut -d ' ' -f 1)
c_sha=$(sha256sum "$work/c.elf" | cut -d ' ' -f 1)
python3 - "$cache" "$b_sha" "$c_sha" <<'PY'
import json
import os
from pathlib import Path
import sys
cache = Path(sys.argv[1])
b = json.loads((cache / f"{sys.argv[2]}.current").read_text())["module"]
c = json.loads((cache / f"{sys.argv[3]}.current").read_text())["module"]
assert os.stat(cache / c).st_mtime_ns < os.stat(cache / b).st_mtime_ns
PY
wait_stats 's["queue_full"] == 1 and s["compiled"] == 3'
stop_service

source_size=$(wc -c <"$work/b.elf")
start_service shutdown "$script_dir/fake-latc-cpu.sh" --cpu-seconds 60 \
  --max-jobs 10 --max-queue-bytes "$source_size"
submit_source "$socket" "$work/a.elf" "$phase/a.client"
wait_stats 's["active_jobs"] == 1 and s["queue_depth"] == 0'
submit_source "$socket" "$work/b.elf" "$phase/b.client"
wait_stats 's["queue_depth"] == 1 and s["queue_bytes"] > 0'
if submit_source "$socket" "$work/c.elf" "$phase/c.client" 2>&1; then
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

compile_failure_compiler=$work/compile-failure-latc
printf '%s\n' '#!/bin/sh' 'set -eu' \
  "if [ \"\${1:-}\" = build-id ]; then exec $latc \"\$@\"; fi" \
  'if [ -n "${LATC_NATIVE_BASE:-}" ]; then exit 1; fi' \
  "exec $latc \"\$@\"" >"$compile_failure_compiler"
chmod 755 "$compile_failure_compiler"
start_service compile-failure "$compile_failure_compiler"
submit_source "$socket" "$guest" "$phase/initial.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/initial-flush.client"
grep -q '^status=0$' "$phase/initial-flush.client"
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, output = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
output.write_text(json.dumps(
    {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
     for path in paths}, sort_keys=True))
PY
python3 - "$cache" "$guest" "$phase/delta.tbset" "$script_dir" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

cache, source, output = map(Path, sys.argv[1:4])
sys.path.insert(0, sys.argv[4])
from tb_key_set import read_key_set, write_key_set
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
_, _, records = read_key_set(cache / manifest["tbset"])
candidate = records[0][0] + 5
assert candidate not in {rva for rva, _ in records}, records
write_key_set(source, output, [(candidate, 3)])
PY
"$latcd" --submit --socket "$socket" --tbset "$phase/delta.tbset" \
  "$guest" >"$phase/delta.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/fallback-flush.client"
grep -q '^status=0$' "$phase/fallback-flush.client"
grep -q 'incremental compile failed, retrying full compile' \
  "$phase/server.stderr"
wait_stats 's["compiled"] == 2 and s["failed"] == 0 and s["active_jobs"] == 0'
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, snapshot = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
expected = json.loads(snapshot.read_text())
actual = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
          for path in paths}
assert actual != expected, (actual, expected)
print(cache / manifest["module"])
PY
module=$(python3 - "$cache" "$guest" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest = json.loads((cache / f"{source_sha}.current").read_text())
print(cache / manifest["module"])
PY
)
"$latc" inspect-module --json "$module" >"$phase/module.json"
stop_service

start_service capacity "$latc" --max-cache-bytes 268435456
submit_source "$socket" "$guest" "$phase/a.client"
"$latcd" --flush-source --socket "$socket" "$guest" \
  >"$phase/a-flush.client"
grep -q '^status=0$' "$phase/a-flush.client"
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, output = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
output.write_text(json.dumps(
    {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
     for path in paths}, sort_keys=True))
PY
orphan=$cache/0000000000000000000000000000000000000000000000000000000000000000-1111111111111111111111111111111111111111111111111111111111111111.native
truncate -s 268429312 "$orphan"
cp "$guest" "$work/capacity-b.elf"
printf z >>"$work/capacity-b.elf"
if submit_source "$socket" "$work/capacity-b.elf" "$phase/b.client"; then
    echo "unsafe capacity admission unexpectedly accepted" >&2
    exit 1
fi
grep -q '^accepted_sequence=0$' "$phase/b.client"
grep -q 'capacity:' "$phase/b.client"
"$latcd" --flush-source --socket "$socket" "$guest" >"$phase/a-reflush.client"
grep -q '^status=0$' "$phase/a-reflush.client"
wait_stats 's["failed"] == 0 and s["active_jobs"] == 0 and not s["generation_capacity_ready"]'
python3 - "$cache" "$guest" "$phase/published.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

cache, source, snapshot = map(Path, sys.argv[1:])
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
manifest_path = cache / f"{source_sha}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name]
                           for name in ("module", "native", "tbset")]
expected = json.loads(snapshot.read_text())
actual = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
          for path in paths}
assert actual == expected, (actual, expected)
PY
stop_service
start_service legacy-lock-prepare "$latc"
submit_source "$socket" "$guest" "$phase/submit.client"
"$latcd" --flush-source --socket "$socket" "$guest" >"$phase/flush.client"
legacy_cache=$cache
legacy_sha=$(sha256sum "$guest" | cut -d ' ' -f 1)
stop_service
python3 - "$legacy_cache" "$legacy_sha" "$phase/legacy-snapshot.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
cache, source, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
manifest_path = cache / f"{source}.current"
manifest = json.loads(manifest_path.read_text())
paths = [manifest_path] + [cache / manifest[name] for name in ("module", "native", "tbset")]
output.write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}))
PY
legacy_snapshot=$phase/legacy-snapshot.json
rm "$legacy_cache/.gc/source-locks/$legacy_sha.lock"
legacy_phase=$work/legacy-lock-online
mkdir -m 700 "$legacy_phase"
socket=$legacy_phase/latcd.sock
stats=$legacy_phase/stats.json
"$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$legacy_phase/server.stdout" 2>"$legacy_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
for reader in 1 2; do
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$legacy_cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" \
LATX_AOT_V2_AUTOSTART=0 LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 \
LATX_AOT_V2_TEST_LOCK_MISSING_READY="$legacy_phase/missing-$reader.ready" \
LATX_AOT_V2_TEST_LOCK_MISSING_RELEASE="$legacy_phase/missing.release" \
LATX_AOT_V2_TEST_SOURCE_LATCH_READY="$legacy_phase/reader-$reader.ready" \
LATX_AOT_V2_TEST_SOURCE_LATCH_RELEASE="$legacy_phase/reader-$reader.release" \
LATC_DISABLE_PRETRANSLATE=1 LATC_STRICT_AOT=1 \
  timeout 60 "$runner" "$guest" >"$legacy_phase/reader-$reader.stdout" \
    2>"$legacy_phase/reader-$reader.stderr" &
eval "legacy_reader_$reader=$!"
done
for reader in 1 2; do
  eval "reader_pid=\$legacy_reader_$reader"
  n=0
  while [ ! -e "$legacy_phase/missing-$reader.ready" ] && kill -0 "$reader_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 3000; sleep 0.01
  done
  test -e "$legacy_phase/missing-$reader.ready"
done
test ! -e "$legacy_cache/.gc/source-locks/$legacy_sha.lock"
touch "$legacy_phase/missing.release"
for reader in 1 2; do
  eval "reader_pid=\$legacy_reader_$reader"
  n=0
  while [ ! -e "$legacy_phase/reader-$reader.ready" ] && kill -0 "$reader_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 3000; sleep 0.01
  done
  test -e "$legacy_phase/reader-$reader.ready"
done
legacy_latch=$legacy_cache/.gc/source-locks/$legacy_sha.lock
if flock -n "$legacy_latch" -c true; then
    echo "online readers did not hold the source latch" >&2
    exit 1
fi
for reader in 1 2; do
  touch "$legacy_phase/reader-$reader.release"
  eval "reader_pid=\$legacy_reader_$reader"
  set +e
  wait "$reader_pid"
  runner_status=$?
  set -e
  test "$runner_status" -eq 42
  grep -q 'module=registered' "$legacy_phase/reader-$reader.stderr"
  eval "legacy_reader_$reader="
done
flock -n "$legacy_latch" -c true
wait_stats 's["generation_capacity_ready"]'
cp "$guest" "$legacy_phase/new-source.elf"
printf x >>"$legacy_phase/new-source.elf"
submit_source "$socket" "$legacy_phase/new-source.elf" "$legacy_phase/new-source.client"
"$latcd" --flush-source --socket "$socket" "$legacy_phase/new-source.elf" \
  >"$legacy_phase/new-source-flush.client"
grep -q '^status=0$' "$legacy_phase/new-source-flush.client"
wait_stats 's["generation_capacity_ready"]'
python3 - "$legacy_cache" "$legacy_snapshot" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
cache, snapshot = map(Path, sys.argv[1:])
expected = json.loads(snapshot.read_text())
assert {name: hashlib.sha256((cache / name).read_bytes()).hexdigest()
        for name in expected} == expected
PY
stop_service
rm "$legacy_latch"
drop_phase=$work/legacy-lock-drop-reply
mkdir -m 700 "$drop_phase"
socket=$drop_phase/latcd.sock
stats=$drop_phase/stats.json
LATCD_TEST_DROP_SOURCE_LOCK_REPLY=1 "$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$drop_phase/server.stdout" 2>"$drop_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
set +e
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$legacy_cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 timeout 60 "$runner" "$guest" >"$drop_phase/runner.stdout" 2>"$drop_phase/runner.stderr"
runner_status=$?
set -e
test "$runner_status" -eq 42
test -f "$legacy_latch"
grep -q 'module=registered' "$drop_phase/runner.stderr"
grep -q 'test dropped source lock reply' "$drop_phase/server.stderr"
submit_source "$socket" "$legacy_phase/new-source.elf" "$drop_phase/new-source.client"
"$latcd" --flush-source --socket "$socket" "$legacy_phase/new-source.elf" >"$drop_phase/flush.client"
grep -q '^status=0$' "$drop_phase/flush.client"
wait_stats 's["generation_capacity_ready"]'
stop_service
rm "$legacy_latch"
for crash_point in before after; do
crash_phase=$work/legacy-lock-request-crash-$crash_point
mkdir -m 700 "$crash_phase"
socket=$crash_phase/latcd.sock
stats=$crash_phase/stats.json
if [ "$crash_point" = before ]; then
    crash_variable=LATCD_TEST_CRASH_BEFORE_SOURCE_LOCK=1
    expected_crash=86
    crash_message='test crash before source lock creation'
else
    crash_variable=LATCD_TEST_CRASH_CREATED_LOCK=$legacy_sha.lock
    expected_crash=87
    crash_message='test crash after source lock creation'
fi
env "$crash_variable" "$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$crash_phase/server.stdout" 2>"$crash_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
set +e
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$legacy_cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 timeout 60 "$runner" "$guest" >"$crash_phase/runner.stdout" 2>"$crash_phase/runner.stderr"
runner_status=$?
wait "$server_pid"
crash_status=$?
set -e
server_pid=
test "$crash_status" -eq "$expected_crash"
grep -q "$crash_message" "$crash_phase/server.stderr"
test "$runner_status" -eq 42
test -f "$legacy_latch"
grep -q 'module=registered' "$crash_phase/runner.stderr"
socket=$crash_phase/restart.sock
stats=$crash_phase/restart-stats.json
"$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$crash_phase/restart.stdout" 2>"$crash_phase/restart.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
submit_source "$socket" "$legacy_phase/new-source.elf" "$crash_phase/restart.client"
"$latcd" --flush-source --socket "$socket" "$legacy_phase/new-source.elf" >"$crash_phase/restart-flush.client"
grep -q '^status=0$' "$crash_phase/restart-flush.client"
wait_stats 's["generation_capacity_ready"]'
stop_service
rm "$legacy_latch"
done
offline_phase=$work/legacy-lock-daemon-exit
mkdir -m 700 "$offline_phase"
socket=$offline_phase/latcd.sock
stats=$offline_phase/stats.json
"$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$offline_phase/server.stdout" 2>"$offline_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$legacy_cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 LATX_AOT_V2_TEST_LOCK_MISSING_READY="$offline_phase/missing.ready" \
LATX_AOT_V2_TEST_LOCK_MISSING_RELEASE="$offline_phase/missing.release" \
  timeout 60 "$runner" "$guest" >"$offline_phase/runner.stdout" 2>"$offline_phase/runner.stderr" &
legacy_reader_1=$!
n=0
while [ ! -e "$offline_phase/missing.ready" ] && kill -0 "$legacy_reader_1" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 3000; sleep 0.01
done
test -e "$offline_phase/missing.ready"
test ! -e "$legacy_latch"
stop_service
touch "$offline_phase/missing.release"
set +e
wait "$legacy_reader_1"
runner_status=$?
set -e
legacy_reader_1=
test "$runner_status" -eq 42
test -f "$legacy_latch"
grep -q 'module=registered' "$offline_phase/runner.stderr"
restart_phase=$work/legacy-lock-restart
mkdir -m 700 "$restart_phase"
socket=$restart_phase/latcd.sock
stats=$restart_phase/stats.json
"$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$restart_phase/server.stdout" 2>"$restart_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
submit_source "$socket" "$legacy_phase/new-source.elf" "$restart_phase/new-source.client"
"$latcd" --flush-source --socket "$socket" "$legacy_phase/new-source.elf" \
  >"$restart_phase/new-source-flush.client"
grep -q '^status=0$' "$restart_phase/new-source-flush.client"
python3 - "$legacy_cache" "$legacy_snapshot" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
cache, snapshot = map(Path, sys.argv[1:])
expected = json.loads(snapshot.read_text())
assert {name: hashlib.sha256((cache / name).read_bytes()).hexdigest()
        for name in expected} == expected
PY
stop_service
direct_phase=$work/legacy-direct-no-current
mkdir -m 700 "$direct_phase"
direct_current=$legacy_cache/$legacy_sha.current
direct_hidden=$direct_phase/current.saved
direct_module=$(python3 - "$direct_current" "$legacy_cache" <<'PY'
import json, sys
from pathlib import Path
print(Path(sys.argv[2]) / json.loads(Path(sys.argv[1]).read_text())["module"])
PY
)
mv "$direct_current" "$direct_hidden"
rm "$legacy_latch"
socket=$direct_phase/latcd.sock
stats=$direct_phase/stats.json
"$latcd" --serve --socket "$socket" --cache-dir "$legacy_cache" \
  --latc "$latc" --runner "$runner" --runtime-dir "$runtime_dir" \
  --stats "$stats" --workers 1 >"$direct_phase/server.stdout" 2>"$direct_phase/server.stderr" &
server_pid=$!
n=0
while [ ! -S "$socket" ] && kill -0 "$server_pid" 2>/dev/null; do
    n=$((n + 1)); test "$n" -lt 500; sleep 0.01
done
test -S "$socket"
wait_stats 's["generation_capacity_ready"]'
set +e
LD_LIBRARY_PATH="$runtime_dir" LATX_AOT_V2_CACHE_DIR="$legacy_cache" \
LATX_AOT_V2_LATCD_SOCKET="$socket" LATX_AOT_V2_AUTOSTART=0 \
LATX_AOT_V2_MODULE="$direct_module" LATX_AOT_V2_SOURCE="$guest" \
LATX_AOT_V2_STRICT=1 LATX_AOT_V2_REPORT=1 LATC_DISABLE_PRETRANSLATE=1 \
LATC_STRICT_AOT=1 timeout 60 "$runner" "$guest" >"$direct_phase/runner.stdout" 2>"$direct_phase/runner.stderr"
runner_status=$?
set -e
test "$runner_status" -eq 42
grep -q 'registered module with' "$direct_phase/runner.stderr"
test -f "$legacy_latch"
wait_stats 'not s["generation_capacity_ready"]'
stop_service
mv "$direct_hidden" "$direct_current"
direct_hidden=
echo "test-latcd-service: PASS"
