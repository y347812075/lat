#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
build="$root/build64"
service_user=
service_uid=
service_gid=
client_home=
client_group=
cache_dir=
client_uid=${LAT_AOT_CLIENT_UID:-${SUDO_UID:-$(stat -c %u "$root")}}
config_dir=/etc/lat-aot-v2
managed_config="$config_dir/managed.json"
client_env="$config_dir/client.env"
state_dir=/var/lib/lat-aot-v2
admin_dir="$state_dir/admin"
run_dir=/run/lat-aot-v2
unit_file=/etc/systemd/system/lat-aot-v2-latcd.service
worker_cgroup=/sys/fs/cgroup/system.slice/lat-aot-v2-latcd.service
dry_run=0
case ${1:-} in
    '') [[ $# == 0 ]] || exit 2 ;;
    --dry-run) [[ $# == 1 ]] || exit 2; dry_run=1 ;;
    --help|-h)
        printf 'Usage: sudo %s\n       %s --dry-run\nInstalls build64 products and configures the managed AOT v2 daemon with automatic retirement enabled.\n' "$0" "$0"
        exit ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac
[[ $dry_run == 1 || $EUID == 0 ]] || {
    printf 'Run with sudo, or use --dry-run.\n' >&2; exit 1;
}
options="$build/meson-info/intro-buildoptions.json"
[[ -f $options ]] || { printf 'Missing build64 configuration.\n' >&2; exit 1; }
[[ $client_uid =~ ^[1-9][0-9]*$ ]] || {
    printf 'A non-root client UID is required (SUDO_UID or LAT_AOT_CLIENT_UID).\n' >&2
    exit 1
}
client_record=$(getent passwd "$client_uid") || {
    printf 'Client UID does not exist: %s\n' "$client_uid" >&2
    exit 1
}
IFS=: read -r service_user _ _ _ _ client_home _ <<< "$client_record"
service_uid=$client_uid
service_gid=$(id -g "$service_user")
client_group=$(id -gn "$service_user")
[[ $client_home == /* ]] || {
    printf 'Client account has no absolute home directory: %s\n' "$service_user" >&2
    exit 1
}
build_id=$($build/latc build-id)
[[ $build_id =~ ^[0-9a-f]{64}$ ]] || {
    printf 'Invalid LATC build identity: %s\n' "$build_id" >&2
    exit 1
}
cache_dir="$client_home/.cache/lat-aot-v2/$build_id/live"
mapfile -t directories < <(python3 - "$options" <<'PY'
import json
from pathlib import PurePosixPath
import sys
options = {entry['name']: entry['value'] for entry in json.load(open(sys.argv[1]))}
prefix = PurePosixPath(options['prefix'])
for key in ('bindir', 'libdir', 'libexecdir'):
    path = PurePosixPath(options[key])
    path = path if path.is_absolute() else prefix / path
    expected = {'bindir': '/usr/bin', 'libdir': '/usr/lib',
                'libexecdir': '/usr/libexec'}
    if str(path) != expected[key]:
        raise ValueError('Rebuild with ./latxbuild/build64.sh -c: expected ' + expected[key])
    print(path)
PY
)
[[ ${#directories[@]} == 3 ]] || { printf 'Cannot read configured install paths.\n' >&2; exit 1; }
sources=()
destinations=()
modes=()
add() { sources+=("$1"); destinations+=("$2"); modes+=("$3"); }
for name in latc latcd latu-runtime-manager; do
    file="$build/$name"
    [[ $name == latu-runtime-manager ]] && file="$build/runtime/$name"
    add "$file" "/usr/bin/$name" 755
done
add "$build/latx-x86_64" /usr/libexec/latc/latx-x86_64 755
add "$build/latx-x86_64" /usr/bin/latx-x86_64 755
add "$build/latcd-worker-bootstrap" /usr/libexec/latc/latcd-worker-bootstrap 755
add "$build/liblat-aot-runtime.so.2" /usr/lib/liblat-aot-runtime.so.2 755
helper=/usr/libexec/latc
for name in compile-aot-v2-module.sh compile-native-image.sh compile-aot.sh link-aot-v2-module.sh; do
    add "$root/tools/latc/scripts/$name" "$helper/scripts/$name" 755
done
add "$root/tools/latc/aot-v2/include/lat-aot-v2.h" "$helper/aot-v2/include/lat-aot-v2.h" 644
add "$root/tools/latc/aot-v2/compiler/module.map" "$helper/aot-v2/compiler/module.map" 644
unit_source="$root/tools/latc/scripts/lat-aot-v2-latcd.service.in"
binfmt_source="$root/latxbuild/debian/x86_64.conf"
# Check all sources before copying anything.
for file in "${sources[@]}"; do
    [[ -f $file ]] || { printf 'Missing source: %s\n' "$file" >&2; exit 1; }
done
for file in "$unit_source" "$binfmt_source"; do
    [[ -f $file ]] || { printf 'Missing source: %s\n' "$file" >&2; exit 1; }
done
for i in "${!sources[@]}"; do
    printf '%s -> %s\n' "${sources[i]}" "${destinations[i]}"
    if [[ $dry_run == 0 ]]; then
        destination=${destinations[i]}
        install -d -m 755 "$(dirname "$destination")"
        temporary=$(mktemp "$(dirname "$destination")/.lat-copy.XXXXXXXX")
        trap 'rm -f -- "$temporary"' EXIT
        install -m "${modes[i]}" -o root -g root "${sources[i]}" "$temporary"
        mv -fT -- "$temporary" "$destination"
        trap - EXIT
    fi
done

if [[ $dry_run == 1 ]]; then
    printf 'Would run the managed system service as: %s (UID %s)\n' "$service_user" "$service_uid"
    printf 'Would initialize managed cache: %s\n' "$cache_dir"
    printf 'Would write managed config: %s\n' "$managed_config"
    printf 'Would write client environment: %s\n' "$client_env"
    printf 'Would install and enable: %s\n' "$unit_file"
    printf 'Would register binfmt interpreter: /usr/bin/latx-x86_64\n'
    exit 0
fi

getent passwd "$client_uid" >/dev/null || {
    printf 'Client UID does not exist: %s\n' "$client_uid" >&2
    exit 1
}

install -d -m 755 -o root -g root "$config_dir" /etc/binfmt.d
install -d -m 755 -o root -g root "$state_dir"
for directory in "$client_home/.cache" "$client_home/.cache/lat-aot-v2" \
    "$client_home/.cache/lat-aot-v2/$build_id" "$cache_dir"; do
    [[ ! -L $directory ]] || {
        printf 'Cache path component must not be a symlink: %s\n' "$directory" >&2
        exit 1
    }
done
runuser -u "$service_user" -- sh -c 'umask 077; mkdir -p -- "$1"' sh "$cache_dir"
[[ -d $cache_dir && $(stat -c %u:%a "$cache_dir") == "$service_uid:700" ]] || {
    printf 'Cache directory must be owned by UID %s with mode 0700: %s\n' "$service_uid" "$cache_dir" >&2
    exit 1
}
install -d -m 700 -o "$service_uid" -g "$service_gid" "$admin_dir"
install -d -m 755 -o "$service_uid" -g "$service_gid" "$run_dir"

temporary_config=$(mktemp "$config_dir/.managed.XXXXXXXX")
temporary_env=$(mktemp "$config_dir/.client.XXXXXXXX")
temporary_unit=$(mktemp "/etc/systemd/system/.lat-aot-v2-latcd.XXXXXXXX")
trap 'rm -f -- "$temporary_config" "$temporary_env" "$temporary_unit"' EXIT
python3 - "$temporary_config" "$service_uid" "$client_uid" "$cache_dir" \
    "$admin_dir" "$run_dir" "$worker_cgroup" <<'PY'
import json
import sys

path, service_uid, client_uid, cache, admin, broker, cgroup = sys.argv[1:]
config = {
    "service_uid": service_uid,
    "client_uid": client_uid,
    "cache": cache,
    "admin": admin,
    "broker": broker,
    "compiler": "/usr/bin/latc",
    "runner": "/usr/libexec/latc/latx-x86_64",
    "runtime": "/usr/lib",
    "worker_cgroup": cgroup,
    "worker_bwrap": "/usr/bin/bwrap",
    "worker_bootstrap": "/usr/libexec/latc/latcd-worker-bootstrap",
    "worker_toolroot": "/usr",
    "automatic_retirement": True,
    "retirement_grace_us": 600000000,
}
with open(path, "w", encoding="ascii") as output:
    json.dump(config, output, separators=(",", ":"), sort_keys=True)
    output.write("\n")
PY
printf '%s\n' \
    'LATX_AOT_V2_AUTOSTART=0' \
    'LATX_AOT_V2_KEY_JOURNAL=1' \
    'LATX_AOT_V2_JOURNAL_BROKER=/run/lat-aot-v2/broker.sock' \
    "LATX_AOT_V2_JOURNAL_BROKER_UID=$service_uid" \
    'LATX_AOT_V2_REPORT=1' > "$temporary_env"
sed -e "s|@SERVICE_USER@|$service_user|g" \
    -e "s|@SERVICE_GROUP@|$client_group|g" \
    -e "s|@CACHE_DIR@|$cache_dir|g" "$unit_source" > "$temporary_unit"
install -m 444 -o root -g root "$temporary_config" "$managed_config"
install -m 444 -o root -g root "$temporary_env" "$client_env"
install -m 644 -o root -g root "$temporary_unit" "$unit_file"
install -m 644 -o root -g root "$binfmt_source" /etc/binfmt.d/x86_64.conf
trap - EXIT
rm -f -- "$temporary_config" "$temporary_env" "$temporary_unit"

if [[ ! -e "$cache_dir/.gc/domain.ini" ]]; then
    setpriv --no-new-privs --reuid="$service_uid" --regid="$service_gid" \
        --clear-groups /usr/bin/latcd gc --init-domain --cache-dir "$cache_dir"
fi

ldconfig
systemctl daemon-reload
systemctl enable lat-aot-v2-latcd.service >/dev/null
systemctl restart lat-aot-v2-latcd.service
if ! systemctl is-active --quiet lat-aot-v2-latcd.service; then
    journalctl -u lat-aot-v2-latcd.service -n 80 --no-pager >&2 || true
    exit 1
fi
for _ in $(seq 1 100); do
    [[ -S "$run_dir/broker.sock" ]] && break
    sleep 0.05
done
[[ -S "$run_dir/broker.sock" ]] || {
    printf 'Managed broker socket did not appear: %s\n' "$run_dir/broker.sock" >&2
    exit 1
}
systemctl restart systemd-binfmt.service

printf 'Done. Managed AOT v2 daemon is enabled; automatic retirement is on.\n'
printf 'Service user/client: %s (UID %s)\n' "$service_user" "$service_uid"
printf 'Cache: %s\nManaged config: %s\n' "$cache_dir" "$managed_config"
