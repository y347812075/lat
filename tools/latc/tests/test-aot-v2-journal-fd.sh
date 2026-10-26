#!/bin/sh
set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: $0 INSTALL_PREFIX GUEST_DIR WORKDIR [TEST_ARGS...]" >&2
    exit 2
fi
prefix=$1
guest_dir=$2
work=$3
shift 3
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ "${LATX_JOURNAL_FD_NAMESPACE_INSIDE:-}" != 1 ]; then
    exec env LATX_JOURNAL_FD_NAMESPACE_INSIDE=1 \
        unshare -Urm /usr/bin/bash "$0" "$prefix" "$guest_dir" "$work" "$@"
fi

mount --make-rprivate /
mount --bind "$prefix/bin/latx-x86_64" /usr/bin/latx-x86_64
mount --bind "$prefix/libexec/latc" /usr/libexec/latc
exec env LATX_JOURNAL_FD_NAMESPACE_INSIDE=1 \
    python3 "$script_dir/test-aot-v2-journal-fd.py" \
    "$prefix" "$guest_dir" "$work" "$@"
