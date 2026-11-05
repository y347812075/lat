#!/bin/sh
set -eu

mode_set=${LATX_AOT_V2+x}
mode=${LATX_AOT_V2-}
legacy_set=${LATX_AOT+x}
legacy=${LATX_AOT-}

set -a
. /etc/lat-aot-v2/client.env
set +a

if [ "$mode_set" = x ]; then export LATX_AOT_V2="$mode"; fi
if [ "$legacy_set" = x ]; then export LATX_AOT="$legacy"; fi

exec /usr/libexec/latc/latx-x86_64 "$@"
