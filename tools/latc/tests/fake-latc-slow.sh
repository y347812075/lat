#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
sleep 1
exec "$script_dir/../build/latc" "$@"
