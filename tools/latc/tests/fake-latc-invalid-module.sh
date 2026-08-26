#!/bin/sh
set -eu

output=
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ] && [ "$#" -gt 1 ]; then
        output=$2
        shift 2
    else
        shift
    fi
done
test -n "$output"
cp /bin/true "$output"
