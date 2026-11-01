#!/bin/sh
set -eu

module=0
config_replay=0
static_tbset=0
while :; do
    case "${1:-}" in
        --module) module=1; shift ;;
        --config-replay) config_replay=1; shift ;;
        --static-tbset) static_tbset=1; shift ;;
        *) break ;;
    esac
done
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 [--module | --config-replay] [--static-tbset] LATC RUNNER X86_GUEST OUTPUT [TBSET]" >&2
    exit 2
fi

latc=$1
runner=$2
guest=$3
output=$4
tbset=${5:-}

if [ "$config_replay" -eq 1 ] && { [ "$module" -eq 1 ] ||
   [ "$static_tbset" -eq 1 ] || [ -z "$tbset" ] ||
   [ -z "${LATC_TRANSLATION_CONFIG_FROM:-}" ]; }; then
    echo 'latc: config replay requires a configuration and explicit TB set' >&2
    exit 2
fi

unset LATC_NATIVE_STATIC_CHECK
if [ "$module" -eq 1 ] && [ -z "${LATC_TBSET_SELECTION+x}" ]; then
    export LATC_TBSET_SELECTION=bounded
fi
if [ "$module" -eq 1 ] && [ -z "${LATC_TBSET_CLOSURE_LIMIT+x}" ]; then
    export LATC_TBSET_CLOSURE_LIMIT=20000
fi
if [ -z "$tbset" ] || [ "$static_tbset" -eq 1 ] ||
   [ "${LATC_TBSET_SELECTION:-}" = exact-static ]; then
    export LATC_NATIVE_STATIC_CHECK=1
fi

case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac
work=$(mktemp -d "${TMPDIR:-/tmp}/latc-native.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

missing="$work/missing.tbset"
if [ "$config_replay" -eq 1 ] && [ -n "${LATC_NATIVE_BASE:-}" ] &&
   [ -e "$output" ] && [ "$output" -ef "$LATC_NATIVE_BASE" ]; then
    echo 'latc: output must differ from native base' >&2
    exit 1
fi
rm -f "$output"
if [ "$module" -eq 1 ] || [ "$config_replay" -eq 1 ]; then
    export LATC_NATIVE_ALLOW_MISSING=1
else
    unset LATC_NATIVE_ALLOW_MISSING
fi
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
compile_part()
(
    part=$1
    image=$2
    directory=$3
    mkdir "$directory"
    missing=$directory/missing.tbset
    status=0
    LATC_NATIVE_IMAGE_OUT="$image" LATC_NATIVE_MISSING_OUT="$missing" \
        "$script_dir/compile-aot.sh" "$latc" "$runner" "$guest" \
        "$directory/compile-bundle" "$part" >/dev/null || status=$?
    if [ "$status" -eq 0 ]; then
        test -s "$image"
        exit 0
    fi
    rm -f "$image"
    if [ "$module" -eq 1 ] && [ "$status" -eq 75 ]; then
        echo "latc: splitting exhausted native translation input" >&2
        "$latc" split-tbset "$part" "$directory/left.tbset" \
            "$directory/right.tbset" || exit 1
        compile_part "$directory/left.tbset" "$directory/left.native" \
            "$directory/left" || exit 1
        compile_part "$directory/right.tbset" "$directory/right.native" \
            "$directory/right" || exit 1
        "$latc" merge-native "$directory/left.native" \
            "$directory/right.native" -o "$image" || exit 1
        rm -f "$directory/left.native" "$directory/right.native"
        exit 0
    fi
    if [ -s "$missing" ]; then
        missing_count=$(wc -l <"$missing")
        echo "latc: native compilation missing $missing_count static targets; first entries:" >&2
        sed -n '1,32p' "$missing" >&2
    else
        echo "latc: native compilation failed without static missing targets" >&2
    fi
    exit "$status"
)

if [ "$module" -eq 1 ] && [ -z "$tbset" ]; then
    static_tbset=1
    tbset=$work/static.tbset
    "$latc" emit-static-tbset "$guest" -o "$tbset" >/dev/null
fi
status=0
case "${LATC_TBSET_SELECTION:-}" in
    exact|exact-static) planned=0 ;;
    *) planned=$module ;;
esac
if [ "$planned" -eq 1 ]; then
    plan=${LATC_NATIVE_PLAN_DIRECTORY:-$work/plan}
    set --
    if [ "$static_tbset" -eq 1 ]; then set -- --static; fi
    "$latc" plan-tbset "$guest" "$tbset" "$plan" "$@"
    "$latc" list-tbplan "$guest" "$plan" >"$work/parts"
    index=0
    paired=${LATC_NATIVE_BASE_MODULE:-}
    if [ -n "$paired" ] && [ -z "${LATC_NATIVE_BASE:-}" ]; then
        echo 'latc: base module requires paired native image' >&2
        exit 1
    fi
    if [ -n "$paired" ]; then
        "$latc" validate-native-base "$paired" "$LATC_NATIVE_BASE"
    fi
    while read -r mode name; do
        case "$mode" in exact|exact-static) ;; *) exit 1 ;; esac
        case "$name" in required-*.tbset|static-*.tbset) ;; *) exit 1 ;; esac
        image=$work/part.native
        part=$plan/$name
        if [ -n "$paired" ]; then
            delta=$work/delta-$index.tbset
            "$latc" missing-module-tbset "$paired" "$part" -o "$delta" \
                >"$work/delta-count"
            count=$(sed -n 's/^missing_tb_keys=//p' "$work/delta-count")
            case "$count" in ''|*[!0-9]*) exit 1 ;; esac
            printf '%s %s %s\n' "$mode" "$name" "$count" >>"$plan/consumed-deltas.log"
            if [ "$count" -eq 0 ]; then
                rm -f "$delta"
                index=$((index + 1))
                continue
            fi
            part=$delta
        fi
        (
            export LATC_TBSET_SELECTION=$mode
            unset LATC_NATIVE_STATIC_CHECK
            if [ "$mode" = exact-static ]; then export LATC_NATIVE_STATIC_CHECK=1; fi
            compile_part "$part" "$image" "$work/part-$index"
        ) || { status=$?; break; }
        if [ -n "$paired" ]; then rm -f "$part"; fi
        level=0
        while [ -f "$work/level-$level.native" ]; do
            "$latc" merge-native "$work/level-$level.native" "$image" \
                -o "$work/merge.native" || { status=$?; break; }
            rm -f "$work/level-$level.native" "$image"
            mv "$work/merge.native" "$image"
            level=$((level + 1))
        done
        if [ "$status" -ne 0 ]; then break; fi
        mv "$image" "$work/level-$level.native"
        index=$((index + 1))
    done <"$work/parts"
    if [ "$status" -eq 0 ]; then
        for image in "$work"/level-*.native; do
            test -f "$image" || continue
            if [ ! -f "$output" ]; then mv "$image" "$output"; continue; fi
            "$latc" merge-native "$image" "$output" -o "$work/final.native" || { status=$?; break; }
            rm -f "$image" "$output"
            mv "$work/final.native" "$output"
        done
        if [ "$status" -eq 0 ] && [ -n "$paired" ]; then
            if [ -f "$output" ]; then
                "$latc" merge-native "$LATC_NATIVE_BASE" "$output" \
                    -o "$work/paired.native" || status=$?
                if [ "$status" -eq 0 ]; then
                    rm -f "$output"
                    mv "$work/paired.native" "$output"
                fi
            else
                cp "$LATC_NATIVE_BASE" "$output" || status=$?
            fi
        fi
    fi
else
    if [ "$config_replay" -eq 1 ] && [ -n "${LATC_NATIVE_BASE:-}" ]; then
        "$latc" missing-replay-tbset "$LATC_NATIVE_BASE" "$LATC_TRANSLATION_CONFIG_FROM" \
            "$tbset" "$guest" -o "$work/delta.tbset" >"$work/delta-count" || exit $?
        count=$(sed -n 's/^missing_tb_keys=//p' "$work/delta-count")
        case "$count" in ''|*[!0-9]*) exit 1 ;; esac
        if [ "$count" -eq 0 ]; then
            cp "$LATC_NATIVE_BASE" "$output" || status=$?
        else
            compile_part "$work/delta.tbset" "$output" "$work/root" || status=$?
        fi
    else
        compile_part "$tbset" "$output" "$work/root" || status=$?
    fi
fi
if [ "$status" -eq 0 ] && [ "$config_replay" -eq 1 ] && [ -n "${LATC_NATIVE_BASE:-}" ] && [ "$count" -ne 0 ]; then
    "$latc" merge-native "$LATC_NATIVE_BASE" "$output" -o "$work/replay-merged.native" || status=$?
    if [ "$status" -eq 0 ]; then
        mv "$work/replay-merged.native" "$output"
    fi
fi
if [ "$status" -ne 0 ]; then
    rm -f "$output"
    exit "$status"
fi
if [ ! -s "$output" ]; then
    echo "latc: native compilation produced no image" >&2
    exit 1
fi
if [ "$config_replay" -eq 1 ]; then
    if ! "$latc" validate-replay-native "$output" "$LATC_TRANSLATION_CONFIG_FROM" "$tbset"; then
        rm -f "$output"
        exit 1
    fi
elif [ "$module" -eq 0 ]; then
    "$latc" mark-native-x86 "$output"
fi
"$latc" inspect-native --json "$output"
