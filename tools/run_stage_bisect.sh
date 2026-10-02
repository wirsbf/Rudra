#!/usr/bin/env bash
set -u

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <oracle.proj> <rudra.proj>\n' "$0" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/stage_bisect.py" --v1 "$1" "$2"
exit $?
