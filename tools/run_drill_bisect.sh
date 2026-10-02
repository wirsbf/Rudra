#!/usr/bin/env bash
# RUDRA-GLUE: pure consumer driver for tools/drill_diff.py (v2 drill files).
# Exit codes follow the stage_bisect convention: 0 identical, 1 differences
# reported, 2 usage or format error.
set -u

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <oracle.drill> <rudra.drill>\n' "$0" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/drill_diff.py" "$1" "$2"
exit $?
