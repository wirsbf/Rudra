#!/usr/bin/env bash
# Projection bank verification gate (mechanism B2 solidified fixtures).
#
# For every function entry under tests/fixtures/projections/<name>/ this
# gate verifies, in order:
#   1. the entry is complete (manifest.toml + oracle.projection +
#      rudra.projection);
#   2. the banked projection bytes still match the sha256 pins recorded in
#      manifest.toml (drift of the frozen anchor itself is a gate failure,
#      independent of comparison outcome);
#   3. tools/run_stage_bisect.sh (stage_bisect.py --v1, strict offsets)
#      reports kind=MATCH for the oracle/rudra pair (exit 0).
#
# Exit codes: 0 all entries MATCH, 1 any failure, 2 usage. CI gate form:
#   tools/verify_projection_bank.sh
# Single-entry triage form:
#   tools/verify_projection_bank.sh curl_next_url
# (entry names are directory names under tests/fixtures/projections/).
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
bank_root="$repo_root/tests/fixtures/projections"

usage() {
  cat >&2 <<EOF
usage: tools/verify_projection_bank.sh [<entry-name> ...]
  entry-name: directory under tests/fixtures/projections/ (e.g. curl_next_url)
  no arguments: verify every entry in the bank
EOF
}

manifest_value() { # manifest_value <file> <key>
  sed -n "s/^$2 = \"\\(.*\\)\"\$/\\1/p" "$1" | head -1
}

fail=0
verified=0

verify_entry() { # verify_entry <entry-dir>
  local dir=$1 name
  name=$(basename "$dir")
  local manifest="$dir/manifest.toml"
  local oracle="$dir/oracle.projection"
  local rudra="$dir/rudra.projection"

  if [[ ! -f $manifest ]]; then
    printf 'FAIL %-38s missing manifest.toml\n' "$name" >&2
    fail=1
    return
  fi
  local want_oracle want_rudra func corpus
  want_oracle=$(manifest_value "$manifest" oracle_sha256)
  want_rudra=$(manifest_value "$manifest" rudra_sha256)
  func=$(manifest_value "$manifest" function)
  corpus=$(manifest_value "$manifest" corpus)
  if [[ -z $want_oracle || -z $want_rudra || -z $func || -z $corpus ]]; then
    printf 'FAIL %-38s manifest.toml missing required keys\n' "$name" >&2
    fail=1
    return
  fi
  local side file want have
  for side in oracle rudra; do
    file=$oracle
    want=$want_oracle
    [[ $side == rudra ]] && { file=$rudra; want=$want_rudra; }
    if [[ ! -f $file ]]; then
      printf 'FAIL %-38s missing %s.projection\n' "$name" "$side" >&2
      fail=1
      return
    fi
    have=$(sha256sum "$file" | cut -d' ' -f1)
    if [[ $have != "$want" ]]; then
      printf 'FAIL %-38s %s.projection sha256 drift: %s (pin %s)\n' \
        "$name" "$side" "$have" "$want" >&2
      fail=1
      return
    fi
  done

  # The comparison gate itself: strict --v1 (no relax-unique), exit 0=MATCH.
  local bisect_out status
  bisect_out=$(bash "$script_dir/run_stage_bisect.sh" "$oracle" "$rudra" 2>&1)
  status=$?
  if [[ $status -ne 0 ]]; then
    printf 'FAIL %-38s stage_bisect --v1 exit=%s\n' "$name" "$status" >&2
    printf '%s\n' "$bisect_out" | sed 's/^/    /' >&2
    fail=1
    return
  fi
  if ! printf '%s\n' "$bisect_out" | grep -q '^kind: MATCH$'; then
    printf 'FAIL %-38s stage_bisect exit 0 but kind is not MATCH\n' "$name" >&2
    printf '%s\n' "$bisect_out" | sed 's/^/    /' >&2
    fail=1
    return
  fi
  local stages ops
  stages=$(printf '%s\n' "$bisect_out" | sed -n 's/^left: .*stages=\([0-9]*\), ops=.*/\1/p')
  ops=$(printf '%s\n' "$bisect_out" | sed -n 's/^left: .*ops=\([0-9]*\)).*/\1/p')
  printf 'PASS  %-38s %s/%s  MATCH (%s stages, %s ops)\n' \
    "$name" "$corpus" "$func" "${stages:-?}" "${ops:-?}"
  verified=$((verified + 1))
}

if [[ $# -eq 0 ]]; then
  entries=()
  while IFS= read -r dir; do
    [[ -f $dir/manifest.toml ]] && entries+=("$dir")
  done < <(find "$bank_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
  if [[ ${#entries[@]} -eq 0 ]]; then
    echo "no bank entries found under $bank_root" >&2
    exit 1
  fi
  for dir in "${entries[@]}"; do
    verify_entry "$dir"
  done
else
  for name in "$@"; do
    verify_entry "$bank_root/$name"
  done
fi

if [[ $fail -ne 0 ]]; then
  printf 'projection bank: FAILED (%d verified)\n' "$verified" >&2
  exit 1
fi
printf 'projection bank: OK (%d entries verified)\n' "$verified"
exit 0
