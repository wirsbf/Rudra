#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

for required_command in cargo rustc timeout pgrep ps sha256sum awk grep sed env cp chmod kill cat; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'timeout isolation: required command is unavailable: %s\n' "$required_command" >&2
        exit 1
    fi
done

workspace=$(mktemp -d "${TMPDIR:-/tmp}/rudra-timeout-isolation.XXXXXX")
active_pid=''
active_pgid=''
cleanup() {
    rm -rf -- "$workspace"
}
terminate_active() {
    if [[ ! "$active_pid" =~ ^[0-9]+$ && "${guard_process_PID:-}" =~ ^[0-9]+$ ]]; then
        active_pid=$guard_process_PID
        active_pgid=$guard_process_PID
    fi
    if [[ -n "$active_pgid" ]]; then
        kill -KILL -- "-$active_pgid" 2>/dev/null || true
    fi
    if [[ "$active_pid" =~ ^[0-9]+$ ]]; then
        kill -KILL "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    active_pid=''
    active_pgid=''
}
handle_signal() {
    signal_name=$1
    signal_status=$2
    trap - EXIT HUP INT TERM
    terminate_active
    cleanup
    printf 'timeout isolation: interrupted by %s\n' "$signal_name" >&2
    exit "$signal_status"
}
trap 'terminate_active; cleanup' EXIT
trap 'handle_signal HUP 129' HUP
trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM

run_guarded() {
    guard_limit=$1
    guard_cwd=$2
    shift 2
    active_pid=''
    active_pgid=''
    coproc guard_process {
        cd "$guard_cwd"
        exec timeout --kill-after=10s "$guard_limit" "$@"
    }
    active_pid=$guard_process_PID
    active_pgid=$active_pid
    observed_pgid=$(ps -o pgid= -p "$active_pid" | awk '{$1=$1};1')
    if [[ "$observed_pgid" != "$active_pid" ]]; then
        guard_pid=$active_pid
        guard_pgid=$observed_pgid
        terminate_active
        printf 'timeout isolation: guard process group isolation failed: pid=%s pgid=%s\n' \
            "$guard_pid" "$guard_pgid" >&2
        return 1
    fi
    exec {guard_stdout}<&"${guard_process[0]}"
    exec {guard_stdin}>&"${guard_process[1]}"
    cat <&"$guard_stdout" &
    guard_forwarder=$!
    exec {guard_stdout}<&-
    exec {guard_stdin}>&-
    if wait "$active_pid"; then
        guard_status=0
    else
        guard_status=$?
    fi
    active_pid=''
    active_pgid=''
    wait "$guard_forwarder" || true
    return "$guard_status"
}

assert_pid_absent() {
    probe_pid=$1
    if ps -p "$probe_pid" -o pid= >/dev/null 2>&1; then
        printf 'timeout isolation: recorded probe pid is still alive: %s\n' "$probe_pid" >&2
        return 1
    else
        ps_status=$?
    fi
    if [[ $ps_status -ne 1 ]]; then
        printf 'timeout isolation: recorded pid check failed: pid=%s rc=%s\n' \
            "$probe_pid" "$ps_status" >&2
        return 1
    fi
}

assert_group_absent() {
    probe_pgid=$1
    if ! process_groups=$(ps -eo pgid=); then
        printf 'timeout isolation: unable to enumerate process groups\n' >&2
        return 1
    fi
    if awk -v pgid="$probe_pgid" '$1 == pgid { found = 1 } END { exit found ? 0 : 1 }' \
        <<<"$process_groups"
    then
        printf 'timeout isolation: recorded probe process group is still alive: %s\n' \
            "$probe_pgid" >&2
        return 1
    else
        awk_status=$?
    fi
    if [[ $awk_status -ne 1 ]]; then
        printf 'timeout isolation: recorded process-group check failed: pgid=%s rc=%s\n' \
            "$probe_pgid" "$awk_status" >&2
        return 1
    fi
}

verify_ready_probe_reaped() {
    ready_token=$1
    ready_prefix="[TIMEOUT-PROBE] ready token=$ready_token "
    if [[ $(grep -Fc "$ready_prefix" "$probe_stderr") -ne 1 ]]; then
        printf 'timeout isolation: hang probe did not reach exactly one ready state: %s\n' \
            "$ready_token" >&2
        return 1
    fi
    ready_fields=$(awk -v prefix="$ready_prefix" '
        index($0, prefix) == 1 {
            sub(/^worker_pid=/, "", $4)
            sub(/^descendant_pid=/, "", $5)
            sub(/^pgid=/, "", $6)
            print $4, $5, $6
        }
    ' "$probe_stderr")
    read -r worker_pid descendant_pid probe_pgid <<<"$ready_fields"
    if [[ ! "$worker_pid" =~ ^[0-9]+$ || ! "$descendant_pid" =~ ^[0-9]+$ \
        || ! "$probe_pgid" =~ ^[0-9]+$ || "$worker_pid" != "$probe_pgid" ]]
    then
        printf 'timeout isolation: invalid recorded probe identities: %s\n' "$ready_fields" >&2
        return 1
    fi
    assert_pid_absent "$worker_pid"
    assert_pid_absent "$descendant_pid"
    assert_group_absent "$probe_pgid"
}

target_root="$workspace/target"
host_target=$(rustc -vV | sed -n 's/^host: //p')
if [[ ! "$host_target" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    printf 'timeout isolation: invalid rustc host target: %s\n' "$host_target" >&2
    exit 1
fi
build_driver="$target_root/$host_target/release/examples/curl_decompile"
if ! run_guarded 20m "$repo_root" env CARGO_TARGET_DIR="$target_root" \
    cargo build --offline --locked --release --target "$host_target" --example curl_decompile
then
    printf 'timeout isolation: guarded driver build failed or timed out\n' >&2
    exit 1
fi
if [[ ! -x "$build_driver" ]]; then
    printf 'timeout isolation: driver is not executable: %s\n' "$build_driver" >&2
    exit 1
fi

snapshot="$workspace/snapshot"
mkdir -p "$snapshot/examples" "$snapshot/sleigh_specs"
driver="$snapshot/curl_decompile"
cp -- "$build_driver" "$driver"
cp -- examples/curl "$snapshot/examples/curl"
cp -- sleigh_specs/x86-64.sla "$snapshot/sleigh_specs/x86-64.sla"
cp -- sleigh_specs/x86-64.pspec "$snapshot/sleigh_specs/x86-64.pspec"
cp -- sleigh_specs/x86-64-gcc.cspec "$snapshot/sleigh_specs/x86-64-gcc.cspec"
chmod 0500 "$driver"
chmod 0400 "$snapshot/examples/curl" "$snapshot/sleigh_specs/"*
snapshot_manifest="$workspace/snapshot.sha256"
(
    cd "$snapshot"
    sha256sum curl_decompile examples/curl \
        sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
        sleigh_specs/x86-64-gcc.cspec
) > "$snapshot_manifest"

# Make the verification configuration explicit; the controller and every
# self-exec worker inherit this same cleared option set.
unset RUDRA_RULE_STATS RUDRA_7PHASE RUDRA_LOOP_DEBUG
unset RUDRA_DEBUG_ACTIVEPARAM RUDRA_DEBUG_CALLS
if [[ ! -r "$snapshot/examples/curl" ]]; then
    printf 'timeout isolation: missing readable snapshot input\n' >&2
    exit 1
fi

probe_token="rudra_timeout_${BASHPID}"
deadline_token="$probe_token.deadline"
disconnect_token="$probe_token.disconnect"
probe_stdout="$workspace/probe.stdout"
probe_stderr="$workspace/probe.stderr"
if ! run_guarded 45s "$snapshot" "$driver" --rudra-timeout-isolation-self-test "$probe_token" \
    >"$probe_stdout" 2>"$probe_stderr"
then
    printf 'timeout isolation: guarded fault-injection probe failed or timed out\n' >&2
    sed -n '1,200p' "$probe_stdout" >&2
    sed -n '1,200p' "$probe_stderr" >&2
    exit 1
fi

for expected in \
    'timeout=PASS' \
    'subsequent-worker=PASS' \
    'panic=PASS' \
    'nonzero=PASS' \
    'output-disconnect=PASS' \
    'monitor-disconnect=PASS' \
    'invalid-request=PASS' \
    'zero-residual-groups=PASS'
do
    if ! grep -Fqx "timeout-isolation probe: $expected" "$probe_stdout"; then
        printf 'timeout isolation: missing probe result: %s\n' "$expected" >&2
        sed -n '1,200p' "$probe_stdout" >&2
        sed -n '1,200p' "$probe_stderr" >&2
        exit 1
    fi
done

if ! verify_ready_probe_reaped "$deadline_token" \
    || ! verify_ready_probe_reaped "$disconnect_token"
then
    sed -n '1,200p' "$probe_stderr" >&2
    exit 1
fi

if residual_pids=$(pgrep -f -- "--rudra-curl-function-worker --probe-label $probe_token"); then
    printf 'timeout isolation: residual worker found for token %s\n' "$probe_token" >&2
    printf '%s\n' "$residual_pids" >&2
    ps -eo pid,ppid,pgid,stat,args | grep -F -- "$probe_token" >&2 || true
    exit 1
else
    pgrep_status=$?
    if [[ $pgrep_status -ne 1 ]]; then
        printf 'timeout isolation: pgrep worker check failed: rc=%s\n' "$pgrep_status" >&2
        exit 1
    fi
fi
if residual_pids=$(pgrep -f -- "--rudra-timeout-descendant-probe $probe_token"); then
    printf 'timeout isolation: residual descendant found for token %s\n' "$probe_token" >&2
    printf '%s\n' "$residual_pids" >&2
    ps -eo pid,ppid,pgid,stat,args | grep -F -- "$probe_token" >&2 || true
    exit 1
else
    pgrep_status=$?
    if [[ $pgrep_status -ne 1 ]]; then
        printf 'timeout isolation: pgrep descendant check failed: rc=%s\n' "$pgrep_status" >&2
        exit 1
    fi
fi

compare_stdout="$workspace/compare.stdout"
compare_stderr="$workspace/compare.stderr"
if ! run_guarded 5m "$snapshot" "$driver" --rudra-timeout-isolation-compare-function \
    main_init main_free \
    >"$compare_stdout" 2>"$compare_stderr"
then
    printf 'timeout isolation: guarded normal-output comparison failed or timed out\n' >&2
    sed -n '1,240p' "$compare_stderr" >&2
    exit 1
fi

for function_name in main_init main_free; do
    if [[ $(grep -Fc "[TIMEOUT-ISOLATION] normal output MATCH function=$function_name " \
        "$compare_stderr") -ne 1 ]]
    then
        printf 'timeout isolation: direct/isolated output comparison did not pass: %s\n' \
            "$function_name" >&2
        sed -n '1,240p' "$compare_stderr" >&2
        exit 1
    fi
    if [[ $(grep -Ec "^/\\* ---- 0x[0-9a-f]+: $function_name \\([0-9]+ bytes\\) ---- \\*/$" \
        "$compare_stdout") -ne 1 ]]
    then
        printf 'timeout isolation: normal function header changed or duplicated: %s\n' \
            "$function_name" >&2
        exit 1
    fi
done
if [[ $(grep -Fc 'typedef unsigned char byte;' "$compare_stdout") -ne 1 ]]; then
    printf 'timeout isolation: typedef preamble was not emitted exactly once\n' >&2
    exit 1
fi

if ! (cd "$snapshot" && sha256sum --check "$snapshot_manifest"); then
    printf 'timeout isolation: private snapshot changed during verification\n' >&2
    exit 1
fi
binary_sha=$(sha256sum "$snapshot/examples/curl" | awk '{print $1}')
driver_sha=$(sha256sum "$driver" | awk '{print $1}')
sla_sha=$(sha256sum "$snapshot/sleigh_specs/x86-64.sla" | awk '{print $1}')
pspec_sha=$(sha256sum "$snapshot/sleigh_specs/x86-64.pspec" | awk '{print $1}')
cspec_sha=$(sha256sum "$snapshot/sleigh_specs/x86-64-gcc.cspec" | awk '{print $1}')
printf 'timeout isolation: PASS\n'
printf '  input_sha256=%s\n' "$binary_sha"
printf '  driver_sha256=%s\n' "$driver_sha"
printf '  sla_sha256=%s\n' "$sla_sha"
printf '  pspec_sha256=%s\n' "$pspec_sha"
printf '  cspec_sha256=%s\n' "$cspec_sha"
printf '  probe_timeout_kill_reap=PASS\n'
printf '  post_timeout_worker=PASS\n'
printf '  panic_nonzero_disconnect_invalid=PASS\n'
printf '  residual_worker=0\n'
printf '  recorded_worker_descendant_pgid_residual=0\n'
printf '  normal_function_direct_vs_isolated=MATCH\n'
printf '  normal_function_count=2\n'
printf '  typedef_preamble_count=1\n'
printf '  residual_build_environment=INHERITED_TOOLCHAIN_FLAGS\n'
printf '  residual_resource_caps=WALLCLOCK_ONLY\n'
