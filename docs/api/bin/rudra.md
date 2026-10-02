# `bin/rugra.rs` — current Rugra CLI

Source: `src/bin/rugra.rs`.

## 2026-08-13 Action 根入口

CLI 的默认 decompile 根动作现在通过 `ActionDatabase::perform_action` 运行，先
reset 整棵 action tree，再进入 Ghidra `Action::perform` 状态机。旧路径直接调用
`apply`，会跳过 once/repeat/status/count 语义。该修复只闭合执行入口；默认树、
Heritage、原型恢复与打印仍为 L2/MISMATCH。

实际反编译函数也不再在根动作前手工执行 `run_heritage_direct` 和
`ActionInferParams`；Heritage/参数恢复只由 action tree 的对应阶段负责。用于构建
兼容 prototype-count 数据库的旧预扫描仍存在，继续归 `PARAM-BIND-0001`，不能视为
Ghidra 参数恢复等价实现。

## Actual entry point

The binary accepts an ELF path and an optional maximum function count. It discovers ELF
symbols/strings, performs a compatibility prototype pre-pass, then builds one `Funcdata`
per selected function, runs flow/heritage/actions, and prints unmarked C to stdout.

This is an experimental pipeline driver, not a stable multi-subcommand CLI. It does not
provide historical `decompile`/`analyze`/`pcode` subcommands, and successful process exit is
not proof that emitted C is equivalent to Ghidra.

## 2026-08-13 reachable SLEIGH path

`PIPE-REACH-0001` removed the main loop's old split decoding path (iced-x86 instruction
lengths followed by per-instruction SLEIGH contexts). For each function, the CLI now:

1. finds the containing file-backed ELF section;
2. configures one owned `SleighLifter` with that section image and base;
3. calls `flow::follow_flow` from the function entry;
4. consumes the atomic `Sleigh::oneInstruction` step and emitted ops while following only
   reachable addresses;
5. runs the existing direct heritage/action/printing path.

The locked `GetStr` pipeline fixture confirms that the unreachable six-byte alignment NOP at
`0x3702` is no longer lifted and that the numeric raw-op signature sequence is identical to
Ghidra for all 103 reachable ops. This is a narrow `MISMATCH` reduction, not full CLI
alignment. Remaining blockers include complete pspec/context state, Flow overrides/errors/
injection/jump tables, dynamic address spaces and call specs, canonical Heritage/Action
execution, parameter recovery, types, and PrintC.

The preliminary prototype-discovery pass now decodes through the production
SLEIGH engine (SLEIGH-RUSTIFY-PHASE3-0001): one full-PT_LOAD-image
`SleighLifter` at ELF-relative base 0 serves both pre-pass loops; CALL ops'
ram-space input(0) replaces the retired iced `is_call`/`branch_target`
metadata, and undecodable bytes skip one byte with zero ops (the iced
walk's "Unimplemented" fallback contract). It remains diagnostic
compatibility code, tracked separately by `PARAM-RECOVERY-0001` and
`DWARF-PROTO-0001`.

## Verification

The specific flow claim is tested with the locked Ghidra 12.0.4 runner:

```bash
tools/run_getstr_pipeline_oracle.sh
```

Canonical end-to-end smoke remains:

```bash
cargo run --release --example curl_decompile > result/curl_cur.c
python3 tools/audit_syntax.py result/curl_cur.c
```

These checks retain `MISMATCH` status until all six observed layers agree.
