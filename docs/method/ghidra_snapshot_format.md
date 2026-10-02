# Ghidra 侧语义快照导出格式规范

> **版本**: 1.0  
> **状态**: 初始设计  
> **目标**: 定义 Ghidra Headless Analyzer 可导出、Rudra 可导入的 JSON 快照格式

## 概述

本文档定义了 Ghidra 侧导出函数级语义快照的 JSON 格式，使其能与 Rudra 的
`FunctionSemanticSnapshot` 结构兼容，实现跨工具的 P-code / CFG / SSA 对比。

## Schema 映射

Ghidra 导出的 JSON 必须符合 `FunctionSemanticSnapshot` 的 serde 反序列化格式：

```json
{
  "schema_version": 1,
  "function": {
    "name": "<function_name>",
    "entry": { "space": "Ram", "offset": <entry_addr> },
    "size": <function_size_bytes>
  },
  "summary": {
    "pcode_op_count": <int>,
    "basic_block_count": <int>,
    "varnode_count": <int>,
    "has_symbols": <bool>,
    "has_strings": <bool>
  },
  "pcode": {
    "ops": [
      {
        "seq": { "addr": { "space": "Ram", "offset": <addr> }, "order": <int> },
        "opcode": "<OpCode_variant>",
        "output": { "space": "<space>", "offset": <int>, "size": <int> } | null,
        "inputs": [
          { "space": "<space>", "offset": <int>, "size": <int> }
        ]
      }
    ]
  },
  "cfg": {
    "blocks": [
      {
        "index": <int>,
        "start": { "space": "Ram", "offset": <addr> },
        "ops": [ { "addr": ..., "order": ... } ],
        "successors": [ { "space": "Ram", "offset": <addr> } ],
        "predecessors": [ { "space": "Ram", "offset": <addr> } ]
      }
    ]
  },
  "ssa": {
    "varnodes": [
      {
        "varnode": { "space": "<space>", "offset": <int>, "size": <int> },
        "version": <int>,
        "is_input": <bool>,
        "is_written": <bool>,
        "defining_op": { "addr": ..., "order": ... } | null,
        "uses": [ { "addr": ..., "order": ... } ]
      }
    ]
  },
  "tags": [],
  "notes": ["exported_from_ghidra"]
}
```

## 关键约定

### 1. AddressSpace 映射

| Ghidra Space Name | Rudra `AddressSpace` 枚举 | `space_id()` |
|---|---|---|
| `ram` | `Ram` | 2 |
| `register` | `Register` | 3 |
| `const` / `constant` | `Const` | 0 |
| `unique` | `Unique` | 1 |

Ghidra 导出时应使用 Rudra 的枚举名称（如 `"Ram"`, `"Register"` 等），
或者使用 space_id 数值。Rudra 侧的 serde 反序列化器使用枚举变体名。

### 2. OpCode 映射

使用 Rudra 的 `OpCode` 枚举名称，例如：

| Ghidra P-code Op | Rudra OpCode |
|---|---|
| `COPY` | `CPUI_COPY` |
| `LOAD` | `CPUI_LOAD` |
| `STORE` | `CPUI_STORE` |
| `INT_ADD` | `CPUI_INT_ADD` |
| `INT_SUB` | `CPUI_INT_SUB` |
| `INT_EQUAL` | `CPUI_INT_EQUAL` |
| `CBRANCH` | `CPUI_CBRANCH` |
| `BRANCH` | `CPUI_BRANCH` |
| `RETURN` | `CPUI_RETURN` |
| `MULTIEQUAL` | `CPUI_MULTIEQUAL` |

### 3. Unique 空间偏移

Ghidra 的 unique space 偏移与 Rudra 的分配策略不同。
对比时应 **跳过 unique space varnode 的 offset 比较**，
只比较 space 和 size。这与现有 `rudra_compare_pcode` 的策略一致。

### 4. SeqNum 格式

```json
{
  "addr": { "space": "Ram", "offset": 4096 },
  "order": 0
}
```

`order` 是同一机器地址内的 P-code 子序号。

### 5. 排序约定

- P-code ops: 按 SeqNum 排序（先 addr 再 order）
- CFG blocks: 按 (start_address, index) 排序
- SSA varnodes: 按 (space_id, offset, size, version) 排序

## Ghidra 导出脚本示例（Python / Ghidra Headless）

```python
# ghidra_export_snapshot.py — 在 Ghidra Headless Analyzer 中运行
# Usage: analyzeHeadless <project> <name> -process <binary> \
#        -postScript ghidra_export_snapshot.py <output_dir>

import json
import os

def export_function_snapshot(func, output_dir):
    """Export a single function's P-code snapshot as JSON."""
    listing = currentProgram.getListing()
    entry = func.getEntryPoint()
    
    snapshot = {
        "schema_version": 1,
        "function": {
            "name": func.getName(),
            "entry": {"space": "Ram", "offset": entry.getOffset()},
            "size": int(func.getBody().getNumAddresses()),
        },
        "summary": {
            "pcode_op_count": 0,  # filled below
            "basic_block_count": 0,  # filled below
            "varnode_count": 0,
            "has_symbols": False,
            "has_strings": False,
        },
        "pcode": {"ops": []},
        "cfg": {"blocks": []},
        "ssa": {"varnodes": []},
        "tags": ["ghidra_export"],
        "notes": [f"Ghidra version: {getGhidraVersion()}"],
    }
    
    # Collect raw P-code
    addr_set = func.getBody()
    inst_iter = listing.getInstructions(addr_set, True)
    op_idx = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        pcode_ops = inst.getPcode()
        for pcode in pcode_ops:
            op_entry = {
                "seq": {
                    "addr": {"space": "Ram", "offset": inst.getAddress().getOffset()},
                    "order": op_idx,
                },
                "opcode": "CPUI_" + pcode.getMnemonic(),
                "output": None,
                "inputs": [],
            }
            
            out = pcode.getOutput()
            if out is not None:
                op_entry["output"] = varnode_to_dict(out)
            
            for inp in pcode.getInputs():
                op_entry["inputs"].append(varnode_to_dict(inp))
            
            snapshot["pcode"]["ops"].append(op_entry)
            op_idx += 1
    
    snapshot["summary"]["pcode_op_count"] = len(snapshot["pcode"]["ops"])
    
    # Write JSON
    fname = f"{func.getName()}_{entry.getOffset():x}.json"
    path = os.path.join(output_dir, fname)
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2)
    print(f"Exported: {path}")

def varnode_to_dict(vn):
    space_name = vn.getAddress().getAddressSpace().getName()
    space_map = {
        "ram": "Ram",
        "register": "Register",
        "const": "Const",
        "unique": "Unique",
    }
    return {
        "space": space_map.get(space_name.lower(), space_name),
        "offset": vn.getOffset(),
        "size": vn.getSize(),
    }

# Main
output_dir = getScriptArgs()[0] if getScriptArgs() else "/tmp/ghidra_snapshots"
os.makedirs(output_dir, exist_ok=True)

fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if not func.isExternal():
        export_function_snapshot(func, output_dir)
```

## Rudra 侧导入流程

```rust
// 已由 function_snapshot.rs 提供：
let ghidra_snap = FunctionSemanticSnapshot::read_json_file("path/to/ghidra_export.json")?;
let rudra_snap = FunctionSemanticSnapshot::from_funcdata(&funcdata);
let result = FunctionSemanticCompareResult::compare(&rudra_snap, &ghidra_snap);

if !result.matched {
    for m in &result.mismatches {
        println!("[{}] {}: {}", m.layer, m.code, m.details);
    }
}
```

## 当前限制

1. **SSA 层级**：Ghidra 的 raw P-code（`inst.getPcode()`）不含 SSA 信息。
   要导出 SSA，需要使用 Ghidra 的 High-level P-code API（`DecompInterface`），
   这更复杂但提供了 SSA 版本化的 varnode。

2. **CFG 导出**：上述脚本骨架未包含 CFG 导出逻辑。完整实现需使用
   `BasicBlockModel` API 获取基本块和边。

3. **Unique space 偏移**：Ghidra 和 Rudra 的 unique space 分配不同。
   比较时应忽略 unique space 的 offset。
