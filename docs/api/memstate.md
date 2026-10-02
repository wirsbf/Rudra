# `memstate.rs` API Reference

**源代码路径**: `src/memstate.rs`
**Ghidra 对应**: `memstate.hh` / `memstate.cc` (738 行)
**状态**: 🔧 **L2 / NO_ORACLE**——主要容器和方法表面已实现，20 个
Rust 单元测试全绿；但地址空间身份/端序来自简化的 `AddressSpace`，
`MemoryState` 未持有 Ghidra `Translate*`，命名寄存器被哈希为伪偏移，且没有
锁定 12.0.4 的同输入行为 fixture（`MEMSTATE-0001`）。

## 模块说明

内存存储/状态：为 LOAD/STORE 模拟提供字节级读写，对应 Ghidra 的 `memstate.hh` / `memstate.cc`。函数来源注释不表示当前实现已经行为等价。

Ghidra 把 `MemoryBank` 建模为带两个纯虚方法（`insert`/`find`）与四个带默认实现的虚方法（`getPage`/`setPage`/静态 `constructValue`/`deconstructValue`）的抽象基类，派生类有 `MemoryImage` / `MemoryPageOverlay` / `MemoryHashOverlay`。Rudra 用具体结构体 + `Option<Box<MemoryBank>>` 作为各 Overlay 的 `underlie` 指针，忠实映射 C++ 继承语义。

## 导出的公共 API

### `pub struct MemoryBank`（对应 Ghidra `MemoryBank`, memstate.hh:38）
单一地址空间的内存存储。每个方法上方均有 `// Ghidra: memstate.cc:<行号> <函数名>` 注释。

- `new(space, wordsize, pagesize)` — 构造（memstate.cc:75）
- `get_word_size()` / `get_page_size()` / `get_space()` — 访问器（memstate.hh:67/76/84）
- `insert(addr, val)` / `find(addr)` — 纯虚对齐字插入/查找（memstate.hh:45/46）
- `get_page(addr, skip, size)` — 默认 `getPage` 实现（memstate.cc:93），逐字 `find` + 端序交换
- `set_page(addr, val, skip, size)` — 默认 `setPage` 实现（memstate.cc:136），逐字 `insert` + 部分字合并
- `set_value(offset, size, val)` — `setValue`（memstate.cc:182），按字拆分并保持未触及字节
- `get_value(offset, size)` — `getValue`（memstate.cc:252），按字重建并 `calc_mask(size)` 截断
- `set_chunk(offset, val)` / `get_chunk(offset, size)` — `setChunk`/`getChunk`（memstate.cc:302/335），按页切片
- `construct_value(ptr, bigendian)` / `deconstruct_value(val, size, bigendian, out)` — 静态编解码（memstate.cc:27/53）
- `clear()` — RUDRA-GLUE 辅助

### `pub struct MemoryImage`（对应 Ghidra `MemoryImage`, memstate.hh:95）
只读 LoadImage 后端银行。
- `new(space, wordsize, pagesize, loader)` — 构造（memstate.cc:407）
- `insert()` — 抛 panic，对应 C++ `throw LowlevelError`（memstate.hh:98）
- `find(addr)` — 从 LoadImage `load_fill` 取字，`DataUnavailError` 时填 0（memstate.cc:365）
- `get_page(addr, skip, size)` — 从 LoadImage 取整页，失败填 0（memstate.cc:386）
- `get_value` / `get_chunk` — 继承的 `getValue`/`getChunk` 委托
- `set_value()` — 抛 panic（继承路径抵达抛异常的 `insert`）

### `pub struct MemoryPageOverlay`（对应 Ghidra `MemoryPageOverlay`, memstate.hh:112）
写时复制覆盖银行。
- `new(space, wordsize, pagesize, underlie)` — 构造（memstate.cc:533）
- `insert(addr, val)` — 缺页时分配并从 underlie `get_page` 拷入，再 `deconstructValue` 写字（memstate.cc:419）
- `find(addr)` — 缺页时转发 underlie 或返回 0（memstate.cc:450）
- `get_page(addr, skip, size)` — 缺页转发 underlie 或填 0（memstate.cc:476）
- `set_page(addr, val, skip, size)` — 部分写时先从 underlie 填页（memstate.cc:502）
- `read/write/get_value/set_value` — RUDRA-GLUE：经由忠实 `get_page`/`set_page`/`find`/`insert` 的便利包装
- `is_page_overlayed` / `num_pages` — RUDRA-GLUE 辅助

### `pub struct MemoryHashOverlay`（对应 Ghidra `MemoryHashOverlay`, memstate.hh:130）
哈希表覆盖银行。`0xBADBEEF` 哨兵、`collideskip=1023`、`alignshift=log2(ws)` 全部 1:1 复刻。
- `new(space, wordsize, pagesize, hashsize, underlie)` — 构造（memstate.cc:602）
- `insert(addr, val)` — 哈希表写入 + 线性探测（memstate.cc:551），表满抛 `LowlevelError`
- `find(addr)` — 哈希表查找 + 缺失转发 underlie（memstate.cc:575）
- `get_value` / `set_value` — 继承的 `getValue`/`setValue` 委托

### `pub fn construct_memory_bank(space, wordsize, pagesize)`
RUDRA-GLUE 工厂：为某空间构造默认 `MemoryBank`。Ghidra 在 `Architecture` 初始化时按需构造 MemoryImage / Overlay；rudra 暴露单一入口。

### `pub struct MemState`（对应 Ghidra `MemoryState`, memstate.hh:150）
跨地址空间的内存管理。
- `new()` — RUDRA-GLUE（Ghidra 构造器接收 `Translate*`；rudra 暂未接入）
- `set_memory_bank(bank)` — `setMemoryBank`（memstate.cc:620），按 `space.name()` 索引
- `get_memory_bank(space_name)` — `getMemoryBank`（memstate.cc:636）
- `set_value(space, off, size, val)` — `setValue(AddrSpace*,...)`（memstate.cc:652）
- `get_value(space, off, size)` — `getValue(AddrSpace*,...)`（memstate.cc:668），含 IPTR_CONSTANT 快路径
- `get_chunk` / `set_chunk` — `getChunk`/`setChunk`（memstate.cc:712/729）
- `set_register_value(name, val)` / `get_register_value(name)` — RUDRA-GLUE：对应命名寄存器重载（memstate.cc:684/697），缺少 `Translate` 时按 FNV-1a 哈希名到偏移
- `set_bank` / `get_bank` / `get_bank_mut` — RUDRA-GLUE 兼容别名（供 `emulate.rs` 使用）

## 端序与字大小

这些方法保留了 Ghidra 的 `HOST_ENDIAN`/space-endian 分支形状，但 Rudra
当前 `AddressSpace::is_big_endian()` 对所有空间返回 false，且固定空间枚举
无法表达架构拥有的动态 space 属性；因此大端和跨空间行为尚未对齐。

## 测试

`memstate::tests` 共 **20** 个测试：
- 编解码（小/大端）、字对齐/部分字/跨字 `set_value`/`get_value`、`set_chunk`/`get_chunk`
- `MemoryImage` 从 `RawLoadImage` 读字/读页、写时 panic
- `MemoryPageOverlay` COW：insert/find、get_page/set_page、write/read、underlie 透传与覆盖
- `MemoryHashOverlay` insert/find、underlie 透传与覆盖、get/set_value
- `MemState`：value/chunk 操作、IPTR_CONSTANT 快路径、`setMemoryBank` 按名索引
- `construct_memory_bank` 工厂

## KUNAUB-PAGECOPY-0001：get_page/set_page 死修剪裁决 (a) 维持 panic（2026-09-26，wt/kunaub2）

Oracle 默认实现 `MemoryBank::getPage`（memstate.cc:93-123）/`setPage`
（:136-171）的头部修剪条件写错比较对象：`if (startalign < addr)`
（getPage :113 / setPage :153）——`addr` 是 getChunk/setChunk（:335-359 /
:302-327）传入的**页对齐**地址，而错位量在 `ptraddr = addr + skip`
（:97/:140）上；`startalign = ptraddr & ~(wordsize-1) ≥ addr` 恒成立 ⇒
头部修剪恒为死代码。`skip % wordsize != 0` 时字循环多拷至多 wordsize-1
个请求范围外字节：getPage :119 `memcpy(res,ptr,sz)` 越界写 / setPage :161
`memcpy(ptr,val,sz)` 越界读 caller 缓冲区——**oracle 在该输入上没有已定义
行为可对拍**（静默堆越界=UB）。受影响面：仅未覆写 getPage/setPage 的 bank
（`MemoryHashOverlay`，memstate.hh:130-141，仿真/standalone 面）；主管线用
page-overlay 族不受影响。

Rudra `get_page/set_page`（memstate.rs）镜像同一死修剪，载体为 `Vec<u8>`/
slice ⇒ 同输入下越界形态变为 slice range panic（全 profile 恒 panic，与
overflow-checks 无关）。**裁决 起算原文 (a)（KUNAUB-SDIV-0001 先例）：oracle-UB
输入无对拍义务，panic 严格安全于 oracle 的静默越界，保持 panic 形态，
memstate.rs 零改动**。崩溃形态由 `tests/memstate_pagecopy_panic.rs` 锁定：
2 个 `#[should_panic]`（get 侧 res[8..9]/set 侧 val[8..9]，ws=8 +
skip=1 推演双侧同形）+ 1 个字对齐对照（对齐 skip 双侧均为已定义路径）。

**约束（票面沿用）**：本裁决站立期间禁止为 `get_chunk/set_chunk` 引入
生产调用方；选项 (b)（按 `startalign < ptraddr` 意图语义修=与
oracle-as-written 分歧）须先记 ALIGNMENT_ROADMAP 再动。当前双侧主管线均
零调用方（Rudra src/examples 无用户；MemState 消费方走 word 级 API）。

## Alignment Evidence

- 2026-08-11 ANN-D provenance-only pass: added function-local annotations for
  14 inherited container/accessor mappings and Rust-only helpers; no behavior
  changed. Oracle `e40ed13014025f82488b1f8f7bca566894ac376b`
  `memstate.cc` / `memstate.hh` were reread in full.
- `cargo check --lib`：**0 错误**（在 `src/memstate.rs` 上；其他模块的预存编译错误与本任务无关）
- `cargo test --lib memstate`：**20 passed; 0 failed**
- 每个移植方法上方有 `// Ghidra: memstate.cc:<行号> <函数名>` 注释；Rust 胶水标 `// RUDRA-GLUE: <理由>`
- 行号锚点对照 Ghidra `memstate.cc`：constructValue=27、deconstructValue=53、构造器=75、getPage=93、setPage=136、setValue=182、getValue=252、setChunk=302、getChunk=335、MemoryImage::find=365、getPage=386、构造器=407、PageOverlay::insert=419/find=450/getPage=476/setPage=502/构造器=533、HashOverlay::insert=551/find=575/构造器=602、MemoryState::setMemoryBank=620/getMemoryBank=636/setValue=652/getValue=668/setValue(named)=684/getValue(named)=697/getChunk=712/setChunk=729
<!-- annotation-pass: 2026-07-22 -->
