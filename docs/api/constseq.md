# `constseq.rs` API Reference

## 2026-09-25（CR 修）：锁定文本链滤与非锁定 type set（CR-STRNCPY F1/F2）

- **F1** `find_duplicate_bases` 两处链判定（回溯 break / 前向 accept）由三臂
  （PTRSUB/INT_ADD/PTRADD）改为**双臂（PTRSUB/INT_ADD）**：锁定 12.0.4 文本
  constseq.cc:510-511/526-527 的链滤是 `!= CPUI_PTRSUB && != CPUI_INT_ADD &&
  != CPUI_PTRSUB`——CPUI_PTRSUB 写两遍=上游原文即锁定行为，**PTRADD 被排除在
  链外**（仅 cc:495 入口门收）。注释改为如实描述锁定文本形态；cc:531-532 的
  PTRADD 偏移缩放在锁定滤下为死支（与 oracle 文本同构保留）。
- **F2** `build_string_copy` 五处类型赋值（cc:720/727/736/746/758 对应点）由
  `update_type_lock(ct, true, false)` 全改**单参非锁定形 `update_type(ct)`**
  （varnode.rs:1483）；三参锁定形仅保留在 oracle 同形位点
  （get_internal_string 的 cc:1431），两形态不再混用。
- 五档输出与 01879607 二进制 cmp 字节恒等（F1 不在 ap_ht_time 家族路径上、
  F2 只改 typelock 状态不改打印字节）；四口径 297/868/200/309+51 双零；
  mirror-gate 三面 PASS；bank 391/391；ROADMAP 第 24 行已随同 commit 刷新
  （B2 现状注：wcsncpy/memcpy 选择、baseOffset≠0、nonConstAdds、dedup abort、
  大端=UNTESTED，L2 维持）。

## 2026-09-25：STRNCPY 族 IR 层收口（Lane STRNCPY，MIRROR3-STRNCPY-RULE-0001）

`RuleStringStore` 从简化收集器换为完整 HeapSequence 链路（constseq.cc:986-1002 逐行）：

- **interfere_between** 重写为 oracle 语义（constseq.cc:42-56）：`nextOp()`
  块序游走（op.cc:323-339，跨唯一出边）+ special-eval 五豁免表
  （INDIRECT/CALLOTHER/SEGMENTOP/CPOOLREF/NEW）。旧实现按 order 窗口扫全函数
  alivelist 且谓词不同（call/branch/STORE）——foreign-block STORE 落窗内即误判
  干扰，是规则不触发的第二根因。
- **check_interference** 重写（constseq.cc:62-96）：按 `SeqNum::order`（块执行
  序字段，address.hh:124）排序 move_ops，从 root 前后扩展最大无干扰集并截断。
  旧实现自行重收集 COPY 候选（STORE 路径完全错位）。
- **form_byte_array(sz, slot, root_off, big_endian)** 忠实签名+语义
  （constseq.cc:108-155）：used 标记 1/2（数据/NUL）、前导连续计数允许单个
  NUL 结尾、count != moveOps.size() 时截断越界 op。替换旧的 COPY-only 低字节
  简化版；`is_valid_string`/`get_string`（Rudra 本地 helper）删除。
- **select_string_copy_function(fd)** 忠实化（constseq.cc:161-175）：与工厂
  canonical char/wchar 的 identity 比较（Arc::ptr_eq 直译 C++ 指针等值，回退
  (name,size,char-print flags) 等值），不再按 size 猜 strncpy/wcsncpy。
- **HeapSequence::build_string_copy** 新增忠实版（constseq.cc:698-762）：
  destPtr=basePointer（baseOffset/nonConstAdds≠0 时建 index 链+PTRADD）、
  srcPtr=`Funcdata::get_internal_string`（funcdata_varnode.cc:1413）、
  `register_builtin_with_local_types`（userop.cc:449-478 的 DatatypeUserOp 局部
  类型）、lenVn 经 builtin slot-3 局部类型定型（int4）。旧的共享
  ArraySequence::build_string_copy/transform（假 ANNOTATION 指针 varnode）删除。
- **RuleStringStore::apply_op** 接通完整链（cc:986-1002 守卫：in(2) 常量、
  in(1) TYPE_PTR、pointee isCharPrint 且非 opaque → new_heap → is_valid →
  transform）。旧 `ptr_shares_base` 简化 helper 删除（只认链式 PTRADD，不认
  兄弟 PTRADD——同基兄弟形是本语料主形态，是规则不触发的第一根因）。
- **MAXIMUM_SEQUENCE_LENGTH** 1024→0x20000（constseq.cc:21-22 常量对齐）。
- gather_indirect_pairs 改走 op.rs 的 `previous_op_in_block`（op.cc:344 忠实
  版，OP-PREVIOUSOP-ALIVELIST-0001 交付）；本地 alivelist 扫描版与
  `ArraySequence.fd` raw 指针字段删除。
- **RuleStringCopy::apply_op** ~~保持 inert~~ → **2026-09-26 接通完整链**
  （WORKPKG-UNMAP-STRFOLD-0006）：`queryContainer` 桥接 =
  `ScopeLocal::find_container_entry`（stack 面）+ `query_container_entry_parent_scope`
  （ram 面投影）；`StringSequence` 七函数全量落地（见 2026-09-26 节）。

## 2026-09-26：StringSequence 全量落地（WORKPKG-UNMAP-STRFOLD-0006 / CONSTSEQ-STRINGCOPY-0001 收口）

- **StringSequence::new**（constseq.cc:188-219 ctor）：space/size/零常量守卫、
  entry Symbol 类型经 `getSubType` 逐层下降到字符类型（跟踪最内层数组与
  lastOff）、`collect_copy_ops → check_interference → form_byte_array` 链；
  `parentType == ct` 比较用 `Arc::ptr_eq`（+ name/size 回退，镜像
  `matches_factory_char` 回退形）。
- **collect_copy_ops**（cc:227-264）：loc-tree span [beginAddr..endAddr] 迭代
  （VarnodeCompareLocDef 序）、written/COPY/同块/常量输入/尺寸守卫（错尺寸
  返回 false——待分裂）、`tmpDiff` 前元素/间隙/前进算术。
- **construct_typed_pointer**（cc:273-339）：spacebase PTRSUB 基 +
  逐层 PTRSUB（结构域）/PTRADD（数组域，元素 0 跳过 cc:304-307）+
  残差 INT_ADD（cc:327-337）；每层 `getTypePointerStripArray`
  （type.cc:3849 镜像：stripped twin + 数组层剥除 + 工厂 intern）。
- **build_string_copy**（cc:347-372）：`numBytes = moveOps.size() * charSize`
  （cc:351——收集数而非元素数）、getInternalString 源指针、
  selectStringCopyFunction + `HeapSequence::register_builtin_typed`（userop.cc:449
  局部类型臂）、lenVn slot-3 定型。
- **remove_forward/remove_copy_ops**（cc:383-447）：descend 遍历的双臂
  （xref 二次访问 PIECE 合并取 min offset + 普通读点）、deadOps PIECE 级联、
  存活读点 INDIRECT(const(0), iop) 围绕 CALLOTHER 重定义、
  moveOps+deadOps 销毁序。`map<PcodeOp*,list-iter>` xref 镜像为
  `Arc::as_ptr` 键 + points 索引 + alive 投影。
- **transform**（cc:453-461）。
- **B2 双侧 fixture**：`tests/oracle/constseq_stringcopy_1204.{cc,rs}` 八 case
  （flat/nested_struct/array_offset_root/too_short/root_not_first/gap_in_copies/
  wide_copy/concat_cascade——含 PIECE 级联 + INDIRECT 重定义 + STRINGDATA hash
  回读经真实 `getStringData`），双侧 stdout **字节恒等 77/77 行**
  （`/dev/shm/rudra-tests/strfold/{ghidra,rudra}_fixture.out`，oracle 直跑
  e40ed130 libdecomp）。

**源代码路径**: `src/constseq.rs`
**Ghidra 对应**: `constseq.hh` / `constseq.cc` (1146行)
**状态**: 🔧 **L2.5（StringSequence/HeapSequence 双链 1:1 + 双侧 fixture MATCH；
  接线于主管线 Rule 池——RuleStringCopy/RuleStringStore 均已接通）**

**验证**：httpd 镜 ap_ht_time 的 "+0000" 五连 STORE → `builtin_strncpy`
CALLOTHER 对（STRINGDATA+strncpy）在最终 stage projection 中存活（亲采
`/dev/shm/rudra-tests/strncpy/apht_stage_after.txt`）；httpd 镜 301→297、
ap_ht_time 13→9、defects/numbering 双零。**残差**：printc.rs 的
`dispatch_op_rpn` 无 CPUI_CALLOTHER 臂（自述 "everything else is a no-op"）、
`op_callother` 为零调用死码、display_string 臂硬编码 "badstring"——语句现
渲染为裸 `;`，STRNCPY-PRINT-CALLOTHER-0001 登记移交 printc 车道（本轮
printc 写域被 STRLIT 并行持有，禁触）。

## 2026-08-24：Rule 名对齐锁定 oracle 构造器字符串

`RuleStringCopy::get_name` → `stringcopy`、`RuleStringStore::get_name` →
`stringstore`（constseq.hh:121/132 ctor 精确名，原 snake_case 漂移）。


**源代码路径**: `src/constseq.rs`
**Ghidra 对应**: `constseq.hh` / `constseq.cc` (1146行)
**状态**: 🔧 **L2 / `NO_ORACLE`（2026-08-11 锁定源码复核）**——现有 Rust 测试与源码锚点不能证明 L3；地址单位、space identity 和块内 predecessor 仍有确定性结构差异。

## 模块说明

常量序列分析：将 COPY/STORE 操作序列合并为字符串拷贝。
对应 Ghidra 的 `constseq.hh`。

## 导出的公共 API

### `pub struct WriteNode`
数据流边 + 内存偏移。对应 `ArraySequence::WriteNode`。

### `pub struct ArraySequence`
收集最大连续 op 序列。对应 `ArraySequence`。

### `pub struct StringSequence`
收集 COPY op 序列写入栈/local 数组。对应 `StringSequence`。字段 =
`base: ArraySequence` + `root_addr`/`start_addr`（栈偏移）/`space`/
`entry_first`/`entry_size`/`symbol_type`（容器 SymbolEntry 投影，constseq.hh:67-69
成员的 Rust 分裂形）。方法：`new`（ctor 链）、`collect_copy_ops`、
`construct_typed_pointer`、`build_string_copy`、`remove_copy_ops`、`transform`
（`remove_forward` 为静态私有）。

### `pub struct HeapSequence`
收集 STORE op 序列通过堆指针写入。对应 `HeapSequence`。

### `pub struct RuleStringCopy` / `pub struct RuleStringStore`
触发 Rule。对应 Ghidra `RuleStringCopy`/`RuleStringStore`。两者均已完整接通
（RuleStringStore 见 2026-09-25 节；RuleStringCopy 见 2026-09-26 节——
`queryContainer` 桥 + StringSequence 全链）。

测试：constseq::tests 7 个。

## 2026-08-11 ANN-J annotation bootstrap

The five newly anchored helpers were annotation-only changes. Their current
behavior must not be counted as oracle `MATCH`:

- `byte_to_address_int` / `address_to_byte_int` map to
  `space.hh:541/532`, where Ghidra divides/multiplies by `wordsize`. The current
  `constseq.rs` helpers ignore the supplied word size and return the input.
- `get_space_from_const` maps to `varnode.hh:426`. Ghidra recovers the encoded
  `AddrSpace*`; Rudra decodes a flat numeric `SpaceId` and adds a non-constant
  fallback absent from the oracle.
- `calc_ptradd_offset_inner` maps to
  `constseq.cc:604 HeapSequence::calcPtraddOffset`, but inherits the above
  address-unit and space-model gaps.
- `previous_op_in_block` mapped to `op.cc:344 PcodeOp::previousOp`. ~~Ghidra
  takes the immediately preceding list iterator in the same block; Rudra scans
  the global alive bank by mutable order.~~ **2026-09-25 STRNCPY lane**: the
  local alivelist-scan helper was deleted; `gather_indirect_pairs` now uses
  `PcodeOp::previous_op_in_block` from op.rs (the faithful OP-PREVIOUSOP
  delivery), removing this gap.

No behavior was changed in ANN-J. A locked 12.0.4 HeapSequence fixture is
still required, so this module remains L2/`NO_ORACLE`.

## 2026-06-26（续）：constseq.rs 完善实现

新增 ArraySequence 分析方法：
- `new(root_op)` — 构造
- `sort_ops()` — 按操作序排序 move_ops（constseq.cc）
- `form_byte_array()` — 从常量 COPY 收集字节数组（constseq.cc formByteArray）
- `is_valid_string()` — 检查是否有效字符串（null 结尾 + 最小长度）
- `get_string()` — 获取字符串内容（截至首个 null）
- `select_string_copy_function()` — 根据 char 类型大小选择 strncpy/wcsncpy/memcpy（constseq.cc selectStringCopyFunction）

测试：新增 2 个（form_byte_array "Hello\0" + select_string_copy_function）。

### 2026-06-27（会话3 L1）：constseq.cc 核心算法移植

移植 ArraySequence 的干扰检测和序列收集算法：

- **interfere_between(fd, start, end)** — interfereBetween(constseq.cc:42-58)：检查两个 op 之间是否有干扰 op（call/branch/STORE）
- **check_interference(fd, root_offset, element_size)** — checkInterference(constseq.cc:62-103)：从 root 开始收集同块 COPY 常量到连续偏移的 op，找无干扰的最大连续集
- **RuleStringCopy::apply_op** — RuleStringCopy::applyOp(constseq.cc:954-1002)：检测 COPY 常量字符序列，形成字节数组，验证字符串有效性。transform（替换为 strncpy CALLOTHER）需要 userop 基础设施。

### 2026-07-01（续）：StringCopy/StringStore CALLOTHER 替换（非 stub）
- userop.rs：BUILTIN 常量对齐 Ghidra（MEMCPY/STRNCPY/WCSNCPY），register_string_copy_op/register_string_store_op/register_builtin_by_id + builtin_map。
- constseq.rs：select_string_copy_function（constseq.cc:161）+ build_string_copy（347-372）+ transform（453-461）。RuleStringCopy/Store 现在真正创建 CPUI_CALLOTHER op + op_destroy_recursive。2 新测试。
<!-- annotation-pass: 2026-07-04 -->


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
