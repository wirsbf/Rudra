# `userop.rs` API Reference

## 2026-09-27：兼容路径 volatile builtin 缺省 display 旗标（FUNCDEV-VOLATILE-DEVIATIONS-0001）

`try_register_builtin_by_id` 对 `BUILTIN_VOLATILE_READ`/`BUILTIN_VOLATILE_WRITE`
建立的缺省记录现在带上 `NO_OPERATOR`/`ANNOTATION_ASSIGNMENT`——对齐 oracle
`UserOpManage::registerBuiltin` 的按需缺省 `VolatileReadOp("read_volatile",glb,
false)`/`VolatileWriteOp("write_volatile",glb,false)`（userop.cc:443-447，
functional=false → userop.hh:190-191/205-206 的构造器置位）。此前缺省 flags=0
（functional 形），使 `Funcdata::replace_volatile` 的 cc:758-759 hold 决策
（`getDisplay()!=0` 才 hold）在兼容路径上取反。cspec 侧 `format="functional"`
（decodeVolatile，userop.cc:566-570）仍是唯一零旗标来源。新回归测试
`test_register_builtin_volatile_display_defaults` 钉死两缺省。

> MB24 union 注记：USEROPDEV 并入后 `try_register_builtin_by_id` 改为
> `register_builtin(id, None, 1)` 委托单行，volatile 旗标缺省随之落到
> `register_builtin` 构造体内（与 oracle cc:443-447 位于 registerBuiltin
> 本体一致），兼容路径观察行为不变。

## 2026-09-27：registerBuiltin Datatype 缺省元数据 + VolatileWriteOp 写臂（Lane USEROPDEV）

两项 VOLATILEDEV/VOLATILEOUT 移交收口（USEROP-REGISTERBUILTIN-DEFAULTS-0001 /
USEROP-VOLATILEWRITE-INPUTLOCAL-0001）：

- **`register_builtin(builtin_id, type_factory, default_space_word_size)`** —
  oracle `UserOpManage::registerBuiltin(uint4)`（userop.cc:432-484）的 1:1 入口。
  `type_factory` 参数线程替代 oracle 的 `glb->types` 可达边（userop.hh:74/327；
  参数线程 vs 反链的裁决见 docs/api/varnode.md 2026-08-25 节），
  `default_space_word_size` 替代 `glb->getDefaultDataSpace()->getWordSize()`
  （cc:452/462/472，锁定 x86-64 gcc 语料=ram 空 1）。带工厂时三个 Datatype 臂
  按需构造 cc:449-477 的 ptr/char 指针元数据（`datatype_builtin_local_types`：
  ptrSize=`getSizeOfPointer()`，元素=void/`getTypeChar(getSizeOfChar())`/
  `getTypeChar(getSizeOfWChar())`，ptrType=`getTypePointer(ptrSize,元素,ws)`，
  intType=`getBase(4,TYPE_INT)`，out=in0=in1=ptrType、in2=intType）；
  无工厂时保持 metadata-less 兼容记录。首次注册胜出（cc:435-437），
  未知 id 逐字 `Bad built-in userop id` 且零突变（cc:479-480）。
- **`try_register_builtin_by_id`** 现在是无线程兼容形态
  （`register_builtin(id, None, 1)`）—— Datatype 调用方持工厂时须用
  `register_builtin`（按需缺省）或 `register_builtin_with_local_types`
  （显式类型；constseq typed 路径入口，构造与按需缺省恒等，
  constseq 域空闲时可合并）。
- **`VolatileWriteOp::get_input_local(op, slot, type_factory, symboltab)`** —
  userop.cc:159-172 写臂（VOLATILEOUT 读臂 getOutputLocal cc:128-141 的镜像）：
  `!doesSpecialPropagation() || slot != 2` 双门 → `addr = in(1)->getAddr()`、
  `size = in(2)->getSize()`、usepoint=op 地址 → 全局 scope
  `queryProperties`（vflags 弃读）→ `entry->getSizedType(addr,size)`。
  `symboltab` Option-thread 替代描述符 `glb->symboltab` 边（读臂同形）。
  **消费面分派接线**（C++ 虚分派替代物——varnode.rs `op_input_type_local`
  CALLOTHER 臂的 `is_volatile_write()` 臂插入）登记为 varnode 域后续票，
  见 TODO_BOARD 本行。构造性休眠：锁定 x86-64-gcc.cspec / x86-64.pspec
  `grep -c volatile` 均为 0（本道亲证复跑），触发链首环即断，五语料零差为
  构造性必然（CR-VOLATILEOUT §3 论证复用）。
- 旧名列表便捷器 `register_builtin(name, id)` 更名
  `register_builtin_named`（`initialize_builtins` 专用；oracle 名位让给
  `registerBuiltin(uint4)` 对应物；零行为变化，`initialize_builtins`
  全库无调用方）。
- 新测 5 个：`test_register_builtin_datatype_defaults`（三 id 按需元数据：
  元素名/尺寸/wordsize/slot 布局/Arc 同一性/幂等指针恒等）、
  `test_register_builtin_datatype_first_wins_orders`（typed↔按需双向首注胜出）、
  `test_register_builtin_wcsncpy_dataorg_degrade`（DataOrg 无 size-2 宽字符的
  降级钉死——oracle 该工厂形态会抛 LowlevelError，Rudra 线程降级为
  metadata-less，与 constseq typed 入口同状态降级一致；活架构不可达）、
  `test_register_builtin_bad_id`、
  `test_volatile_write_input_local_symbol_arm`（正例+四负例：非 slot-2 /
  无 special_prop / 地址无符号 / 无 symboltab）。
- VOLATILEDEV 交互注记：其分支（未并入本基）给 `try_register_builtin_by_id`
  volatile 臂补 functional=false 旗标缺省（NO_OPERATOR/ANNOTATION_ASSIGNMENT）；
  本道保留该着陆区（同一 switch 骨架），root 合并时为文本级机械解冲突。

## 2026-09-25：STRINGDATA builtin 的 display_string 旗标（Lane STRNCPY）

`try_register_builtin_by_id` 对 `BUILTIN_STRINGDATA` 建立的记录现在带上
`userop_flags::DISPLAY_STRING`（userop.cc:355-359 `InternalStringOp` 构造器
的 `flags |= display_string`）。此前记录 flags=0，`PrintC::opCallother` 会把
STRINGDATA CALLOTHER 当 functional syntax 渲染而非字符字面量通道。这是
constseq STRNCPY 变换（constseq.cc:705 `getInternalString` 产出的源指针）的
打印前置件之一；printc 侧的 dispatch 臂与字面量渲染见
STRNCPY-PRINT-CALLOTHER-0001（printc 车道）。

## （历史节，见下）

**源代码路径**: `src/userop.rs`
**Ghidra 对应**: `userop.hh` / `userop.cc` (1009行)
**状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——派生 userop 类型/selector/conflict/builtin 契约未闭合；SegmentOp 硬编码 `base<<4`，JumpAssist consumer 与真实 ActionSegmentize 缺失，Architecture/Flow 生产路径未安装 userops。正式门禁 `NO_ORACLE`。

## 模块说明

用户自定义 P-code 操作（CALLOTHER）管理。对应 Ghidra 的 `userop.hh`。

## 导出的公共 API

### `pub enum UserOpType`
用户操作类型（Unspecialized/Injected/VolatileRead/VolatileWrite/Segment/JumpAssist/StringData/Datatype）。

### `pub struct UserPcodeOp`
用户定义 P-code 操作的基础定义。对应 Ghidra `UserPcodeOp`。
- `new(name, type, index)` / `get_name()` / `get_type()` / `get_index()` / `get_display()`

### `pub struct UserOpManage`
所有注册用户操作的管理器。对应 Ghidra `UserOpManage`。
- `register_op(name, type) -> i32` / `get_op(index)` / `get_index_by_name(name)` / `num_ops()`
- `register_datatype_user_op(descriptor)` — 在主 descriptor 容器中定制 typed userop
- `get_output_local(index)` / `get_input_local(index, slot)` — 查询 canonical local type metadata
- `register_builtin_with_local_types(id, out, inputs)` — 用 TypeFactory canonical Arc 首次注册 typed builtin
- `register_builtin(id, type_factory, ws)` — userop.cc:432-484 的 1:1 按需缺省入口（2026-09-27；Datatype 臂带工厂构造 cc:449-477 元数据）
- `try_register_builtin_by_id(id)` — 保留 missing-metadata 兼容路径并显式返回未知 id 错误（现= `register_builtin(id, None, 1)` 委托）

### Built-in IDs
`BUILTIN_STRINGDATA/VOLATILE_READ/VOLATILE_WRITE/MEMCPY/STRNCPY/WCSNCPY`

测试：`userop::tests` 现有 16 个。

## 2026-06-26（续）：userop.rs 完善实现

新增完整 UserOpManage 和专用子类构造函数：
- `initialize_builtins()` — 初始化所有内置 CALLOTHER ID
- `register_builtin_named(name, id)` — 注册内置操作（名列表便捷器，2026-09-27 更名自 `register_builtin(name,id)`，oracle 名位让给按需缺省入口）
- `get_op_mut(index)` — 可变访问
- `is_volatile_read/write(index)` — 检查类型
- `create_unspecialized/injected/volatile_read/volatile_write/segment/jump_assist` — 专用子类构造函数

测试：新增 2 个（initialize_builtins + create_specialized）。

### 2026-06-27（会话3 L1）：userop.cc 专用子类移植

移植 UserPcodeOp 的专用子类 + DatatypeUserOp：
- **DatatypeUserOp** — 提供 CALLOTHER 的输入/输出数据类型（get_output_local/get_input_local）
- **VolatileReadOp** — 易失性读操作（extract_annotation_size 返回 varnode size）
- **VolatileWriteOp** — 易失性写操作
- **SegmentOp** — 分段地址操作（x86 real mode far pointer）
- **JumpAssistOp** — 跳转表辅助操作（index2case/index2addr/defaultaddr/calcsize 注入 ID）
- **InternalStringOp** — 内部字符串操作

UserPcodeOp 新增：get_operator_name/extract_annotation_size/is_volatile_read/is_volatile_write/is_segment/is_jump_assist/is_injected/is_string_data。

### 2026-07-01：segment_ops + get_segment_op
- `UserOpManage.segment_ops: HashMap<i32, SegmentOp>`（userop.hh:347）+ `get_segment_op(space_idx)`。

### 2026-07-01（续）：CALLOTHER 注册 API
BUILTIN 常量对齐 userop.cc:30-35。register_builtin_by_id/register_string_copy_op/register_string_store_op + builtin_map + get_call_other_name。4 新测试。

### 2026-07-01（续 2）：SegmentOp::execute + supports_far_pointer
SegmentOp::execute（userop.cc:218-223）：2输入(base,inner)→(base<<4)+inner；1输入→inner。supports_far_pointer 字段 + has_far_pointer_support()。
<!-- annotation-pass: 2026-07-04 -->

# 2026-08-16：UserOpManage decode 链（CSPEC-UNIVERSAL-CHILD-0001）

- `UserPcodeOp` 摊平 `InjectedUserOp::injectid`（-1 非 injected）。
- `SegmentOp` 补 Ghidra 字段：`space_id`（spc）、`baseinsize`/`innerinsize`、
  `constresolve: Option<VarnodeData>`、`inject_id`。
- `UserOpManage` 补 `jump_assist_ops` 与 decode 链：
  `register_user_op`（userop.cc:490：同名异 index `Conflicting indices`、
  同 index 异名 `User op X has same index as Y`、segmentop 同空间
  `Multiple segmentops defined for same space`）、
  `decode_call_other_fixup`（cc:589+cc:85：decodeInject 先注册库 payload、
  再查 Unspecialized userop，错误 `Unknown userop name in <callotherfixup>`/
  `<callotherfixup> overloads userop with another purpose`）、
  `decode_segment_op`（cc:533+cc:225）、`decode_jump_assist`（cc:606+cc:302）、
  `decode_volatile`（cc:551：inputop/outputop 必填、functional→flags、
  重复注册错误逐字）、`read_varnode_attrs`（pcoderaw.cc:33）。
- `get_op(index)` 补 builtinmap 回落（userop.cc:408-415）。
对拍：unknown-target 编译后残留/segment 定制/volatile 双探针 MATCH；
segmentop/jumpassist 已移植无 oracle 观察（UNTESTED）。模块保持 L2。

## 2026-08-20：DatatypeUserOp local-type 元数据（USEROP-LOCALTYPE-METADATA-0001）

- `UserPcodeOp` descriptor 直接持有 TypeFactory 产出的 canonical
  `Arc<Datatype>` output/input handles；`UserOpManage` 的 index/name 查询返回
  同一个 descriptor，不另设 `index -> type` 旁路表。
- `DatatypeUserOp::new` 严格复现 `userop.cc:55`：只检查前四个 input，
  并依次追加其中的非空项，因而空洞会压缩；`get_input_local(slot)` 再按
  `slot - 1` 查询，slot 0、越界和负 slot 返回 `None`。
- `UserOpManage::get_output_local(index)` / `get_input_local(index, slot)`
  通过 descriptor 虚拟语义查询。无 metadata 时返回 `None`，供后续
  `TypeOpCallother` 使用 TypeOp 的 size-derived fallback。
- `register_datatype_user_op` 消耗 `DatatypeUserOp` wrapper 并把其 base
  descriptor 放入唯一的 `ops` 容器；同名同 index 替换、同名异 index、
  同 index 异名和负 index 的错误顺序与 `UserOpManage::registerOp` 一致。
  稀疏 index 使用真实空 slot，`get_op` 不再把占位记录当成已注册 op。
- `register_builtin_with_local_types` 显式接收 Architecture TypeFactory 的
  canonical Arc，覆盖 `builtin_memcpy` / `builtin_strncpy` /
  `builtin_wcsncpy`；首次注册胜出，重复注册保持同一 descriptor 和原始
  metadata。兼容 API `register_builtin_by_id` 对这三项建立正确的
  `Datatype` descriptor 类型，但明确保留 missing-metadata fallback；未知
  builtin 由 `try_register_builtin_by_id` 返回逐字 `Bad built-in userop id`。
- `builtin_map`/`ops` 内部用 `Box` 保持 descriptor 地址在容器增长时稳定，
  对应 Ghidra manager 存放 heap-allocated `UserPcodeOp*` 的身份语义。

真实 12.0.4 门禁：
`tools/run_userop_localtype_metadata_oracle.sh` 对比 61 条完整观察记录，覆盖
builtin factory identity、slot-1/空洞压缩、missing metadata、重复注册、
三类注册异常及异常后的索引/名称/descriptor 状态，投影结果
`projection_status=MATCH`。runner 从提交 `a29f5b7` 的完整归档构建，只覆盖
当前 `src/userop.rs`，不读取工作树中的 TypeFactory 或其他依赖源码。
`TypeOpCallother` 的 Architecture-owned caller/fallback 闭包尚未接入对拍，
所以 `overall_status=UNTESTED`；该证据只解锁 CALLOTHER metadata 地基，
下游仍属于 `TYPEOP-LOCALTYPE-DISPATCH-0001`，模块总体保持 L2。

## 2026-09-29：`initialize` + `register_op_at_index`（MCENSUS4-SQLITE-FTSTYPING-0001，Lane FTSINCRMERGE）

- **`initialize(basicops: &[&[u8]]) -> Result<(), String>`** — `UserOpManage::
  initialize`（userop.cc:392-403）的 1:1 移植：空名跳过，其余按 SLEIGH
  索引注册为 UnspecializedPcodeOp（.sla `userop` 名表 = `Translate::
  getUserOpNames` 的 CALLOTHER-index 序）。架构还原序（architecture.cc:635
  `userops.initialize(this)`，早于 :642 parseCompilerConfig）的基座层——
  后续 `<callotherfixup>`/`<segmentop>`/`<jumpassist>` 经同一 registerOp
  索引纪律定制。
- **`register_op_at_index(name, index)`** — `UserOpManage::registerOp`
  （userop.cc:490-532）的显式索引形态：同名异 index 冲突（LowlevelError）、
  同 index 同名=定制替换、index/name 双 crossref 重写。原 `register_op`
  （len 追加式）保留给非 SLEIGH 索引的生产注册路径。

生产接线=gen 驱动 `build_architecture`（examples/gen_decompile.rs，
architecture.cc:635 位置对应物）：`sleigh.user_op_names()` →
`UserOpManage::initialize`。恢复 CALLOTHER 名通道：x86 `ud2` 语义的
`invalidInstructionException`（CALLOTHER #77）以名渲染（printc.cc:673-692
functional 语法），不再是 `CALLOTHER[77]` fallback；earlyJumpTableFail 的
userop-type 咨询解析真实描述符。canon curl/httpd 语料输出零 CALLOTHER 站点
（双侧 golden 亲证），名表安装构造性 canon 中性。
