# `pcodeinject.rs` API Reference

**源代码路径**: `src/pcodeinject.rs`
**Ghidra 对应**: `pcodeinject.hh` / `pcodeinject.cc` (638行)
**状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——decoder、参数 index、script/id-vector/tempbase、dynamic payload 与 duplicate-error 契约不全；Architecture 无 inject library，Flow 不排队 CALLOTHER 也不调用 injection，直接 API 还从 HashMap 非确定取首项。生产闭包不可达，正式门禁 `NO_ORACLE`。

## 模块说明

P-code 注入引擎。对应 Ghidra 的 `pcodeinject.hh`。
允许用用户定义的 p-code 模板替换特定操作（CALL fixup 等）。

## 导出的公共 API

### `pub struct InjectParameter`
注入 payload 的输入/输出参数。对应 `InjectParameter`。

### `pub enum InjectPayloadType`
注入类型（CallFixup/CallOtherFixup/CallMechanism/ExecutablePcode）。

### `pub struct InjectPayload`
可注入的 p-code 操作容器。对应 `InjectPayload`。

### `pub struct PcodeInjectLibrary`
所有注入 payload 的管理器。对应 `PcodeInjectLibrary`。
- `register_payload(payload) -> id` / `get_payload(name)` / `get_id(name)` / `num_payloads()`

测试：pcodeinject::tests 3 个。

## 2026-06-26（续）：pcodeinject.rs 完善实现

新增完整注入基础设施：
- `InjectPayload::add_input/add_output/get_input/get_output` — 参数管理
- `InjectContext` — 注入上下文（base_addr/next_addr/call_addr/input_list/output）（pcodeinject.hh:79）
- `PcodeEmit` trait — 注入操作发射回调
- `PcodeEmitArray` — 内存收集发射器（dump + ops 数组）

测试：新增 3 个（inject_context + pcode_emit_array + payload_add_params）。
<!-- annotation-pass: 2026-07-04 -->

# 2026-08-16：Ghidra 结构重构 + decode 链（CSPEC-PCODEINJECT-CALLFIXUP-0001）

`PcodeInjectLibrary` 重构为 Ghidra 结构（pcodeinject.hh:187 +
inject_sleigh.hh:110）：id 索引 `injection: Vec<InjectPayload>`、四对
name→id map / id→name 向量（`call_fixups`/`call_fixup_names`、
`call_other_fixups`/`call_other_target`、`call_mechanisms`/`call_mech_target`、
`script_map`/`script_names`）、SLEIGH 库成员 `tempbase`（初始化自
`Translate::getUniqueStart(INJECT)`）与 sleigh 符号 lookup（`set_sleigh_lookup`）。

decode/注册链（错误逐字）：`register_call_fixup` 等（cc:220/236/252/268，
Duplicate 先抛后扩向量）、`allocate_inject`（inject_sleigh.cc:418，CALLFIXUP/
CALLOTHER 占位名 "unknown"）、`decode_inject`（cc:352 = allocate→decode→
register，失败留 orphan payload 非事务）、`InjectPayload::decode_callfixup`
（inject_sleigh.cc:171）/`decode_callother`（cc:201）/`decode_pcode`（cc:84）/
`decode_executable`（cc:256）/`decode_payload_attributes`（cc:83）/
`decode_payload_params`（cc:111）/`decode_body`（cc:72）/`decode_parameter`
（cc:46）/`order_parameters`（cc:67）、`register_inject`（cc:433：map 注册先于
编译）、`parse_inject`（cc:373：addOperand、setUniqueBase、parseStream、
`<src>: Unable to compile pcode: <msg>`、成功后 tpl 替换 parsestring）、
`manual_call_fixup`/`manual_call_other_fixup`（cc:493/504）。
`InjectPayload` 摊平 InjectPayloadSleigh/InjectPayloadCallfixup 子类字段
（source/parsestring/tpl/target_symbol_names）。`get_payload(name)` 保留为
FlowInfo 兼容视图（id 序首匹配）。旧 `register_payload`/`name_to_id`/
`num_payloads`/`get_id` 自创 API 删除。

对拍：runner 16 真实 callfixup 模板 XML 逐字节 MATCH + callother 编译失败
残留探针。残差：InjectPayloadDynamic addrMap/debug-decode（仅 ELEM_INJECTDEBUG
可达）UNTESTED。模块保持 L2。

# 2026-08-23：`InjectPayload::inject` 执行器 + 真空间 `InjectContext`（FLOW-INJECT-WIRING-0001）

锁定 oracle Ghidra 12.0.4 commit `e40ed130…`。完整读取
`InjectPayloadSleigh::inject`（inject_sleigh.cc:48-65）、`setupParameters`/
`checkParameterRestrictions`（inject_sleigh.cc:105-159）、`ConstTpl::fix`/
`fixSpace`（semantics.cc:116-215）、`PcodeBuilder::build`（semantics.cc:925-952）、
`SleighBuilder::dump`/`generateLocation`（sleigh.cc:160-280）、
`PcodeCacher::resolveRelatives`/`emit`/`addLabel`/`addLabelRef`（sleigh.cc:86-144）
后移植：

- **`InjectContext` 真空间化**：`input_list`/`output` 从数值空间标签元组改为
  `Vec<VarnodeRaw>`（Ghidra 是 `vector<VarnodeData>`，pcodeinject.hh:85-86），
  模板执行需要真实 `AddressSpace` 做 const 掩码/unique 判定。
- **`PcodeEmit` trait / `PcodeEmitArray`**：`dump(addr, opc, &[VarnodeRaw],
  Option<VarnodeRaw>)` 对齐 `PcodeEmit::dump`（translate.hh:96）签名。
- **`InjectPayload::inject(&self, context) -> Result<Vec<PcodeOpRaw>, String>`**：
  模板执行链 = checkParameterRestritions（错误逐字）→ setupParameters 固定句柄
  （inputs 0..n-1、outputs n..，offset_space 恒 null → `isDynamic` 恒 false，
  动态 LOAD/STORE 展开不可达）→ `PcodeBuilder::build`（BUILD/DELAY_SLOT/
  CROSSBUILD 硬错误——snippet 禁用；LABELBUILD=CPUI_PTRADD 记 label 位置）→
  `dump_op`（generateLocation：const 空间 `&calc_mask(size)`、unique 空间
  uniqueoffset=0、其余 wrapOffset；JRelative input(0) 记 label ref）→
  `resolve_relatives`（`labels[id]-calling_index` 掩码，缺失 label 报
  `Reference to non-existant sleigh label` 逐字）→ `cacher.emit(baseaddr)`
  （每个注入 op 都带 baseaddr）→ `Vec<PcodeOpRaw>`。`fix`/`fix_space` 覆盖
  JStart/JNext/JNext2/JFlowRef/JFlowDest/JCurSpace(Size)/JRelative/SpaceId/
  Handle{v_space,v_offset,v_size,v_offset_plus（const 时 `>>8*(plus>>16)`）}。
  RUDRA-GLUE：JFlowRef/JNext2 在注入上下文未设置（ParserContext 默认
  Address 偏移 0）；JCurSpaceSize 固定 8（x86-64 机型，ADDRESS-0001 族残差）；
  非 const/unique 空间不做 wrapOffset 归约（AddressSpace 标签枚举无 highest）。
- **emit 桥**：inject 产物经 `Funcdata::inject_raw_ops_single`（= `PcodeEmitFd::dump`
  funcdata.cc:878）入 bank——借用拆分在 flow.rs 侧说明。

测试：pcodeinject::tests 16 全绿（copy/add/label-branch 三 snippet 的
操作数替换、const 掩码、`<manual callotherfixup …")` 逐字 source、参数
count/size 失败、无模板失败）。

### 2026-08-23（续）：`flow_inject_1204` oracle 门禁 MATCH

`InjectPayload::inject` 执行器与 `InjectContext` 真空间化随
`tools/run_flow_inject_oracle.sh` 通过锁定 oracle 差分：cpuid（生产
CALLOTHER 路径）、add（const 掩码/操作数替换）、label（label 相对分支）
三 case 的注入后 op 序列（SeqNum addr/time、opcode、STARTBASIC、块归属、
输入/输出 varnode token）双侧逐字节一致，含 moveSequenceDead 落位与
被替换 CALLOTHER 的销毁。模块 L2（CALLFIXUP 触发与 dynamic payload 残差
见 metadata）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 2 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-27 — PARSEADJ-PARSEFACE-PCODE-0001 label-size re-pin（测试侧）

`test_inject_execute_label_branch_snippet` 的 label 分支目标断言由 size 8
改为 4：oracle 真值是 `sizeof(uintm)`（pcodeparse.y:199 jumpdest label 形；
types.h:27 `typedef uint32_t uintm` = 4），已由整面 fixture
`pcode_snippet_face_1204` 的 st20/LF|clrlbl 记录（`const_real val="0x4"`）
逐字节钉死。仅测试断言重钉，生产代码零改动（g6 修复在
`docs/api/pcodeparse.md` 2026-09-27 节）。
