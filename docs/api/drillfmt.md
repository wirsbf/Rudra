# drillfmt

> 对应 `src/drillfmt.rs`。RUDRA-GLUE 模块:Ghidra 无单一对应物;这是
> stage-bisect v2 drill 发射器(Lane AA)专用的 oracle 原文格式化层,把
> Rugra IR 渲染成 Ghidra console debug 原语的精确文本拼写,只读、不回灌
> 管线。激活条件:`RUGRA_STAGE_DRILL=1`(经 `drillobserve::is_enabled`)。

## 2026-09-22: 建模块(Lane AA, v2 drill emitter)

- `seqnum_raw(pc, uniq)`:`<pc.printRaw>:<uniq-hex>` — address.cc:32-38 +
  AddrSpace::printRaw(space.cc:206-221)留下的 hex 流状态使 uniq 也按
  十六进制输出;地址宽度按 8/6/4 字节动态收缩(space.cc:208-215)。
- `DrillFmt::varnode_raw`:varnode.cc:711-756 printRawNoMarkup/printRaw 全
  语义 — 寄存器名(含 `+off` 子寄存器后缀,xref 反查 point.offset/size)、
  否则 `<shortcut><offset>`、`expect!=size` 时 `:size`、`(i)`、
  `(<def-seqnum>)`(无前导空格)、`(free)`。
- `DrillFmt::op_print_debug`:op.cc:376-385 — `<seqnum>: ` + dead/unattached
  `**` 或 printRaw。
- `DrillFmt::op_raw`:typeop.cc 各 TypeOp 结构形式 — binary/unary/func、
  copy、load/store(空间名)、call/callind、return、branch/cbranch
  (Block_<i>:<start> printShortHeader)、multiequal(` ? ` 连接)、
  indirect(`[]`/`[create]`)、ptradd(`(*i2)`)、ptrsub(`->`)、
  subpiece(动态 `SUB<in><out>`,typeop.cc:2127-2135);operator 名取
  Ghidra ctor 名 + getOperatorName 覆盖(float 系 `f+` 等,与
  src/typeop.rs 注册名一致)。

### 2026-09-26 — FUNCDATA-PRINT-0001 修正(shortcut 表 + null 槽渲染)

- `space_shortcut` 重写为 translate.cc:517-570 `assignShortcut` 的忠实
  表:const `#`(cc:524-526)、名为 "register" 的 IPTR_PROCESSOR `%`
  (cc:527-529)、其余 IPTR_PROCESSOR 取 name[0](cc:530-533,故 ram=`r`)、
  spacebase `s`(cc:535-537)、internal `u`(cc:538-540)、join `j`
  (cc:543-545)、iop `i`(cc:546-548)、default `x`(cc:550-552)。
  **SB-DRILL-RAM-SHORTCUT 关闭**:ram='r' 由 print_family fixture 的
  oracle 直跑证明(`r0x00001100`),与真实 x86-64 oracle 符号转储
  (regsym-evidence:code 符号 `r0x...`、register 存储 `%0x...`)一致;
  旧表 Register='r'/Ram='0' 两处皆误。v1 bank 投影不经本模块,零影响
  (bank 391/391 复跑验证)。
- `op_raw` null 槽渲染:每个 TypeOp 形态的 varnode 槽位都经
  `Varnode::printRaw(ostream&, const Varnode*)` 静态包装
  (varnode.cc:1207-1214),null 槽印 `<null>`;Ghidra op 构造即预留
  null 槽(op.cc:71-84 `inrefs(s)`),Rugra `inrefs` 只存已设输入,
  缺席槽位在此按 `<null>` 渲染(print_family fixture 的无输出
  INT_ADD 证明:`<null> = <null> + <null>`)。
- CALLIND 形态修正:typeop.cc:791-807 `s << name` 后**无空格**直接接
  in0(CALL 是 `name << ' '`,cc:668-670,两者不对称);RETURN 分隔符
  修正:typeop.cc:882-900 — in1 前空格、in2+ 前逗号(旧实现全用空格)。
- 模块头与 op_raw 的 typeop.cc 行号引用重锚(cited-line-drift 修正:
  copy 425-431、load 502-509、store 572-580、branch 590-601、
  cbranch 621-636、return 882-900、multiequal 1967-1983、
  indirect 2022-2033、call 668-684、callind 791-807、
  ptradd 2283-2296、ptrsub 2380-2388)。
- 已登记格式缺口(不影响本语料,不构成管线差异):
  - SB-DRILL-FSPEC-NAME:CALL 目标恒 `ffunc_<addr>`;oracle 经 FspecSpace
    打印被调函数真名,命名 callee 会差(本语料被调者全是无名 PLT stub,
    双侧一致)。
  - iop varnode:经 drillobserve 指针注册表解析为被引 op 的 SeqNum
    (op.cc:41-47 非分支形式);被引 op 已销毁时退化为原始偏移。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
