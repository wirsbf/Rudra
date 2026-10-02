# drillobserve

> 对应 `src/drillobserve.rs`。RUDRA-GLUE 模块:Ghidra 无单一对应物;
> stage-bisect v2 drill 的只读 per-application 修改记录器,镜像 oracle
> `OPACTION_DEBUG` 机制的同位钩子。激活条件:`RUDRA_STAGE_DRILL=1`;
  env 未设置时所有入口为 no-op,管线行为与无此模块逐字节一致。

## 2026-09-22: 建模块(Lane AA, v2 drill emitter)

镜像的 oracle 机制(锁定 e40ed130):

- `mod_check`(funcdata.cc:1010-1022 debugModCheck):首次触碰缓存
  before 串,以 `op_addl_flags::MODIFIED`(0x4)去重;由 src/funcdata.rs
  的变更入口在守卫之后、首次实际变更之前调用(对应 funcdata_op.cc
  :25-33/:52-66/:70-87/:104-141/:150-186/:203-221/:291-317 与
  funcdata_varnode.cc:269-292 的 #ifdef 钩子位)。锁纪律:钩子自带
  短暂读写锁,调用点均在函数入口或既有守卫之后,不与函数体内的长
  写锁重叠(死锁风险已规避)。
- `activate`/`flush(leaf_name)`(action.cc:316-322 perform 边界与
  :839-845 processOp per-rule 边界;flush 镜像 funcdata.cc:1034-1057
  debugModPrint:count 先打印后自增,首号 0;仅当 application 实际修改
  了 traced op 才产生块/计数)。
- `register_iop`/`resolve_iop_seq`:iop 空间 varnode 的
  指针→op 注册表(funcdata.rs new_varnode_iop 注记),供 drillfmt 输出
  op.cc:41-47 的确定性 SeqNum 形式。
- 块缓冲 `drain()`:每次 application flush 追加完整 DEBUG 块文本,
  由 examples/curl_decompile.rs 的 drill 驱动在每个管线暂停点取走并
  包 @BEGIN/@END。

语义保障:flush 生成的 after 串在 application 边界读取 op 当前状态
(dead op 保留 `<seqnum>: **`,与 oracle 时序一致);MODIFIED 位在
flush 时清除;记录器线程本地(每 worker 线程独立)。

## 2026-10-03：resolve_iop_printraw 全派发（VNPRINT-JOINIOP 收口）

- 新增 `resolve_iop_printraw(offset: u64) -> Option<String>`：
  `IopSpace::printRaw` 全派发（op.cc:41-59）供 legacy 枚举打印路径
  （`AddressSpace::print_raw_offset_arch` 的 Iop 臂）调用。非分支臂印
  `op->getSeqNum()`（op.cc:48-50）；分支臂印 `code_` + 目标块起始地址
  shortcut + 起始地址 printRaw（op.cc:52-58）——sizeOut()==2 时目标 =
  `isFallthruTrue() ? getOut(0) : getOut(1)`（印非落穿条件块），否则
  `getOut(0)`。无空间句柄的 legacy 起始地址按镜面码空间 ram 投影
  （'r' + 基类形，与 heritage.rs warnop 形同判据）；tagged 地址走
  SpaceAddress::print_raw/get_shortcut。
- 查找侧无 env 门（设计性）：注册侧 `register_iop` 仍持 RUDRA_STAGE_DRILL
  门 → 生产运行注册表恒空 → 本函数返回 None（与门控形观测恒等），单测
  fixture 可直接注入 thread_local 注册表而绕开 OnceLock 闩锁。None 同时是
  oracle 悬空解引用臂（被引用 op 已销毁）的确定性映射，调用方回退基类形。
- `resolve_iop_seq` 重构为共享 `lookup_iop_op`（行为不变，drillfmt 消费者
  观测恒等）。单测五例：非分支 SeqNum 形/未注册 None/双出边
  fallthru_true→out(0)/非 fallthru_true→out(1)/单出边→out(0)。
