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
