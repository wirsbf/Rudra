# L2 — 确定性构造化（Determinism by Construction）

> 依赖: 无(与 L1 并行)。状态: 设计。

## 动机（wave 实证）

wave 抓到三起确定性 P0,全部证明同一结论:**差分门禁的信任链建立在 run-to-run
字节恒等之上**,而 Ghidra 移植代码引入无序容器即摧毁它:

| 事故 | 根因 | wave 代价 |
|---|---|---|
| DETERM-COPYTRIM-0001 | merge.rs process_copy_trims 用 HashMap into_iter 驱动合并序 | 16 跑 9:7 双版本,E2E 数字不可信 |
| DETERM-DOMINANTCOPY-0001 | 同源(DominantCopy 委托 processCopyTrims) | 与上合并修复 |
| run-to-run 1 行漂移 | 输出路径某处顺序不定 | AX 车道实证 16 次 3:3 互换 |

Ghidra 自身是确定性的(map 序/单线程序),Rudra 的任何无序引入都是移植缺陷。

## 设计原则

1. **IR 关键路径禁无序容器**: 涉及迭代进输出/合并/创建序的路径用 `BTreeMap`/
   `BTreeSet`/`IndexMap`(保持插入序),迭代顺序成为类型系统保证而非代码评审纪律。
2. **审计手段固化**: 静态 lint(工具)扫描 IR 层文件的 `HashMap`/`HashSet` 使用,
   新增需显式豁免注解+理由(仅限确认无序无关的缓存层)。
3. **门禁前置**: 确定性双跑对比(E2E stdout sha256 相等)纳入 CI——wave 已把它作为
   车道验收标准,正规化为自动检查。
4. **并行探索的前提**: L5 fast 模式必须以"同输入同事件流(序确定)"为基准语义,
   否则并行结果不可比对。

## 与现有资产

- wave 的三起修复(merge.rs 首见序/总线排序/examples payload 排序)是前哨战,
  验证手段(双跑 sha/A-B 树对比)已就绪。
- L1 事件流的序号稳定性(stage_seq 单调)依赖本层。
