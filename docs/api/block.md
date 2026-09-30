# `block.rs` API Reference

**源代码路径**: `src/block.rs`

## 2026-09-30：BlockBankView/hold/adopt（Lane ARENAFLIP-d 步骤 2）

- `BlockBank::hold() -> BlockBankView`：扫描级单一读守卫视图；`view.index/
  btype/arc(id)` 为影子槽读（block.hh:160/184 字段读形态）。`BlockBank::
  adopt(&Arc)`：复合块经 Vec 槽位安装（identify_internal 等旁路 add_block）
  的注册路径（幂等；同 add_block 的 cell+身份映射记账）。
- 行为恒等面见 docs/api/blockaction.md 2026-09-30 步骤 2 条。

## 2026-09-30：per-graph block bank + BlockEdge point_id 值孪生（Lane ARENAFLIP-d 步骤 1）

- **BlockBank**：`BlockGraph` 新增 `bank: BlockBank` 字段——
  `RwLock<Arena<BlockCell, BlockId>>`（arena.rs 冻结 Arena）+ Arc 身份映射
  （`Arc::as_ptr` 键 → `BlockId`，既定身份键模式）。`add_block` 插入 cell
  （`arc` + `btype` 影子[插入后不可变] + `index` 影子）并登记身份映射项；
  槽位在 Vec 列表移除路径后**不回收**（zombie = oracle FlowBlock 堆存活
  直到图 clear；`clear()` 是唯一回收点，bump generation 使陈旧 id 失效）。
- **无锁身份解析**：`bank.id_of(&Arc) -> Option<BlockId>` /
  `registered_id_of`（SENTINEL 形态）**不触碰 block 自身的 RwLock**——
  这是给边打孪生标记的唯一无死锁方式（自环边的 point 正是持有写守卫
  的 block 本身；point.read() 打孪生会死锁，测试挂起现场捕获后重构为
  bank-map 形态）。
- **BlockEdge.point_id**：`BlockEdge` 新增 `point_id: BlockId` 值孪生
  （未标记时为 `BlockId::SENTINEL`；裸测试 fixture 保持 SENTINEL）。oracle
  依据：block.hh:57-65 `BlockEdge` 本就是值类型。生产打标位：`add_edge`
  （双半边守卫前预打）、`build_copy` remap、`replace_out/in_edge_target`、
  `rewrite_in/out_edges_to_idx`、`force_output_num`（自环边）、funcdata
  `replaceInEdge`/node-split、flow splitBasic tail 重定向——全部经 bank
  映射，绝不在 point 守卫下解析。
- **index 影子单点维护**：`BlockGraph::set_block_index` 镜像全部活体
  set_index 突变位（find_spanning_tree 重置/rpost 赋值/第二趟重置/
  build_dom_tree 重编号/identify install 换位）；`decode_header_trait`
  保持字段-only set_index（无调用者，已注明）。
- **影子读 API**：`bank.index_of(id)`/`btype_of(id)`/`arc_of(id)`/
  `set_index_shadow`。block.hh:160/184 index/getType 为纯字段读，影子
  镜像之。
- **行为恒等**：cargo test --lib 2018P/0F/5I；canon curl md5
  4ab1db2a177e854c6bddca2ecf413685 defects 0/0/0（124/124）；canon httpd
  md5 7d5b9e7c3348ee8da1865df281ec05b9。

## 2026-09-29：FlowBlock 引用形边访问器 get_out_ref/get_in_ref + absorbed_into 键型切换（Lane BLOCKSTRUCT per-rule 常数）

- **引用形访问器**：FlowBlock trait 新增 `get_out_ref(&self, slot) ->
  Option<&BlockEdge>` / `get_in_ref(&self, slot) -> Option<&BlockEdge>`
  （RUGRA-GLUE 借用安全 helper；11 个具体类型 impl 各两行）。对应 oracle
  `FlowBlock::getOut/getIn` 的直接 `outofthis[i]`/`intothis[i]` 引用读形态
  （block.hh:301-306）。既有 `get_out`/`get_in` 返回拥有型 `Option<BlockEdge>`
  （含 Arc 克隆）保持不变——collapse 规则 miss 路径（VdbeExec 4M+ 规则试
  ×23.2M out_edge_is_goto 调）只读 `.flags`/`.point`，改走引用形后零
  refcount 往返；fire 路径与需要拥有边的调用点继续用拥有形。读语义逐字节等价
  （同一 Vec 的同一 slot）。
- **absorbed_into 键型**：`HashMap<i32,i32>` →
  `FxHashMap<i32,i32>`（rustc-hash 2.0 既有依赖，此前未用）。`is_consumed()`
  成员测试在 collapse 扫描里每规则试/每入边运行（VdbeExec 数千万次），
  SipHash 探测 ~40ns → pass-through ~8ns。键值语义、contains_key/get/insert/
  remove/clear 行为不变；唯一非测试 `.keys()` 消费
  （blockaction.rs identify_internal 停靠槽位改写）为顺序无关条件更新，
  迭代序无消费者（blockaction.rs:4555 亲核；block.rs:9784 与
  blockaction.rs:9784 均为测试 fixture）。
- **行为恒等**：canon curl/httpd base==opt 字节恒等、sqlite 全语料 assembled
  5,287,820B cmp 恒等、VdbeExec --one 1055 md5 ad90320e 恒等、镜面五面钉值
  全 PASS（详见 docs/api/blockaction.md 2026-09-29 SPEEDPROF-BSPERULE-0001 条）。

## 2026-09-29：print_tree_dbg 补 InfLoop 臂（Lane SWITCHDISPATCH 诊断完善）

- **缺口**：`print_tree_dbg`（RUGRA-GLUE 结构树调试转储器，`RUGRA_DUMP_FUNC`
  /`RUGRA_TREE1` 的输出后端）此前对 `BlockType::InfLoop` 落入 `other` 兜底臂，
  只打印 `#N InfLoop @addr` 一行而不递归 `body` —— SetCoderProperties/
  GetOptimumFast（MIRROR-GIANTS-SWITCHDISPATCH-0001 双侧钉形）的结构树转储
  里最外层 InfLoop 的整个循环体不可见，导致与 oracle
  `BlockGraph::printTree`（block.cc:1290-1301，无类型遗漏）的逐节点对照
  无法进行。
- **修复**：补 `BlockType::InfLoop` 臂——打印 `#N InfLoop @addr` 后递归
  `body`，与 WhileDo/DoWhile/Switch 臂同形。诊断面零行为差异（生产管线
  不读该转储器）。
- **配套**：`examples/blockstruct_tree_dump.rs` 同 commit 补 Architecture/
  ProtoModelFull 接线（FUNCPROTO-MODEL-BIND-0001——call-effect 动作经
  `FuncProto::effect_iter` 读默认原型模型，无 arch 时 panic；镜像驱动同
  形接线见 gen_decompile），独立函数结构树转储示例恢复可用。

## 2026-08-29：absorbed_into 升级为唯一消费记录（不再依赖 f_dead）

`identify_internal`/序列合并不再对被组合块吸收的子块置 `block_flags::DEAD`
（Ghidra `BlockGraph::identifyInternal` block.cc:940-963 对组件不设任何 flag；
`f_dead` 专属于 Funcdata 死基本块移除 funcdata_block.cc:333/370）。组件的
"已被消费、对规则不可见"状态由 `BlockGraph::absorbed_into`（消费索引 → 组合块
install 槽）这一 parent 记录承担：`is_consumed()` 成员测试替代 Ghidra
`list = newlist` 列表压缩（block.cc:953-960）的可观测效果，
`finalize_structure` 用同一成员关系做末端物理压缩。组件保留 component-to-component
内部边（selfIdentify block.cc:905-928 对 `parent == this` 的对端从不重写）；
边界半边由 `replaceOutEdge/replaceInEdge`（block.cc:160-191）成对迁移到组合块，
平行边按 `dedup`（block.cc:525-539）首槽保留 + 单侧标签 OR 合并。
双侧 fixture 全量观测 MATCH（详见 docs/api/blockaction.md 2026-08-29 节）。

## 2026-08-28：结构化条件真实取反

`BlockList` 与 `BlockCondition` 现通过 `FlowBlock` 虚派发实现
`negateCondition`。基础 `swapEdges` 交换完整的两个 outgoing half-edge，修正目标
incoming half 的 `reverse_index` 并翻转 `FLIP_PATH`；`BlockCondition` 同时对两个
child 分发取反并执行 AND/OR 对偶。锁定 structured-negate fixture 覆盖 13 cases、
14 lines、3628 bytes，双侧 raw stdout 逐字节一致
（sha=`d47ef9da438012d850b3374dddf6d54cf7bdbaaf82b145b5b7c280ab5151c57d`），
独立 reviewer 仅作 scoped APPROVE。GetStr 聚焦极性已经恢复，但 BlockBasic/Copy
全分支、完整 FlowBlock/identifyInternal 与 structurer/PrintC 闭包仍为
`MISMATCH/UNTESTED`，不得由此升级 L3。

## 文档状态

- **状态**: 已核对（当前有效；2026-08-28 真实 BlockCopy/buildCopy）
- **2026-08-28 追加（BLOCK-BUILDCOPY-MIRROR-0001）**: `BlockGraph::new_block_copy/build_copy` 与真实 `BlockCopy` 已接入。锁定 12.0.4 的 5-case fixture 对边向量/标签/reverse slot、状态复制、copymap、append-prefix、实时委托、Basic end-insert 及 swap 后平行边删除产生 37 records / 5577 bytes，双侧逐字节相同（covered projection `MATCH`），并获得独立 scoped review APPROVE。default-switch 标签以 Ghidra 的 `0x04` 同步写入出入两半边，`BlockBasic::insert_op` 对 `BRANCHIND` 设置 `f_switch_out`。完整状态仍为 `MISMATCH`：真实 parent 身份、内建 structured source 状态、BlockCopy negate/print/marshal、Action executor 与完整结构化消费闭包均未取得完整行为门禁。
- **2026-08-27 追加（TRI2-STRUCT-IRREDUCIBLE-TRACE-0001）**: `BlockGraph` 新增 `absorbed_into: HashMap<i32,i32>` 字段（吸收块索引 → 吸收它的组合块 install 槽位）+ `resolve_to_graph_level(&self, idx) -> i32`（沿链传递解析；live 块返回自身；`clear()` 一并重置）。该 map 只是对 Ghidra `FlowBlock::parent` 链的索引近似，不能保存对象身份、真实别名或父对象状态，因此不算等价 parent 实现；完整修复绑定 `BLOCK-ADDGRAPH-SEMANTICS-0001`。
- **Ghidra 12.0.4 对齐级别**: L2；edge flags、双向 reverse-index、parent、RPO/loop/dominator 与 marshal 均有已复现反例
- **文档目标**: 说明 Rugra 当前控制流块模型、CFG 相关对象和结构化块表示
- **可信边界**: 本文档描述的是当前 `block.rs` 在工程中的职责与公开接口角色，不代表“控制流恢复已经与 Ghidra 完全一致”
- **阅读建议**: 建议与以下文档配合阅读：
  - `funcdata.md`
  - `op.md`
  - `varnode.md`
  - `heritage.md`
  - `printc.md`
  - `../data_contract.md`

---

## 模块定位

`block.rs` 是 Rugra 当前**控制流块模型与块图组织层**的核心模块之一。  
它的主要职责是：

1. 定义基本块及其共同抽象
2. 定义块之间的连接关系
3. 提供控制流图容器
4. 提供若干结构化块类型，用于把低层 CFG 逐步表达成更接近高级语言控制结构的形式

从整体链路看，它位于大致如下位置：

```text
raw ops / PcodeOp
  -> Funcdata
  -> BlockBasic / BlockGraph
  -> dominance / loop / structure-related processing
  -> structured blocks (if / while / list / goto ...)
  -> PrintLanguage / PrintC
```

因此，`block.rs` 更适合被理解为：

- **函数级控制流组织层**
- **从操作节点走向结构化输出的中间桥梁**
- **SSA、循环分析、结构恢复和打印层的重要依赖**

而不是：

- 反汇编层
- 类型恢复层
- 最终输出层
- 当前已完成全部控制流恢复证明的证据

---

## 与 Ghidra 的关系

本模块中的主要概念明显参考了 Ghidra 的 `block.hh`，包括：

- `FlowBlock`
- `BlockBasic`
- `BlockGraph`
- `BlockIf`
- `BlockWhileDo`
- `BlockDoWhile`
- `BlockList`
- `BlockGoto`
- `BlockCopy`

但需要明确：

- **命名与对象分层对齐，不等于行为已经完全对齐**
- 本模块当前更能证明“架构方向与对象模型接近 Ghidra”
- 不能仅因为这些对象存在，就宣称：
  - CFG 已全面恢复正确
  - dominance / frontier 已全面验证一致
  - loop structuring 已全部成熟
  - 最终控制流输出已与 Ghidra 等价

---

## 当前设计思路

`block.rs` 主要解决两个层次的问题。

### 第一层：低层控制流组织
围绕基本块和边关系，回答：

- 一组 `PcodeOp` 如何按控制流边界切成 block
- block 之间如何建立前驱/后继关系
- 如何在图层表达 dominance、RPO、loop 等分析基础

### 第二层：高层结构块表达
围绕结构化块对象，回答：

- 某段图能否被表达为 `if`
- 某段图能否被表达为 `while-do`
- 某段线性块能否被表达为 `BlockList`
- 某段无法自然结构化的图是否应退化为 `goto`

这说明 `block.rs` 并不只是“保存基本块列表”的地方，它还是：

- CFG 分析基础设施
- 结构恢复过渡层
- 打印层语句组织的重要语义来源

---

## 公共 API 总览

本文重点覆盖以下公开项：

- `BlockType`
- 一组 block 标志常量
- `FlowBlock`
- `BlockBasic`
- `BlockEdge`
- `BlockRef`
- `BlockGraph`
- `BlockCopy`
- `BlockGoto`
- `BlockIf`
- `BlockWhileDo`
- `BlockDoWhile`
- `BlockList`
- `BlockSwitch`

---

## 1. `BlockType`

### `pub enum BlockType`

用于标识控制流块的类型。

## 角色

`BlockType` 是块层分类的基础枚举，用于说明一个 block 当前属于哪类结构。  
它的作用通常包括：

- 区分基础块与结构化块
- 让打印层和结构恢复阶段按类型分支处理
- 作为调试和图遍历时的快速分类依据

## 当前应如何理解

它更适合作为：

- **控制流块类别标签**

而不是：

- 高级语言语法本身
- 最终代码生成的直接替代物

也就是说，`BlockType` 用来表达“当前块是什么类型”，但不等于最终一定能生成完全理想的高级语言结构。

---

## 2. 控制流块标志位常量

本模块公开了一组 `u32` 标志位，用于表示块对象的状态或属性。

### 当前公开常量

Ghidra 共享位包括 `SWITCH_OUT`、`UNSTRUCTURED_TARG`、`MARK`、
`MARK2`、`ENTRY_POINT`、`INTERIOR_GOTOOUT`、`INTERIOR_GOTOIN`、
`LABEL_BUMPUP`、`DONOTHING_LOOP`、`DEAD`、`WHILEDO_OVERFLOW`、
`FLIP_PATH`、`JOINED_BLOCK` 与 `DUPLICATE_BLOCK`。Rugra 专用位为
`RETURN_TERMINAL`、`CASE_BODY`、`GOTO_EDGE_0` 与 `GOTO_EDGE_1`。

### 这些标志的作用

它们主要用来回答类似问题：

- 这个 block 是否为终结块
- 它是不是通过 `goto` 终结
- 它是不是 `return` 终结
- 它是不是函数入口块
- 它是不是已经被标记为 dead
- 它是不是被分析流程临时标记过

### 推荐理解方式

#### A. 终结性质相关
- `RETURN_TERMINAL`（Rugra 胶水位）

这些标志主要帮助判断 block 的控制流结束方式。

#### B. 生命周期与入口相关
- `ENTRY_POINT`
- `DEAD`

这些标志主要描述 block 的角色和生命周期状态。

#### C. 临时分析标记
- `MARK`

通常用于分析过程中的临时标识，而不是最终用户语义。

### 注意事项

这些标志存在，只说明 block 层已经有较细的状态语义。  
它们不等于：

- CFG 已完全正确
- 所有 block 分类都已完成验证
- 结构恢复已成熟稳定

---

## 3. `FlowBlock`

### `pub trait FlowBlock: std::fmt::Debug + Send + Sync`

所有块类型的共同抽象接口。

2026-08-28 的 Copy 闭包新增/接通了 `sub_block`、`first_op`、
`get_split_point` 与边/状态访问。`BlockGraph::add_block` 为块建立
`self_ref`，并给已在 Basic 中的 op 写入 parent；
`BlockBasic::add_op` 统一经 `insert_op`，保持 `SeqNum` 顺序、op parent，
并在插入 `BRANCHIND` 时设置 `SWITCH_OUT`。图本身的真实
parent 仍未等价；`BlockCopy` 的 print/raw/marshal 及所有取反组合
路径仍为 `UNTESTED/MISMATCH`。

## 角色

`FlowBlock` 是 block 体系中的统一抽象层，用于把以下对象纳入同一控制流块体系：

- 基本块
- 图块
- 条件块
- 循环块
- 顺序块
- goto 块
- copy 块
- 其他结构化块

## 设计意义

有了 `FlowBlock`，上层逻辑可以：

- 用统一引用类型持有不同 block
- 在图结构中混合使用基础块与结构化块
- 让结构化恢复不是“重建另一套完全独立的树”，而是继续使用统一块抽象

这使 `block.rs` 更接近 Ghidra 风格的“块也是对象、图也是块、结构块也是块”的设计方式。

## 当前边界

`FlowBlock` 的存在说明架构设计成熟度较高，但不自动证明：

- 所有块类型都已完整实现
- 所有结构化块都已进入主线
- 结构恢复行为已经与 Ghidra 一致

---

## 4. `BlockBasic`

### `pub struct BlockBasic`

表示一个基本块。

## 角色

`BlockBasic` 是当前控制流层最基础、最重要的块类型之一。  
它通常表示一段：

- 顺序执行
- 中间不被控制流切断
- 由若干 `PcodeOp` 组成
- 以控制流终结点结束或自然落空结束

的基础块。

## 当前应如何理解

`BlockBasic` 是：

- CFG 的基本单位
- dominance、frontier、loop 分析的对象
- 结构化恢复进一步聚合的基础积木
- 输出层组织语句时的重要局部语义块

它不是：

- 最终高级语言块
- 直接等同于源码中的一个语句块
- 完整的函数表示

---

### `pub fn new(index: i32, start_addr: Address) -> Self`

创建一个新的基本块。

#### 参数
- `index`: 块索引
- `start_addr`: 块起始地址

#### 作用
建立一个新的基础块对象，作为后续装载 `PcodeOp` 和连接 CFG 的起点。

#### 说明
这个构造函数只建立“块壳”，并不自动填充：

- 操作序列
- 前驱/后继关系
- dominance 信息
- loop 信息

`start_addr` 同时是存量直接读取者的兼容镜像。`FlowInfo::split_basic`
完成分块时会通过 `set_initial_range` 安装闭区间；区间的两端是完整
`Address`，因此不会丢失 address-space 身份。与 Ghidra `setInitialRange`
一样，结束端取 `beg` 的空间和 `end` 的 offset。

`set_initial_range` 本体是 `pub`（原为 `pub(crate)`，BLOCK-STOPADDR-
FIXTURE-REGRESSION-0001 放宽）。Ghidra 侧 `setInitialRange` 为 private +
`friend class Funcdata`（block.hh:462/467），公开构造路径是
`Funcdata::setBasicBlockRange(bb, beg, end)`（funcdata.hh:556，内联转发）。
Rugra 直接在 `BlockBasic` 上暴露 `pub`，使 crate 外的 oracle fixture
能构造同等的合法块状态（锁定 C++ fixture 经 `#define private public`
走 `fd.setBasicBlockRange`）。生产语义不变；无 range 时的回退仍见下条。

### `pub fn get_stop_addr(&self) -> Address`

返回初始指令覆盖范围的最后一个地址，对应 `BlockBasic::getStop`
(`block.cc:2328-2335`)。这个值来自 `set_initial_range` 记录的结束端，
不再用块内最后一条 op 的地址近似。尚未安装初始范围的存量
Rust 块仍回退到构造时的 `start_addr`；Ghidra 原生构造器不接受
这个兼容参数（Ghidra 在 cover 为空时返回 invalid `Address()`，
该差异归 `BLOCKBASIC-COVER-0001`；Ghidra 没有任何“末条 op 地址”
回退，因此 0d2252d 移除旧近似是对的，手工构造块必须显式安装
cover 才是合法状态）。

本轮只闭合 `setInitialRange` 建立的单范围。`copyRange`/`mergeRange`、
多不相连范围下的 `contains`/`getEntryAddr`与 RangeList marshal 仍归
`BLOCKBASIC-COVER-0001`，不由该字段的存在推断已完成。

### 2026-09-22（SB-HERITAGE50-BLOCKCOVER-0001）：多范围 cover + copyRange/mergeRange + getEntryAddr

- `initial_range: Option<(Address, Address)>` 升级为 `cover: RangeList`
  （block.hh:465 `RangeList cover` 的 1:1 对应，复用 `crate::address::RangeList`）。
  `set_initial_range` 语义不变（cover.clear + 单闭区间插入）。
- 新增 `copy_range(&BlockBasic)`（block.hh:468 `copyRange`）：node-split
  重复块继承原块完整 cover（funcdata_block.cc:832 已接线）。
- 新增 `merge_range(&BlockBasic)`（block.hh:469 `mergeRange`）：拼接块
  cover 取并集；`splice_block_basic` 在 CFG 拼接前调用（funcdata_block.cc:942）。
- `get_start_addr`/`get_stop_addr`（block.cc:2319/2328）改为读 cover 的
  **按 (space,offset) 排序的首/末范围**首/末地址——拼接块吸收了更低地址
  的块后，`getStart()` 返回那个更低的地址（正是 heritage MULTIEQUAL
  创建 `fd->newOp(sizein, bl->getStart())` 所取的地址；Ghidra oracle
  next_url block28 实测 cover={[0x2534..],[0x50e7..]}→getStart=0x2534）。
- 新增 `get_entry_addr()`（block.cc:2302 `getEntryAddr`）：单范围=范围首
  地址；多范围=**包含首条 op 的那个范围**的首地址。printc emitLabel
  （printc.cc:3170）用它而不是 getStart——label 与 getStart 在拼接块上
  可以不同（首 op 是 heritage 插在块头的 MULTIEQUAL，其地址=getStart）。
- 残余（仍归 `BLOCKBASIC-COVER-0001`）：`contains`（cover.inRange）的
  comment 域消费、RangeList marshal、Ghidra 空 cover invalid-Address()
  语义的精确化。

---

### `pub fn add_op(&mut self, op: PcodeOpRef)`

向块尾部追加一条操作。

#### 作用
把 `PcodeOp` 纳入当前基本块中。

#### 语义
说明 `BlockBasic` 当前承担了“有序操作容器”的职责。

#### 注意
操作加入 block 后，调用方仍需保证：

- 顺序是正确的
- 这条 op 属于该 block
- 与 CFG 终结语义不冲突

---

### `pub fn last_op(&self) -> Option<PcodeOpRef>`

获取块中的最后一条操作。

#### 作用
常用于：

- 判断块的终结指令语义
- CFG 边推断
- 结构恢复分析
- 打印阶段决定语句收尾

---

### `pub fn first_op(&self) -> Option<PcodeOpRef>`

获取块中的第一条操作。

#### 作用
常用于：

- 块调试输出
- 起始语义识别
- 块级遍历和打印准备

---

## 5. `BlockEdge`

### `pub struct BlockEdge`

表示控制流图中的一条边。

字段：`point`（另一端 block 句柄）、`point_id: BlockId`（point 的 bank 值
孪生——生产构造位经 `bank.registered_id_of` 打标；SENTINEL = 未注册/裸
fixture）、`flags`、`reverse_index`。

## 角色

`BlockEdge` 用于表达 block 与 block 之间的连接关系，是 CFG 的基本组成单元之一。

## 当前应如何理解

它承担的是：

- 图连接信息
- 前驱/后继关系组织
- loop 边 / 正常边 / 反向索引等图层辅助信息

它不是：

- 高级语言中的 `if` / `while` 语法对象
- 最终输出结构本身

---

### `pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self`

创建一条新的边记录。

#### 参数
- `point`: 边所连接到的 block
- `reverse_index`: 反向索引或与边组织相关的辅助位置编号

#### 作用
建立块间关系的一个边对象，供图结构维护使用。

---

## 6. `BlockRef`

### `pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

块对象的统一引用包装。

## 角色

`BlockRef` 的意义类似于 `PcodeOpRef`：

- 为不同类型的块提供统一引用包装
- 方便进入集合、图结构和容器
- 让调用方不用到处显式操作底层共享锁类型

## 使用价值

它体现出当前 block 体系并不是简单的值复制模型，而是：

- 共享对象
- 可被图结构和分析流程共同持有
- 可能在多个阶段被读取或改写

---

## 7. `BlockGraph`

### `pub struct BlockGraph`

表示一个块图，同时自身也作为一种块存在。

## 角色

`BlockGraph` 是当前 CFG 组织层的核心容器。  
它的重要性在于：

- 它不只是“块列表”
- 它还包含块间连接
- 它可以作为更高一级结构块继续参与控制流建模

这种“图也是块”的设计，是理解 Rugra 当前 block 架构的关键。

## 它通常承担的职责

- 保存 block 集合
- 保存 block 之间的边关系
- 提供 dominance 分析入口
- 提供 RPO 计算入口
- 提供 loop 计算和结构恢复相关入口
- 作为结构化控制流分析的基础容器

---

### `pub fn
 new() -> Self`

创建一个空的块图。

---

### `pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

将一个块加入图中。

#### 作用
把基础块或结构化块纳入当前图容器管理；保持插入顺序，并按
`BlockGraph::addBlock`（block.cc:862-875）把 graph index 更新为所有组件
index 的最小值。当前内联 `BlockGraph` 所有权仍不能生成指向自身的稳定
`Weak<RwLock<BlockGraph>>`，所以 Ghidra 的 `bl->parent=this` 是已登记的
`BLOCK-ADDGRAPH-SEMANTICS-0001` 剩余差异。

---

### `pub fn new_block_copy(&mut self, source: Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Arc<RwLock<dyn FlowBlock + Send + Sync>>`

对应 `BlockGraph::newBlockCopy`（block.cc:1681-1697）。创建真实
`BlockCopy`，原序复制 incoming/outgoing 全向量（端点、label、reverse slot）、
immediate dominator、index、numdesc 与 flags；visit-count 从 0 开始，输出超过
2 条时补 `f_switch_out`，然后追加到目标图。

---

### `pub fn build_copy(&mut self, graph: &BlockGraph)`

对应 `BlockGraph::buildCopy`（block.cc:1925-1938）。保存目标图原长度，不清空
prefix；按源列表顺序追加副本并写回每个源块的 `copymap`。全部映射建立后，
仅处理本轮追加 suffix，把边端点和 idom 经 `copymap` 替换。边的顺序、label、
reverse index 以及既有 prefix 均不归一化、不重建。

---

### `pub fn get_size(&self) -> usize`

返回图中块的数量。

---

### `pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

按索引获取图中的块。

---

### `pub fn clear(&mut self)`

清空图内容。

#### 作用
用于重置或重新构建图结构。

---

### `pub fn add_edge(`

为图添加一条边。

#### 作用
建立块与块之间的连接关系。

#### 说明
这是 CFG 构建的核心接口之一，但具体的边类型语义仍要结合终结操作和控制流分析来理解。

---

### `pub fn build_dom_tree(&mut self)`

构建支配树。

#### 作用
为后续以下阶段提供基础：

- dominance 分析
- frontier 计算
- SSA Phi 放置
- loop 结构判断
- 结构恢复

#### 当前边界
该函数的存在说明图层已具备 dominance 分析入口，  
但不能仅凭文档存在就宣称 dominance 行为已与 Ghidra 完全对齐。

---

### `pub fn build_dom_depth(&mut self)`

基于支配树构建深度信息。

#### 作用
为后续遍历、优先级和结构恢复提供辅助层级信息。

---

### `pub fn build_dom_subtree(&mut self)`

构建支配子树关系。

#### 作用
使支配树不仅可作为父子关系，也可更方便用于后续子树级分析。

---

### `pub fn calc_dom_frontier(&mut self)`

计算支配边界（dominance frontier）。

#### 作用
这是 SSA、Phi 节点放置等分析的重要基础。

#### 重要性
这意味着 `block.rs` 不只是控制流展示层，还直接和 SSA 构造有耦合。

---

### `pub fn calc_rpo(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

计算反向后序（RPO）。

#### 作用
RPO 常用于：

- CFG 遍历
- 数据流分析
- dominance 算法
- 结构恢复顺序控制

---

### `pub fn structure_loops(&mut self, rootlist: &mut Vec<...>) -> anyhow::Result<()>`

执行循环结构化（`BlockGraph::structureLoops`，block.cc:2194-2215）。

#### 作用
`do { findSpanningTree; findIrreducible; needrebuild 时清生成树 label 并重跑 } while(needrebuild)`，
最后 `irreduciblecount > 0` 时调用 `calc_loop`。产出 RPO 成员列表、边分类与
rootlist（含不可归约边标记）。

#### 返回
- `Ok(())`；`find_spanning_tree` 两遍后仍有 extraroots 时返回 LowlevelError 等价错误。

#### 注意
`irreduciblecount > 0` 时调用完整实现的 `calc_loop`（BLOCK-CALCLOOP-0001，
oracle fixture `block_calcloop_1204` MATCH）：DFS 环检测补标 f_loop_edge。

---

### `pub fn find_irreducible(&self, preorder: &[...], irreduciblecount: &mut i32) -> bool`

识别不可归约边（`BlockGraph::findIrreducible`，block.cc:1147-1199）。

#### 作用
反向前序遍历 `preorder`；对每个回边入点 x，用 FIND(y)=`copymap` 种子
reachunder 集，BFS 中区间测试 `[visitcount, visitcount+numdesc)` 之外的 y'
标记边为 `f_irreducible`（唯一写者），树边触发 needrebuild，非树边清除
cross/forward 旧分类；末尾把集合坍缩为 x（清 mark、copymap 指向 x）。

#### 返回
- `needrebuild`：存在不可归约的树边时需要重建生成树（见下方暴力证据）。

#### 注意
区间快照（cc:1174 读 x->visitcount/numdesc 与 y'->visitcount）在 y'==x
（循环头自身入 reachunder 成员的边：y==x 且 copymap 仍指向自身，cc:1027/1122）
时经 ptr_eq 预判从单一 x 读锁取双值——std::sync::RwLock 同线程同锁二次
read() 文档标注 "might panic"（BLOCK-RWLOCK-RECURSIVE-READ-0001 加固；
oracle C++ 裸指针无锁形态，同对象二次读取天然合法，值恒等由对象同一性
保证）。

---

### `pub fn add_loop_edge(&mut self, begin: &Arc<...>, outindex: usize)`

标记既有出边为 loop 边（`BlockGraph::addLoopEdge`，block.cc:1451-1464）。

#### 作用
把 `begin` 的第 `outindex` 条**既有**出边标记为 `f_loop_edge`（cc:1463 经
`setOutEdgeFlag`，两侧 halves 同写：out 边 + 目标块的镜像 in 边，block.cc:240-246）。
Ghidra 按 out-index（而非目标块身份）定位边——同一目标的多条平行出边必须可区分
（cc:1459-1462 注释）。`#ifdef BLOCKCONSISTENT_DEBUG` 的 parent 检查在 oracle
release 构建中编译掉。

---

### `pub fn calc_loop(&mut self)`

DFS 环检测补标 loop 边（`BlockGraph::calcLoop`，block.cc:2104-2147）。

#### 作用
从 `blocks[0]`（cc:2118 `list.front()`）起做显式栈 DFS，按出边槽序访问
（cc:2130 先递增 per-path-level 游标再用槽位）。`f_mark`=已访问、
`f_mark2`=在当前 DFS 路径上（cc:2120）：

- 出边指向仍带 `f_mark2` 的块 → 成环 → `add_loop_edge(bl, i)` 标
  `f_loop_edge`（cc:2133-2137，oracle 的 throw 被注释掉——不可归约 failsafe）；
- 出边已带 `f_loop_edge` → 跳过（cc:2131 `isLoopOut`，重跑时视早前环断边不存在）;
- 已访问但已弹栈（f_mark 置、f_mark2 清）→ 截断搜索（cc:2138 else）；
- 新块 → 置 `f_mark|f_mark2` 入栈（cc:2138-2142）。

弹栈只清 `f_mark2`（cc:2124-2128）；栈空后按 list 序清所有块的
`f_mark|f_mark2`（cc:2145-2146）。在 structureLoops 中仅当
`irreduciblecount > 0` 时运行（cc:2211-2214）。

#### 对齐证据
oracle fixture `tests/oracle/block_calcloop_1204`（BLOCK-CALCLOOP-0001）：
7 用例（可归约回边/嵌套循环/自环/双跑 isLoopOut 跳过/截断/不可归约
end-to-end/structureReset 链含支配树）双侧投影 byte-MATCH。

---

## 8. 结构化块类型

除了基础块和块图，本模块还定义了一组更高层的结构化块类型。  
这些类型的意义在于：把“原始 CFG”逐步表达成更接近高级语言控制结构的对象。

---

## `pub struct BlockCopy`

表示结构图中对原 `FlowBlock` 的实时镜像，对应 block.hh:510-538。

### 作用
当前字段保存完整 FlowBlock 基础状态：incoming/outgoing、immed_dom、copymap、
index、numdesc、visit_count、flags，以及指向任意源 `FlowBlock` 的强引用。
`sub_block(i)` 对任意 i 都返回源块；`get_ops`、first/last op、isComplex 与
getSplitPoint 都实时委托源块；getExitLeaf 返回副本自身。negateCondition 先
无条件取反源块，再按 top-or-bottom 参数交换副本自身的两条边。

### 注意
`BlockCopy` 是结构化主管线的正式叶节点，不再用带回指字段的 `BlockBasic`
替身。完整函数级状态仍为 `MISMATCH`：目标图 parent 指针受当前 Rust 所有权
模型阻塞；covered buildCopy 状态由 `block_buildcopy_1204` 双侧 fixture 门禁。

---

## `pub struct BlockGoto`

表示 `goto` 结构。

### 作用
当某段控制流不能自然表达成更高级结构时，`BlockGoto` 提供一种显式跳转表达方式。

### 设计意义
它很重要，因为真实反编译器不能假设所有 CFG 都能完美结构化。  
因此：

- `goto` 不是失败的标志
- 而是“在语义保真优先”原则下的保守表达方式

---

## `pub struct BlockIf`

表示结构化 `if` / `if-else` 块。

### 作用
用于把某段条件控制流表达成更高级的分支结构。

### 当前语义
它通常包含：

- 条件块
- true 分支
- 可选 false 分支

### 重要边界
`BlockIf` 的存在说明结构恢复层正在把图表达成高级控制流，  
但并不自动说明：

- 所有分支都能恢复成漂亮的 `if`
- 所有条件都已正确折叠
- 输出已经与成熟反编译器等价

---

## `pub struct BlockWhileDo`

表示 `while-do` 结构化循环块。

### 作用
用于把某类 loop 结构表达成 `while` 风格控制流。

### 当前语义
通常包含：

- 循环头 / 条件块
- 循环体

---

## `pub struct BlockDoWhile`

表示 `do-while` 结构。

### 作用
用于表达先执行后判断的循环模式。

---

## `pub struct BlockList`

表示线性顺序执行的一组块。

### 作用
把若干按顺序执行、无复杂分支打断的块组合成一个更高层的顺序块。

### 设计意义
这使打印层更容易把图结构转换成顺序语句块，而不是裸 CFG 节点遍历。

---

### `pub fn new(index: i32, children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) -> Self`

创建一个新的顺序块。

#### 参数
- `index`: 块索引

- `children`: 顺序子块列表

#### 作用
把一组按顺序执行的块包装为单个 `BlockList`。

---

## `pub struct BlockSwitch`

表示 `switch-case` 结构化选择块。

### 作用
用于把多路分支（通常是间接跳转或跳转表）表达为高级 `switch-case` 结构。

### 当前语义
通常包含：
- `control`: 包含 `BRANCHIND` 的控制块
- `cases`: 对应的 case 体分支块列表
- `case_values`: 与 cases 对应的常量匹配值（例如 `case 0:`, `case 1:`）
- `default_case`: 可选的 `default` 分支块
- `index_varnode`: 可选的控制 switch 索引的变量

---

## 当前模块的核心价值

从当前架构看，`block.rs` 的价值主要在于：

1. **为函数级控制流提供统一对象模型**
2. **为 dominance、frontier、loop 等分析提供基础结构**
3. **为结构化恢复提供逐层提升的块表示**
4. **为 `PrintLanguage` / `PrintC` 提供更接近高级语句组织的输入**

换句话说，它是：

- CFG 层
- SSA 辅助层
- 结构恢复层
- 输出准备层

共同依赖的重要中间支柱。

---

## 当前风险与边界提示

### 1. 块对象存在不等于结构恢复成熟
有 `BlockIf`、`BlockWhileDo`、`BlockDoWhile` 不等于所有真实程序都能稳定恢复为高级结构。

### 2. dominance 接口存在不等于行为已验证一致
有 `build_dom_tree()`、`calc_dom_frontier()` 不等于已与 Ghidra 一致。

### 3. `goto` 是保守表达，不是错误
当无法自然结构化时，`BlockGoto` 是合理结果，而不是单纯失败。

### 4. `BlockGraph` 是主真相源之一
如果控制流
图已经进入 `BlockGraph`，不应在其它层偷偷维护一套脱离图的平行控制流结构。

---

## 推荐联动阅读

建议接着阅读：

1. `op.md`
2. `varnode.md`
3. `funcdata.md`
4. `heritage.md`
5. `action.md`
6. `printlanguage.md`
7. `printc.md`
8. `../data_contract.md`

---

## 一句话总结

`block.rs` 是 Rugra 当前**控制流块模型与结构化块表示层**的核心模块：它既负责基本块和 CFG 的组织，也为 dominance、loop 分析和更高层的 `if/while/list/goto` 结构表达提供对象基础，是从底层操作图走向可打印控制流结构的关键桥梁。
### 2026-06-23（续）：F_SWITCH_DISPATCH 边标记

- `edge_flags` 新增 `F_SWITCH_DISPATCH` 用于标记 switch dispatch 边。

### 2026-06-23（续）：CASE_BODY flag

- `block_flags` 新增 `CASE_BODY`，标记 cascade switch 的 case body 块。供 blockaction/printc 层检测。

### 2026-06-23（续）：CASE_BODY flag

- `block_flags::CASE_BODY` 标记 cascade switch case body。

### 2026-06-23（续）：effective_size_out + GOTO_EDGE flags

- FlowBlock 新增 `effective_size_out()`/`effective_get_out()`，排除 goto 标记边。
- block_flags 新增 `GOTO_EDGE_0`/`GOTO_EDGE_1`。

### 2026-07-16：B4 INTERIOR_GOTOOUT/GOTOIN flags + set_goto_branch 完整化

- block_flags 新增 `INTERIOR_GOTOOUT`（0x400, block.hh:97）+ `INTERIOR_GOTOIN`（0x800, block.hh:98），匹配 Ghidra 位值。
- `set_goto_branch(bl, j)` 对齐 Ghidra `FlowBlock::setGotoBranch`（block.cc:305-314）**三件事**：edge flag + source `INTERIOR_GOTOOUT` + target `INTERIOR_GOTOIN`。此前只设 source 的 GOTO_EDGE，target 侧 `is_interior_goto_target` 失效。
- `is_interior_goto_target` 先查 `INTERIOR_GOTOIN`（Ghidra 模型），回退 in-edge 扫描。
- 新增 `has_interior_goto`（block.hh:324）查 `INTERIOR_GOTOOUT`。

### 2026-07-16：B3 BlockInfLoop struct

- 新增 `BlockInfLoop` struct（对齐 Ghidra `BlockInfLoop` block.hh:735）：包装单 body 块（自循环），incoming/outgoing/parent/flags。`get_type()` 返回 `BlockType::InfLoop`，`get_ops`/`get_start_addr` 委托 body。
- printc `emit_structured_infloop` 输出 `do { <body> } while(true);`（对齐 emitBlockInfLoop printc.cc:3097）。

### 2026-06-25：is_consumed() + 对齐 Ghidra collapseInternal

- FlowBlock::is_consumed() — DEAD flag 检查，对齐 Ghidra sizeIn==0&&sizeOut==0。
- interleaved 循环跳过 consumed 块。
- gcc 53/53，175/176 测试。getparameter 5 if，控制流差 174。

### 2026-06-25：BlockBasic size_in/out 返回 0 当 consumed

- BlockBasic::size_in/size_out 在 DEAD flag 设置时返回 0。
- 对齐 Ghidra collapseInternal 的 sizeIn==0&&sizeOut==0 检查。
- curl 24/24 OK，httpd 12/29（大量函数因 consumed 块边清零导致变量声明遗漏）。
- 175/176 测试。

### 2026-06-25：过滤 DEAD 边的 size_in/out

- BlockBasic::size_in/out 过滤来自 DEAD 块的边（对齐 Ghidra identifyInternal）。
- get_in/get_out 也过滤 DEAD 边。
- 效果：后继块的 effective size_in 减少，使 proper_if 能匹配。
- 175/176 测试（预存失败）。

### 2026-06-25：回退到简单 DEAD size_in/out

- 移除动态过滤（死锁/性能问题）。
- BlockBasic size_in/out 在 DEAD 时返回 0。
- gcc 53/53，175/176 测试。getparameter 5 if。

### 2026-06-25：set_flags 清空 edges（实验）

### 2026-06-25：block.rs 恢复最佳状态

### 2026-06-25：FlowBlock as_any_mut + BlockBasic 边操作

### 2026-08-23：halfDelete reciprocal reverse-index 修复

- `BlockBasic::half_delete_in_edge` 对应 locked Ghidra
  `FlowBlock::halfDeleteInEdge`（`block.cc:100-112`）：从删除槽开始逐项左移
  `incoming`，保留 surviving 本地 half-edge 的 `reverse_index` 与 label，并把每条
  surviving source 的 `outgoing[reverse_index].reverse_index` 逐次减一。
- `BlockBasic::half_delete_out_edge` 对应
  `FlowBlock::halfDeleteOutEdge`（`block.cc:115-127`）：对 `outgoing` 做同序滑动，
  并更新每条 surviving target 的 `incoming[reverse_index].reverse_index`。删除的
  另一半按 half-delete 契约暂时保留，由 `removeInEdge/removeOutEdge` 等调用者删除。
- Rust trait-object 边端点可能是任一持有边表的结构化块；内部胶水覆盖这些具体类型。
  自环在当前 per-`Funcdata` 单线程图改写中复用已持有的 `&mut BlockBasic`，避免二次
  获取同一 `RwLock`。
- `BLOCK-HALFDELETE-REVIDX-0001` 的 locked 12.0.4 双侧 fixture 逐槽观察所有块的
  `peer/reverse_index/label`，覆盖非末槽入/出删除、连续删除、PHI 输入槽映射、
  self/parallel 边、双向有序边，以及 single/last-slot 合法边界。空表或越界 slot
  在 Ghidra 函数中没有定义的异常分支，不作为可比较输入。

### 2026-06-27（会话2）：边操作原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），BlockBasic 新增忠实于 Ghidra block.cc 的边操作：
- `get_out_rev_index(slot) -> i32` / `get_in_rev_index(slot) -> i32` — `FlowBlock::getOutRevIndex/getInRevIndex`（block.cc）：返回反向边索引。
- `half_delete_in_edge(slot)` / `half_delete_out_edge(slot)` — `FlowBlock::halfDeleteInEdge/halfDeleteOutEdge`（block.cc:100/115）：只删除指定 half-edge；本地 surviving edge 依序左移，对端 surviving half-edge 的 reciprocal reverse index 随槽位更新。
- `replace_edges_thru(in_slot, out_slot)` — `FlowBlock::replaceEdgesThru`（block.cc:198-216）：移除本块的入/出边，但在入块与出块间建立直连边，保留槽位。condexe 的 `removeFromFlowSplit` 核心。

BlockGraph 新增：
- `remove_block_arc(bl)` — `BlockGraph::removeBlock`（block.cc:1517）：先断开所有入/出边，再从 blocks 列表移除（不 drop Arc）。
- `remove_edge_blocks(src, dst)` — `BlockGraph::removeEdge`：按 `dst`
  incoming 原顺序选中第一条来自 `src` 的边，先记住它的
  reciprocal source slot，再删除 target half 和那一条精确配对的
  source half。平行边不能分别在两端独立查“第一条”。

### 2026-06-27（会话2 续）：find_common_block（解锁 RuleOrPredicate）

- `BlockGraph::find_common_block(bl1, bl2) -> Option<BlockArc>` — `FlowBlock::findCommonBlock`（block.cc:736-795）：支配者树最近公共祖先（标准等深上溯算法，等价 Ghidra mark 版）。被 `PcodeOp::compareOrder` 用于判定不同块内两 op 的控制流顺序。

### 2026-06-27（会话3 G4）：FlowBlock 标记原语 + edge flags（解锁 LoopBody）

为支撑 Ghidra LoopBody 算法（blockaction.cc:46-490），新增忠实于 Ghidra block.hh 的标记原语：

**block_flags**：复用现有 `MARK`（f_mark）。
**edge_flags 新增**：
- `F_LOOP_EXIT_EDGE`（Ghidra f_loop_exit_edge）— LoopBody::setExitMarks 标记
- `F_BACK_EDGE`（Ghidra f_back_edge）— 可归约图的回边
- `F_IRREDUCIBLE_EDGE`（Ghidra f_irreducible）— 结构化器引入的不可归约边
- **历史修正**：早期文档曾把 `F_GOTO_EDGE` 和 spanning-tree
  分类写成与 Ghidra 不同的位值；该记录已失效。
- **当前精确 edge bits**：`F_GOTO_EDGE=0x01`、`F_LOOP_EDGE=0x02`、
  `F_DEFAULTSWITCH_EDGE=0x04`、`F_IRREDUCIBLE_EDGE=0x08`、
  `F_TREE_EDGE=0x10`、`F_FORWARD_EDGE=0x20`、`F_CROSS_EDGE=0x40`、
  `F_BACK_EDGE=0x80`、`F_LOOP_EXIT_EDGE=0x100`。`SPANNING_MASK` 仅包含
  tree/forward/cross/back/loop 分类位。

**FlowBlock trait 新增方法（2026-06-28）**（对齐 Ghidra block.hh:288/331）：
- `set_out_edge_flag(slot, flag)` — 对第 slot 条出边 OR-set 边 flag（Ghidra setOutEdgeFlag）。默认实现用 `as_any_mut` downcast 到 `BlockBasic`/`BlockGraph` 的 `outgoing` 字段。
- `clear_out_edge_flag(slot, flag)` — 清除第 slot 条出边的 flag 位（Ghidra clearOutEdgeFlag block.hh:289，set_out_edge_flag 的配对）。**2026-07-16 B5 新增**，供 LoopBody::clearExitMarks。
- `BlockWhileDo.overflow_syntax`（bool，对齐 hasOverflowSyntax block.hh:692）—— **2026-07-16 P7 新增**：条件块 isComplex 时设 true，printc 发射 while(true)+if(cond)break 形式（emitBlockWhileDo cc:3017-3044）。
- `get_flip_path()`（block.hh:297）—— **2026-07-16 新增**：检查 FLIP_PATH flag，供 jumptable checkUnrolledGuard 使用。
- `restricted_by_conditional(cond)`（block.cc:405-425）—— **2026-07-16 新增**：检查块是否完全被条件块 cond 支配（所有路径经 cond 的边到达）。供 ActionConditionalConst apply()。
- `BlockBasic::lift_verify_unroll(var_array, slot)`（block.cc:2802）—— **2026-07-16 新增**：静态方法，验证 varArray 中所有 varnode 由相同 opcode + 匹配常量操作数定义，然后按 slot 展开。供 checkUnrolledGuard。
- `clear_edge_flags(mask)` — 清除所有出边的 mask 位（Ghidra clearEdgeFlags）。
- `is_back_edge_out(slot)` — 第 slot 条出边是否为回边（Ghidra isBackEdgeOut）。

**BlockBasic 新字段**：`visit_count: i32`（Ghidra getVisitCount/setVisitCount）。

**FlowBlock trait 新增方法**（默认 no-op，BlockBasic 覆盖）：
- `is_mark`/`set_mark`/`clear_mark`（block.hh:286-288）
- `get_visit_count`/`set_visit_count`（block.hh visit count）
- `is_goto_in(i)`/`is_goto_out(i)`（block.hh:346-347）——**2026-06-29 修复**：`BlockBasic::is_goto_out` 此前只查边级 `F_GOTO_EDGE`，但 TraceDAG 把 goto 标在 block 级 `GOTO_EDGE_0/1` 上。修复后同时查边级和 block 级标志，使 ruleBlockWhileDo 能正确识别 break 边。
- `set_loop_exit(i)`/`clear_loop_exit(i)`（block.hh:294-295）
- `remove_in_edge_from(exclude_indices)`（block.cc:1469 忠实移植）——从块的 incoming 列表中移除 index 匹配的前驱边。对应 Ghidra `BlockGraph::removeEdge(begin, end)`，是 newBlockGoto/newBlockIfGoto "消费" goto 边的机制（使 goto 源对 target 的 sizeIn 不可见）。2026-06-29 新增，当前未被调用（ruleBlockGoto 消费实验因 Rugra 非对称边追踪导致图损坏，已回退；保留为未来对称边图工作的基础设施）。

### 2026-06-29：BlockIf goto_target 字段（newBlockIfGoto 风格，block.cc:1799）
- BlockIf 新增 `goto_target: Option<Arc<...>>` 字段。当 Some 时，表示 if-goto 块（`if (cond) goto target;`），body 保持外部（非嵌入）。忠实 Ghidra BlockIf::gototarget（block.hh:660）。
- 所有 7 个 BlockIf 构建点已更新（goto_target: None 为默认）。

### 2026-06-29（续）：remove_in_edge_from 自环死锁修复
- `remove_in_edge_from` 的 retain 闭包中 `e.point.read()` 改为 `try_read()`。此前若 `e.point == self`（自环边），在持有自身 write lock 时 read 会永久死锁（ap_count_dirs 挂起根因）。try_read 失败时保留边（安全默认）。

### 2026-06-29（续 2）：VarnodeBank::find_input
- `find_input(size, loc)` — 忠实移植 `VarnodeBank::findInput`（varnode.hh）。查找指定 size+address 的 INPUT varnode。用于 ActionRestrictLocal + AncestorRealistic。

### 2026-07-01：CBRANCH 出边 + 支配查询（解锁 RuleConditionalMove/Int2FloatCollapse/IgnoreNan）
- `FlowBlock::dominates(other)`（block.cc:386-395）— 沿 immed_dom 链上溯判断支配。
- `FlowBlock::get_true_out(cbranch)/get_false_out(cbranch)`（block.hh:299-300）— **2026-08-23 CONDEXE-TRUEOUT-0002 修正为纯位置语义**：`get_false_out()=out[0]`、`get_true_out()=out[1]`，与 Ghidra 逐字一致，**不读 BOOLEAN_FLIP**。Rugra 流构造（flow.rs:920-928，同 flow.cc:960-967）先压 fallthru 再压 branch，因此 out[0]=false 路径、out[1]=true 路径，与 Ghidra 布局相同；negateCondition（block.cc:2351）翻转 flip 同时交换两条出边以维持该不变量。BOOLEAN_FLIP 只在显式调用点消费（condexe.cc:612、expression.cc:227-230、ruleaction.cc:8981/9428、coreaction.cc:4538、double.cc:922）。`cbranch` 形参已废弃（纯位置实现忽略之），仅为带租约消费文件（ruleaction.rs）保持签名兼容，租约释放后应移除。
- `FlowBlock::swap_edges()`（block.cc:218-233）— **2026-08-23 补齐 cc:225-228**：交换 out[0]/out[1] 后，按交换后槽位回写目标块入边的 reverse_index（此前缺失，negateCondition 后 get_in_rev_index 会过期）。
- `FlowBlock::get_in_rev_index(slot)` trait 方法（block.hh:308）— 入边的反向索引。
- `find_condition(bl1,edge1,bl2,edge2)` 自由函数（block.cc:839-858）— 返回支配两路径的 CBRANCH 块 + slot1。解锁 RuleInt2FloatCollapse 核心。
  - **2026-09-23（MYPROGRESS-INT2FLOATCOLLAPSE-0001）修正 bl1/edge1 步进语义**：Ghidra 循环体（cc:845-847）每跳一步执行 `bl1=cond; edge1=0`，最终 `slot1=bl1->getInRevIndex(edge1)`（cc:856）取的是 **cond 正下方块** 对 cond 的反向出边槽位（即 dir2unsigned 判向）。旧实现误用调用方原始 bl1/edge1 求反索引——菱形（walk≥1 hop）场景恒返回臂块唯一出边槽 0，导致 RuleInt2FloatCollapse 的 `dir2unsigned` 判向永假、规则在 `(basevn<0)` 形态永不 fire。现随 walk 维护 `cur_bl1/cur_edge1`，逐字对齐。

### 2026-07-01（续 2）：is_entry_point + get_start_block
- `FlowBlock::is_entry_point()`（block.hh:325）— ENTRY_POINT flag 检查，trait default。
- `BlockGraph::get_start_block()`（block.cc:1649-1655）— 第一个 entry point 块。

### 2026-07-01（续 2）：build_dom_tree reindex
build_dom_tree 开头 reindex 所有块到向量位置（防止 dead-flow 删块后索引越界）。

### 2026-07-01（续 3）：BlockWhileDo +for_init/for_iter

### 2026-07-01（续 4）：JOINED_BLOCK flag + create_new_block
block_flags: +JOINED_BLOCK (1<<9, block.hh:97)。Funcdata: +create_new_block。

### set_order（2026-07-03 续）
- 新增 `BlockBasic::set_order`：重置块内所有 op 的 SeqNum::order，均匀分布。对齐 Ghidra block.cc:2638-2651。用于 spliceBlockBasic 后。

### SWITCH_OUT / UNSTRUCTURED_TARG flags（2026-07-03 续 7）
- **历史记录**：当时曾临时用 `1<<10`/`1<<11`。
- 对齐 Ghidra `f_switch_out`（block.hh:92）/`f_unstructured_targ`（block.hh:93）。
- 当前实现已用 oracle 精确位 `0x10`/`0x20`；早期“位值待重排”
  技术债已失效。
- 用于 `splice_block_basic` 的 flags 合并（block.cc:1609-1619）：splice 后 `bl->flags = (bl & (unstructured_targ|entry_point)) | (outbl & switch_out)`。

### 2026-07-04（续）：find_common_block_n + get_stop_addr（历史状态）
- `BlockGraph::find_common_block_n(block_set)`（对齐 block.cc:796）：N-way 支配树 LCA，用 HashSet 模拟 mark。供 build_dominant_copy 使用。
- 当时 `BlockBasic::get_stop_addr()` 用最后 op 地址近似块结束。
  2026-08-24 的 `FLOW-TRUNCATED-0001` 切片 B 已用完整 `Address`
  初始范围取代该近似；本条仅保留为历史记录。

### 2026-07-04：block_flags 位值完整对齐 Ghidra block.hh:88-105
- 所有 Ghidra 共享 flags 用精确位值：SWITCH_OUT=0x10, UNSTRUCTURED_TARG=0x20, MARK=0x80, ENTRY_POINT=0x200, DEAD=0x4000, JOINED_BLOCK=0x20000。
- Rugra 独有 flags 当前位值：RETURN_TERMINAL=0x100000,
  CASE_BODY=0x200000, GOTO_EDGE_0=0x400000, GOTO_EDGE_1=0x800000。
- 删除死代码 TERMINAL/GOTO_TERMINAL（从未被读取）。
- 验证：所有 flag 访问通过命名的 `block_flags::*` 常量（无原始十六进制掩码），所以位值变更不影响任何调用点语义。952/952 测试通过，curl 无回归。

### 2026-07-04（续，2026-08-28 纠正）：block-graph 默认边重写
- 当前入口为 `set_default_switch_mirrored(block, pos)`（block.cc:318-320）：把 `F_DEFAULTSWITCH_EDGE` 同步写到 source out-half 与 target in-half；reverse index 和槽位顺序不变。
- `edge_flags::F_DEFAULTSWITCH_EDGE = 0x04`，与 Ghidra `f_defaultswitch_edge` 完全相同；`F_TREE_EDGE = 0x10`，两者不存在位碰撞。旧文档所述 `1<<7` 是已纠正的历史错误。

### 2026-07-04（续 2）：新增 DUPLICATE_BLOCK flag
- `block_flags::DUPLICATE_BLOCK = 0x40000`（f_duplicate_block, block.hh:106）。nodeSplit 创建的重复块。
<!-- annotation-pass: 2026-07-04 -->

### 2026-07-22：移植 block.cc Block 子类型 inherent impls（B5 对齐）

历史实现曾声称完整覆盖 Ghidra `block.cc` 的 BlockCopy / BlockGoto / BlockIf /
BlockWhileDo / BlockDoWhile / BlockInfLoop / BlockList / BlockCondition /
BlockSwitch 虚方法；该全量声明已撤销。当前仅 structured-negate fixture 覆盖的
base/List/Condition negate 投影以及 buildCopy fixture 覆盖的 Copy 投影为 MATCH；
printHeader、markUnstructured、scopeBreak、nextFlowAfter、flipInPlace、marshal/emit
等完整子类闭包仍有 MISMATCH/UNTESTED。Rust 的 inherent/downcast 适配也不能单凭
代码形似视为虚派发等价。

**新增模块级常量：**
- `block_flags::LABEL_BUMPUP = 0x1000`（f_label_bumpup, block.hh:99）。
- `block_flags::DONOTHING_LOOP = 0x2000`（f_donothing_loop, block.hh:100）。
- `block_flags::WHILEDO_OVERFLOW = 0x8000`（f_whiledo_overflow, block.hh:102）。
- `goto_type` 模块：`GOTO_GOTO=1` / `BREAK_GOTO=2` / `CONTINUE_GOTO=4`
  （block.hh:89-91，对应 f_goto_goto/f_break_goto/f_continue_goto）。

**新增 FlowBlock trait 方法（默认实现）：**
- `scope_break_trait(cur_exit, cur_loop_exit)`（block.hh:266 FlowBlock::scopeBreak）。
- `get_exit_leaf_trait() -> Option<...>`（FlowBlock::getExitLeaf）。
- `flip_in_place_test() -> i32`（FlowBlock::flipInPlaceTest，默认 2=不可翻转）。
- `flip_in_place_execute()`（FlowBlock::flipInPlaceExecute）。
- `last_op() -> Option<PcodeOpRef>`（FlowBlock::lastOp，默认 None）。

**新增 inherent impl 方法（每个对应 Ghidra block.cc 中的虚方法重写）：**

- **BlockCopy**（block.cc:2835-2854）：`print_header` / `print_tree` /
  `encode_header`。
- **BlockGoto**（block.cc:2856-2903）：新增 `goto_type: u32` 字段；
  `get_goto_target` / `get_goto_type` / `mark_unstructured_target` /
  `scope_break_goto_type` / `goto_prints` / `print_header` /
  `next_flow_after_index`。
- **BlockIf**（block.cc:3067-3135）：新增 `goto_type: u32` 字段；
  `set_goto_target` / `get_goto_target` / `get_goto_type` /
  `mark_unstructured_target` / `scope_break_goto_type` / `print_header` /
  `get_exit_leaf` / `last_op` / `next_flow_after_parent` / `prefer_complement`
  （cc:3093-3109，翻转 CBRANCH 并交换 if_body/else_body）。
- **BlockWhileDo**（block.cc:3316-3351）：`get_initialize_op` /
  `get_iterate_op` / `has_overflow_syntax` / `set_overflow_syntax` /
  `mark_label_bump_up` / `scope_break_children` / `print_header` /
  `next_flow_after`。
- **BlockDoWhile**（block.cc:3426-3452）：`mark_label_bump_up` /
  `scope_break_body` / `print_header` / `next_flow_after`。
- **BlockInfLoop**（block.cc:3454-3483）：`mark_label_bump_up` /
  `scope_break_body` / `print_header` / `next_flow_after`。
- **BlockList**（block.cc:2953-2988）：`get_exit_leaf` / `last_op` /
  `negate_condition` / `get_split_point` / `print_header` / `outgoing_swap`。
- **BlockCondition**（block.cc:2990-3065）：`get_opcode` / `is_split_point` /
  `is_complex` / `last_op` / `negate_condition`（分布 NOT 到两个子条件并
  切换 AND<->OR）/ `scope_break_children` / `print_header` /
  `next_flow_after` / `encode_header` / `flip_in_place_execute`。
- **BlockSwitch**（block.cc:3596-3661）：`get_switch_block` /
  `get_num_case_blocks` / `get_case_block` / `get_num_labels` / `get_label` /
  `is_default_case` / `mark_unstructured_targets` /
  `scope_break_break_cases` / `print_header` / `next_flow_after` /
  `get_switch_varnode`。
  （`is_exit` 已删除——CASEWRAP-CR-F2：零调用者，且读取期从已消费 case 块重导
  `size_out()==1` 在 identifyInternal 半删出边后恒 false；oracle 的 `isExit(i)`
  读的是 addCase 期捕获的 `caseblocks[i].isexit`（block.hh:791），对应 Rugra 的
  `case_isexit`/`default_isexit` 捕获旗标数组，block.cc:3511-3514。）

**调用点更新（blockaction.rs）：**
- 3 个 `BlockIf` 构造点（blockaction.rs:3128/3163/3630）+ 1 个 `BlockGoto`
  构造点（blockaction.rs:3715）添加 `goto_type: GOTO_GOTO` 字段
  （由并发会话在 commit 4b5584f 中完成）。

**scope_break 接入主管线（block.rs / blockaction.rs）：**
- 新增 `BlockGraph::scope_break(cur_exit, cur_loop_exit)`（block.cc:1270-1288
  `BlockGraph::scopeBreak`）：按顺序遍历 `blocks`，对每个子块调用
  `scope_break_trait(ind, cur_loop_exit)`，其中 `ind` 是下一个兄弟块的
  index（最后一个子块继承传入的 `cur_exit`）。这是 `ActionFinalStructure::apply`
  的入口（blockaction.cc:2193 `graph.scopeBreak(-1,-1)`）。
- `FlowBlock::scope_break_trait` 在 7 个结构化子类型中重写，dispatch 到
  已有的 inherent 辅助方法（之前定义但从未被调用，导致所有 BlockGoto/BlockIf
  保留默认 `GOTO_GOTO`，emit 阶段打印 `goto code_r0x...;`）：
  - `BlockGoto` → `scope_break_goto_type`（block.cc:2866）
  - `BlockIf` → `scope_break_goto_type`（block.cc:3075）
  - `BlockWhileDo` → `scope_break_children`（block.cc:3324）
  - `BlockDoWhile` → `scope_break_body`（block.cc:3434）
  - `BlockInfLoop` → `scope_break_body`（block.cc:3462）
  - `BlockCondition` → `scope_break_children`（block.cc:3034）
  - `BlockSwitch` → `scope_break_break_cases`（block.cc:3613）
  - `BlockList` → 内联 `BlockGraph::scopeBreak` 遍历（Ghidra 中 BlockList
    继承 BlockGraph，不重写 scopeBreak）
- `ActionFinalStructure::apply`（blockaction.rs）在标记 BRANCH/CBRANCH
  之前调用 `fd.sblocks.scope_break(-1, -1)`，把目标 == 内层循环 exit 的
  goto 重分类为 `BREAK_GOTO`，emit 阶段打印 `break;` 而非 `goto code_r0x...;`。

**验证：** `cargo check` 通过（block.rs / blockaction.rs / coreaction.rs 零错误；
剩余 4 个 E0308 错误位于 printc.rs / typefactory.rs，属其他并发会话的进行中工作）。
每个移植方法上方均有 `// Ghidra: block.cc:<行号> <函数名>` 注释；Rust 粘合代码
标记为 `// RUGRA-GLUE: <reason>`。
 
 
 
 

### 2026-08-15：公共 BlockGraph::find_spanning_tree（BLOCK-INDEX-ASSIGN-0001）

Ghidra `FlowBlock::index` 生产唯一赋值点的 1:1 移植：`BlockGraph::findSpanningTree`
（block.cc:1009-1136，Tarjan 生成树 + 反向后序）。此前 Rugra 侧只有
blockaction.rs 的私有 `find_spanning_tree`（位置索引域、HashMap 局部状态、
不写 `FlowBlock.index`）——本次新增**公共**方法，全副作用对齐：

- `BlockGraph::find_spanning_tree(&mut self, preorder, rootlist) -> anyhow::Result<()>`
  （block.cc:1009）。副作用：
  - 每个成员块 `index = -1`、`visitcount = -1`、`copymap = self`（cc:1023-1030/1118-1123）；
  - 每遍开始 `clear_edge_flags_all()` = `clearEdgeFlags(~((uint4)0))`（cc:1045），
    清空所有成员块入/出边两侧的全部 label 位；
  - DFS 出边分类 tree / back|loop / forward / cross（cc:1093-1105），出边与
    镜像入边两侧同时 OR-set（Ghidra setOutEdgeFlag block.cc:240-246）；
  - `numdesc` 在发现时置 1、子树弹栈时向上累加（cc:1073/1084/1098）；
  - `rpostcount` 自 n 递减后赋 `index`（cc:1080-1082）；
  - 结束 `list = rpostorder`：成员列表本身重排为反向后序（cc:1135）；
  - `preorder` 输出前序、`rootlist` 为 in/out 参数（尾交换使 orighead 最后访问
    →RPO 最前，cc:1031-1035/1129-1133；两遍 repeat + extraroots 提升与
    rootlist 换位 cc:1041-1127；repeat==1 仍发现 extraroots 时返回
    LowlevelError 等价的 anyhow 错误，cc:1110-1111）。

**支撑原语（均为 trait 默认实现或自由函数）：**
- `set_in_edge_flag(slot, flag)` — setOutEdgeFlag 的镜像入边半边（block.cc:240）。
- `set_out_edge_flag_mirrored(cur, i, lab)`（自由函数，pub）— 完整 Ghidra
  setOutEdgeFlag（block.cc:240-246）：出边 + 目标块镜像入边；自环边（目标即
  本块）在单一把锁内同时写两侧，避免对调用方已持有的写锁重入死锁。
- `is_irreducible_out(i)`（block.hh:332）— DFS 跳过不可归约出边判定
  （cc:1089；注意 cc:1045 的全清使外部预置 label 不存活，跳过分支对外部
  预置不可达——与锁定 oracle 行为一致）。
- `get_copy_map`/`set_copy_map`（block.hh:163 + 私有 copymap 字段 block.hh:123）。
- `get_num_desc`/`set_num_desc`（私有 numdesc 字段 block.hh:126；未发现时 -1
  对应 C++ 未初始化值）。
- `BlockBasic`/`BlockGraph` 新字段 `copy_map: Option<Weak<...>>`、`num_desc: i32`。

**对齐证据：** `tools/run_block_index_assign_oracle.sh` 权威差分（锁定 oracle
e40ed130 重建 + pinned base + overlay src/block.rs），8 case 逐字节一致
（空图早退/单块/单入口 DAG + 状态污染复位/多入口 rootlist 交换/无根假定
首块 + 回环/不可达分量两遍 extraroots/stale-root 机制 + 自环/irreducible 与
goto 预置 label 全清）。blockaction.rs 私有变体保留未接线（接线需统一
index 域并重过差分门禁，注释已注明）。

## 支配树重建域（block_domroot_1204，2026-08-19）

**`BlockGraph::structure_loops(&mut rootlist)`** — `block.cc:2194-2215`
`BlockGraph::structureLoops(vector<FlowBlock*> &rootlist)` 的完整移植：
`do { find_spanning_tree; find_irreducible; needrebuild 时
clear_edge_flags_mask(SPANNING_MASK) + 清 preorder/rootlist 重跑 } while
(needrebuild)`，`irreduciblecount > 0` 时调用 `calc_loop`（登记 stub，见
下方 BLOCK-FINDIRREDUCIBLE-0001 节残差）。`findIrreducible`（cc:1147）已
随本 wave 移植；`calcLoop`（cc:2104）为剩余残差。

**`BlockGraph::calc_forward_dominator(&rootlist)`**（及预留
`calc_forward_dominator_on`）— `block.cc:1954-2032`
`calcForwardDominator` 的 CHK 迭代支配树：prefill `dom[root]=VRoot`、
postorder 降序主循环（排除 root 槽位）、first-processed-pred 按 in-edge 序、
无前驱 idom 置 null。多根图虚拟根（createVirtualRoot/excise，cc:1970-2029）
以 `Dom::VRoot`（dom_index=0，复刻 FlowBlock ctor `index=0` 别名语义，
cc:61-69）建模——finger 走入 VRoot 时落到 rpo[0] 的 postorder 槽
（cross-root merge 得 idom=rpo[0]），excise 后入口块 immed_dom=null。

**`compute_spanning_rpo`** — RUGRA-GLUE：block.cc:1009-1136 的无副作用
RPO 视图（不重排成员列表），供 fixture 观察使用。

**对齐证据：** `tools/run_block_domroot_1204_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + 不可变 fd runner + fixture 哈希
pin），四 case 双侧逐字节 MATCH（stdout_sha256=080948a5…）：A 尾部孤儿
rootlist swap / B 入口回环 / C 多根 cross-merge VRoot 别名 / D 单根基线。
复核：机制 C 独立 APPROVE（2026-08-19，含四类语义逐项）。

## 不可归约边标记域（block_findirreducible_1204，2026-08-23）

### 2026-08-23：BlockGraph::find_irreducible + structure_loops 完整重建环（BLOCK-FINDIRREDUCIBLE-0001）

Ghidra `f_irreducible` 唯一写者的 1:1 移植：
`BlockGraph::findIrreducible`（block.cc:1147-1199，Tarjan 可归约性测试），
并把 `structure_loops` 从"仅可归约路径"升级为完整
`structureLoops`（block.cc:2194-2215）重建环。

**`BlockGraph::find_irreducible(&self, preorder, irreduciblecount) -> bool`**
（block.cc:1147）逐语句对齐：
- 反向前序遍历 `preorder`（cc:1152-1155 `xi` 自尾部递减）——每个循环体先于
  包围它的循环头被坍缩；
- 对每个 x 的**回边入**（cc:1157-1158 isBackEdgeIn）：源 y 的 `FIND(y)` =
  `copymap` 一步读种子进 reachunder 集并置 mark（cc:1161-1162，无去重——
  平行边会双重种子/双倍计数）；自环 y==x 跳过（cc:1160）；
- reachunder BFS（cc:1164-1189）：跳过已标不可归约的入边（cc:1170）；
  对 y' = FIND(y) 做区间测试——y' 落在 x 的前序区间
  `[visitcount, visitcount+numdesc)` **之外**（cc:1174：严格在 x 之前，或
  达/超过子树末端）即不可归约：`irreduciblecount` 累计（cc:1176，跨
  structureLoops 重建累计）、y 的 `getInRevIndex(i)` 出边槽 + 镜像入边半边
  OR-set `f_irreducible`（cc:1177-1178）、树边 → needrebuild（cc:1179-1180）、
  非树边仅清 cross|forward 旧分类（cc:1182）；否则未标记且 ≠x 的 y' 入集
  （cc:1184-1187）；
- 末尾整集坍缩为 x：清 mark、成员 `copymap` 指向 x（cc:1191-1195）——
  即 FIND 并查集的 union 步，后续顶点经 `y->copymap` 读到（cc:1161/1173）。

**`BlockGraph::structure_loops`** 升级为完整 do-while：`find_spanning_tree`
→ `find_irreducible` → needrebuild 时 `clear_edge_flags_mask(SPANNING_MASK)`
（cc:2206，保 f_irreducible）+ 清 preorder/rootlist 重跑；收敛后
`irreduciblecount > 0` 调 `calc_loop`（完整实现见下方 BLOCK-CALCLOOP-0001
节）。注意
`find_spanning_tree` 每遍开头的 `clearEdgeFlags(~0)`（cc:1045）会把上一遍
findIrreducible 标的 f_irreducible 也清掉——重建遍的收敛依赖 cc:1135
`list = rpostorder` 重排改变下一遍根扫描顺序，与 oracle 一致。

**支撑原语（本次新增，均为 trait 默认实现或自由函数）：**
- `is_tree_edge_in(i)`（block.hh:329）/ `is_back_edge_in(i)`（block.hh:330）/
  `is_irreducible_in(i)`（block.hh:333）— 入边半边谓词（get_in 读 flags，
  与既有 `is_loop_in`/`is_irreducible_out` 同模式）。
- `clear_in_edge_flag(slot, flag)` — clearOutEdgeFlag 的镜像入边半边
  （block.cc:250）。
- `clear_out_edge_flag_mirrored(cur, i, lab)`（自由函数，pub）— 完整
  Ghidra clearOutEdgeFlag（block.cc:250-256）：自环边单锁双写，与
  `set_out_edge_flag_mirrored` 对称。
- `BlockGraph::clear_edge_flags_mask(fl)` — block.cc:966-978 的通用双半边
  mask 清除（`clear_edge_flags_all` 即其 ~0 特例）。
- `find_copy_map(y)`（RUGRA-GLUE）— FIND(y) 的 `copymap` Weak 升级读；
  findSpanningTree 保证 list 内块恒有 copymap（cc:1027/1122），Option 回退
  不可达。

**needrebuild 分支可达性（重要发现）：** 对锁定 oracle 做穷举实验——全部
4 节点有向图 2^16=65536 个（含自环）与全部 5 节点无自环有向图 2^20=1048576
个，`findSpanningTree → findIrreducible` 后 **needrebuild=true 出现 0 次**
（不可归约图分别为 24000/730112 个）。与区间套论证一致：新鲜一致生成树下，
reachunder 成员恒在 x 的 DFS 子树内，其树父不可能既是 x 的真祖先又满足
区间包含。该分支为防御性代码，fixture 投影记 UNTESTED（同 BLOCK-INDEX 对
不可达分支的先例）。

**残差（BLOCK-CALCLOOP-0001 已闭环，更新登记）：**
- ~~`calcLoop`（block.cc:2104-2147）未移植~~ → 2026-08-23 完整移植
  （见下方 BLOCK-CALCLOOP-0001 节 + oracle fixture `block_calcloop_1204`
  全 case MATCH）。
- ~~`EDGEFLAG-BIT7-COLLISION-0001`~~ → 2026-08-28 复核确认旧登记无效：
  `F_DEFAULTSWITCH_EDGE=0x04`、`F_TREE_EDGE=0x10`；default-switch 现双半边镜像。
- ~~生产管线未消费~~ → 2026-08-28 真实 `buildCopy` 直接复制 basic CFG 已有的
  tree/back/irreducible/default 标签；`order_loop_bodies` 只消费这些标签，不再
  重跑 `structure_loops`。完整结构化闭包仍保持 MISMATCH。

**对齐证据：** `tools/run_block_findirreducible_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + pinned base 296c128 + overlay
src/block.rs/docs，pin-base schema2），7 case 双侧逐字节 MATCH
（stdout_sha256=62c35679…）：可归约菱形零标记 / 自环头排除 / 经典双入口
forward→i 提升 / 平行边双计数 / 嵌套不可归约 FIND 复用 + copymap 坍缩链 /
多根 cross→i 提升 / structureLoops 端到端可归约驱动。投影含
rebuild/cnt、preorder、rootlist、list、每块
index/visitcount/numdesc/mark/copymap、出入边双侧 label 终态。

## calcLoop 环断边补标域（block_calcloop_1204，2026-08-23）

### 2026-08-23：BlockGraph::calc_loop 完整移植（BLOCK-CALCLOOP-0001）

Ghidra `f_loop_edge` 唯一写者链的 1:1 移植：`BlockGraph::calcLoop`
（block.cc:2104-2147）+ 忠实签名的 `BlockGraph::add_loop_edge(begin,
outindex)`（block.cc:1451-1464，替换原先误标 addLoopEdge 的"加新边"死代码
——旧实现语义是 addEdge cc:1439 且无调用者）。

**`BlockGraph::calc_loop(&mut self)`** 逐语句对齐：
- 空图早退（cc:2113）；从 `blocks[0]`（cc:2118 `list.front()`）种子化显式栈
  DFS，置 `f_mark|f_mark2`（cc:2120）；
- per-path-level 游标 `state` **先用后增**（cc:2130 `state.back() += 1` 发生在
  读槽位之后、所有检查之前）——continue 跳过已标边后不会重扫同一槽；
- `is_loop_out(i)` 跳过已带 `f_loop_edge` 的出边（cc:2131）——单次调用内
  同槽不重扫，故仅对**调用前已存在**的 l 标签生效（重跑/stale 场景）；
- 目标带 `f_mark2` → 成环 → `add_loop_edge(&bl, i)`（cc:2133-2137，oracle 的
  LowlevelError throw 被注释掉）；目标带 `f_mark` 无 `f_mark2` → 截断（else
  分支无事发生）；否则新块入栈（cc:2138-2142）；
- 弹栈仅清 `f_mark2`（cc:2125）；栈空后按 list 序对每块清
  `f_mark|f_mark2`（cc:2145-2146）。

**支撑原语（本次新增）：**
- `block_flags::MARK2`（=0x100，block.hh:95 f_mark2）；
- `FlowBlock::clear_flags(f)`（trait 必选方法，block.hh:156 clearFlag
  `flags &= ~fl`；全部 10 个 FlowBlock 实现类落地）。

**生产接线历史：** `structure_loops` 内 cc:2211-2214 调用点仍闭环；
本节原记录 blockaction.rs 在 `order_loop_bodies` 重跑
`structure_loops` 的补偿路径，该路径已于 2026-08-28 撤销。
当前由 basic CFG 上的 `structureReset` 生成 loop/tree/back 标签，
`buildCopy` 原样复制，`order_loop_bodies` 仅消费它们。

**对齐证据：** `tools/run_block_calcloop_1204_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + pinned base + overlay
src/block.rs+src/blockaction.rs，pin-base schema2），7 case 双侧逐字节
MATCH。投影含 list 序、每块 index/visitcount/numdesc/mark/mark2/copymap/
immed_dom、rootlist + unreachable 判定、出入边双侧 label 终态。直接调用
case 的 desc/copymap 投影为 "-"：oracle FlowBlock 用户构造器（cc:61-69）
不初始化这两个字段（findSpanningTree 才初始化，cc:1025-1027），直接投影
是堆噪声而非算法输出——这一非确定性两侧同因同果，按"不可比即不投影"处
理并在 metadata normalization 登记。

### 2026-08-25：FlowBlock 边 flag 写入 trait 化（selectGoto 非终止修复）
- `FlowBlock::out_edges_mut` / `in_edges_mut`（新 trait 方法）— Ghidra 的 FlowBlock 基类持有
  `outofthis`/`intothis`（block.hh:124-127），对所有子类型生效；Rugra 每个具体类型各存
  `outgoing`/`incoming`，`set_out_edge_flag`/`clear_out_edge_flag`/`clear_edge_flags`/
  `set_in_edge_flag`/`clear_in_edge_flag` 改经这对访问器路由，替换原先只覆盖
  BlockBasic/BlockGraph 的 downcast 链。此前 goto 标记在结构化块（BlockIf/BlockList/
  BlockCondition 等）上被静默丢弃，TraceDAG 反复重提同一边导致 selectGoto 死循环
  （GetStr 家族 >10s 超时根因）。BlockCopy 补空 `incoming`/`outgoing` 字段保持 trait 全。
- `set_out_edge_flag_mirrored` / `clear_out_edge_flag_mirrored` 的 self-edge 分支 — 同步改为
  out_edges_mut/in_edges_mut 访问器（原 downcast 链在结构化块 self-loop 上同样丢标记）。
## isComplex 条件守卫域（RULEBLOCKOR-ISCOOMPLEX-0001，2026-08-25）

`FlowBlock::is_complex`（trait 默认，block.hh:250）从恒 `false` 改为恒
`true`——oracle 基类即 `return true`（非叶/非委托子类一律太复杂，不能当
条件子句）；`BlockBasic::is_complex`（block.cc:2388-2444）全量移植 statement
计数：分支本身（sizeOut>=2 时 statement=1）→ 每 CALL +1（先于输出判空）→
无输出非流断 op（STORE 等）+1 → 有输出计算的保守 calc-explicit 判定
（无 descendant / addr-tied / 被 marker 或块外 op 读 / 引用数 >
max_implied_ref(默认 2, architecture.cc:1420) 任一命中 +1），statement>2
即拒绝折叠。`BlockCopy::is_complex`（block.hh:536）委托
`original.is_complex()`；`BlockCondition::is_complex`（block.hh:635）改为
`first.is_complex()`（原无条件 `true` 是背离 oracle 的占位）。消费方：
blockaction.rs `try_rule_or`（ruleBlockOr blockaction.cc:1342）在折叠
INT_OR/AND 条件前用 `orblock.is_complex()` 守卫——此前恒 false 宽松放行，
导致 my_fwrite 出现 Ghidra 不会做的错误折叠（空体 `if (…||…) {}` 形态）。
注：Ghidra 对 `bl` 自身的 isComplex 检查在 cc:1333-1334 处于注释状态，Rugra
同样不查 `bl` 只查 `orblock`。Rugra 的 BlockBasic 无 arch 回指针，
max_implied_ref 取默认常量 2（与 ActionRestructureVarnode 同一先例）。

### 边互惠（reciprocal reverse_index）修复族（2026-08-25，BLOCK-RECIPROCAL-OOB-0001）
- `FlowBlock::half_delete_in_edge/half_delete_out_edge`（block.cc:100-115）
  上移为 trait 默认方法（经 `in_edges_mut/out_edges_mut`），对**所有**子类型
  生效；原 BlockBasic 专属实现对结构块（BlockIf/BlockGoto/BlockList/…）静默
  跳过，留下过期 reverse_index → 后续 OOB panic。
- `FlowBlock::dedup/eliminate_in_dups/eliminate_out_dups/find_dups`
  （block.cc:446-523）完整移植：消除重复边用**成对** half-delete
  （cc:461-462/490-491），两侧 reverse_index 同步维护；`find_dups` 的
  f_mark/f_mark2 标记协议照搬（自环经 self_arc 报告）。
- `FlowBlock::remove_in_edge_from`（Rugra 排除表形式的 removeInEdge
  block.cc:130-141）改为全双边：先 `half_delete_in_edge(slot)` 再对源块
  `half_delete_out_edge(rev)`；原单侧 `retain` 版本留下源侧出边半边与
  幸存边的互惠索引全 stale。
- `BlockGraph::collect_reachable`（block.cc:2154-2187）移植：正向 mark
  传播收集（不可）可达块集合，供 `Funcdata::remove_unreachable_blocks`
  使用。
- `BlockGraph::remove_edge_blocks`（block.cc:1469 removeEdge）：按指针找到
  两侧槽位后**先重结对**（`src.out[os].rev = is_; dst.in[is_].rev = os_`，
  恢复 checkEdges 不变量 block.cc:545-570，一致状态下为 no-op）再双侧
  half-delete；half-delete 不再经 BlockBasic downcast。
- `decrement_reciprocal_reverse_index`：记录槽越界时跳过递减并打
  `[BLOCKSTRUCT] WARN`（BLOCK-RECIPROCAL-OOB-0001 残差，见 TODO_BOARD；
  修复路径 = selfIdentify 的 replace*Edge 完整移植 block.cc:160-191）。
  httpd 29/30 函数 0 panic；该残差 WARN 在 httpd 全量出现 28 次。

## BlockCopy 活视图（2026-08-28）

2026-08-26 曾在 `BlockBasic` 上增加 `live_ops_source`/`source_basic` 作为
临时过渡。`BLOCK-BUILDCOPY-MIRROR-0001` 已删除这两个非 oracle 字段：
`BlockGraph::build_copy` 现在创建正式 `BlockCopy`，其 `original` 保存通用
FlowBlock 引用，`get_ops`/firstOp/lastOp 直接读取源块当前 op 列表。因此
ActionBlockStructure 之后插入的 CAST、SplitStore 等仍可见，但结构图本身不再
保存 op 快照，也不存在 Basic 回指链。

## GOTO-LABEL-UNPRINTED-0001：goto 标记/打印族（2026-08-26）

- 新增 `front_leaf`（block.cc:340 FlowBlock::getFrontLeaf）：沿
  subBlock(0) 下行到叶。oracle 与当前 Rugra 的结构树叶均为 t_copy
  (`BlockCopy`)；Basic 不再充当结构图叶替身。
  List→children[0]、If→condition、WhileDo→condition、DoWhile/InfLoop→
  body、Condition→first、Switch→control，与各类 subBlock(0) 一致。
- 新增 `mark_front_leaf` / `mark_front_leaf_dyn`（block.cc:1233
  BlockGraph::markCopyBlock：`bl->getFrontLeaf()->flags |= fl`，标记
  落在前叶而非包装块）与 `front_leaf_basic`（getGotoTarget()->
  getFrontLeaf() 组合的类型化形态，block.cc:2885）。
- 新增 `BlockGraph::next_flow_after`（block.cc:1335-1353）：子块 bl
  之后流中下一语句所在块 = 列表中 bl 的下一块前叶化；列表末尾在根处
  返回 None（Rugra 的 BlockGraph 不是 FlowBlock，嵌套图不可能出现在
  父图列表中，父递归臂结构性不可达）。
- `BlockGoto::goto_prints`（block.cc:2881-2890）修正：无 parent 臂
  oracle 返回 **false**（旧实现恒 true 恰好反转了该臂）；parent-present
  比较移入 `goto_prints_in`（cc:2884-2888：
  gotobl=getGotoTarget()->getFrontLeaf() vs
  nextbl=getParent()->nextFlowAfter(this)，不等才打印）。Rugra 结构器
  目前不接线 BlockGoto::parent（try_rule_goto 构造为 None），空 parent
  臂承载现状。
- `BlockGoto::mark_unstructured_target`（block.cc:2856-2863）与
  `BlockIf::mark_unstructured_target`（block.cc:3067-3072）的
  f_unstructured_targ 标记改走前叶路径（markCopyBlock 契约）——旧实现
  标在包装块上，叶从未带标，emitLabelStatement 永不点火（httpd label
  未打印症状的根因之一）。

## TRI2-CALLOUT-ASSIGN-0001 集成：BlockCopy 活委托

正式 `BlockCopy` 直接委托活动源列表，使结构化后插入的 CAST/拆分 op 对打印
可见，匹配 block.hh:520-535。旧的 `BlockBasic` 回指实验与构造时 ops 快照均已
删除；任何由真实副本暴露出的结构化差异必须在上游 Rule/parent 模型修复，不能
再通过冻结 op 快照规避。

## Edge flag collision fix（2026-08-27）

Ghidra `block.hh:108-118` 定义完整 edge_flags：
`goto=1, loop=2, default=4, irreducible=8, tree=0x10,
forward=0x20, cross=0x40, back=0x80, loop_exit=0x100`。
Rugra 现按 oracle 位值实现；仅 Rugra 结构化 break/continue/switch-dispatch
标注使用高位扩展。单测锁定位值并断言全部 edge flags 两两唯一。

## MAIN-RC2-BLOCKGOTO-WRAPPED-0001：BlockGoto 持有 wrapped 组件 + 真实 goto target（2026-08-30）

oracle：`BlockGoto : BlockGraph`（block.hh:547），`newBlockGoto(bl)`（block.cc:1702-1713）
先 `new BlockGoto(bl->getOut(0))` 捕获 gototarget，再 `identifyInternal(ret,[bl])`
使 bl 成为唯一 list 组件（getBlock(0)），`addBlock(ret)`、`forceOutputNum(1)`、
`removeEdge(ret,ret->getOut(0))`。旧 Rugra 实现三者全缺：无 wrapped 字段
（identify_internal 换槽后组件蒸发）、`goto_target=None`、get_ops 走 trait 默认
空 Vec、goto_prints 硬编码 false —— main 的 14 个包装块整体静默丢失。

- `BlockGoto` 新增 `wrapped`（block.hh:547 组件 = getBlock(0)；emit
  printc.cc:2771 `bl->getBlock(0)->emit(this)`、lastOp/firstOp/getExitLeaf 委托
  源）与 `target_dyn`（block.hh:548 gototarget，按 block.cc:1705 在删边前捕获
  的活 dyn Arc；scopeBreak cc:2872 的 getIndex 与 gotoPrints cc:2886 的
  getFrontLeaf 都读它）。旧类型化 `goto_target: Option<Arc<BlockBasic>>>` 保留
  为 printc 遗留投影但恒 None（结构树叶为 BlockCopy，typed Arc 不可恢复共享
  身份；printc 发射侧切 target_dyn+get_start_addr() 属 PRINTC-GOTOPRINTS-0001，
  另一 agent 协调）。
- `impl FlowBlock for BlockGoto`：`get_ops` 委托 wrapped（getBlock(0) 虚链的
  flatten 投影）；`sub_block(0)` 返回 wrapped；`first_op`（block.cc:1327
  BlockGraph::firstOp）与 `get_exit_leaf_trait`（block.hh:561）委托 wrapped。
- `BlockGoto::mark_unstructured_target`（block.cc:2856-2864）：先递归
  wrapped（cc:2859 BlockGraph::markUnstructured），再在 gototype==f_goto_goto
  且 goto_prints() 时经 mark_front_leaf(target_dyn) 标记前叶
  （markCopyBlock 契约 cc:2860-2863）。签名 &self → &mut self（递归需要）。
- `BlockGoto::scope_break_goto_type`（block.cc:2866-2874）：先
  wrapped.scope_break(gototarget->getIndex(), curloopexit)（cc:2869 —— 包装
  组件可为复合块，旧"wrapped 是 Basic 递归无操作"注释过时），再
  gototarget->getIndex()==curloopexit 时置 f_break_goto（cc:2872-2873），
  target 侧读 target_dyn 活索引；类型化字段仅作手搭 fixture 回退。
- `BlockGoto::goto_prints`（block.cc:2881-2890）不再硬编码 false：返回
  `prints_precomputed` —— `BlockGraph::compute_goto_prints` 在最终结构树上
  一次性求值同一比较（front_leaf(target) != 流中后继，后继按 block.cc:1335-
  1353 nextFlowAfter 递归：下一兄弟前叶 / 末子沿父链 / 根为 null），由
  ActionFinalStructure 在 scopeBreak 之后、markUnstructured 之前调用（oracle
  首次求值点）。默认 false 即 oracle 无 parent 臂（cc:2889）。新增
  `goto_prints_walk_level`/`goto_prints_visit`（RUGRA-GLUE：上述递归的
  Rust 投影）与 `component_list_dyn`（RUGRA-GLUE：Ghidra 统一 list/getBlock(i)
  协议在 Rust 类型化字段上的投影，顺序 = 各工厂 identifyInternal 的 nodes 序：
  List[nodes]、If goto 时 [cond]（newBlockIfGoto cc:1799）否则 [cond,tc(,fc)]、
  WhileDo[cond,cl]、DoWhile[condcl]、InfLoop[body]、Condition[b1,b2]、
  Switch[cases...,default]、Goto[bl]）。
- `front_leaf` 增加 Goto 臂：下钻 wrapped（block.hh:559 printRaw/561 getExitLeaf
  均按 getBlock(0) 链），修正旧“BlockGoto 包装 Basic”注释（ruleBlockGoto 纯
  拓扑，可包装任意单出块）。删除无引用的 `mark_front_leaf_dyn`。
- `BlockIf::get_ops`（MAIN-RC3 block.rs 半）：if-goto（goto_target Some）仅
  [cond]（newBlockIfGoto nodes=[cond]，if_body 为 condition 占位别名）；否则
  cond+if_body+else_body 全量 —— 旧实现只返回 condition，flatten 路径丢弃全部
  嵌套 body ops（main 50×curl_easy_setopt 级联消失的直接根因之一）。
- `BlockWhileDo::get_ops`：condition+body（newBlockWhileDo nodes=[cond,cl]，
  block.cc:1858-1865）—— 旧实现丢 body（BlockGoto 包装 WhileDo 时同样蒸发）。
  BlockDoWhile/BlockCondition/BlockList/BlockInfLoop/BlockCopy 保持不变（单组件
  或已按组件序拼接）。

E2E curl（124/124，0 panic）：skeleton 2911→3416，defects 1→1（__cxa_finalize，
基线即有），numbering 0→1（main iVar3 重复声明，w-main2 预告的 RC-2 暴露类
编号 issue，登记 TODO）。per-func vs golden：main +386/getparameter.constprop
+58/parseconfig +23/glob_set +10/glob_word +4/glob_range +2，其余 118 函数全部
0 变化 —— skeleton 增量全部来自被救回内容的形态仍偏离 golden（RC-3 printc
body_is_dead 门禁 + RC-4 循环形态 + RC-5 条件错接均未修），内容本身完整
（main 体 245→643 行，0x2a8a..0x2ff9 区 51×setopt 级联/perform/cleanup 全部
恢复，无双重发射）。

- `component_list_dyn` 提升为 pub（Ghidra 统一 getBlock(i) 协议的唯一 Rust 可见
  投影）：双侧 fixture blockstruct_blockgoto_wrapped_1204 的树遍历入口。fixture
  状态 MISMATCH（14 行），登记于 BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 —— 两个
  探针形态上 oracle 的 collapseAll 留下纯 BlockGoto 包装（double_back_goto:
  wrapped=b3 basic/target=whiledo 复合；loop_exit_conflict_gotos: wrapped=list
  与 properif 复合、其一 target 指向另一 goto 节点），Rugra 侧同图结构化不产
  t_goto（与 goto_cascade 185 行/deadregion 149 行同根因族，两 fixture 在
  master 上即 MISMATCH，本次重钉 comparand sha 后复核数字不变）。oracle 侧
  观测同时实证了 target 为复合块（whiledo/list/goto）—— dyn target 设计的
  直接依据。

### 2026-08-30（BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001）：诊断设施

- `print_tree_dbg`（RUGRA-GLUE，BlockGraph::printTree 的诊断复刻，block.cc:616
  printTree 语义）：递归 dump 结构树（索引/类型/front-leaf 地址/BlockGoto 目标
  + goto_type + prints 预计算/if-goto 目标/Switch cases），供 curl/httpd runners
  的 RUGRA_DUMP_FUNC hook 与 examples/blockstruct_tree_dump.rs 使用。
- `dbg_front_leaf_start_addr`：穿透 BlockCopy 包装读 front leaf 起始地址（组合
  节点自身无地址；BlockCopy 未覆写 get_start_addr）。

## 2026-09-22：JUMPTABLE-TABLEAPI-0001 P0-A — BlockBasic::noInterveningStatement

`BlockBasic::no_intervening_statement()`（block.cc:2712-2747）：block 内不产生
外流值的检查——marker/branch 跳过；special 拒 CALL/STORE/NEW；非 special 跳
COPY/SUBPIECE；输出 addr-tied 拒绝；任一后代 op 的 parent 不在本块拒绝。
自块身份用 self_ref Arc 与 op.parent Arc 的 ptr_eq（add_block 同时建立两者）。
供 JumpBasic::foldInOneGuard（jumptable.cc:1394）守卫使用。

## 2026-09-22 追加（BLOCKSTRUCT-MULTIGOTO-0001 — BlockMultiGoto 类型 + BlockSwitch per-case gototype）

- 新增 `BlockMultiGoto`（Ghidra block.hh:573-593）:gotoedges（addEdge 纯 vector push,不建图边,block.hh:580）、defaultswitch（setDefaultGoto/hasDefaultGoto）、wrapped（getBlock(0) 组件,同 BlockGoto::wrapped 模式）。FlowBlock impl:getType=t_multigoto；scope_break_trait→wrapped.scope_break(-1,cur_loop_exit)（cc:2918-2922,curexit 丢弃换 -1）；mark_unstructured_trait 纯递归（无覆写=BlockGraph 递归语义）；nextFlowAfter 恒 None（cc:2931-2936）；get_ops/sub_block/first_op/get_exit_leaf 委托 wrapped；print_header "Multi goto block"。
- `front_leaf` 补 MultiGoto arm（经 wrapped 下降,block.hh:587-589 委托链）——此前落入 catch-all 返回自身。
- `BlockSwitch` 新增 `case_gototypes: Vec<u32>`（CaseOrder::gototype per case,block.hh:778）与 `default_gototype: u32`:`mark_unstructured_targets` 与 `scope_break_break_cases` 从"conservative no-op"落为真实实现（cc:3607-3610 gototype==f_goto_goto→markCopyBlock(UNSTRUCTURED_TARG);cc:3620-3623 goto case 目标==curexit→提升 f_break_goto）。
- 新增 `front_leaf_start_addr`（printc.cc:2303 emitGotoStatement 的 exp_bl→emitLabel 投影）:front leaf 的 BlockCopy original 起始地址（BlockCopy 不覆写 getStart,与 oracle 一致,block.hh:505-538）。

## 2026-09-22 追加（GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001 — nextFlowAfter 分臂单一事实源 + 死代码清理）

- **`next_flow_after_successors`（pub，模块级）提升进 block.rs**：oracle
  `getParent()->nextFlowAfter(this)`（block.cc:2885 经 BlockGoto::gotoPrints 触达）
  的逐父类型虚分发表，对一 composite 的全部组件一次算清 —— 原
  `goto_prints_walk_level` 只建了 12 个 override 中的 BlockGraph 兄弟臂
  （block.cc:1335-1353），If/WhileDo/DoWhile/InfLoop/Goto/Switch 六类父类型的
  分臂全部缺失（Lane BJ 审计：while body 尾 break-goto 会被旧纯兄弟规则吞成
  死循环）。分臂逐条对照 oracle：
  - `FlowBlock` 基类（block.hh:884-887）恒 null —— 叶子不经 walk 触达；
  - `BlockGraph`/`BlockList`（block.cc:1335-1353；block.hh:600 无 override）
    兄弟规则（提取为 `graph_sibling_successors`（pub），末组件 = 外层 succ，根
    null）；
  - `BlockGoto`（block.cc:2899-2903）任意组件 → 目标 front leaf；
  - `BlockMultiGoto`（block.cc:2931-2934）恒 null —— Rust component_list_dyn
    对 MultiGoto 为空（wrapped 是调度 basic 叶，无内部 goto），结构上不可达；
  - `BlockCondition`（block.cc:3053-3056）恒 null；
  - `BlockIf`（block.cc:3127-3134）槽0（条件，含 if-goto 单组件形态）→ null，
    其余槽（tc/fc）→ 父臂 succ，**无兄弟扫描**（两个 body 的后继是整个 if 的
    后继，不是对方）；
  - `BlockWhileDo`（block.cc:3341-3351）槽0 → null，body → front_leaf(cond) =
    **循环头**（body 尾 goto 对比的是头而非循环后 —— break-goto 不再被吞）；
  - `BlockDoWhile`（block.cc:3448-3451）恒 null（可能在迭代）；
  - `BlockInfLoop`（block.cc:3476-3483）任意组件 → front_leaf(getBlock(0)) =
    循环头（显式回边 goto → prints=false，不再多打 goto+标签）；
  - `BlockSwitch`（block.cc:3639-3661）：oracle 臂① `getBlock(0)==bl → null`
    指**调度根 cs[0]**（Rust 存于 `BlockSwitch::control`，不在组件表内 —— 旧
    coreaction 分表把 components[0]（第一个 case）误当调度根给 null，本次修
    正：无槽0 特判）；臂② 非 t_goto case → null（"break statement in the
    flow"）；臂③-⑤ t_goto case → 打印序下一 caseblock 的 front leaf，末位 →
    父臂。序基准：oracle caseblocks 经 finalizePrinting label/depth stable_sort
    （block.cc:3591，ActionFinalStructure 在 scopeBreak/markUnstructured 前先调
    finalizePrinting，blockaction.cc:2192）；Rust 以组件序（cases+default 追
    尾）= 自身发射序建模（printc emit_block_switch 同序）——真实 label 排序
    落地于 JUMPTABLE-TABLEAPI-0001，届时两侧须同步排序。
- **`goto_prints_visit` 改用分表递归**（`goto_prints_walk_level` 删除）：
  `compute_goto_prints` 根层走 `graph_sibling_successors(components, None)`，
  每层经 `next_flow_after_successors` 派发 —— 与 coreaction.rs
  ActionReturnSplit 的 gather walk 共用同一实现（**单一事实源**；
  ReturnSplit 保持 mid-pipeline 现算、不读 prints_precomputed —— 与 oracle
  两态惰性求值语义一致）。
- **删除 7 个无调用点的死代码 typed 方法**（各有简化且未接入任何链路，避免
  双源漂移）：`BlockGoto::next_flow_after_index`、
  `BlockIf::next_flow_after_parent`、`BlockWhileDo::next_flow_after`、
  `BlockDoWhile::next_flow_after`、`BlockInfLoop::next_flow_after`、
  `BlockCondition::next_flow_after`、`BlockSwitch::next_flow_after`。
  `BlockGraph::next_flow_after`（block.cc:1335 根图形态）保留 —— 仍被
  `goto_prints_in`（parent 接线形态）消费。
- **双侧 fixture**：`tests/oracle/goto_prints_nextflowafter_1204.{cc,rs}` +
  `tools/run_goto_prints_nextflowafter_oracle.sh` —— 六形态（while 尾
  break-goto / infloop 回边 / switch fallthru / goto 套 goto / if-else 尾 /
  dowhile 尾）锁定全部 12 分臂，**MATCH**（per-(composite,component) 后继身份
  + per-goto gototype/prints 双侧逐字节一致）；Switch 槽位以 oracle 索引打印
  （调度根=槽0），label 全 0 使 stable_sort 保序（真实 label 排序绑定
  JUMPTABLE-TABLEAPI-0001）。
## 2026-09-22：BlockSwitch label 管道结构层（JUMPTABLE-TABLEAPI-0001 消费半部）

BlockSwitch 补齐 Ghidra ctor/finalizePrinting 语义（block.cc:3485-3601）：
- 新增字段 `jump: Option<Arc<RwLock<JumpTable>>>`（block.hh:753，ctor
  cc:3488 `jump = ind->getJumptable()`，经 block.cc:630 FlowBlock::getJumptable
  的 BRANCHIND last-op 反查）与 `case_order: Vec<CaseOrder>`（block.hh:767
  caseblocks 的 Rust 平行数组形态）。
- 新增 `pub struct CaseOrder`（block.hh:755-767）：basicblock/label/depth/
  chain/outindex，`CaseOrder::placeholder` 对应 addCase 的逐字段初始化
  （cc:3498-3505：label=0/depth=0/chain=-1）。
- `BlockSwitch::finalize_case_labels`（block.cc:3556-3592）：pass1 标记
  fall-thru 链非根 depth=-1（cc:3562-3570）；pass2 仅链根设 label
  （numIndicesByBlock>0 && depth==0，cc:3571-3589）并沿链下传
  depthcount/label；stable_sort 按 CaseOrder::compare（block.hh:903-909，
  label→depth），Rust 侧 cases/case_gototypes/case_values/case_order 四数组
  联动置换；最后按 print-time 查询（block.hh:780/787）物化
  `case_values[i][j] = getLabelByIndex(getIndexByBlock(basic_i, j))`，
  get_num_labels/get_label 读取物化结果（值与 oracle 的活查询恒等，
  finalizePrinting 先于任何打印运行）。
- `BlockGraph::finalize_printing`（block.cc:1364-1371）：子节点递归入口，
  由 ActionFinalStructure 调用（见 docs/api/blockaction.md）。
- 自由函数 `finalize_printing_block`（RUGRA-GLUE，C++ virtual dispatch 的
  Rust 形态）：Switch 分支先递归 control+非 goto case+结构化（gototype==0）
  default 臂（= newBlockSwitch 经 identifyInternal 消费的 list 成员，
  cc:3559/1913；goto 臂目标与 gototype!=0 的 default 留在周围图由父图递归
  覆盖，cc:3548-3553）再跑 finalize_case_labels；其余复合块走
  component_list_dyn 继承递归；叶子为 FlowBlock::finalizePrinting 空实现
  （block.hh:262）。（default 臂下推为 2026-09-26 BLOCK-FINALIZE-DEFAULT-
  RECURSE-0001 修复，见下节。）

fixture：tests/oracle/printc_switch_emit_1204.rs 字面量补
`jump: None, case_order: Vec::new()`（行为不变，仅结构体字段跟进），
metadata rust_fixture_sha256 重钉（e8f69bfc→81656ef8）。

## 2026-09-22（续）：CaseOrder 补 Clone

`CaseOrder` derive 补 `Clone`（collapse 期重建点需按位携带 caseblocks）。

## 2026-09-22（续 2）：finalize 见证 dump（调试工具）

`finalize_case_labels` 尾部新增 RUGRA_BS_DUMP=1/2 门控的
`[BLOCKSTRUCT] finalizePrinting case[i] label=0x.. depth= chain= outindex=
labels=[..]` 逐臂见证输出（RUGRA-GLUE，无 Ghidra 对应物；label 管道结构层
验收的观察窗口）。

## 2026-09-22（续 3）：orderBlocks 顶层排序（BLOCKSTRUCT-ORDERBLOCKS-0001，Lane BV）

`BlockGraph::order_blocks`（block.hh:430-431）：`if (list.size()!=1)
sort(list.begin(),list.end(),compareFinalOrder)` 的完整移植——单元素列表
跳过排序；排序用 `compare_final_order`（见下），在 ActionFinalStructure
（blockaction.cc:2191）内、finalizePrinting/scopeBreak/markUnstructured
**之前**调用，使 scopeBreak 的 next-sibling fall-thru（block.cc:1277-1287）、
gotoPrints 的 next-in-flow 后继（block.cc:2881-2890）与 emitBlockGraph 的
发射序都看到最终打印序。

自由函数 `compare_final_order`（block.cc:709-730 FlowBlock::compareFinalOrder）
返回 `std::cmp::Ordering`，三个排序键逐行对齐：

1. **entry 键**（cc:712-713）：`getIndex()==0` 恒最前（双侧索引互异，
   both-zero 分支映射 Equal 仅为保持全序）；
2. **RETURN 键**（cc:717-728）：`lastOp()`（per-type virtual 分派）为
   CPUI_RETURN 的块排在所有非 RETURN 结尾块之后，含
   (RETURN,null)/(null,RETURN) 两臂；两个 RETURN 结尾块双向比较均为
   false（cc:719+724），即并列（tie），映射 `Ordering::Equal`，永不落入
   索引比较；
3. **index 键**（cc:729）：其余按 `getIndex()` 升序。

tie 解析：libstdc++ `std::sort` 对 ≤16 元素范围走插入排序 phase（对 tie
稳定）；Rust 用稳定 `sort_by`，小列表（真实结构图的常态）tie 保序与 oracle
一致。>16 元素范围的 quicksort phase tie 置换差异为已登记残差（metadata
residual_diffs，当前 curl/httpd 全语料所有函数顶层列表均为单元素，
block.hh:431 守卫直接跳过，A/B 字节恒等）。

新增 per-type `lastOp` 委托覆盖（compareFinalOrder 的依赖，此前 trait 默认
None 与 oracle 分派不符）：

- `BlockGoto::last_op`（block.hh:562）：`wrapped`（getBlock(0)）委托；
- `BlockMultiGoto::last_op`（block.hh:590）：同上。

`Ord for BlockRef` 注释更正：其纯 index 比较对应 `compareBlockIndex`
（block.hh:893，Varnode def-block 排序用），非 compareFinalOrder；真正的
compareFinalOrder 落在 `compare_final_order` 自由函数。

单测：`compare_final_order_sort_keys_and_order_blocks_guard`
（entry/RETURN/null 三臂、双 RETURN tie、index 键、单元素守卫、
order_blocks 端到端置换）。B2 双侧 fixture：
`tests/oracle/blockstruct_orderblocks_1204`（5 case：entry-first+return-last+
stable tie、null/RETURN 混合臂、真 BlockGoto 包裹 RETURN 块委托、真
BlockMultiGoto 包裹非 RETURN 块委托、单元素跳过）——双侧投影逐字节
MATCH（runner `tools/run_blockstruct_orderblocks_oracle.sh`）。

### 2026-09-22：markLabelBumpUp 家族接线与死代码纠偏（BLOCKSTRUCT-MARKLABELBUMPUP-0001，Lane CC）

- **新增 trait 默认方法** `FlowBlock::mark_label_bump_up_trait(bump)`（对应
  block.hh:195 虚方法声明、block.cc:259-264 基类体）：`bump=true` 时置
  `f_label_bumpup`，无递归无清除；叶子（BlockBasic/BlockCopy）继承该默认
  （Ghidra 二者均直接继承 FlowBlock）。
- **新增 `BlockGraph::mark_label_bump_up`**（block.cc:1258-1268）：基类法
  标自身（bump=true 时）→ list 为空即返 → list[0] 原样接收 bump、
  list[1..] 一律 false（虚派发）。`ActionFinalStructure::apply` 以
  `mark_label_bump_up(false)` 驱动（blockaction.cc:2195）。
- **新增继承 override**（Ghidra 中继承 BlockGraph::markLabelBumpUp 的类）：
  BlockGoto/BlockMultiGoto（单一 `wrapped`=list[0]，gotoedges/gototarget
  不在 list 内不递归）、BlockList（children[0] 收 bump 其余 false）、
  BlockCondition（first 收 bump、second false）、BlockIf（[condition,
  if_body, else_body?] 列表序，condition 收 bump，cc:newBlockIf/
  newBlockIfElse block.cc:1822-1852）、BlockSwitch（[control, cases...,
  default]，control=getBlock(0) 收 bump，grabCaseBasic block.cc:3524-3534）。
- **死代码三 override 重写**（BlockWhileDo block.cc:3316 / BlockDoWhile
  block.cc:3426 / BlockInfLoop block.cc:3454）：旧实现对 condition+body
  双双平铺 `set_flags(LABEL_BUMPUP)`（WhileDo 连 body 也置位）且无递归，
  违背 cc:3319/3429/3457 的 `BlockGraph::markLabelBumpUp(true)` 语义。
  重写后：自置位 → WhileDo: condition(true)/body(false)；DoWhile/
  InfLoop: 唯一子（list[0]）(true) → `!bump` 时清自身。嵌套前链（内层
  循环收到 true）保持自身旗标——B2 fixture nested_loops_front 判别。
- **消费侧**（printc.rs `emit_any_label_statement` 顶部）：补
  printc.cc:3222 `if (bl->isLabelBumpUp()) return;` 早退——被旗标块的
  label 语句跳过，由外层循环构造入口的调用统一打印（walker 级
  `emit_any_label_statement` 于构造首个 token 前触发，位置等价 oracle
  的 cc:3014/3076/3104/2965 构造入口调用）。
- 验证与三门禁见 docs/api/blockaction.md 同日条目；B2 双侧 fixture
  `tests/oracle/blockstruct_marklabelbumpup_1204`（runner
  `tools/run_blockstruct_marklabelbumpup_oracle.sh`）5/5 MATCH。

## 2026-09-22 追加（PRINTC-SWITCH-EMIT-0001 — default_label 字段）

`BlockSwitch` 增 `default_label: Option<u64>`：oracle 的 default 是 caseblocks 普通成员
（addCase cc:3515 isdefault），label 取其基本块首个表索引（finalizePrinting
block.cc:3573-3576），与全部 case 一起按 (label,depth) 稳定排序（cc:3591）——
`default:` 印在 label 秩位而非末位。Rugra default 走独立槽，该字段由
`finalize_case_labels` 末尾按同款配方计算（front_leaf→original 基本块 +
getIndexByBlock(basic,0)→getLabelByIndex）；无表索引或 case_order/cases 长度不齐时
None（printc 保持末位旧位）。已知角落：default 为 fall-thru 链非根时 oracle 继承
链根 label（cc:3577-3584），Rugra 按自身首索引排位（语料未见）。消费方与门禁见
docs/api/printc.md 同日条目。

## 2026-09-23：RULE-PULLSUBMULTI-LOOPIN-0001 关闭 — FlowBlock::hasLoopIn 落地

新增 trait 默认方法 `has_loop_in`（block.cc:428-428-433 逐行）：任一入边带
`f_loop_edge` 即真。边标已由 `find_spanning_tree`（block.cc:1101 回边标
`F_BACK_EDGE|F_LOOP_EDGE`，Rugra block.rs:3492 同字面）维护，
`ActionLaneDivide` 前无清除点，规则期读取即 oracle 语义。消费者
`RulePullsubMulti::applyOp` cc:883 守卫（"We only pull up, do not pull down
to bottom of loop"）接入：match_url Phase 2 ordinal 28 oppool1 首个发射错位
（idx 358，Rugra 多发 pullsub_multi+dumptyhump）即 __libc_csu_init 循环体
phi@0x5440（5454→5440 回边）被错误放行；守卫接入后该池 861=861 对齐。
四类核对：引用参数=无（只读入边 flags）；遍历序=入边槽位序；计数器=无；
排序键=flag 位测试（block.hh:110 f_loop_edge=2）。

## 2026-09-25 追加（BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 — case_isexit 平行数组 + nextFlowAfter 合并打印序）

1. **`BlockSwitch::case_isexit`/`default_isexit`**：`CaseOrder::isexit`（block.hh:763，
   addCase block.cc:3511-3514 于 grabCaseBasic 时、identifyInternal 半删组件外部出边
   之前捕获的 `bl->sizeOut()==1`）的 Rust 平行数组传输——与 `case_gototypes` 同形
   态；`finalize_case_labels` 稳定排序联合置换；捕获点在 blockaction.rs
   `try_rule_switch`（写域主 commit）。
2. **`next_flow_after_successors` Switch 臂**：对齐 `BlockSwitch::nextFlowAfter`
   （block.cc:3639-3661）的 caseblocks 遍历序——default 以其 label 序位插入合并
   打印序（def_pos 配方同 printc），goto 组件的后继=合并序下一位的前叶，最后一个
   caseblock 交父臂（cc:3659-3660）；不再用「cases+尾部 default」的原始组件序（该
   序使最后真实 case 的后继成为 default 前叶，goto 目标恰好是 default 时丢 goto
   语句，httpd main case 0x66 实证）。文档注释同步改写。

## 2026-09-25 追加（BLOCKACTION-SWITCH-DEFAULTCHAIN-0001 — default 进入链图 + 排序 rank key）

1. **`BlockSwitch::default_order`**（新字段）：oracle 的 `caseblocks` 含正式 default
   为普通成员（grabCaseBasic cc:3529-3533 逐组件 addCase；仅 cc:3515 isdefault 旗
   标区分）。Rugra 把 default 体放独立 `default_case` 槽，此前链图（cc:3536-3544
   fall-thru chain）无法把「case 组件 goto 目标=default 基本块」的链边接上——
   glob_set 的 `'\\'`(0x4c48→0x4c5e) 链断，default 以自身首表项 0x5e 排序，落
   `'`'` 之后并显式 `goto switchD_..._5e`。新虚拟条目（index=case_order.len()）
   由 `grab_case_order`（blockaction.rs）注册进同一 casemap，default 自身的
   fall-thru 链（default→另一 case 的罕见形）同样建模。
2. **`finalize_case_labels` 扩展视图**：cc:3562-3591 两遍 label/depth + 稳定排序
   在 `case_order + default_order` 扩展向量上执行（链索引=grab 时索引，先遍历后
   排序，同 oracle）；default 作为链非根继承链根 label（cc:3577-3584），合并序中
   落在根后（depth tie-break，block.hh:907）。
3. **`default_label` 语义升级为 rank key**：printc 的 def_pos 与
   `next_flow_after` 的合并序都数 `label < default_label`；key=
   `max(前缀 regular label)+1`（首位为 0），使 count==oracle 合并序前缀数 r
   （链根与 default 同 label 时仍计入前缀=oracle 的 depth tie-break）。残角：
   链穿过 default 延续（default 后还有同 label regular）无精确标量，key 尽力
   （RUGRA_BS_DUMP 见证；双语料实测 0 次触发）。
4. **效果**（curl 默认脸 489→474）：glob_set 38→23——switch 体与 canon 同构
   （`case '\\':` 直落 `default:` 无 goto、`case ']'` 居 default 后）；httpd
   908 逐字节恒等；glob_word 等 label-rank 消费者 def_pos 数学等价（root-default
   的 count 不变量，A/B 零差亲证）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 10 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — BlockWhileDo for 循环形成族整体移植（HTTPDMAIN-F8-FORLOOP-0001，Lane F8FOR）

按锁定 oracle (e40ed130) 1:1 移植 `BlockWhileDo` 的 for-loop 形成机制族：

- **结构体字段**（block.hh:694-696）：`BlockWhileDo` 新增 `initialize_op` /
  `iterate_op` / `loop_def`（`Option<PcodeOpRef>`，对应 oracle `mutable PcodeOp*`
  三元组）。原 `for_init`/`for_iter` 文本对降级为 legacy 通道（coreaction.rs
  过渡渲染器专属，见下）。
- **findLoopVariable**（block.cc:3164-3213）：`while_do_find_loop_variable` —
  归纳变量检测。CBRANCH 条件 varnode 起锚，显式 `path[4]` 栈 DFS（非
  MULTIEQUAL def 下探至 4 级、call/marker 剪枝）；head 内 MULTIEQUAL 的
  tail-槽输入 def 须驻 tail 且过 `isMoveable(lastOp)` 门 → 设
  `loop_def`+`iterate_op`。
- **findInitializer**（block.cc:3223-3244）：`while_do_find_initializer` —
  head 双入边、entry-槽 def 终结于单出边初始化块 → 设 `initialize_op` 并
  返回该块 lastOp。
- **testTerminal**（block.cc:3256-3283）：`while_do_test_terminal` —
  notPrinted COPY 穿透、isExplicit + 可打印根、`moveRespectingCover`
  （**提交移动**，funcdata_op.cc:1488-1495 语义）。
- **testIterateForm**（block.cc:3287-3314）：`while_do_test_iterate_form` —
  迭代语句须以 loopDef 输出 high 为输入（annotation/explicit 截断 DFS）。
- **finalTransform**（block.cc:3356-3397）：`while_do_final_transform` +
  `final_transform_block`/`for_loop_final_transform`（树递归 + 顶层入口）—
  **iterateOp 迁移**：`op_uninsert`/`op_insert_after` 将迭代/初始化语句移至
  宿主块终端位置（isMoveable 门）。
- **finalizePrinting**（block.cc:3403-3424）：`while_do_finalize_printing` +
  `finalize_printing_graph`/`finalize_printing_block`（签名改收 `&mut
  Funcdata`——WhileDo 覆盖需要 `moveRespectingCover`/`opMarkNonPrinting`）—
  终检 + `opMarkNonPrinting(iterateOp/initializeOp)` 喂 printc 的 for 头。
- **锁纪律**（RUGRA 侧）：`final_transform_block` 在持块写锁前解析
  `front_leaf()->sub_block(0)` 头块——std RwLock 同线程读写在同锁上死锁
  （实测 main 15s 超时根因）；共享子节点 visited 集防二次处理。
- **visited 不对称的语义裁定**（F8FOR-FINALIZE-VISITED-0001，CR-F8FOR
  发现项①处置）：oracle 两棵扫描均无守卫（cc:1355-1362/1364-1371 纯递归），
  靠结构树单所有权不变式保证每块恰访一次——`addBlock` 唯一 `parent` 指针
  （cc:862-875）+ `identifyInternal` 物理摘除组件（cc:953-960）+ goto 臂
  switch 目标留在周围图不消费（cc:3548-3553），且 `BLOCKCONSISTENT_DEBUG`
  构建在折叠期断言所有权（cc:945-948）。Rugra 的 Arc 块模型有一个**受制裁
  别名**：multigoto 控制的 `BlockSwitch` 把 goto 臂目标留在顶层根的同时
  记进 `cases`（gototype != 0，镜像 cc:3548-3553）。由此：
  ①`final_transform_block` 走 `component_list_dyn`（Switch 臂=cases+
  default，含 goto 臂）→ 别名成员可经两路到达，其 visited 守卫是**承重**
  的（去重后等价 oracle per-node-once）；②`finalize_printing_block` 的
  Switch 分发只走 control+gototype==0 cases+gototype==0 default 臂
  （default 下推为 2026-09-26 BLOCK-FINALIZE-DEFAULT-RECURSE-0001 修复）→
  别名成员被结构性排除，**无需守卫**——不对称是两扫描成员集不同的必然
  结果，非缺陷。③新增
  debug-only `BlockGraph::debug_assert_structure_tree_unique`（两扫描入口
  各调一次，oracle 走形=control+结构化 cases+结构化 default，其余=
  component_list_dyn）：任何其他重复可达（真共享子/父环）在 debug 构建
  即 panic（镜像 BLOCKCONSISTENT_DEBUG 哲学于扫描期），release 编译剔除
  （fast-release=release 继承，canon 零扰动结构保证）。构造性验证 4 测
  （block.rs `finalize_visited_tests`）：共享子检出/父环检出/goto 臂别名
  合规+oracle 走形唯一/默认 5 步折叠端到端单所有权。
- **放置偏差登记**：oracle 在 :5715（ActionStructureTransform，merge 组前）
  跑 finalTransform；Rugra 的该 Action apply 在 coreaction.rs（车道写域
  冻结，为 no-op），扫描改挂在 blockaction.rs 的 ActionFinalStructure
  （:5736 槽，紧邻 finalizePrinting 前）——canon 双语料字节级 A/B 验证
  放置无行为差（间隔 merge/cast 动作只读 observe 迭代 op 原位置 vs 移后
  位置，语料上不可观察）。coreaction.rs 的过渡渲染器
  `for_loop_finalize_printing` 与本通道在检测上互斥（真 finalizePrinting
  先标 NONPRINTING，收窄版 testTerminal 拒 notPrinted 根），至多单通道触发。

行为证据见 TODO_BOARD HTTPDMAIN-F8-FORLOOP-0001 行（canon/mirror A/B 全表）。

## 2026-09-26：finalizePrinting default 臂递归（BLOCK-FINALIZE-DEFAULT-RECURSE-0001）

`finalize_printing_block` 的 Switch 分发补齐 oracle 形状的 default 臂下推
（block.cc:3556-3559）：`default_gototype == 0` 时把 `default_case` 槽的
结构化 default 体加入先序递归子列表——与 checker
`debug_assert_component_tree_unique` 的 oracle 走形臂逐字一致，与 oracle 的
朴素 list 递归（cc:3559 `BlockGraph::finalizePrinting(data)` 先于 label
pass 遍历全部 identifyInternal 消费成员，含 ruleSwitch cc:1714-1720 push 进
cs 的 default 臂体）对齐；`default_gototype != 0` 的 default 体留周围图不
递归（镜像 cc:3548-3553 goto 臂语义）。

- 缺陷表现：default 臂内嵌 WhileDo 的 for 提取 finalize
  （BlockWhileDo::finalizePrinting cc:3403-3424 的 testTerminal→
  testIterateForm→opMarkNonPrinting）不被执行 → iterate 语句保持可打印
  （for→while 降级）。潜伏缺陷：canon/mirror 语料无 default-内嵌循环样本
  （golden `default:` 臂均为直线体），F8VISITED 车道 checker（oracle 走形
  含 default）与递归分发（漏 default）不一致自证。
- 顺带同 commit 更新三处描述旧走形的注释（finalize_printing_block 文档/
  finalize_printing_graph 守卫论证/final_transform_block 的 twin 论证）。
- B2 双侧 fixture：`tests/oracle/blockstruct_switch_default_whiledo_1204`
  （runner `tools/run_blockstruct_switch_default_whiledo_oracle.sh`）——
  canonical for 形态 switch-default-WhileDo 经生产工厂安装
  （newBlockWhileDo→newBlockSwitch/try_rule_switch；单次 collapse 先消费裸
  default 目标，语料无样本，见 metadata normalizations），锁定 oracle 同
  输入/同输出 MATCH：决定性观察行 `op blk2#0 INT_ADD notprinted=1`
  （cc:3422）；A/B 验证：修复摘除→该行 0（MISMATCH），恢复→MATCH。
  oracle 自身 findInitializer 门（cc:3336 初始化块须只流入循环）拒绝本
  形态（初始化 COPY 在 2 出边的 switch 头内）→ initialize=- 双侧一致，
  iterate 侧为决定性观察。
- 单元锁：block.rs `finalize_visited_tests::
  finalize_recurses_into_structured_default_whiledo_for_extraction`
  （同 CFG 全管线，断言 INT_ADD 置 NONPRINTING + iterate_op/loop_def 存活）。

## 2026-09-26：findIrreducible 区间快照同锁递归读加固（BLOCK-RWLOCK-RECURSIVE-READ-0001）

`find_irreducible` 的区间测试快照（block.cc:1174 形：读 x->visitcount、
x->numdesc、y'->visitcount）原实现同时持 x 与 y' 两个读守卫；y'==x（循环头
自身入 reachunder 成员的边——y==x 且 copymap 指向自身，cc:1027/1122）时即
对同一 RwLock 同线程二次 read()。std 文档标注该形态 "might panic"（Linux
futex 实现恰好读者可重入故现网安全，属标准库实现依赖）；oracle C++ 裸指针
无锁，同对象二次读取天然合法。加固=ptr_eq 预判分支（`// RUGRA-GLUE:` 注释
说明锁形态对应关系）：y'==x 臂从单一 x 守卫取双值（对象同一性 ⇒ 值恒等），
y'!=x 臂保持原双守卫快照。零行为变化机器证明：canon curl/httpd 字节恒等 +
镜面四面零漂移 + bank 391/391 + 单元锁 `findirreducible_lock_tests`（3 块
最小可归约环 b0→b1→b2→b1 亲证 y'==x 点：A 侧探针证递归路径真实命中且首守卫
持有中二次取锁、B 侧证单锁臂；坍缩/copymap/边分类 oracle 语义断言 +
structure_loops 驱动端到端）。

## 2026-09-27 — F8FOR-REJECT-RESIDUAL-0001 两门拒例钉因 + 门链回归锁（Lane F8FOR 续）

F8FOR 残量票（oracle 转 for 而 Rugra 拒的两门）逐函数探针钉因结论（探针
eprintln 逐门打点，`--one`/`RUGRA_GEN_ONLY` 逐函数跑 sq 21 + sqlite 44 个
census 两族函数，探针代码提交前全数移除）：

- **门 1（findLoopVariable 的 isMoveable 分量）——根因不在 block.rs**：
  探针实测拒例（LzmaEnc_Construct / BitvecSet / BitvecClear / EndTable /
  NestedParse / file2string 等）全部命中 `pit_nomoveable`——迭代 op（如
  `V = V - LIT` INT_SUB）到分支剥离后 lastOp（后期创建、块内位置在 BRANCH
  之前的 COPY）之间，`is_moveable` 旧实现按 alivelist（markAlive 追加序）
  游走，把块末 BRANCH 虚增为交叉（alivelist 序 [SUB,ZEXT,BRANCH,COPY] vs
  块序 [SUB,ZEXT,COPY,BRANCH]），special-op default 臂误拒。oracle 走
  basiciter 块序（op.cc:223-269）只跨 ZEXT/STORE/COPY → 收。该根因即已登记
  潜在票 OP-ISMOVEABLE-WALKORDER-0001，**已由 MB24 车道在 master 落地**
  （61051133/9c6ca5dc，与本道独立探针结论一致）；本道基线随之推进到
  e5fb3e54，重复实现已弃（铁律 5：不重复落地已验证工作）。
- **门 2（testIterateForm）——判决 oracle 一致，非缺陷**：残存 tif 拒例
  （LzmaEnc_CodeOneBlock、sqlite 巨物族 VdbeExec/Select/mprintf 等）经
  golden 对照全部为 oracle 同拒（golden 同为 while 形）；探针 high Arc
  不匹配是这些循环迭代语句输入确实不达 loopDef 输出 high（oracle 同判）。
- **flv_dfs 深度耗尽分量——上游 IR 表示分歧，超出 block.rs 写域**：
  sqlite 仅剩 2 函数缺 for（sqlite3ExprAffinity / sqlite3_str_vappendf，
  211→209）：条件链里 Rugra IR 多一枚 CAST（EQUAL→AND→SEXT→**CAST**→LOAD，
  吃掉 path[4] 一级深度）或指针算术用 INT_ADD+CAST 而非 PTRADD（链深 5>4），
  oracle IR 无此 CAST 故深度 4 内可达 MULTIEQUAL。根因在 cast 插入/op 选择
  上游域（CAST-SHAPE 族邻域，GEN4-SQ-CASTFUSE-DEPTH-0001 域），已归因登记。
- **init 提取分歧类（sq 面 +10 行/4 函数）**：LzmaEnc_Construct /
  LzmaEncProps_GetDictSize / LzmaEnc_FastPosInit / _GLOBAL__sub_I——Rugra
  提取 initializer 而 golden 留空 `for(;`（探针 `init_accepted
  init=INT_ZEXT span_to=COPY`）。判决链（findInitializer→isMoveable→
  testTerminal(1-slot)）对该 IR 是 oracle 忠实的；分歧根因是 init 块内
  op 顺序/块结构与 oracle 不同（mask 语句与 ZEXT 根的相对位置），上游
  IR 布局域。与 MB24 ISMOVEABLE 车道 parseconfig +2 同类（其 Differential
  块已归因 upstream IR-layout divergence）。
- **canon ap_getparents 残差**：现差 19 行归 CANON-LOOPFORM-GETPARENTS-
  INVERT-0001 机制域（overflow 形 vs 条件反转，非 for 门）。

**门链回归锁**（block.rs `while_do_gate_tests`，2 测，cfg(test) 零生产行为）：

- `gate_chain_extracts_iterate_and_marks_non_printing`——最小 whiledo IR
  （head=[MULTIEQUAL,INT_NOTEQUAL,CBRANCH]，tail=[INT_SUB 迭代,ZEXT,
  COPY,BRANCH]，COPY 为后期创建插 BRANCH 前=块序/alivelist 分歧形状；
  head 双入边 entry/tail，tail 单出边 reverse_index=1）端到端钉
  finalTransform→finalizePrinting 全链：findLoopVariable 过 isMoveable
  门收迭代 op、cc:3381-3384 迁移至终端语句位、常量 entry 输入使
  findInitializer 落空（空 init `for(;` 形）、testTerminal/testIterateForm
  重推导、cc:3421 opMarkNonPrinting。fixture 置 `HIGHLEVEL_ON`（镜像
  finalizePrinting 时点的管线状态——testIterateForm 读合并后 high 同一性）。
- `iterate_form_mismatch_rejects_without_marking_but_keeps_move`——
  迭代 op 输入接外部 high 的 W 时 testIterateForm 拒（cc:3413 置空）且
  语句**不**标 NONPRINTING（while 形回退），但 cc:3410 testTerminal 的
  已提交移动保留（oracle "committed move" 副作用的忠实钉）。

行为证据：镜面 sq for 循环 21/21 与 golden 逐函数一致（FORWHILE 族清零）、
sqlite 209/211（残 2=上游 CAST 链）、canon 双语料与 master 字节恒等
（cfg(test) 零生产行为）、bank 391/391、cargo test --lib 1935P/0F（亲父
1933+2 新）。逐函数归因与门探针全表见 TODO_BOARD F8FOR-REJECT-RESIDUAL-0001
行与 LANE_F8FOR_2026-09-27.md 终报。

## 2026-09-28：for_loop_final_transform 槽位注记更正（INITEXTRACT-PIPE-SLOT-0001，Lane INITEXTRACT）

`for_loop_final_transform`（本文件，blockaction.cc:2110 图入口）的调度点
自 2026-09-26 起错挂在 blockaction.rs ActionFinalStructure（:5736），其
头注「lane-frozen write-set, currently a no-op」已过时——本日恢复 oracle
槽位：**coreaction.rs `ActionStructureTransform::apply`（:5715）**，在
merge 组（:5717-:5729）与 ActionSetCasts（:5735）之前。判决门
`isMoveable`（block.cc:3197，经 `while_do_find_loop_variable`）必须读
原始 iterate op：setcasts 会把 LOAD 型 iterate 包装成 CAST 使门翻转
（ap_fini_vhost_config fixture，oracle drill 2026-09-28）。2026-09-26 的
「放置无行为差」登记（上方放置偏差段）被该 fixture 证伪并作废。本文件
零行为改动（仅头注更正）；`while_do_final_transform` /
`while_do_find_loop_variable` / `while_do_finalize_printing` 函数体未动。

## 2026-09-29 追加（L1SURGERY-GATHER-DEFPOS-0001 — gather 期 default 构造序位）

**问题**：`next_flow_after_successors` Switch 臂在 `default_label` 未置位阶段
（ActionReturnSplit 的 gatherReturnGotos 链走,blockaction.cc:2210-2232 — 先于
ActionFinalStructure 的 finalizePrinting）把 default 追加在合并序**末尾**
（`_ => sw.cases.len()`）。oracle 在该阶段遍历的是**构造序** caseblocks
（grabCaseBasic 的 cs 出边扫描序,block.cc:3529-3534;default 为普通成员,
cc:3515 isdefault;label 稳定排序要到 finalizePrinting cc:3591 才发生）。
后果:最后一个真实 case 的 nextFlowAfter 后继错位成 default 前叶;当该 case 是
以 default 块为 goto 目标的 BlockGoto 时,gotoPrints（block.cc:2881-2890,
gotobl != nextbl）翻 false,gatherReturnGotos 拒选该边 → nodeSplit 少拆 →
结构树形态级联（SetCoderProperties 0x2891e:oracle 17 边拆/Rugra 16;if-goto/
dup_ 标签/default 位/嵌套标签位全系）。

**修复**（src/block.rs）:

1. **`switch_default_construct_pos(sw)`（pub,模块级,新增）**:default 在 oracle
   构造序 caseblocks 中的 rank = 基本图出边索引（`CaseOrder::outindex`,
   cc:3509 `getInRevIndex`）先于 default 出边的 **regular（gototype==0）** case
   数——multigoto 臂追加的 case（cc:3548-3553,GOTO_GOTO）在 oracle 中本来就
   整体后置,不计数。坐标残缺（outindex<0 / 平行数组失配）时回退原 append-last
   （oracle 该形态会 LowlevelError,cc:3507-3508,Rugra 保守降级不变原行为）。
2. **`next_flow_after_successors` Switch 臂 def_pos 分派相位化**:
   `default_label` 已置（finalizePrinting 后,compute_goto_prints/printc 消费
   者）→ label rank（不变）;未置（gather 期）→ 构造序 rank（新）。

**验证**：sasquatch SetCoderProperties（idx 470）:双侧 GATHER 探针对拍 —
oracle（gold_gather_trace,RUGRA_GATHER_TRACE）edge 7 链 `t_goto prints=1
parent_null=0`（后继链终于 InfLoop 头 0x288db）;Rugra 修复前
`target=0x2890a succ=0x2890a`（后继=自身目标 → prints=false 拒选）,修复后
`succ=0x289f0`（≠ 目标 → 选入）→ nodeSplit 17 份对齐,函数体规范化 diff 归零
（typedef 前导为 --one harness 差,非代码生成差）。default 在输出中回到
case 0x442 与 0x450 之间的 oracle 位。

### 2026-09-29 补（L1SURGERY-GATHER-DEFPOS-0001 — 单测固化）

`switch_default_construct_pos_tests`（src/block.rs,4 测）:
①`construction_rank_interleaves_default_at_outedge_position` — SetCoderProperties
形（出边序 [0x440,0x441,0x442,default@3,0x450,0x451]）端到端:构造 rank=3;
走查里末位真实 case（0x451 的 BlockGoto）后继=父臂 succ（None）而非 default
前叶,default 前的 0x442（非 goto）→ null（cc:3647 非 goto 臂先于下一位查找）。
②`multigoto_appended_cases_do_not_advance_rank` — multigoto 追加条目
（gototype!=0）不推进 default 构造 rank（oracle cc:3548-3553 整体后置）。
③`incomplete_coordinates_fall_back_to_append_last` — 无 default_order/
坐标 -1 三形回退 append-last（oracle 该形态 LowlevelError cc:3507-3508,
Rugra 保守降级不变原行为）。
④`label_rank_arm_unchanged_post_finalize` — default_label 置位后 label-rank
臂接管（print 期相位,cc:3591 排序后语义）,构造序臂不介入。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。

## ARENAFLIP-e（2026-09-30）规则派发快照化随迁

`try_rule_switch` 签名增 `block: &Arc<...>` 参数（blockaction 派发快照化的
测试调用点随迁: block.rs 的 switch 规则单测改为先取 `fd.sblocks.get_block`
再传入,行为不变;tests 2018P 保持）。

## ARENAFLIP-f（2026-09-30）BANKSTATS 观测探针（默认关）

`RUGRA_BANKSTATS=1` 时 `src/block.rs::bank_stats` 累计 per-read bank 解析面
事件计数（read_index/read_btype/read_arc/view_holds/view_index/view_btype/
view_arc/id_lookups/publishes/shadow_writes），`bank_stats::report()` 在
gen_decompile 尾部（all 模式与 --one 模式）打一行 stderr。纯观测（默认零成
本一次分支）；(f) 段交接面①的量化底座（(e)-tip 树替代语料实测 ~393M 次锁
获取，见车道终报）。
