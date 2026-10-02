# ADDRESS_SPACE_PHASES — Address 空间维奠基分阶段设计（ADDRESS-0001，权威稿）

> 状态：阶段一已实现（WIP 在树，待 root 集成）；阶段二/三为设计，待 root 评审排程后作为后续 wave 输入。
> （续作 agent 的 PHASE_PLAN.md 已并入附录，原文件移除）
> Oracle：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{address.hh,address.cc}` @
> `e40ed13014025f82488b1f8f7bca566894ac376b`（Ghidra_12.0.4_build）。
> 消费面数据：grep 实测 2026-08-17，基线 HEAD `197b34c`。
> 关联 TODO：`ADDRESS-0001`（本设计）、`SPACE-0001`（registry 地基，已 DONE）、
> `SLEIGH-0002C`（跨空间 context）、`SPACE-IOP-PRINTRAW-0001`（阶段二解锁物）、
> `RANGEADDR/BLOCK/VARNODE/SEQNUM/MEMSTATE-0001`（阶段三下游）。

---

## 0. 问题陈述

Ghidra 的 `Address`（address.hh:59）= `AddrSpace *base` + `uintb offset`。Rudra 的 legacy
`Address(u64)`（阶段一前）只有 offset：**所有地址被隐式压进单一匿名空间**。后果：

1. **跨空间地址不可区分**——`ram:0x1000` / `register:0x1000` / `const:0x1000` 相等、
   排序上重合、哈希碰撞。
2. **比较器缺 Ghidra 的空间半部**——operator<（address.hh:375-393）的 base 腰比较
   （null → 最小；`~0` → 最大；否则 index）不存在；overlap/containedBy 的
   `base != op.base → -1` 守卫不存在；operator+/- 的 `wrapOffset`（4 字节空间在
   `0xffffffff` 回卷）不存在。
3. **下游被锁死**——IopSpace::printRaw（op.cc:46 的 `SeqNum.addr` 下钻 + 分支形式读
   父块目标块起始地址）需要空间 shortcut/宽度；SLEIGH-0002C 的 context
   `partmap<Address,·>`（globalcontext.hh:283-284）按 Address 全序做跨空间 partition，
   两类消费者都无法在无空间维的 Address 上实现。

SPACE-0001 已交付 1:1 的 `SpaceAddress`（空间句柄版，fixture
`address_space_handle_1204` 双侧 MATCH），但它**未接线**：主管线 39+ 模块仍以 legacy
`Address` 为键。本设计给出从"并存"到"合一"的分阶段迁移路径。

---

## 1. 消费面清单（grep 实测 2026-08-17，HEAD 197b34c）

### 1.1 容器键——序/哈希直接依赖 `Address` 的比较语义

| 消费点 | Ghidra 对应物 | 迁移敏感度 |
|---|---|---|
| `SeqNum.addr`（address.rs:362）→ `PcodeOp.start`（op.rs:299）→ PcodeOpBank 按 SeqNm 序（op.hh:280 `map<SeqNum,PcodeOp*>`） | SeqNum operator< = pc operator< 再 uniq（address.hh:154） | **阶段二主对象** |
| `BlockBasic.start_addr`（block.rs:970；flow.rs:1918 铸 `Address::new(start)`） | block.hh:478 `getStart` | **阶段二主对象** |
| `Varnode.loc`（varnode.rs:135）→ VarnodeBank `loc_tree` BTreeSet 键 | varnode.hh `loc` | 阶段三（VARNODE-0001） |
| override_rs 四张 `BTreeMap<Address,·>`（forcegoto/indirectover/protoover/flowover，override_rs.rs:72-83） | override.hh `map<Address,·>` | 阶段三 |
| lib.rs `pcode_cache`/`analysis_cache` `HashMap<Address,·>`（lib.rs:169/172） | （Rudra 自有缓存） | 阶段三（无 oracle 面） |
| jumptable.rs `adset: BTreeSet<Address>`（:3137） | jumptable.hh `adset` | 阶段三 |
| rangeutil.rs `HashMap<SeqNum, ValueSetRead>`（:2206） | rangutil.hh `map<SeqNum,·>` | 随 SeqNum 迁移 |
| binary/mod.rs `functions: HashMap<Address,String>`（:50） | （加载器面） | 阶段三 |
| context.rs `database/trackbase: Vec<(Address,·)>`（:211/215） | **globalcontext.hh:283-284 `partmap<Address,FreeArray>/partmap<Address,TrackedSet>`** | **阶段三 SLEIGH-0002C 解锁物** |

### 1.2 记录字段——存储 `Address` 但不作为键

- comment.rs `funcaddr`/`addr`（:39/41）+ `comment_sort_key=(u64,u64,i32)`（:244，
  comment.cc:30 CommentOrder 对应物）——排序键已退化为裸 offset 元组。
- flow.rs `baddr/eaddr/minaddr/maxaddr`（:234-238）+ `addrlist` LIFO 栈（:254）+
  `unprocessed`（:222）。
- funcdata.rs `baseaddr`（:386）；fspec.rs `op_addr`（:1685）/`addr`（:3030/:4219）；
  jumptable.rs `norm_address`（:3141）/`opaddress`（:3550）；
- heritage.rs LocationMap 键 `(AddressSpace, Address)`（:142/:181/:194）——**空间维已在键
  里单独携带**，Address 本体仍是裸 offset。
- paramid/double_precis/merge/condexe 等 transient 形参（不落容器）。

### 1.3 比较/哨兵依赖"无空间假设"的点（迁移时的破坏面）

| 点 | 现状假设 | 阶段二/三正确形态 |
|---|---|---|
| heritage.rs:142/181/194 `range((space, Address::new(0))..=(space, Address::new(u64::MAX)))` | 同一元组键内 None↔None 纯 offset 序，u64::MAX 即上界 | None 排在所有 Some 之前 → **上界失效**；须改为 tagged 上界或 `(space, +∞)` 键设计 |
| funcdata.rs:8627 `symbol_table.get(&addr).map(..).unwrap_or(u64::MAX)` | None 域内 u64::MAX 为 miss 哨兵 | 混域后哨兵小于任何 tagged → 误命中；须改 Option/Ordering 处理 |
| coreaction.rs:1639 `min_addr = u64::MAX` / flow.rs:365 `minaddr == u64::MAX` | 裸 u64 最小值扫描 | 换 `Option<Address>` 或 tagged 哨兵 |
| funcdata.rs:1473 `vbank.create(1, Address::new(u64::MAX))` 哨兵 varnode loc | None loc 不与真实 loc 相邻 | tagged 域内 u64::MAX(None) 排最前 → loc_tree 插入位置改变；须独立哨兵机制 |
| comment.rs `comment_sort_key` u64 元组 | funcaddr/addr 同域 None | 排序键须扩为含空间维（Ghidra CommentOrder 按 Address 全序） |
| SeqNum `encode/decode` "addr:time" 冒号串（address.rs:423/435） | Display 是 `0x{:x}` 无冒号 | tagged Display 走 printRaw（`ram:00100000` 含冒号）→ **串格式破坏**；encode/decode 须限定 debug 域或换形式（Ghidra 本体是 XML encodeAttributes，address.cc:60） |

### 1.4 铸造点分布（`Address::new(` 计数）

ruleaction 387 / coreaction 110 / database 91 / funcdata 85 / fspec 56 / heritage 48 /
subflow 36 / jumptable 36 / comment 29 / dynamic 24 / address 68 / flow 20 / varnode 20 /
context 11 / block 2 / op 0（op.rs 只消费 SeqNum）。
`SeqNum::new(` 分布：ruleaction 201 / coreaction 18 / jumptable 10 / funcdata 9 /
varnode 9 / condexe 3 / flow 3 / constseq 5 / 其余 ≤2。

> 关键结构事实：**绝大多数 `SeqNum::new`/`Address` 传递是拷贝而非出生**。出生点只有
> 三类——flow.rs/disasm 指令地址提升、funcdata.rs 函数入口/常量铸造、各 Action 的
> 合成 varnode loc。阶段二把出生点接上 `with_space` 后，拷贝链自动携带 tag；只需
> grep 审计确认没有中途 `Address::new(x)` 重铸（重铸=丢 tag=混铸）。

---

## 2. 阶段一（已实现）：兼容空间字段 + 核心比较链

**write-set**：`src/address.rs`、`docs/api/address.md`、fixture
`tests/oracle/address_space_phase1_1204.{cc,rs,metadata.json}` +
`tools/run_address_space_phase1_oracle.sh`。

**机制**：legacy `Address` 增 `space: Option<SpaceTag>`（`SpaceTag(NonZeroU32)` =
address.rs 私有 thread-local intern 表的 Copy 槽位，表持强句柄防 `identity_ptr`
复用）。保持 `Copy` → 55 个消费文件零改动。所有现存铸造点产出 `None` =
Ghidra null-base（invalid）形态，None↔None 比较保持 offset-only = 现存行为逐位不变。

**比较链**（逐条对照 oracle）：

| Rust | Ghidra | 语义 |
|---|---|---|
| `Eq = (tag, offset)` | address.hh:356 `(base==op2.base)&&(offset==op2.offset)` | tag 身份=指针身份；None 只等 None |
| `Ord`: None<一切 Some → space index → offset →（仅跨 registry 同 index 的）tag tiebreak | address.hh:375-393 阶梯：base≠→null 最小/`~0` 最大/else index；同 base→offset | None≡null-base（:377/:383）；index 序（:389）；offset 序（:391）；tiebreak 是 Rust 全序要求，Ghidra 单 registry 内 index↔指针双射不可达 |
| `Hash` 随 Eq | （Ghidra 无 Address 哈希；Rust 容器键要求） | tag 再 offset |
| `offset()/next()/prev()` Some 时经 `wrap_offset` | address.hh:423/433 `base->wrapOffset(offset±off)` | None 保 legacy 裸回卷（Ghidra null-base 为 UB） |
| `overlap` Some×Some：同空间守卫+constant 排除+wrap 距离+size 比较 | address.cc:153-165 全四行 | None 参与时保 legacy offset-only（Ghidra null 解引用） |
| `Display` tagged → `print_raw` | address.cc:47→address.hh:305→space.cc:206 | None 保 legacy `0x{:x}` 拼写（**偏差登记**：Ghidra null-base 打 `invalid_addr`；阶段三消亡） |
| 桥 `from/to_space_address` | —— | Null↔None；`m_maximal` 过桥显式 panic（legacy 无极值哨兵，静默映射会把它从"排最后"翻成"排最前"） |

**显式登记的过渡偏差（Ghidra 无对应物）**：
- D1 None 的 Display 拼写（上表）；
- D2 None 的算术/overlap 无 oracle（Ghidra 在 null-base 上是空指针解引用 = 未定义；
  Rust 保留阶段零行为，靠 Rudra 侧回归 + E2E 证明不变）；
- D3 `m_maximal` 不可表达（桥上 panic）；
- D4 SpaceTag serde 数值是 thread-local 表槽位——序列化态不可跨线程/跨会话复活
  （现状无持久化消费者，grep 证实 comment/range/seqnum encode 均为手写串）。

**验收**（已达成）：`cargo test --lib` 1426 pass / 5 fail = 预存基线
（comment/dynamic/funcdata×2/ruleaction）零新增；E2E curl skeleton 2926 / defects=0 /
numbering=0 / Matched=123 双零；fixture `address_space_phase1_1204` 双侧逐字节 MATCH
（见 §5）；`check_ghidra_annotations --all` / `check_ghidra_refs --all --strict` 过。

---

## 3. 阶段二：`SeqNum.addr` / `BlockBasic.start_addr` 句柄化

**目标**：指令地址域（P-code SeqNum + 基本块起始）成为第一个全域携带空间的比较域，
解锁 `SPACE-IOP-PRINTRAW-0001`（IopSpace::printRaw 两种终态渲染，op.cc:41-59：
非分支形式需要 `SeqNum.addr` 的 `pc.printRaw + ':' + uniq`；分支形式需要父块
`sizeOut()==2 ? (isFallthruTrue?getOut(0):getOut(1)) : getOut(0)` 目标块起始地址的
`code_` + shortcut + printRaw——两者都需要地址知道自己的空间/宽度/shortcut）。

**铁则：按域整体迁移，禁逐铸造点混铸。** None≠Some 同 offset 不相等；一个域内
只要有一处 `Address::new` 重铸混入，HashMap/BTreeMap 查找即 miss、序即断裂
（§1.3 的哨兵陷阱全部由此触发）。

**迁移面（write-set 建议）**：
1. **出生点接线**：
   - flow.rs 指令地址提升（`Address::new(start)` 于 :1918 等）→ 从 disasm 的
     `SpaceAddress`（loadimage 空间）经 `from_space_address`/`with_space` 铸造；
   - funcdata.rs 函数 `baseaddr`/入口铸造（:386 一族）→ tagged；
   - 常量/unique varnode loc 铸造（varnode.rs 20 处中的出生子集）→ const/unique 空间。
2. **拷贝链审计**：ruleaction 201 / coreaction 18 / varnode 9 处 `SeqNum::new` 中
   凡显式传 `Address::new(x)` 的，改从源 op 的 `start.addr` 拷贝或 `with_space`。
   完成判据：`grep -rn "SeqNum::new(Address::new\|SeqNum::new(&Address::new"
   src/{ruleaction,coreaction,funcdata,flow,varnode,jumptable,condexe,constseq}.rs`
   在指令地址域内为 0。
3. **哨兵修复**（§1.3 行 3-5 中属于本域者）：min/max 扫描改 `Option<Address>`；
   `Address::new(u64::MAX)` 哨兵 varnode loc 与 tagged loc 的 loc_tree 插入位次复核。
4. **SeqNum encode/decode 串**：冒号歧义（§1.3 行 6）——限制为 debug-only 或改
   `space:offset:time` 三段式（Ghidra 本体 XML，串形式本就是 adapter）。

**预期顺序不变性**（为什么 E2E 应零回归）：单函数 P-code 的 SeqNum.pc 全部来自
同一指令流（同一 ram 空间），Ghidra 序 = (index 相同 → offset, uniq) = 现 None 域
(offset, time) 序。BlockBasic.start_addr 同理（同 ram）。**例外面**：注入
（p-code injection 在 Ghidra 用独立地址）、iop/constant 空间 varnode——这些是本阶段
要观察的新行为，不是回归。

**风险**：
- R2-1 混铸（上文铁则）；用出生点白名单 + grep 门禁 + PcodeOpBank 全序投影 fixture
  三重防。
- R2-2 `PcodeOpBank` 迭代序变化外溢到输出（printC 遍历依赖 op 序）：E2E 差分门禁
  （机制 B）双零为准；任何 skeleton diff 须在 `## Differential` 解释。
- R2-3 thread-local tag 的线程约束：worker 每线程一个 Architecture（现有纪律），
  SeqNum 不跨线程传递（grep 确认无 send 通道）。

**验收**：
- `SPACE-IOP-PRINTRAW-0001` fixture 扩展双侧逐字节 MATCH（两终态渲染）；
- 新增 `seqnum_block_space_1204` fixture：PcodeOpBank 全序（含跨空间对：注入/iop）、
  BlockBasic.start_addr 排序、SeqNum operator< 阶梯；
- E2E curl/httpd 双零 + skeleton 不降；`cargo test --lib` 零新增失败；
- 机制 C 独立复核（op.rs/blockaction 白名单面）。

---

## 4. 阶段三：消费方全域迁移 + SLEIGH-0002C 跨空间 partition

**目标**：剩余比较域全部句柄化，`None` 分支与 intern 表删除，legacy `Address` 与
`SpaceAddress` 合一（终态只有一种 Address = Ghidra 形态）。

**分 wave（每 wave 一个比较域，互不重叠）**：
1. **context.rs**：`database/trackbase` `Vec<(Address,·)>` → Ghidra
   `partmap<Address,FreeArray/TrackedSet>`（globalcontext.hh:283-284）语义：按
   Address 全序（空间 index 优先）的 partition map，跨空间 blob 有序交错——这是
   `SLEIGH-0002C` 的直接解锁物（pspec context_data 的 per-space range 摄取与查询）。
   `Vec` 线性扫描版在混域下会静默串空间，必须换 partmap 或 (space, partmap) 双层。
2. **varnode 域**（VARNODE-0001）：`Varnode.loc` tagged 化，VarnodeBank `loc_tree`
   键、find/read-only 查询、constant/unique/iop 空间的 canonical 化。heritage
   LocationMap 的 `(AddressSpace, Address)` 复合键此时可简化为单 Address 键
   （空间已在地址里），`range(..=Address::new(u64::MAX))` 上界陷阱随之消灭
   （§1.3 行 1）。
3. **comment/override/jumptable/flow/binary/lib 缓存域**：`comment_sort_key` 扩空间维
   （对齐 CommentOrder 的 Address 全序）；override 四表、jumptable `adset`、flow
   `addrlist/minaddr/maxaddr`、lib.rs 两缓存跟随。database 91 处铸造随
   DB-LOCALSCOPE-MAP-0001 的 rangemap 一起迁。
4. **终态合一**：删 `Option<SpaceTag>` 的 None 分支、删 intern 表（或退化为
   `Rc` 直存——不再需要 Copy 时）；`Address::new(u64)` 删除或私有化；
   `SpaceAddress`/桥接 API 折叠；`m_maximal` 以独立 sentinel 表达
   （SpaceBase::Maximal 形态上移）；RANGEADDR/BLOCK/VARNODE/MEMSTATE 按各自 TODO
   依赖展开。

**风险**：
- R3-1 每 wave 的混铸面与哨兵面比阶段二大（§1.4 计数）；沿用水位：先 grep 出生点
  清单写进 wave TODO，再动代码。
- R3-2 partmap 的 `getLastAddrOpen` 类边界（address.cc:265 最终空间 `~0` 哨兵 quirk，
  已在 address_space_handle_1204 case6 观察）须随 context wave 复测。
- R3-3 serde/调试格式（D4）在删除 None 后自然消解；合一前禁止新增持久化消费者。
- R3-4 E2E 门禁每 wave 必跑；任何 defects>0 逐条绑定 TODO ID（铁律 3）。

**验收**（终态）：函数账本 ADDRESS 族无 MISSING/MISMATCH/NO_ORACLE/UNTESTED；
`address_space_handle_1204` 与合并后类型继续 MATCH；全仓 grep 无
`Address::new(` 生产铸造点；`SPACE-IOP-PRINTRAW-0001`/`SLEIGH-0002C` 关闭。

---

## 5. 阶段一 fixture：`address_space_phase1_1204`（复核期 /tmp 构建，未入库登记——write-set 不含此文件；后续需要时再正式登记）

双侧（锁定 oracle C++ vs Rudra）逐字节对比，四 case：

| case | 覆盖 | 状态 |
|---|---|---|
| `none_compat_fallback` | null-base↔null-base（C++ 经 private-write 构造 null-base+任意 offset，对应 Rust `Address::new`）的 ==/!=/</<= 与排序容器序；null-base vs 真空间：eq=0、null 恒小（address.hh:356/377/383）；`isInvalid` 投影 | MATCH |
| `space_ordering` | tagged 跨空间排序容器（const/OTHER/unique/ram/register + null 混入）：(None 最先 → index → offset) 全序走查 + 显式跨空间 < 断言 | MATCH |
| `tag_identity` | 同句柄重复构造相等（intern 幂等 = C++ 同 `AddrSpace*` 指针身份）；HashSet 去重（Hash↔Eq 一致）；同 offset 异空间不等/不 overlap | MATCH |
| `wrap_overlap_tagged` | tagged operator+/- 经 wrapOffset（4 字节空间回卷）；overlap 同空间 wrap 距离/负 skip/constant -1/跨空间 -1（address.cc:153-165） | MATCH |

明确不进 oracle 的面（Rudra 侧回归/E2E 证明）：None 算术与 overlap（Ghidra null 解引用
= D2）、None Display 拼写（D1）、`m_maximal` 过桥 panic（D3）。

---

## 6. 决策记录

- **为什么 Option<tag> 而非直存 `AddrSpace`**：保 `Copy` → 阶段零消费文件零改动；
  `AddrSpace` 是 `Rc<RefCell>` 单线程句柄，直存破坏 Copy 且引入借用检查面。代价 =
  intern 表 + D4（已登记）。
- **为什么 None 排最前而不是最后**：Ghidra null-base 在 operator< 里就是"最小"
  （address.hh:377），且 `Address::new(0)` ≡ `m_minimal`。选"最后"会在阶段二把
  空/哨兵地址顶到排序末尾，与 Ghidra 全序相反。
- **为什么 tiebreak 用 tag 而非 offset**：Rust `Ord` 必须与 `Eq` 一致（同 tag 同
  offset 才相等）；跨 registry 同 index 只在测试态可达，tag tiebreak 是唯一能同时
  保一致性的全序扩展。
- **为什么不先迁 SpaceAddress 接线而先做兼容字段**：SPACE-0001 的消费方迁移顺序
  结论（TODO 行 200）——先给 legacy 类型补空间维，让"域迁移"变成逐域开关而不是
  一次性 55 文件重写；每个 wave 可独立验证、独立回滚。


---

# 附录：续作 agent 的阶段二纪律与风险登记（自 PHASE_PLAN.md 合并）

### 阶段二（root 排程；本 agent 只读登记）——按比较域整体迁移

**纪律（最重要）**：禁止逐铸造点混铸。`None ≠ Some(ram)`（同 offset 也不相等，
Ghidra `base!=base` ⇒ false）；一个比较域内若 None/Some 混产，HashMap/BTreeMap 查找 miss。
每个域迁移时，该域内**全部**铸造点同一 wave 补空间，E2E 差分门禁验证。

| 域 | 文件 | 解锁 |
|---|---|---|
| ① SeqNum + BlockBasic 句柄 | funcdata.rs（SeqNum::new 铸造，13 处）/ flow.rs:1918 / block.rs | `SPACE-IOP-PRINTRAW-0001` 两终态渲染（非分支 `pc.printRaw:uniq`；分支 `code_`+shortcut+块起始 printRaw）|
| ② context partition/trackbase | context.rs | `SLEIGH-0002C` 跨空间交错 |
| ③ VarnodeBank loc + VarnodeData 空间统一 | varnode.rs / funcdata.rs | `VARNODE-0001` |
| ④ comment db / override maps / jumptable / flow addrlist | comment.rs / override_rs.rs / jumptable.rs / flow.rs | 各自键语义 |
| ⑤ database/符号域 | database.rs / rangemap.rs | `DB-LOCALSCOPE-MAP-0001`（另依赖 RANGEADDR） |

接线点示例（阶段二 wave ①）：`op.rs` `IopSpace::print_raw` stub 已就位并文档化了两形式
（op.cc:41-59 逐行注释）；解除后按 funcdata.rs `get_op_from_const` 的 Arc 指针编码回收模式
下钻。**本轮不动 op.rs**——无 Some-space SeqNum 时接通只会渲染 legacy hex（非 Ghidra
printRaw 形态），是伪收益；铸造点在 funcdata.rs（禁域），故只读登记。



## 3. 风险登记

| ID | 风险 | 处置 |
|---|---|---|
| R1 | None-vs-Some 语义 Ghidra 无对应物（Ghidra 无无空间地址） | 显式过渡 adapter（RUDRA-GLUE 注释）；排序 ≡ null-base 最前、Eq 不等；双侧 fixture 锚定可对拍部分；阶段三消亡 |
| R2 | serde 新字段改变序列格式 | 仅内存缓存使用；无持久化 golden 依赖 Address 序列 |
| R3 | 跨 registry 同 index 异 tag（测试态） | Ord tag tiebreak 保 Ord/Eq 契约 |
| R4 | HashMap 迭代序变化 | Rust HashMap 本就 RandomState；BTreeMap 序由 Ord 决定，None↔None 序不变 |
| R5 | `with_space` 非 const | `new` 保持 const fn；无现存调用点受影响 |
| R6 | tag 跨线程流动 | thread-local 表 + resolve panic（响亮失败）；阶段二域迁移按 one-Architecture-per-worker 线律 |
| R7 | 混铸（部分铸造点 Some、部分 None） | 阶段二纪律：按比较域整体迁移，E2E 门禁把关 |


