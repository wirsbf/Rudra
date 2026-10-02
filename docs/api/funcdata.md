# `funcdata.rs` API Reference

## 2026-10-03：SETTLE2 — `replace_lessequal` 补 `copySymbol` 类型传承（Lane SETTLE2 / MISC3-SETTLE-VARCHURN-0001）

`replace_lessequal`（`Funcdata::replaceLessequal`，funcdata_op.cc:1029-1065）
的 `V <= c => V < c±1` 改写补上 oracle cc:1059-1060 的
`newvn->copySymbol(vn)`——新常量从源常量**传承数据类型（及任何 Symbol 标
记）**（`Varnode::copy_symbol_arc`，varnode.cc:493-505 完整移植，含
high/typeDirty 记账）。此前 Rudra 只 `new_constant + op_set_input`，重建常量
从工厂 undefined 起步，下一轮 `ActionInferTypes::writeBack` 首次定型
（undefinedN→具体）向 localcount 报一次幻影"变化"；RuleIntLessEqual 在管线
尾段的两轮迟到改写（R9/R12，探针台账）各贡献一个 singleton 轮，把
sqlite3AddCheckConstraint 的 localcount 轨迹推到 7（0,1,2,3,4,4,4,5,6,6,7），
触发 R-only `/* WARNING: Type propagation algorithm not settling */`（oracle
轨迹 0,1,2,3,4,4,4,5,5,5 稳定 5）。补 copySymbol 后轨迹与 oracle 精确同形，
警告消失；全语料字节归因：canon/mirror corpus 各恰 -1 行（警告行），其余
152k+ 行零位移；canon curl f903372a/httpd 3617ecc3/VdbeExec b3f5b487/606dd8c0
钉值恒等。**根因翻案注记**：MISC3 票面原判"heritage 增量性/INDIRECT 守护
生命周期"为真修域——本道双侧钻定（Rudra 探针轨迹 + oracle wbchange 直方图
亲测 828 事件）**证伪**：Rudra heritage 增量性（globaldisjoint 持久 + prev==2
is_heritage_known 跳过 + addIndirects=newAddresses 一次性守护 + 重启
fd.clear() 全擦除）与 oracle 逐点一致，两轮 guard 扫 = 一次合法重启；迟到
churn 真源是 replace_lessequal 重建常量缺类型传承。oracle 侧同点核对：
`buildVarnodeOutput`（funcdata_block.cc:985-1000）clone 输出同样从
newVarnodeOut（undefined）起步——两侧 clone/join/MULTIEQUAL 输入输出的首
轮定型 churn 是共有基线（oracle 轨迹的 4 个真轮 + 1 个迟到真轮），非缺陷。

## 2026-10-02：DECLB1-JOINLEG-0001 — `link_symbol` 的 join piece 腿解析（Lane DECLB1）

`Funcdata::link_symbol` 的 cc:1177 建符号路径在 `vn_space == Join` 时经
`Architecture::join_db` 的 `find_join(vn_offset)` 取 join 记录，按 oracle
addMap 臂的 LE 序（database.cc:1163-1164，记录 most-significant-first 反向遍
历——最不重要腿先装）把 `(piece 空间, 偏移, 尺寸)` 列表写进新符号的
`LocalSymbol::join_pieces`。无 Architecture 或记录缺失（状态less 回退路径铸造
的未注册 join 地址）时保持空表——行为退回旧形。这些腿建模 addMap 为 join 映
射安装的 per-piece SymbolEntry，由 printc 的 emitScopeVarDecls 拼接序回放消
费（见 varmap/printc 同批条目）。测试：printc 侧
`test_scope_rangemap_list_order_join_leg_anchors` + 镜面 sqlite 面 trio 逐字
节归零对账。

## 2026-09-30：(g) 守卫影子随行（Lane ARENAFLIP-g 步骤 2）
- insert_op 的 SWITCH_OUT 直写改 `set_flags`；块构造字面量增 `bank_slot`
  初始化。值语义不变。

## 2026-09-30：god-object id 读访问器（PERF-ARENA-FLIP-0001 (a)，(b) 交接面）

新增四个 P1 读形态访问器（ARENA_DESIGN §3.2；oracle 依据 = op.hh:63-68 PcodeOp 的
结构性 setter 全部 private + friend `Funcdata`——交叉访问本就 100% 经 Funcdata 中转）：

- `Funcdata::op_by_id(OpId) -> Option<&PcodeOpRef>` — op arena 句柄解析（OpId 由
  `PcodeOpTree` 槽存储分配，`PcodeOp::op_id` 回指；destroy 后槽保留=oracle
  deadandgone 可读语义，op.cc:984-999）。
- `Funcdata::op_id_of(&PcodeOpRef) -> Option<OpId>` — bank 插入过的 op 的句柄。
- `Funcdata::vn_by_id(VnId) -> Option<&Arc<RwLock<Varnode>>>` — varnode arena 句柄
  解析（`Varnode::vn_id` 回指，`VarnodeBank::allocate` 占槽）。
- `Funcdata::vn_id_of(&Arc<RwLock<Varnode>>) -> Option<VnId>` — bank 分配过的
  varnode 的句柄（None=手搓 fixture/外部 Arc）。

W1(b)-(g) 消费迁移（heritage/flow→printc）以此为入口逐步把 `Arc` 句柄形态换
id 形态；(a) 段 PcodeOpRef/Arc 形态本身不变（桥接契约）。

## 2026-09-30：begin/end Loc/Def 前转器返回类型随动（PERF-ARENA-FLIP-0001 (a)）

`Funcdata` 的 begin/end Loc/Def 前转器族（`begin_loc`/`end_loc`/`end_loc_space`/
`end_loc_size`/`end_loc_size_fl`/`end_loc_pc`/`begin_def`/`end_def`/`end_def_fl`/
`end_def_addr`，funcdata.hh:337-394 前转形态）返回类型随 VarnodeBank 双树 POD 键化
（见 `docs/api/varnode.md` 同日条目）由 `std::collections::btree_set::Iter<'_, Varnode{Loc,Def}Ref>`
改为 `impl Iterator<Item = &Varnode{Loc,Def}Ref>`——纯类型随动：迭代序仍为
VarnodeCompareLocDef/DefLoc 比较器投影全序，元素仍逐个 yield `&VarnodeLocRef`/
`&VarnodeDefRef`，所有调用点（含 filter 链式形态）零改动、行为零变。

## 2026-09-29：beginOpAll/endOpAll 迭代器类型随动（PERF-ACTIONPOOL-ITER-0001 / OPTREE 车道）

`Funcdata::begin_op_all`/`end_op_all`（funcdata.hh:518/521 beginOpAll/endOpAll 前转）
返回类型随 bank 主排序容器 SeqNum 键化由 `std::collections::btree_set::Iter<'_, PcodeOpRef>`
改为 `std::collections::btree_map::Values<'_, SeqNum, PcodeOpRef>`——纯类型随动：
迭代序仍为 SeqNum 全序（(addr,time)，与原 `Ord for PcodeOpRef` 投影同一全序），
元素仍逐个 yield `&PcodeOpRef`，所有调用点行为零变。容器本体变更与恒等契约见
`docs/api/op.md` 的 `PcodeOpTree` 节。


## 2026-09-28：set_varnode_properties/new_varnode_symbol_tail 本地域入口完整 setSymbolProperties 端口（FUNCDATA-SETVARNODE-SCOPELOCAL-0001 completion，wt/outstream）

`Funcdata::set_varnode_properties`（funcdata_varnode.cc:25-42 对应物）与
`Funcdata::new_varnode_symbol_tail`（cc:104-122/148-169 共享尾对应物）的
ScopeLocal 腿入口命中此前退化为纯 flags 折叠（`setFlags(vflags & ~typelock)`）；
oracle 在该臂走**完整** `vn->setSymbolProperties(entry)` 端口
（cc:32-33/116-117/163-164）。修法 = 两处入口命中经
`ScopeLocal::live_symbol_entry`（见 docs/api/varmap.md 同日条目）物化活
SymbolEntry 后运行 varnode.rs `set_symbol_properties_arc` 全链：

- `SymbolEntry::updateType`（database.cc:135-144）→ `getSizedType`
  （database.cc:151-162）→ `getExactPiece`（type.cc:4090-4117 完美尺寸
  匹配返字段 Arc）→ `vn->updateType(dt, lock=true, override=true)`
  ——**struct downChain 锁**：TYPELOCKED 结构符号的精确覆盖栈格在
  属性时刻被锁到字段声明类型，阻断后续 ActionInferTypes 传播竞赛
  （coreaction.cc:5092 `isTypeLock()` 早退）。
- 尾随 `setFlags(entry->getAllFlags() & ~typelock)`（varnode.cc:422）
  与旧折叠同效；scope 应答无入口（database.cc:1271-1277 discovery 臂）
  保持 cc:34-35 折叠。
- 活案例（curl main）：`outs`/`heads` 符号 TYPELOCKED `OutStruct(16)`
  （oracle 仪器化 symlock=1 亲证），`.stream` 字段格 0x148/0x158 早期锁
  `ptr->FILE(216)` 字段片 → bare read 不再带 `(FILE *)outs.stream`/
  `(FILE *)heads.stream` 左 cast（golden 形，3 位点）；file2string 同族
  收敛（缺 `bool *` 声明补齐，编号级联对齐 golden）。
- A/B：canon curl 95→85/0/0（main 20→13 = 恰 3 票面位点 + 上下文；
  file2string 19→16；其余 122 函数零漂移）；canon httpd 47/0/0 **字节
  恒等**（md5 e42ec94e 双侧）；镜面五面 PASS。
- 单测 `test_set_varnode_properties_struct_downchain_lock`：downChain
  锁（typelock + `Arc::ptr_eq` 字段片类型身份 + mapentry 绑定）、
  重复属性 pass 恒等（varnode.cc:415 `mapentry != entry` 恒等臂）、
  live Symbol 句柄 memo（`Arc::ptr_eq`）与入口字段（first/offset/size）。

## 2026-09-27：set_varnode_properties 旧名代理 RAM 空间守卫（RULEACTION-NEGCONST-FOLD-0001）

`Funcdata::set_varnode_properties`（funcdata_varnode.cc:25-42 对应物）的
旧名 `symbol_table` 代理腿（driver 平铺 addr→name 代理，无通道/未命中时的
最后回退）此前对**任意空间**的 varnode 做纯 offset 平查。oracle 的
`Scope::queryProperties`（database.cc:1263-1281）全程空间限定：
`stackContainer`（database.cc:943-962）按 space+range 走容器/rangetree
（unique 空间无 scope 拥有，const 在 :950 早退），`SymbolTable::getProperty`
的 flagbase 以完整 space+offset Address 为键（database.hh:946），因此
unique 空间 varnode 的查询恒得 flags==0。修法 = 代理腿加
`space == AddressSpace::Ram` 守卫：unique 空间 varnode 的 offset 与 RAM
函数地址碰撞时不再继承虚假 MAPPED。

- 活案例（sq 面）：RulePtrArith 的 PTRADD 输出（unique offset 0xaa00）与
  `enable_progress_bar@0xaa00` 碰撞，虚假 MAPPED 强制 baseExplicit →
  explicit → merged，产出物化地址临时 `V = (int8 *)(addr); V = (int4 *)*V;`
  而非 golden 的 implied 内联 `V = *(int4 **)(addr)`（ARITH-FOLD 地址物化
  子族主成分）。
- A/B（同机，base=48146429）：sq 镜面 skeleton 4197→4017（−180），
  ARITH-FOLD 93→41（queue_init/cache_init/sigwinch_handler/progressbar_error
  四函数逐函数 skeleton→0）；curl 镜面 56=基线、canon curl 157=基线、
  defects/numbering 全 0；sqlite 镜面 24091=基线（碰撞机制依赖二进制
  函数地址布局，sqlite 无同型碰撞案例）。
- 单测 `test_set_varnode_properties_unique_space_proxy_collision` 钉双分支
  （unique 碰撞不继承 MAPPED / RAM 正控仍置 MAPPED）；测试内
  `fd.arch = None` 隔离旧名代理腿——canonical Architecture 的常驻
  symboltab（architecture.cc:597-602）会先以自身（空 ranges）flags 折叠
  应答 RAM 腿，代理腿需在无通道 fixture 下单独验证。

## 2026-09-27：attempt_dynamic_mapping 尾部镜像 setSymbolProperties 返回语义（DYNMAP-SETPROPS-RET-0001）

`Funcdata::attempt_dynamic_mapping`（funcdata_varnode.cc:1314-1337 对应物）的
尺寸匹配臂此前无条件 `return true`；oracle 在该臂返回的是
`Varnode::setSymbolProperties(entry)` 的布尔（funcdata_varnode.cc:1333-1334）。
修法为逐行镜像该返回链：

- `Varnode::setSymbolProperties`（varnode.cc:410-424）：`res` 初值 =
  `SymbolEntry::updateType(vn)`（database.cc:135-144——仅 symbol typelock
  时经 `getSizedType`（database.cc:151-163，动态条目 offset=0 整尺寸件）
  强制 `vn->updateType(dt,true,true)`）；typelock 臂里 mapentry NULL→entry
  附着强制 `res=true`（:1327 守卫已证 mapentry 为 NULL，附着必发生）；
  `setFlags(getAllFlags() & ~typelock)`（database.hh:271 =
  extraflags|symbol flags——动态铸造 database.cc:1690-1702 即
  `Varnode::mapped`）无条件执行。
- 生产铸造形态（`addDynamicSymbol` 的 `new Symbol(owner,nm,ct)` flags=0）
  下动态符号永不 typelock（`retypeSymbol`/`checkSizeTypeLock` 不写
  `Varnode::typelock`），故 **unlocked 动态符号附着发生（mapped=1）但返回
  false**——这正是 ActionDynamicMapping count 保持 0 的机制
  （coreaction.cc:4864 只在返回 true 时递增）。
- Rudra 侧 typelock 臂从 `scope` 动态 `LocalSymbol`（按 hash 查找）重建：
  typelock 位 + `dtype`（`update_type_lock(dt,true,true)` 的类型写保留
  可观测语义，即便 mapentry 臂随后覆写布尔）；MAPPED 旗标与
  symbol_table 名记录不变（getAllFlags 侧），仅返回值改为镜像。
- 双侧证据：copytrim_remat_1204 `refind_attach_fn` 案例块双侧逐字节一致
  （`call|…|attemptDynamicMapping|res=0`、`after1 t.mapped=1`、二次调用
  `res=0`）；fixture 分歧 11→5 行对，余 5 行全属未并线车道
  （DYNMAP-LATE-CAST-RETARGET / COREACT 双桩）。本支线上
  `attempt_dynamic_mapping` 无生产调用方（ActionDynamicMapping::apply 在
  wt/coreact2 未并线），canon/镜面按构造恒等。

## 2026-09-25：get_internal_string 走 registerInternalStringData（Lane STRNCPY）

`get_internal_string`（funcdata_varnode.cc:1413 的对应物）的手搓校验/插入/
合成 hash 块被替换为已移植的
`StringManager::register_internal_string_data`（stringmanage.cc:185-199）：
- 键从 op 地址改为 **hash 的常量空间地址**——正是 print 侧
  `PrintC::printCharacterConstant` 经 STRINGDATA CALLOTHER 的 in(1) 常量读回
  的地址（printc.cc:701-714），旧键下打印永远 miss；
- 删除非 oracle 的 `has_char_terminator` 拒绝门（oracle `checkCharacters`
  只要求合法编码，无 NUL 也接受——`"+0000"` 5 字节无 NUL 即依赖此语义）；
- hash 采用忠实的 `calcInternalHash`（crc32^offset，stringmanage.cc:95-105），
  替换 addr|charsize<<56 合成值（hash 值从不进入输出文本，属可规范化内部
  ID，但键语义现在与 oracle 同构）。
调用方：constseq.rs `HeapSequence::build_string_copy`（constseq.cc:705）。

## 2026-09-23：spacebase 类型挂载重启用（HERITAGE-LOADCLAIM-0001 / VARGROUP-ABSORB-0001 v3）

`Funcdata::spacebase` 的 SP 输入寄存器 TypeSpacebase 指针挂载
（funcdata.cc:263-264 `vn->updateType(ptr,true,true)`，`ptr = getTypePointer(sb_size,
getTypeSpacebase(stack, getAddress()), 1)`）随 HERITAGE-LOADCLAIM-0001 重新启用。
v1 撤回的两个前提均已被后续车道关闭：

1. **认领链已在主管线工作**（本次经 curl main 阶段投影实证）：调用点 opStackLoad
   LOAD（funclink 建立）在 mainloop 迭代 1 的 oppool2 被 RuleLoadVarnode directify
   成 `COPY(n:stack:fc78:304)`，mainloop restart 后 heritage pass 2 的
   placeMultiequals→collect→refinement→refineRead 把该 304B 自由栈读替换为
   280+8+8+8 的 PIECE 梯（seq 3450-3452，oracle 3501-3503 同形）喂给 CALL——
   与锁定 oracle 的 gdb 逐步轨迹（directify→restart→refineRead→RulePropagateCopy
   折叠 COPY）逐步对应。"LOAD 存活到 directify 且无认领"的旧前提不再成立。
2. **v1 的 config 域回退未复现**：本次 A/B（base=5c610849）glob_set 92/92、
   glob_range 80/80 **零行变化**，glob_url 2/2；curl 全量 2994→2996（+2 为
   in_RSP 声明类型改变引起的换行级 cosmetic），defects=0/numbering=0；
   httpd 2337→2337 全等；next_url/match_url 输出中 next_url 零行变化
   （Phase 2 MATCH 保持）。

**已知 cosmetic 残差**：8 个函数（main/getparameter 等）此前已声明 `int8 in_RSP`
（栈符号映射缺口的既有表现）；挂载后声明曾为 `__spacebase_1_<hash> *in_RSP`
（Rudra get_type_spacebase 旧 dedup 名泄漏）。2026-09-23
SPACEBASE-SYMNAME-0001 起，spacebase 类型名已按 oracle 清空
（type.hh:735-736 空 name + printc.cc:3387-3389），该声明渲染为
`BADSPACEBASE *in_RSP`——oracle 在同符号状态下的机械渲染形态；oracle 真实
golden 中因栈符号映射完整而不打印该声明。声明行本身的存在属
varmap/符号层既有缺口的表现面，随 VARGROUP-ABSORB-0001 §4-4 符号层一并收敛。

- `Funcdata::spacebase`（funcdata.cc:240-266 else 分支）：标记 SPACEBASE 标志后，若该
  varnode 是输入寄存器，按 cc:263-264 `getTypeSpacebase(stack, getAddress())` +
  `getTypePointer(sb_size, ct, 1)` 构造指针类型并以 `updateType(ptr,true,true)` 挂锁。
  此前注释称"类型系统尚无 TypeSpacebase"而跳过——该类型现已存在，且
  ActionInferTypes::propagateSpacebaseRef 依赖它识别 SP 输入。

## 2026-09-24：TypeSpacebase 活跃局部 scope 发布通道（VARMAP-STACKBOUNDARY-0001）

- `Funcdata::publish_scope_to_spacebase`（RUDRA-GLUE，无 oracle 单函数对应物；
  行为对应 Ghidra `TypeSpacebase::getMap` type.cc:2935-2945 的动态解析语义）：
  每趟 ScopeLocal 图变异后（`ActionRestructureVarnode::apply` 内、
  `fd.scope = Some(scope)` 之后）调用——经 Architecture 的 TypeFactory 取
  本函数帧的缓存 spacebase 类型，把当前 ScopeLocal 克隆发布进其
  `fd` 共享句柄（句柄由 `TypeFactory::live_local_scopes` registry 在类型
  构造期挂接，见 typefactory.md）。此后 `TypeSpacebase::get_sub_type`
  的 local-frame 查询（`AddTreeState::calc_subtype` TYPE_SPACEBASE 臂的
  hasMatchingSubType 喂入）读到的是**活跃**重构图而非建期死快照——
  myprogress ord150 的互补常量拆分根因（oracle extra=1 源自
  `line` 数组 [-0x238,-0x138) 容器内偏移，判别实验见
  /dev/shm/rudra-tests/sb-stackbound/discrim/）。

## 2026-09-22：setVarnodeProperties localmap 腿（v2 保留项；spacebase 挂载见 2026-09-23 条）

v1 曾同时落子 spacebase 挂载与本腿，A/B（base=70e76ce6）显示 config 域漂移后
v2 撤回两处；本腿后由 heritage 侧等效修复承接（见 docs/api/heritage.md 同日条目），
spacebase 挂载则于 2026-09-23 按上文条件重启用。
- `Funcdata::setVarnode_properties`（funcdata_varnode.cc:25-42）：补上 Ghidra
  `localmap->queryProperties` 的函数自身作用域腿（database.cc:1268-1277）——栈空间
  varnode 先查 ScopeLocal：容器条目/在域内均折叠 flags（含 mapped|addrtied），
  未应答再走原 Ram/全局通道。此前栈 varnode 从未获得 addrtied，导致
  RuleSubRight 的 overlap 守卫（ruleaction.cc:7265-7268 两侧 addr-tied）不触发，
  splitCopy 建出的 45 个栈地址 SUBPIECE 被 INT_RIGHT 化（42 处 CONCAT 中间态的直接
  诱因）。修复后 heritage MULTIEQUAL 影写链与 SUBPIECE 件均为 addr-tied，守卫按
  Ghidra 语义跳过（Rudra 保守版：双侧 tied 即跳过，等价覆盖 overlap==c 情形）。


## 2026-09-22：INDIRECT 构造器符号尾补齐（FUNCDATA-INDIRECT-SYMBOLTAIL-0001）

CF 裁决表（wt/sb-promosite, `HERITAGE-PROMOTE-SYMBOLTAIL-0001` 收尾行 36）登记的
funcdata 域缺口：`new_indirect_op`（oracle cc:689/692）与
`new_indirect_creation_in_space`（cc:719）的注释声称构造器带符号尾，但实现只有
`Heritage::apply_new_varnode_flags` 的 flags 折叠（无 `setSymbolProperties` 分支）。
本次按 BZ 模式在 create/def 接线与 flags 折叠之间插入
`self.set_varnode_properties(&vn)`（折叠保留，OR 可结合、不 Clear typelock）。

**oracle 双路径 usepoint 语义**（逐字核对）：

- **cc:689 newin（newVarnode 路径,free varnode）**：
  `localmap->queryProperties(vn->getAddr(), vn->getSize(), Address(), vflags)`
  （funcdata_varnode.cc:162）——usepoint 是 INVALID 默认 `Address()`。推论
  （database.cc:117-119 `SymbolEntry::inUse`）：`isAddrTied()` 项对任意 usepoint
  成立；**invalid usepoint 永不命中 window-limited 项**（cc:118
  `if (usepoint.isInvalid()) return false;`）。命中→`setSymbolProperties(entry)`
  （varnode.cc:404-421：`entry->updateType(vn)` 类型强制 + typelocked 时挂
  `mapentry`+`high->setSymbol` + `setFlags(entry->getAllFlags() & ~typelock)`）；
  未命中→`setFlags(vflags & ~typelock)`（cc:166）。
- **cc:692/cc:719 newout（newVarnodeOut 路径,defined varnode）**：尾在
  `op->setOutput(vn)` 接线**之后**跑
  `queryProperties(m, s, op->getAddr(), vflags)`（funcdata_varnode.cc:115）——
  usepoint 是**定义 op 的地址**（两构造器里 = 引发 op 的地址，因
  `newOp(2, indeffect->getAddr())`）。Rust `set_varnode_properties` 内部
  `get_use_point`（varnode.cc:696-703：written→`def->getAddr()`）在接线后调用
  即得同值——**精确对齐**。cc:719 尾先于 cc:720-722 的 `indirect_creation`
  位 OR（顺序保持）。
- free newin 路径已知残差：Rust `get_use_point` 对 free varnode 返
  `fd.getAddress()+-1`（varnode.cc:701 同款），非 INVALID——仅当某 window
  覆盖函数入口前一地址时可观察差异（BZ lane 同款近似，语料内无此形态）。
- in0 走 `newConstant`（cc:716）无尾（oracle cc:74 注释 "no chance of matching
  localmap"）；`newVarnodeIop` 亦无尾。

**A/B 验证（同机同树,base=d3fbe924 vs after,均诚实 exit 0）**：
curl base **3607/0/0** → after **3605/0/0**（skeleton −2）;httpd base=after
**2456/0/0 字节级一致**。diff 恰 5 行,全部在 config 域潜伏位点：
`main` 4 行（3 行 char 字面量 `'\0'`/`'\x01'`→`0`/`1`,golden 为 `false`/`true`
保持非 bool 残差、方向中性;1 行 `::config.outfile != (void *)0x0`→
`(char *)0x0` **与 golden cc:1008 逐字节一致**）、`parseconfig_constprop_0`
1 行（`::config.url != (char *)0x0`,**与 golden cc:1017 一致**）——typelocked
全局 `char*` 经 `setSymbolProperties` 挂上 DWARF 类型（与 BZ lane 的
glob_expand `URLGlob*` 同族机制）。config 域抽验
main/getparameter/parseconfig/glob_set/glob_range/glob_url 逐函数
defects=numbering=0;函数体 A/B:getparameter_constprop_0(652L)/glob_set(67L)/
glob_range(70L)/glob_url(18L) 字节级一致,仅 main(969L) 与
parseconfig_constprop_0(160L) 含上述改善行——零回退。`cargo test --lib`
funcdata/indirect/guard 域 62/17 与 base 完全相同（17 失败为 d3fbe924 既有,
非本改动引入）。annotations/refs hooks 绿。

## 2026-09-22：`set_input_varnode` 补 cc:364 属性遍（HERITAGE-PROMOTE-SYMBOLTAIL-0001）

`Funcdata::set_input_varnode` 此前直通 `vbank.set_input_varnode`，漏掉 oracle
`Funcdata::setInputVarnode` 的 `vn = vbank.setInput(vn); setVarnodeProperties(vn);`
对（funcdata_varnode.cc:363-364）。现按 oracle 控制流补属性遍：早退臂（cc:344
isInput）与去重臂（cc:356-357 返回既有 input）不跑，仅银行真实提升的新鲜
varnode 跑（`Arc::ptr_eq` 判定）；`set_varnode_properties` 的 `isMapped` 守卫使
创建点已挂符号尾时为 no-op——与 oracle 的双重查询逐点一致。

## 2026-09-23：`set_input_varnode` 补 cc:365-370 效果尾（SB-MATCHURL-ORD70-0001）

紧接属性遍，oracle 还查询 `funcp.hasEffect(vn->getAddr(), vn->getSize())` 并按
记录写标志（funcdata_varnode.cc:365-370）：`unaffected` → `set_unaffected()`；
`return_address` → `set_unaffected() + set_return_address()`（return_address
寄存器在函数过程中也应不受影响）。Rudra 侧查询走新增的
`FuncProto::try_has_effect`（`has_effect` 的非 panic 形态——无模型且无效果列表
的裸测试 FuncProto 在 Ghidra 无对应物，None 跳过标志写）。该标志尾是
`ActionRestrictLocal` 循环 2（coreaction.cc:1988 `vn->isUnaffected()`）与
HighVariable 合并偏好（variable.cc:462）的数据源。


## 2026-09-22:`op_stack_load`/`op_stack_store` 空间注记宽度 1→8(FUNCDATA-SPACEID-WIDTH-0001)

`newVarnodeSpace`(funcdata_varnode.cc:190-198)用 `sizeof(spc)`(AddrSpace\*
指针宽,x86-64 = **8**)建 LOAD/STORE 的空间注记常量,值经
`createConstFromSpace`(translate.hh:542)编码。FUNCDATA-OPSTACKLOAD-CONTAIN-0001
修复时 Rudra 两处写成 `new_constant(1, contain.space_id())` —— 值通道正确但宽度
1;镜像投影 emitter 的 `s:<name>` 描述符门是 `size==8`(curl_decompile.rs
`stage_vn`),1 字节常量漏成 `c:3:1`,成为 Phase 2 跨侧对拍 universal:funclink
ordinal 7 op-idx 4 首分歧(oracle `in=s:ram` vs rudra `in=c:3:1`,2534:2e8 LOAD)。

修复:两处改调既有 `new_varnode_space(contain)`(`size_of::<usize>()` = 8,
与 `new_constant` 同走 `vbank.create_with_space(_, Const, id)`,行为只动宽度)。
同族位点 `createStackRef` 的 SEGMENTOP 分支(cc:488,同样
`newVarnodeSpace(containerid)` 宽度 8)x86-64 不可达且 Rudra 未实现该分支,
已在 `create_stack_ref` 注释标注宽度语义(实现时必须走 `new_varnode_space`,
禁止 1 字节常量)。

## 2026-09-22：`op_stack_load`/`op_stack_store` 的 LOAD/STORE 空间输入改用 contain 空间(FUNCDATA-OPSTACKLOAD-CONTAIN-0001)

Ghidra `Funcdata::opStackLoad`(funcdata_op.cc:541-552,关键行 :547)与
`opStackStore`(:508-527,关键行 :523)把 LOAD/STORE 的 in(0) 空间注记建为
`newVarnodeSpace(spc->getContain())` —— 栈空间(x86-64 cspec basespace)的
contain 是 **ram**,不是 `spc` 自己。Rudra 此前写成
`new_constant(1, spc.space_id())`(stack 自身 id),导致
`RuleLoadVarnode::correctSpacebase` 的
`assoc->getContain() == loadspace` 守卫(ruleaction.cc:4181)恒假 →
loadvarnode 规则永不触发(oracle-only 路径 oppool2:loadvarnode 在 Rudra 断链,
0 应用)、`resolveSpacebaseRelative`(fspec.cc:4870)不执行、栈参占位 LOAD
不折叠成栈 varnode(drill 观测 `*(stack,` 38 处 vs oracle `*(ram,`)。

修复:两处均改为经 `Architecture::get_contain`(arch.rs,`space.hh:505` /
`SpacebaseSpace` override `translate.hh:187` 的等价物)解析 contain 空间,
再编码其 `space_id()` 常量;contain 缺失视为 Ghidra 不可达状态(NULL 传给
`newVarnodeSpace` = UB),显式 panic。解锁验证(curl 全语料):oppool2 规则
改动 725 → 1048(+323),`resolve_spacebase_relative` 首次执行(0→1 调用链),
defects=0 / numbering=0,skeleton 3685 → 3694(main +24 / getparameter −7,
gp 函数级 862 → 855)。解锁同时暴露 `Merge::gather_partial_pieces` 缺
`PieceNode::isLeaf` 递归界导致的 main worker 栈溢出(见 merge.md 同日条目
MERGE-GATHERPIECES-ISLEAF-0001,同批修复)。

## 2026-08-30：`Funcdata::new` 构造期绑定 canonical Architecture

Ghidra 的 `Funcdata` 构造函数无条件从 Scope 取得 Architecture(funcdata.cc:48
`glb = scope->getArch();`,database.hh:775),并立即消费它(:49
`minLanedSize = glb->getMinimumLanedRegisterSize();`、:54
`glb->getStackSpace()`);oracle 中不存在 arch-less 的 Funcdata。Rudra 的
`Funcdata::new` 现在通过新的 `canonical_arch()`(OnceLock 共享的
`Architecture::new()` 默认实例,architecture.cc:150 + resetDefaultsInternal
默认值)在构造尾调用 `set_arch`,恢复同一不变式:构造返回的 Funcdata 恒有
Architecture,且同一进程内所有未显式接线的 Funcdata 共享一个实例(对应
Ghidra 单 database 单 Architecture 指针)。持有真实 Architecture 的调用方
(curl/httpd runner)仍用 `set_arch` 覆盖,行为不变(E2E 双语料字节级不变)。

可观察后果(均为向 Ghidra 默认靠拢):未接线路径的 `infer_pointers`
false→true、`split_datatype_config` 0→struct|array|pointer
(architecture.cc:1416-1432);`subflow::tests::test_split_datatype_constructs`
的 arch-less 前提断言按新不变式翻转。双侧构造不变式观察门禁:
`tests/oracle/funcdata_canonical_arch_1204`(.cc 对锁定 oracle 真实
BfdArchitecture 构造链观察,.rs 镜像,in-binary 断言 min_laned_size 接线与
`set_arch` 覆盖路径)。min_laned_size 裸值是 spec-dependent(x86-64 SLEIGH
= 16,无 spec 默认 = -1),不属于接线观察,不进 diffed 投影。

## 2026-08-28：`set_arch` 接通 Architecture-owned TypeFactory

Ghidra 的 `Funcdata::newVarnode*` 在每次创建前都从同一 `glb->types` 调用
`getBase(size, TYPE_UNKNOWN)`，再把该共享 `Datatype *` 交给
`VarnodeBank::create/createDef`。Rudra 的 bank 在内部补这个必需参数，因此
`Funcdata::set_arch` 现在会先把 `arch.types` 的同一 `Arc<RwLock<TypeFactory>>`
注入 `VarnodeBank`，再允许后续 Varnode 分配。

这修复了 GetStr worker 已安装 standalone core table、但初始 bank Varnode
仍落入进程级 DataOrg factory 的分叉：修复前 stage 0 的 272 个 Varnode 中，
Ghidra 为 174×`xunknown8` + 93×`xunknown1` + 5×`code`，Rudra 为
174×`undefined8` + 93×`undefined1` + 5×`code`。修复保持 storage、flags、
create-index 与迭代顺序不变，只让初始未知类型和后续 local/read-facing 类型
共享 Architecture factory 身份。未附 Architecture 的 legacy/test 路径仍使用
process-canonical fallback；完整显式 `Datatype` 参数化 API 继续属于长期
`Funcdata::newVarnode*` 闭包。

Fresh `getstr_pipeline_1204` 复验确认双方 stage 0 的 272 个有序 Varnode 在
`flags + complete type record` 上零差异；stage 0/2/3 Rudra 快照已按当前源码重钉，
最终字符条件和 C 文本哈希保持不变。完整六阶段仍因 FSPEC space、SSA/Action/结构
等已登记残差保持 overall `MISMATCH`。独立 reviewer 只批准“一次、任何 Varnode
分配前注入同一 factory”及这 272-node 投影；late attach、重复 rebind、
`arch.types=None`、无 Architecture fallback、显式 Datatype variants 与完整
assignHigh/laned/symbol/error 闭包仍为 NO_ORACLE/UNTESTED/MISMATCH。

## 2026-08-28：结构条件回归断言纠正

布尔折叠回归测试现在按 Ghidra 的 out-slot 契约记录 `out[0]=false`、
`out[1]=true`，并断言 `ruleBlockIfNoExit` 经 virtual De Morgan 后得到最终 AND。
这是测试期望修正；本次没有据此宣称 `Funcdata` 生产函数新增完整 MATCH。

## 2026-08-28：分支删除与 switch-default 镜像语义

`Funcdata::remove_branch(bb, num)` 现把 `num` 解释为**要删除的 out-edge slot**，
按 `funcdata_block.cc:220-226` 调用 `branch_remove_internal` 后执行
`structure_reset`。内部路径销毁两出口 CBRANCH、以目标 incoming slot 删除对应
MULTIEQUAL 输入，并由该 incoming edge 的 `reverse_index` 删除准确配对的
source out-half。`install_switch_defaults` 通过双半边 helper 写入
`F_DEFAULTSWITCH_EDGE=0x04`，不再产生 source/target 标签不一致。

锁定 fixture 仅覆盖本轮列出的 buildCopy/insert/remove-edge 投影；错误路径、
完整 MULTIEQUAL/Action 调用闭包和所有 jump-table 状态仍为
`MISMATCH/UNTESTED`，因此本模块状态不升级。

## 2026-08-26：GOTO-LABEL-UNPRINTED-0001 收尾验证
- `Funcdata::remove_unreachable_blocks` 保持 `funcdata_block.cc:346-393` 的 reachable 收集、DEAD 标记、出边拆除、块删除和 `structureReset` 顺序；本轮仅移除诊断用 CFG dump。
- httpd 29/29 函数完成且 compare defects=0/numbering=0；goto 引用的未定义 label 与零地址 label 均为 0。curl 124/124 函数 compare defects=0/numbering=0。

**源代码路径**: `src/funcdata.rs`
**2026-07-16**: `link_symbol` + `link_symbol_reference` 已加（funcdata_varnode.cc:1156/1193）。符号链接 + PTRSUB 常量解析。


## 2026-09-30：move_out_edge 尾边打标（Lane ARENAFLIP-d 步骤 2）

- `move_out_edge` 的 cc:167 `BlockEdge` 推送（b->outofthis.push_back）补
  `point_id` 孪生打标（经 `self.bblocks.bank`，无 point 守卫）。语义逐位
  不变。

## 2026-09-30：edge 孪生打标接线（Lane ARENAFLIP-d 步骤 1）

- `replaceInEdge`（funcdata.cc:160 域）/node-split 重定向的 `.point =` 写点
  同步打 `point_id` 孪生（经 `self.bblocks.bank.registered_id_of`，无
  point 守卫）；`replaceEdgesThru` 调用点传入 bank。测试 fixture 字面量
  补 SENTINEL 孪生。语义逐位不变（孪生是纯表示字段）。详见
  docs/api/block.md 2026-09-30 条。

## 文档状态

**2026-08-24（BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001 连带）**: `test_switch_case_structuring`
断言更新：try_rule_switch 现按 newBlockSwitch（block.cc:1904-1919）真正安装 BlockSwitch
（消费 dispatch+cases），sblocks 顶层只剩 Switch（3→1）；case 标签打印断言
（"case 0:"/"case 1:"）暂注释并绑定 TODO PRINTC-SWITCH-EMIT-0001（printc
emit_structured_switch 首例标签落入被换出的 capture buffer）。无生产 API 变化。


- **状态**: 已核对（当前有效）
- **可信度**: 高
- **文档用途**: 说明当前 Rudra 中 `Funcdata` 这一“函数级分析容器”的角色、边界与主要公开接口
- **适用范围**: 以当前 `src/funcdata.rs` 所体现的主干架构为准
- **重要说明**: 本文档描述的是**当前函数分析容器**，而不是旧版 `Program` 驱动架构下的函数表示层

---

## 模块定位

`Funcdata` 是 Rudra 当前反编译主链路中的**函数级核心上下文对象**。  
它承担的职责，不是单纯保存“函数名字和地址”，而是把一个函数在分析过程中的核心状态统一收拢到一个容器里，供后续各阶段共享和改写。

在当前工程中，你可以把 `Funcdata` 理解为：

> “单个函数在进入 Rudra 分析管线后，对应的总工作台 / 总上下文 / 总容器”。

它通常位于以下链路的中心：

```text
binary / disasm
  -> raw p-code
  -> Funcdata
  -> block / CFG
  -> heritage / SSA
  -> ActionDatabase
  -> variable / type enrichment
  -> PrintLanguage / PrintC
```

也就是说，`Funcdata` 既是：

- 原始语义注入的落点
- 控制流和数据流分析的承载体
- 后续规则系统（Action / Rule）的操作对象
- 打印输出阶段读取的主要函数级数据源

---

## 与 Ghidra 的关系

本文档中的 `Funcdata` 对应的是 Ghidra 反编译器中的 `Funcdata` 概念。  
这种对应关系主要体现在：

- 它是**单函数**分析的中心对象
- 它把 P-code、Varnode、Block、原型、符号等信息组织到一起
- 它是后续优化、SSA、变量恢复、输出打印的重要入口

但需要注意：

- **概念对应不等于行为已经完全与 Ghidra 一致**
- 当前 Rudra 中的 `Funcdata` 文档只能说明“角色和结构方向”，不能直接推出“运行时表现已与 Ghidra 1:1 对齐”

如果需要判断对齐层级，应同时查看：

- `../ALIGNMENT_PROGRESS.md`
- `../VERIFICATION_GUIDE.md`
- `../data_contract.md`

---

## 当前角色边界

`Funcdata` 当前更适合被理解为以下几类信息的“函数级聚合体”：

### 1. 函数身份信息
例如：

- 函数名
- 入口地址
- 大小或范围信息

### 2. 图与节点容器
例如：

- `PcodeOp` 集合
- `Varnode` 集合
- block / CFG 相关状态

### 3. 分析期辅助信息
例如：

- 符号名映射
- 字符串字面量映射
- heritage / SSA 阶段统计信息
- 与后续输出或恢复有关的中间状态
- **`scope: Option<crate::varmap::ScopeLocal>`**（2026-06-26 新增）：由
  `ActionRestructureVarnode` (coreaction.cc:2274) 构建的局部变量作用域，
  对应 Ghidra `Funcdata::getScopeLocal()`，供 printc 查询栈变量名。

### 4. 规则系统操作对象
`Funcdata` 是 `ActionDatabase` 等分析动作的主要输入对象。  
因此它不只是“静态数据结构”，还是被多轮分析、改写、增强的工作上下文。

---

## 当前设计原则

在当前架构下，`Funcdata` 的设计应遵循以下原则：

### 单函数边界
一个 `Funcdata` 只应对应一个函数。  
它不应混入多个函数的 IR、Block 或 SSA 状态。

### 可逐步构建
`Funcdata` 不要求一创建就具备全部分析信息。  
更合理的流程是：

1. 先建立函数基本身份
2. 再注入 raw p-code
3. 再建立 block / CFG
4. 再进入 heritage / SSA / Action 处理
5. 最后再供打印层读取

### 可持续增强
分析阶段可以不断往 `Funcdata` 中补充信息，但不应在输出层为了“看起来更好”而反过来篡改底层事实。

### 图一致性优先
只要 `Funcdata` 中保存的是图结构、节点引用和 def-use 关系，那么任何修改都必须优先保证：

- 对象引用不悬空
- 节点状态前后一致
- block / op / varnode 之间关系仍可遍历

---

## 公开 API 说明

`clear_dead_varnodes` 的 `makeFree` 调用点（2026-08-13，`VARNODE-INIT-0001`）从当前 bank 的 loc-tree snapshot 获取 Arc，因而使用带 debug ownership 断言的 prevalidated remove→mutate→reinsert；随后清 cover，并在同一个 `hasNoDescend` 守卫内删除 free 值。`combine_input_varnodes` 按锁定 `funcdata_varnode.cc:381-454` 在 synthetic LE、register storage、无符号/ProtoModel effect、high-level-off 的合法图上执行：PIECE reader 改成 COPY；其他 reader 在入口块首逆序插入 SUBPIECE，输出保留原 source Address space/offset；`totalReplace` 支持同一 op 的重复输入槽；旧输入 detach 后经 checked `delete_varnode` 删除；最终建立并传播 setInput 返回的 canonical Arc。真实 12.0.4 fixture 观察完整 slots、descendants、bank membership/cardinality、op 顺序与 storage，并覆盖 non-input/non-contiguous 两条异常。big-endian、nullable/missing-entry 图，以及 `newVarnodeOut` 的 local-map/`assignHigh`/lane/ProtoModel property 副作用仍未由该 fixture 证明。

`total_replace_constant`（2026-10-02，UNAFFCALL-TRC-0001）现按 oracle 的 descend-entry 语义遍历：descend 列表每个条目对应一个输入槽（同一 op 双槽读 vn 时该 op 出现两次），槽位在循环内 LIVE 解析（对齐 cc:1508 `op->getSlot(vn)` 的每访重读）——首访替换第一匹配槽后，次访的 getSlot 自然解析到另一臂，两臂最终落在同一个 `copyop` 输出上。旧实现的 `(op, slot)` 快照把两个 descend 条目都冻结在 `position()` 首匹配槽，第二臂永不被替换，迫使下一轮 varnodeprops 再造第二个常量 COPY temp（sqlite3WalCheckpoint 的 `unaff_R14 = (uint4 *)0x0` 1→3 重物化族根因；多出的 temp 高位无法并入 unaff 高，arm COPY 打印为三条语句）。修复后 WalCheckpoint/WalFrames 的该族行归零（B2 差分：4→0、5→1，余 1 行为 F4 goto 族）。

`Funcdata::destroy_varnode` 只把 read edges 从 descendant 索引 detach、清定义输出，再走 prevalidated bank 删除。（2026-09-22 更新，SB-ORD159-NULLSLOT-0001：`op_unset_input` 现在把槽置为共享 null 哨兵而非保留 stale Arc——不再依赖"槽中残留旧 Arc"的表示。）本函数对 foreign/stale handle 的行为未闭合，不能当成 public checked `destroyVarnode`。相对地，inline `delete_varnode` 返回 `Result<()>` 并直接走 public checked `VarnodeBank::destroy_varnode`；bank API 的 integrated/foreign/stale 错误由 `Result` 表达。Ghidra delete 与外部 Rust Arc 生命周期差异继续归 `VARNODE-0001`。

`set_input`/`set_def` 的 canonical 返回值已贯穿当前生产调用点：`combine_input_varnodes`、INDIRECT 构造、raw P-code 两种注入路径及 Heritage MULTIEQUAL 输出都把 canonical Arc 接到后续 op/output。`inject_raw_ops` Phase 3（曾在此 snapshot `(opcode, inputs, output)` 做线性序输入提升，2026-09-27 CANON-REGJUNK 双票整体退役，见下方 dated 注记）移除后本段只剩历史锁生命周期描述：fresh/bank-owned 内部路径的锁纪律由 `set_input_varnode` 路径继承。不把 raw 注入桥接整体宣称为 Ghidra `PcodeEmitFd::dump` MATCH。

以下说明围绕当前可见公开接口展开，重点说明“它们在主链路中扮演什么角色”。

---

### `pub struct Funcdata`

函数分析容器。

这是 `funcdata.rs` 中最核心的公开类型，用于表示“一个函数在当前反编译流程中的完整分析上下文”。

从工程视角看，`Funcdata` 通常承载：

- 函数基础元信息
- 原始与正式 IR 之间的桥接结果
- `PcodeOp` / `Varnode` / block 等图对象
- 分析阶段产生的附加信息
- 输出层所需的上下文

从使用方式看，后续许多主流程都围绕 `&mut Funcdata` 展开，因为它是：

- 可被构建的
- 可被改写的
- 可被分析的
- 可被最终打印消费的

---

### `pub fn new(name: &str, addr: Address, size: i32) -> Self`

创建一个新的 `Funcdata` 实例。

#### 语义
这是单个函数分析容器的初始化入口。  
创建时通常只需要最基础的函数身份信息：

- `name`: 函数名
- `addr`: 函数入口地址
- `size`: 函数大小

#### 作用
该方法建立的是“函数分析容器的初始壳”，而不是一个已经完成分析的函数对象。  
调用 `new(...)` 后，通常还需要继续：

- 注入 raw p-code
- 建立 block / CFG
- 补符号和字符串
- 进入 ActionDatabase / heritage 等阶段

#### 适用场景
- 从反汇编或样例程序中开始构造单函数分析对象
- 在测试中创建函数级分析上下文
- 为后续管线准备最小函数容器

#### 注意事项
创建成功不代表：
- 该函数已经可打印
- 该函数已经完成 SSA
- 该函数已经完成变量恢复

它只是主链路的起点。

---

### `pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>)`

设置自身的弱引用。

#### 语义
该方法用于在 `Funcdata` 被包装进共享引用模型后，把“指向自己”的弱引用回填进去。

#### HERITAGE-OWNERSHIP-0001 变更
`Heritage` 不再保存任何 `Funcdata` 自引用（原 `heritage.fd = Some(self_ref)`
行已删除）。Heritage 的 pass 方法现在显式接收 `&mut Funcdata`，由
`Funcdata::op_heritage` 用 `mem::take` 暂移 Heritage 后单 pass 驱动（对齐
Ghidra 非拥有的 `Heritage::fd` 裸指针语义，且无任何锁重入路径）。
`set_self_ref` 现在只回填 `Funcdata::self_ref` 本身。

#### 为什么会有这个接口
当前工程中大量对象采用共享读写容器组织，某些场景下：

- `Funcdata` 内部对象需要回指所属 `Funcdata`
- 或某些图节点/分析过程需要持有函数上下文的弱引用
- 为避免强引用环，需要使用 `Weak<...>`

因此该方法是一个“包装后回填”的初始化步骤。

#### 典型使用顺序
更常见的使用方式不是直接裸建 `Funcdata` 后长期使用，而是：

1. `Funcdata::new(...)`
2. 包装进共享读写容器
3. 调用 `set_self_ref(...)`
4. 再继续进入完整分析流程

#### 注意事项
这是架构层初始化接口，不是面向最终用户的简化 API。  
如果你在更高层封装函数分析入口，通常应由封装层负责调用它，而不是把它暴露成最终用户手工步骤。

---

### `pub fn op_heritage(&mut self)`

执行一整个 heritage pass（对齐 `Funcdata::opHeritage`，funcdata.hh:462）。

#### 语义
Ghidra 侧该函数体即 `{ heritage.heritage(); }` —— 恰好一次
`Heritage::heritage` 调用，单 pass，pass 计数在其最后一行 +1
（heritage.cc:2757）。Rudra 1:1 移植：

1. `std::mem::take(&mut self.heritage)` 暂移持久 Heritage 对象；
2. `heritage.heritage(self)` 在同一个 `&mut Funcdata` 上执行一个
   规范单 pass；
3. 回写同一个 Heritage 状态（pass 计数、持久 `globaldisjoint`、
   per-space HeritageInfo、guards）。

#### 所有权模型（HERITAGE-OWNERSHIP-0001）
旧实现里 `Heritage` 持有 `Weak<RwLock<Funcdata>>`，nominal `heritage()`
先升级并取写锁，嵌套 helper 再取同一写锁 —— 单线程自死锁
（HERITAGE-DRIVER-0001 审计结论）。现在整个 pass 无任何
`Weak` 升级 / 嵌套锁获取；连续多次调用（例如边界测试连续 3 次调用驱动
pass 0→1→2→3）不可能死锁。

#### 注意事项
- 生产管线（`ActionHeritage::apply`）**已切换**到此桥（HERITAGE-DRIVER-SWITCH-0001，
  2026-08-16）：`apply` 逐字对齐 coreaction.hh:289 `{ fd.op_heritage(); Ok(0) }`。
  `run_heritage_direct` / `place_multiequals_direct` 移出生产路径，仅剩 example
  侧 throwaway-Funcdata 参数估计与 crate 内测试调用。
- 与 Ghidra 一致：`Heritage::heritage` 不构建 infolist ——
  `buildInfoList` 属于 `Funcdata::startProcessing`（funcdata.cc:166）。
  未运行 startProcessing 就调用本方法，per-space 阶段对空 infolist
  迭代（零空间），与 oracle 行为一致。

---

### `pub fn run_heritage_direct(&mut self)`

执行**非生产**的 direct SSA pass（`place_multiequals_direct` + `rename_direct`）。

#### 语义
该方法通过 `std::mem::take` 临时剥离 `VarnodeBank` / `PcodeOpBank`，把它们直接传给 direct 系 heritage 算法。

#### HERITAGE-DRIVER-SWITCH-0001 状态（2026-08-16）
Ghidra 没有 `runHeritageDirect` 对应物（此前注释引用的 funcdata.cc:34 实为
`setSelfRef`，属误引，已更正为 RUDRA-GLUE）。自生产路径切换后，本入口
**绕过** canonical `Heritage::heritage`（heritage.cc:2663-2758）的
ADT/guard/refinement 阶段，只服务 example 侧 prototype 估计 helper（在
丢弃型 Funcdata 上）与 crate 内测试；不得在主管线调用。

#### 注意事项
这是用于替换旧版测试代码中手动调用 `place_multiequals_direct` 和 `rename_direct` 的推荐方式。

---

### `pub fn get_name(&self) -> &str`

获取函数名。

#### 语义
返回当前 `Funcdata` 所代表函数的名称。

#### 作用
这个名称通常用于：

- 调试输出
- 打印阶段生成函数头
- 日志和错误上下文
- 与符号信息对齐

#### 注意事项
函数名可能来自不同来源，例如：

- 输入构造时显式给出
- 符号表
- 后续命名恢复逻辑

因此“有名字”不等于“名字一定可靠到可代表源码原名”。

---

### `pub fn add_symbol(&mut self, addr: u64, name: String)`

注册一个符号名。

#### 语义
把某个虚拟地址与一个符号名称关联起来，保存到当前函数上下文中。

#### 作用
这个接口主要用于把来自二进制元信息、外部符号、函数名或全局对象名等信息挂入 `Funcdata`，便于后续阶段使用。

典型用途包括：

- 调用目标名称恢复
- 全局对象访问命名
- 输出阶段显示更友好的标识符

#### 设计意义
这说明 `Funcdata` 不只是保存函数内部 IR，还保存一部分与该函数分析强相关的“环境级辅助信息”。

---

### `pub fn add_string(&mut self, addr: u64, s: String)`

注册一个字符串字面量。

#### 语义
把某个地址与恢复出的字符串内容关联起来，记录到当前函数上下文。

#### 作用
供后续打印或语义恢复阶段使用，例如：

- 把某个地址常量解释为字符串引用
- 在输出中直接恢复为可读文本
- 辅助判断某些调用语义

#### 典型来源
- `.rodata`
- 已知字符串段
- 预处理扫描结果
- 反汇编阶段识别出的字面量地址

#### 注意事项
字符串映射属于“语义增强信息”，不是底层 IR 的替代品。  
即使记录了字符串，也不应直接覆盖底层地址事实。

---

### `pub fn get_symbol(&self, addr: u64) -> Option<&str>`

按地址查询符号名。

#### 语义
查询某个地址是否已经注册了对应的符号名。

#### 作用
这个查询通常会被：

- 打印层
- 调用恢复逻辑
- 调试输出
- 语义恢复逻辑

用来把“裸地址”提升成更可读的名字。

#### 返回值含义
- `Some(...)`: 当前上下文中已有该地址的符号名
- `None`: 没有已知符号，调用方应保守处理

---

### `pub fn get_string(&self, addr: u64) -> Option<&str>`

按地址查询字符串字面量。

#### 语义
查询某个地址是否已被映射为字符串内容。

#### 作用
供输出层和恢复逻辑将地址常量解释为字符串引用。

#### 返回值含义
- `Some(...)`: 当前上下文已知该地址对应字符串
- `None`: 调用方应继续按普通地址/常量处理

---

### `pub fn get_address(&self) -> &Address`

获取函数基地址。

#### 语义
返回当前 `Funcdata` 所对应函数的起始地址。

#### 作用
这个地址常用于：

- 作为函数身份锚点
- 错误上下文定位
- 图构建起点
- 打印和日志标识
- 与二进制符号表、测试样本、对齐验证数据做关联

#### 注意事项
这里返回的是 `Address`，而不是裸整数，这一点很重要。  
它意味着函数入口定位仍然保留地址空间语义，而不是被降级为普通 `u64`。

---

### `pub fn get_size(&self) -> i32`

获取函数大小。

#### 语义
返回创建 `Funcdata` 时记录的函数大小。

#### 作用
这个值通常可用于：

- 调试信息
- 输出摘要
- 与函数范围相关的扫描边界
- 构造或验证分析上下文

#### 注意事项
在反编译工程中，函数大小常常不是绝对可靠事实。  
因此这个字段更适合作为“当前已知函数范围信息”，而不是绝对真理。

---

### `pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw])`

把原始 P-code 序列注入到当前 `Funcdata` 中。

#### 语义
这是当前 `Funcdata` 最关键的桥接方法之一。  
它负责把反汇编 / 提升阶段得到的 `PcodeOpRaw` 序列，转为当前函数容器中的正式图结构。

2026-09-28 INJECT-NEWVARNODEOUT-SYMBOLTAIL-0001（PROTORECOVER）：phase 1 的
varnode 创建改走 `PcodeEmitFd::dump` 的完整序列（funcdata.cc:884/904-907）——
输出经 `new_varnode_out_full`（`Funcdata::newVarnodeOut`，funcdata_varnode.cc:104-122：
createDef + setOutput + assignHigh + laned 探针 + `localmap->queryProperties` 符号尾，
usepoint=op 地址），非 coderef 输入经 `new_varnode_in_space`（`Funcdata::newVarnode`，
cc:148-169：create + assignHigh + laned + 符号尾，usepoint=INVALID）。符号尾对全局
（RAM）空间存储盖上 `mapped|addrtied|persist`（database.cc:1271-1276），该 persist
即返回值裁剪的输入：`onlyOpUse` 的 persist 臂（funcdata_varnode.cc:1889-1892）在
返回值同时被存进全局时把 RETURN 试验标记 inactive，ActionReturnRecovery 随之摘除
（canon httpd ap_init_vhost_config `undefined8 *`+`return &DAT;` → `void`+`return;`，
4→0）。符号尾的父域腿按空间门控（仅 RAM），寄存器/栈/unique 存储保持无 flag——
与 C++ 侧 out-of-scope 的 getProperty 折叠（database.cc:1278-1279）一致。单 op 适配器
`inject_raw_ops_single` 已是此形态（PLTSTUB-THUNKRELRO-0001 先例）；本改动把批量路径
对齐到同一形态。

2026-08-30 CALLSPEC-DRIVER-0001：phase 1（raw dump）与 phase 2（build_blocks）之间——与
flow override 应用同一个 phase-1.5 边界（flow.cc:415-418/474-475 在
`FlowInfo::processInstruction` 内的位置）——补 flow-time callspec 锚定：每个
`CPUI_CALL` op 按 Ghidra `FlowInfo::setupCallSpecs`（flow.cc:683-686）三步走——
`new FuncCallSpecs(op)`（fspec.cc:4931-4938 从 in(0) 捕获目标地址）、
`opSetInput(op, newVarnodeCallSpecs(res), 0)`（in(0) 换成 fspec 注解 Varnode，
varnode.cc:599-601：FSPEC 空间生而 annotation|coverdirty、nzm=~0；Rudra 用 Iop 空间
+ entry 地址做兼容 offset，TYPEOP-FSPEC-SPACE-0001 既有建模）、`qlst.push_back(res)`
（`add_call_specs_owner`）。followFlow 路径的锚定在 `FlowInfo::setup_call_specs`
（flow.rs，xref_control_flow 内），本方法只服务无 FlowInfo 的 linear-scan driver 路径
（httpd 主路径、curl/httpd 原型推断 worker）——两条路径不重叠，不会双重锚定
（FlowInfo 走 `inject_raw_ops_single`）。CALLIND 不换 in(0)（flow.cc:704-723 无
opSetInput，见下方 2026-09-25 重放节——iced lifter 产 CPUI_CALLIND，锚定环已补
CALLIND 臂），FlowInfo 路径由 `setup_callind_specs`
负责。setupCallSpecs 的 FlowInfo 级尾部（applyPrototype/queryCall/循环检查，
flow.cc:688-693）在 linear-scan 路径无对应物：该路径不种 override，callee 解析是
driver 侧 pre-flow 原型表。落地后 ActionDeadCode 的 cc:3846 首操作数 consume 由
spec 循环承担（coreaction.rs mark_consumed_parameters 的 in(0) push 与防御分支
push 等价），callin0 防御分支（COREACTION-CALLIN0-CLOBBER-0001）的退役条件成立
（生产中全部 CALL 出生路径——本锚定 + coreaction deindirect + fspec setFuncdata——
均带 spec 对象），退役动作留给 coreaction 域。

2026-09-22 CALLSPEC-DRIVER-0002（注册门条件）：`qlst.push_back`（`add_call_specs_
owner`）增加门条件 `fd.funcp.has_model()`。Ghidra 的 `setupCallSpecs` 是原子的——
flow.cc:686 注册永不脱离 flow.cc:688-694 尾部（applyPrototype/queryCall/
checkForFlowModification），而尾部解析依赖架构模型空间（queryFunction ->
otherfunc->getFuncProto() -> cspec 绑定的 defaultfp，flow.cc:660-664）。无模型载体的
driver（httpd 的裸 `Architecture::new()`，`funcp.has_model()==false`）跑不了尾部，
却把半初始化 spec 注册进 qlst，会激活 Heritage 逐 call 效果守卫
（`Heritage::callOpIndirectEffect`，heritage.cc:362-364：有 spec 即从保守极性翻到
模型查询）而 ActionFuncLink/ActionActiveParam 无模型可挂实参——每个 call 点长出
无消费方可吸收的 indirect-effect barrier 重载拷贝（实测 httpd 29/29 函数 skeleton
2344→3576，+379 条 `x = x` 死拷贝链；main 137→669 行）。门条件落地后：annotation
swap（CALLSPEC-DRIVER-0001 所列 has_callspec/printc/deadcode 表面）无条件保留，
仅 qlst 注册等待模型载体；curl 原型 worker 绑定 cspec 模型
（FUNCPROTO-MODEL-BIND-0001），锚定行为不变。实测：httpd 2343/defects=0/
numbering=0，curl 3711/defects=0/numbering=0。解除本门条件的修复路径：把
queryCall/checkForFlowModification 尾部移植到 driver 边界（driver 侧 callee 表 +
defaultfp 模型）并补 `ActionCopyPropagation`（coreaction.cc:5510-5511，Rudra
universal 树缺失——守卫重载拷贝今天能以语句形式存活的直接原因）。

2026-09-23 PRINTC-BADSPACEBASE-RENDER-0001（Phase 3 输入效应尾）：Phase 3 把寄存器
读标记为 input 的 `vbank.set_input_prevalidated` 之后，补跑
`Funcdata::setInputVarnode` 的效应尾（funcdata_varnode.cc:365-370）——
`funcp.try_has_effect(space, offset, size)` 命中 `EffectType::Unaffected` 时置
`Varnode::unaffected`，命中 `ReturnAddress` 时置 unaffected+return_address。Ghidra
的每个输入晋升都走 `setInputVarnode`（`vbank.setInput` 唯一调用点即
funcdata_varnode.cc:363，SLEIGH 侧输入经 `Heritage::guardInput`/`renameRecurse` 的
`fd->setInputVarnode` 重建，heritage.cc:1975/2501），效应尾因此到达每个输入；iced
prelude 此前直连 bank 层绕过了它，RSP 输入缺 `unaffected` 位 →
`HighVariable::hasName`（variable.cc:737-744）不落 spacebase 抑制臂 →
`ActionNameVars::linkSymbols`（coreaction.cc:2961-2962）给 spacebase 高变量建符号，
printc 渲染成 `BADSPACEBASE *in_register_00000020;` 声明泄漏（golden 零此形态；
类型名来自 `PrintC::genericTypeName` 的 TYPE_SPACEBASE 兜底，printc.cc:3387——打印层
无第二道门，抑制完全在上游符号不创建）。效应位只在 `funcp` 有效应记录时激活
（curl 全量零观测差异，`__libc_csu_init/fini` 两个 iced 函数字节级不变）；httpd 侧
效应记录由驱动挂载（`tracked_context_architecture` 的 parseCompilerConfig 表面，
examples/httpd_decompile.rs，defaultfp 捕获后清空以维持 CALLSPEC-DRIVER-0002 门
姿态）。观测：httpd 门禁面 2225→2221（main −1、ap_fini_vhost_config −1、
ap_ht_time −2，全部为声明行消除），3 处 BADSPACEBASE 归零，全量 470/470 保持、
全量 L2 37677→37655/2/0。

2026-09-27 CANON-REGJUNK-XMM-EXTRAOUT-0001 + CANON-REGJUNK-INRAX-LIVEVAR-0001
（Phase 3 整体退役）：inject_raw_ops 的 Phase 3（线性指令序把每个寄存器偏移的
首个 free 读提升为 INPUT varnode）整体移除。它是 faithful Heritage 移植落地前
（2026-06-23 f4be0bb6）的 June-era 临时机制，与 Ghidra 模型系统分叉：Ghidra 中
寄存器 INPUT varnode **只**由 Heritage 支配树感知的 renameRecurse 创建
（heritage.cc:2499-2503 空栈 → newVarnode+setInputVarnode），时点在
ActionFuncLink 为锁定原型 call 挂输出（coreaction.cc:1551）与 Heritage::guardCalls
建 call 效果 INDIRECT（heritage.cc:1443-1527）之后；线性序问的是"前面有没有写"，
而正确的 reaching-def 是支配性问题——call 阴影下的读（inject 时 CALL 还没有输出）
被误提升为 `in_RAX` 后，Heritage::collect 把 input 归类为 INPUT 而非 free 读
（heritage.cc:342-343），永不重绑。双侧 stage drill 钉定的两处事件级分叉：
ap_field_noparam 循环 phi `RBX = RAX(i) ? RBX-sub`（oracle 在 propagatecopy 后为
`RAX(callout) ? RBX-sub`，ruleaction.cc:3924-3956）→ `in_RAX` 独立活变量；
ap_fini_vhost_config 首个 `pxor %xmm0,%xmm0` slot 0 被 Phase 3 的偏移去重抢占提升
为 `XMM0(i)`、slot 1 保持 free 绑到循环 phi，RuleTrivialArith 的同输入塌缩
（ruleaction.cc:2362-2380 要求两 slot 为同一 varnode）不点火 → 双 XMM0 拷贝 +
extraout_XMM0 物化 + XMM0 误升第 3 参（第二个 pxor 偏移已被去重，双 slot 都绑
phi，塌缩成 `(undefined1[16])0` 与 golden 一致——机制的自然对照）。效应尾
（PRINTC-BADSPACEBASE-RENDER-0001）由 heritage 晋升路径等价承接
（`Funcdata::set_input_varnode` 的 cc:340-373 尾）；oracle 动作序不变
（fullloop:mainloop heritage 先于 spacebase，coreaction.cc:5506）。观测：
canon httpd skeleton 139→70（defects=0 numbering=0；ap_field_noparam/
ap_strcasestr/ap_pregcomp/ap_make_dirstr_parent 归零），canon curl 逐字节恒等
（md5 51cc85d2），镜面五面全钉值零漂移。

2026-09-25 CALLSPEC-0001 重放（CALLIND 锚定臂）：锚定环补 `CPUI_CALLIND` 臂——
`flow.cc:340-342`（xrefControlFlow CALLIND case）→ `setupCallindSpecs`
（flow.cc:704-723）的换写镜像：`FuncCallSpecs::new_for_op` 对 CALLIND 不读 in(0)
（fspec.cc:4931-4938 ctor 仅 CPUI_CALL 分支取 entryaddress，间接调用保持 invalid；
Rudra `new_for_op` 同语义：非 CALL opcode 即 `direct_target=None`），**无 in(0) 换写**
（annotation swap 只在 overridden-to-direct 臂 flow.cc:717-721，本 override-free
driver 路径不可达），`register_specs` 门同 CALL 臂（flow.cc:709 qlst 注册 riding
CALLSPEC-DRIVER-0002 模型门）。动机：iced lifter 对寄存器间接调用发 CPUI_CALLIND
（x86_lift.rs:4890-4894），旧注释"lifter 只产 CALL"系 CALLSPEC-DRIVER-0001 时代
过期声明——lifter 出生 CALLIND 全程无 FuncCallSpecs → ActionFuncLink 不激活 →
heritage guardCalls 不注册试验 → 间接调用零实参。重放验证（基=master 838f73e2）：
httpd 默认脸 1257→**1217**（ap_vhost_iterate_given_conn 51→**9**；main 687→689，
+2 为 difflib 对齐回声——归一化差异行多重集对比证实无新缺陷族；主噪声族
`plVar9[3]=plVar9[3]` 自赋值 5 条、raw 指针存取形、零实参间接调用全部消除，
`iVar4 = (*(code *)pVar11)((long)plVar12 + 0x34,uVar9);` == canon 逐形）；curl
**577/0/0 字节恒等**；双跑 cmp 恒等；投影银行 391/391；cargo test --lib
1712P/1F（预存 test_nonzeromask_pipeline_wiring）。历史注记：2026-09-25 CALLSPEC
车道在 b708e1cf 上 A/B 时 httpd 1123→1175（main +88，自赋值换形+吸收缺口新表面）
违门回滚；本重放前实测该吸收缺口已被 master 演进关闭（GETPARAM 的 merge.rs
inflate_test 现聚合 + check_implied_cover 惰性 cover 修复落在 b708e1cf 之后），
+88 缺口不复现（+2 对齐回声），解锁条件满足。残差归因：`uVar9 = plVar12[0xb];`
类 LOAD 物化 = GETPARAM-STORECROSS-ALIASGATE-0001（coreaction 保守 alias 门）；
`void(*)()param_2` vs canon `code *UNRECOVERED_JUMPTABLE` = CALLSPEC 移交
(b)(c)（flow setter + coreaction lookForBadJumpTables 消费者，coreaction 车道域）；
LAB_0012bff3 零实参 `strcasecmp()` 为 base 同在的预存残差（非本臂引入）。

2026-09-27 REGAP-FUNCINJECT-CODEREF-0001（coderef 臂落地）：Phase 1 输入循环补
`PcodeEmitFd::dump` 的 coderef 臂（funcdata.cc:892-897）——`if (op->isCodeRef())` 对
**首输入**（i=0，`i += 1` 后跳过 cc:904-907 的 newVarnode walk）调用
`newCodeRef(Address(vars[0].space, vars[0].offset))`（funcdata_varnode.cc:222-233）：
**1 字节** + `Varnode::annotation`（"will hold no value in the data-flow"）+ 核心
`code` 类型（`TypeFactory::getTypeCode`，sleigh_arch.cc:233 建 "code" 核型；Rudra 经
`code_ref_datatype()` 直构等值对象）。coderef 旗标仅 BRANCH/CBRANCH/CALL 三个 TypeOp
构造器置位（typeop.cc:586/605/663；BRANCHIND/CALLIND 刻意不带——op.hh:194
isCodeRef），Rudra 以 `matches!(opcode, BRANCH|CBRANCH|CALL)` 镜像；同一臂
`inject_raw_ops_single`（本文件）早已有，本路径 SLEIGH 换装（sleighp3）后漏——
此前 iced 期目标 1 字节无范围重叠故不可见。**根因链（REGAP 车道双侧钉死）**：
SLEIGH 换装后 BRANCH/CBRANCH 目标以 8 字节 ram varnode 入 Funcdata，ap_pregsub 内
相距 5 字节的两个分支目标（0x12e4c0/0x12e4c5）范围重叠 → heritage 全局
piece/别名机制在纯跳转块 @12e43c 造非 marker `PIECE` → `BlockBasic::isDoNothing`
（block.cc:2596/2618，hasOnlyMarkers cc:2578）恒 false → ActionDoNothing 连锁删除
（oracle @2e43c→@2e43a）失效 → 结构化 fixpoint 振荡（oracle 6 轮收敛 vs Rudra
3 轮环）→ 终态 while 取向翻转+早退合并 = ap_pregsub +103。**验收（基=master
6a458387 亲测，数字==REGAP A/B 预演逐项）**：canon httpd **311→148/0/0** 零回退
（输出 md5 5b04633b==REGAP 预演逐字节；ap_pregsub 122→13[结构=golden 同构，残 13=
变量重编号族]/ap_no2slash 22→8/ap_make_dirstr_prefix 12→0/ap_fini_vhost_config
45→32/ap_getparents 24→19/ap_update_vhost_from_headers 7→5/ap_matches_request_vhost
等 4×2 行函数→0，其余 24 函数 0→0 恒等）；canon curl **157/0/0 md5 51cc85d2
逐字节恒等**（修复对 curl 零行为面）。

2026-09-27 HERITAGE-CALLOUT-LOADSPLIT-0001（Phase 3 CALL/CALLIND 返回寄存器盾）——
**MB25 合并超解注记**: 本节钻探记录保留;其盾补丁落点（Phase 3）已被 MB24 REGJUNK
整层退役（funcdata.rs "Phase 3 (register-input pre-promotion) REMOVED"）,根因同源
（Phase 3 近似层的误晋升）,补丁 moot 弃置,canon 收敛已由 MB24 regjunk 覆盖:
Phase 3 的线性 read-before-write 输入晋升为 CALL 补齐返回寄存器盾——注入期 raw
CALL/CALLIND **无输出 varnode**（SLEIGH `call` 语义不产结果；`PcodeEmitFd::dump`
funcdata.cc:884-890 仅在模板带输出时建 varnode），返回 varnode 由
`ActionFuncLink::funcLinkOutput`（stage funclink，本 pass 之后）才挂上；原
"记录 call 输出为已定义" 的盾臂因输出恒 None 而成死代码，**call 后首个 RAX 读**
（LOAD-through-RAX 形 `mov rcx,[rax]` → `u = LOAD ram,RAX`）被永久晋升为 `in_RAX`，
而 heritage renameRecurse 对 heritage-known 读的忠实跳过（heritage.cc:2495
`if (vnin->isHeritageKnown()) continue;`）使其再不可改写——返回值整链断源（deadcode
合法删除失读者的 call 出口+phi），类型断源后 PTRADD 印算术形。修复：CALL 臂在无输出
时仍把模型返回寄存器（RAX=register offset 0x0，与 funcLinkOutput 无存储回退同约定）
记入 `defined_reg_offsets`；CALLIND 同盾（oracle `Heritage::guardCalls` 经
callspec 逐 call 处理，CALL/CALLIND 同列 heritage.cc:1451），且盾在**该 op 自身
输入处理之后**落位（call 目标读保留 call 前语义）。oracle 语义对齐：带锁定输出时
call 出口即该 range 的 def；无输出/未知效果时 guardCalls 以 INDIRECT
（unknown_effect/return_address，heritage.cc:1511-1520）或 indirect-creation
（killedbycall，cc:1521-1525）补写——oracle 中 call 后的返回寄存器读**永不**晋升为
输入。验收（基=master 48146429 双 worktree A/B 亲测）：canon httpd
**139→108/0/0**（ap_strcasestr `__ctype_tolower_loc(); lVar3 = *in_RAX` →
`pp_Var4 = __ctype_tolower_loc(); p_Var3 = *pp_Var4` + `p_Var3[V]` 索引形==golden；
附带同根 REGJUNK-INRAX 族收敛：ap_field_noparam/ap_make_dir_str_parent `in_RAX`
声明归零、ap_pregcomp 实参恢复 `ap_regcomp(uVar2,param_2,param_3)`——四函数
diff-blocks 4→1/3→1/11→3/3→1 全向 golden 收敛，五函数外零漂移）；canon curl
**157/0/0 逐字节恒等**（96429B cmp 双零）；镜面五面走 `inject_raw_ops_single`/
followFlow 路径不经 Phase 3，字节级不受影响。新测
`test_inject_phase3_call_shields_return_register`（call 后 RAX 读保持 free）+
`test_inject_phase3_callind_shields_return_register`（CALLIND 目标读仍晋升+返回读
盾住）。登记注记：ticket 面写域假设（src/heritage.rs 载荷拆分缺陷）被 fixture-first
drill 证伪——LOAD→unique+COPY→reg 为 SLEIGH 提升正形（oracle 同形），
heritage.rs collect/guard/renameRecurse 对该链路逐行核过无缺陷，真根在
本 Phase 3 晋升近似层。

#### 它在主链路中的位置

```text
disasm / lifting
  -> raw_ops: &[PcodeOpRaw]
  -> Funcdata::inject_raw_ops(...)
  -> PcodeOp / Varnode / block graph 初步建立
```

#### 典型职责
根据当前文档与工程定位，这个方法通常负责：

1. 把每个 `PcodeOpRaw` 转成 `PcodeOp`
2. 为输入输出创建或挂接 `Varnode`
3. 建立基础图关系
4. 识别基本块边界
5. 为后续 block / CFG / heritage / ActionDatabase 提供初始结构

#### 基本块划分（2026-06-28 重大修复）

`build_blocks_from_ops` 现在按 Ghidra 式（BlockGraph::copyBlocks / Funcdata::structureReset）划分基本块，在**两种**点分裂：
1. **terminator 之后**（BRANCH/CBRANCH/BRANCHIND/RETURN）—— 原有逻辑
2. **跳转目标地址处** —— **新增**：收集所有 BRANCH/CBRANCH 的目标地址（input[0] offset），在对应 op 索引处也分裂

此前只做 (1)，导致跳转目标落在块中间时无法解析（CBRANCH target 地址不等于任何块 start_addr），边被静默丢弃。实测 curl main 有 56 个 / 全局 182 个 CBRANCH 目标未匹配，丢失大量回边，while 循环恢复从 ~6 降到 1。

修复后：curl main 块数 102→123，回边检测 3→8（3 个独立循环头：5/7/26，接近 Ghidra 的 6 个），结构化循环数从 8 提升到 17。736/736 测试通过，curl 24/24 gcc 审计。

**已知影响**：httpd 大函数（如 main 12 循环）goto cascade 轮次增加（40 轮），整体变慢但无正确性回归。性能优化是后续工作。

#### 无 op 目标地址的合成边界（2026-08-30 僵尸决策块成因修复）

2026-06-28 的修复只覆盖"目标地址有 op"的分裂。Rudra 提升器对若干指令产出**零个** p-code op
（x86_lift.rs:602 的 push/pop 臂只处理 call/ret；movzx/movsx 无臂），因此 BRANCH/CBRANCH 的
目标地址可能不存在任何 op —— 目标既不分裂也不可解析，CBRANCH 目标边被静默丢弃，
块从出生起就是 "CBRANCH lastOp + 单出边" 的**僵尸决策块**，违反 Ghidra 不变量
（branchRemoveInternal, funcdata_block.cc:203-204 在 sizeOut==2 时先销毁 cbranch，
CBRANCH 永不活得比第二条出边久）。实测 httpd 全局 260 例（curl 0 例）；
下游症状：ap_strcasecmp_match 数据流退化（垃圾常量 0xbaadef）、
determinedbranch 对畸形块跳过导致 mainloop 反复 structureReset 不收敛。

修复语义（Ghidra 对齐）：Ghidra 的 flow 驱动建块（flow.cc FlowInfo）使**每个函数内跳转目标
都是块起点**——在 Ghidra 中每个指令至少产出一个 p-code op，目标地址必然命名一个 op；
Rudra 对 `[baseaddr, baseaddr+size)` 内无 op 的目标地址插入**合成块边界**：块起始地址即目标
地址，吸收其后第一条地址大于目标的 op；连续合成边界（或尾部）产生空块，空块按指令顺序
向下一块落空边。函数范围外的目标（tail-jump/extern）维持丢弃行为。

修复后：httpd 僵尸决策块 260→0；ap_strcasecmp_match 0xbaadef 消失、`'*'`(0x2a) 判定与
do-while 循环骨架恢复（oracle 侧证据：golden ghidra_httpd_1204.c 同函数的 LAB_0012e022
正是 Ghidra 在同类无 op 目标地址 0x2e022 处的标签）；curl 3068/0/0 字节级不变。

#### inject_raw_ops_with_uniq —— op 创建时间的流序铸造（2026-09-28 CANON-DECLORDER-TRANSPORT-0001）

oracle 的 op 创建时间即 FlowInfo 走序（提升在 flow.cc:421 processInstruction 内运行；
`PcodeOpBank::create` 铸 `SeqNum(pc, uniqid++)`，op.cc:941-948），而
`HighVariable::compareName` 的最终平局键直读它（`vn->getDef()->getTime()`，
variable.cc:485-486）。canon 线性传输按**地址序**注入，uniq 因而是地址序——每个
flag 全平的代表权之争（ap_getparents uVar4：oracle ECX t=598 < EAX t=747，地址序
下反转）都选错名字代表 → linkSymbol 建错地址 → 声明槽错位（httpd DECL 族 8 行）。

新入口 `inject_raw_ops_with_uniq(raw_ops, instruction_rank)`：op 列表/集合、块划分、
所有下游传输（halt 旗标、jumptable 恢复、v3sig 安装、管线）与 `inject_raw_ops`
逐字节相同——**只**把 SeqNum uniq 改由调用方提供的"指令地址 → 访问序位"表铸造：
`uniq = rank[instr] * 4096 + 指令内序数`（4096 > 单条 x86-64 SLEIGH 指令可发射的
p-code op 数；跨距保证唯一性）。op 经 `PcodeOpBank::create_with_seq` 创建——保留
bank 的完整 create 侧状态（TypeOp 旗标、code-list 注册、历史 alivelist 插入——
create ⇒ alive 契约），仅编号取 clone 形态的显式 SeqNum（op.cc:957-969；裸
`create_seq` 缺 flags/lists/alivelist 三半，实测注入后 alivelist=0、RETURN 全隐
身、Heritage 全域 panic）。
uniqid 计数器单调尾保持（create_with_seq 抬过注入最大值），管线期新建 op 的时间
仍恒晚于一切注入 op——与 oracle（walk op 0..N，管线 op 在后）同构。

**为什么不重排列表**（本车道第一方案的教训）：`build_blocks_from_ops` 的落空边解析
是列表序语义（fallthru = 列表后继块 i+1），把 op 列表重排为访问序会全局打碎 CFG
（httpd 实测 34→1108）。地址序列表 + 流序 uniq 的解耦只改 `getDef()->getTime()`
的读数，风险面最小。rank 表由 examples/httpd_decompile.rs 的 `flow_visit_uniq_map`
在 scratch Funcdata 上重放 mirror 已验证的 `follow_flow_range` 产生（含尾部未访问
指令的地址序补齐）；curl canon 面本就走路径加载，无需此钩子。

已知残余：httpd skeleton 2214→2374（+160）、defects 5→5 —— 因 pop/movzx/movsx 指令
仍无 p-code（disasm/x86_lift.rs 提升缺口，非本文件 write-set），正确 CFG 下这些区域
以空 if/else 形态出现，等 lifter 补齐后消解。

Rudra 侧回归锁：`test_build_blocks_synthetic_target_creates_block_no_zombie` /
`test_build_blocks_external_target_edge_still_dropped` /
`test_branch_remove_internal_destroys_cbranch_at_two_out`（funcdata.rs tests）。

#### 块 cover 初始化（2026-09-24 标号地址漂移修复，ACTION-REWORKFIX-STRUCT-0001）

`build_blocks_from_ops` 建块时此前从不调用 `set_initial_range` —— 块的 cover 恒为空，
`BlockBasic::get_entry_addr`（block.rs，对 block.cc:2302）落入"首个 op 地址"回退臂。
死代码消除删除块首 op 后（实测：httpd 0x2cfc6/0x2d7f0 的栈 canary 重载 `mov`、
0x2e410 的循环增量 `add`），回退地址漂移到下一条指令，所有经
`emitLabel`（printc.cc:3164-3193）取 `getEntryAddr` 的 goto 标号跟着漂移
（`code_r0x0012cfcb` vs golden `LAB_0012cfc6`，5 字节偏移同族）。

修复语义（flow.cc:1004/1016 `setBasicBlockRange(cur, start, stop)` → block.cc:2625
`setInitialRange`）：块建好后立刻锚定闭区间 `[start, 最大 op 地址]`；cover 是块的
**原始指令区间**，不随后续 Action 删 op 移动。合成空块锚定退化区间 `[taddr, taddr]`。

修复后：httpd `goto LAB_0012cfc6`/`LAB_0012d7f0` 标号与 golden 同址同名
（ap_parse_vhost_addrs / ap_update_vhost_from_headers 两站点）；httpd skeleton
2148→2092、defects 0、numbering 0；curl 2152/0/0 字节恒等。残余同族：
ap_pregsub `LAB_0012e414` vs `LAB_0012e410` —— 0x2e410 块（`add $1,%r13`）在
Rudra 数据流中整个死亡被重工作删除（golden 保留增量），属 var 级 dead-code 差异，
非 cover 机制缺口（已登记 ACTION-REWORKFIX-STRUCT-0001 残余项）。

#### CBRANCH 出边顺序（2026-08-30 边序反转修复,HTTPD-EMPTYELSE-LIVEARM-0001）

Ghidra `FlowInfo::generateBlockEdges`(flow.cc:960-967)对 CBRANCH 先 push **fall-thru 边**、
再 push **branch target 边**;`connectBasic` 按此顺序 `bblocks.addEdge`,因此出边约定为
**out[0]=fall-through(false),out[1]=branch target(true)**——与 `FlowBlock::getFalseOut()=getOut(0)` /
`getTrueOut()=getOut(1)`(block.hh:294-301)及 `BlockBasic::negateCondition` 的"swap 边+翻
boolean_flip/fallthru_true"配对维持极性不变。Rudra 此前按 [target, fallthru] 顺序建边,
使全部依赖 `getOut(0)/getOut(1)` 真/假语义的消费者读反:

- `ActionConditionalConst::findConstCompare`(coreaction.cc:4496):INT_EQUAL 的 constEdge=1
  选取"值==常量"的一侧;边序反了以后 constBlock 落到错误一侧,把分支常量代入**错误路径**
  支配的块。实证(httpd ap_getparents 0x2e6a3 `je 2e768`,cond=INT_EQUAL(uVar4_phi,1)):
  Rudra 把 uVar4=1 代入 uVar4!=1 支配的菱形(s[uVar4-1]→s[0],s[uVar4-2]→s[-1],
  Y 臂 param_1+(uVar4-1)→param_1 折叠为 identity)→ Y 臂只剩活 PIECE/COPY(implied,
  print 无语句)→ 结构化出现空 else;oracle 同区域(12.0.4 探桩 livearm_opsdump)三臂
  INT_ADD 全部非 implied、条件不特化,golden 为 if/else-if/else 三臂链。
- jumptable 真槽位索引(`true_slot = flip?0:1`,jumptable.rs)同类读反风险。

修复后:httpd **defects 3→0**(ap_getparents 2 + ap_pregsub 1 空 else 全部消失,复合条件
链恢复),skeleton 2231→2277;curl **字节级不变**(3095/0/0,124 函数 byte-identical)。
Rudra 侧回归锁:`test_build_blocks_synthetic_target_creates_block_no_zombie`
(更新为断言 edge0=fallthru@0x1007, edge1=synthetic target)。

#### 入边顺序 = Ghidra 走序（2026-09-27 合并块入边序修复,CANON-COPYJUNK-NOOP-ORDER-0001）

出边极性（上节）之外，`collectEdges` 的**入边顺序**同样是决定性语义：Ghidra 的
`PcodeOpBank::create` 把每个 op 追加到 dead list 尾部（op.cc:941-948
`deadlist.insert(deadlist.end(), op)`），dead list 的迭代序 = **op 创建序**；而 op 创建序
= FlowInfo 地址流走序 —— LIFO `addrlist` 栈（flow.cc:545-580）：指令的 fall-through 在
`processInstruction` 尾部 push（cc:479-480），分支目标在 `xrefControlFlow`/`newAddress`
（cc:219-234，已 visited 的目标不 push）**先于** fall-through push，因此 pop 序永远是
"先走直落、路径终结后再走队列目标"。`FlowInfo::collectEdges`（flow.cc:906-977）按该
创建序扫 op 并逐终结符收边 —— CBRANCH 先收 fall-thru 边再收 branch 边（cc:960-966）、
BRANCH 只收 branch 边（cc:927-932）、非终结符块尾收直落边（cc:968-973）；
`connectBasic`（cc:1021-1037）按收集序 `addEdge`。**合并块的入边序因此是"源块被走序
发现序"，不是地址序。**

入边序的下游链条（ap_getword 0x12e9f0 双侧 projection 钉死）：heritage 的 MULTIEQUAL
槽序一比一映射入边序（rename 后继环 walk，heritage.cc:2531-2552）→ `mergeOp` /
`trimOpInput`（merge.cc:692-712）把无法与输出 high 合并的 φ 输入在**该槽入块的块尾**
（`bb->getStop()`）插 COPY trim → 同源 trims 成组后 `ActionDominantCopy` →
`processCopyTrims` → `buildDominantCopy`（merge.cc:1151-1238）在公共支配块尾造单条
dominant COPY 并 `totalReplace` 掉旧 trims。走序正确时，join-φ 的 then 侧（base）与
loop-head φ 的 entry 侧都 trim base → 两组同源 COPY 塌缩成**一条支配 COPY**
（golden `pcVar6 = pcVar3;` 提升形，两 φ 同吃）；地址序时 join-φ 的 else 侧（iter）被
trim → 两组 COPY 不同源 → dominant 不可组 → 逗号内联 `(pcVar5 = pcVar6, ...)` + 尾部
多余 COPY 残骸（V=V 族）。

修复：`build_blocks_from_ops` 的加边循环改为先模拟 Ghidra 走序（块粒度等价：栈起于
entry 块，per 块 push 未访问目标再 push 直落，LIFO pop 即直落先行；已访问目标不重
push），再按**访问序**加边（每 CBRANCH 仍 fall-thru 先、branch 后，保持出边极性契
约）。走序不可达的块（Rudra 线性注入独有的从未流入区域）按原地址序追加，行为与修复
前完全一致。

修复后（canon，基=master cc744670）：httpd **70→62/0/0** —— ap_getword 6→0（函数体
逐字 golden：`pcVar3 = (char *)*param_2; pcVar6 = pcVar3; if((*pcVar3 == param_3) ||
(*pcVar3 == '\0'))` 提升形+无逗号/尾 COPY）+ ap_pregsub 6→4（两处 COPY/LOAD 语句序
对齐；余 4=声明序族）；curl **110/0/0 字节恒等**。Rudra 侧回归锁见
`build_blocks_walk_order_edge_sequence` 等 tests（funcdata.rs tests）。

#### 为什么这个方法重要
如果没有这一步：

- raw p-code 只是“线性原始语义记录”
- 不能方便地进入函数级图分析
- 后续 Action / SSA / 输出层都缺少统一工作对象

因此这一步可以看作：

> 从“原始语义序列”进入“正式函数分析容器”的桥

#### 输入要求
`raw_ops` 应满足最基本的顺序性和语义完整性，例如：

- 操作顺序正确
- 输入输出槽位可解释
- 地址 / 顺序信息可关联
- 不应把缺失支持的语义静默吞掉

#### 调用后预期
调用后，`Funcdata` 应进入“可供进一步分析”的状态，但**不应自动被理解为“全部分析已经完成”**。

更合理的理解是：

- block 初始结构可能已建立
- 正式 `PcodeOp` / `Varnode` 图已建立
- 后续还需要进入 heritage / Action / type / print 等阶段

---

### `pub fn clear(&mut self)`

清空与反编译（analysis）关联的全部状态（`Funcdata::clear`，
funcdata.cc:84-112 逐步对齐）。

#### 语义
按 Ghidra 语句顺序执行：

1. `flags &= ~(HIGHLEVEL_ON|BLOCKS_GENERATED|PROCESSING_STARTED|
   TYPE_RECOVERY_START|TYPE_RECOVERY_ON|DOUBLE_PRECIS_ON|RESTART_PENDING)`
   （cc:88-89；七位分析期旗标清零，`BLOCKS_UNREACHABLE`/`PROCESSING_COMPLETE`/
   `JUMPTABLERECOVERY_*` 等保留位不动），并同步复位独立的
   `restart_pending: bool` 镜像。
2. `high_level_index = 0`（cc:91；`clean_up_index`/`cast_phase_index` 无
   Rust 字段，coreaction.rs 标记为忠实 no-op，此处为 no-op）。
3. `min_laned_size` 重新从 Architecture 派生（cc:93，无 lane 记录时为 -1，
   Rust 用 `u32::MAX` 表示同一哨兵）。
4. localmap 建模（cc:95-96）：`scope.clear_symbols_wholesale()`（symbols +
   nametree + category_lists + mapentry_log 同拍清空——镜像 oracle
   clearUnlocked→removeSymbol→removeSymbolMappings 的原子对，
   database.cc:2117-2149；2026-09-26 GENWIRE 起 start_processing/clear
   两 seam 统一换用，PIPE-RESTART-0001 链②——重启第二遍在 populated
   scope 上清空时，旧 `symbols.clear()` 单清 arena 会留下三处 id 配对
   结构的陈旧索引：mapentry_log 残留条目在 materialize_maptable/
   entry_in_use 索引死槽 panic，且 slot id 从 0 复用会让 nametree 残留
   key 把名字错绑到新占位符号）+ 伴生 `high_symbols`/
   `symbol_entry_cache` 清空，`min_param_offset`/`max_param_offset`
   复位（varmap.cc:443-444）；typelock 符号存活为已登记 MISMATCH 残差
   （MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001）。
5. `active_output = None`（cc:98 clearActiveOutput）。
6. `funcp.clear_unlocked_output()`（cc:99；fspec.rs 侧为简化版，残差同上）。
7. `union_map.clear()`（cc:100）。
8. `clear_blocks()` → `obank.clear()` → `vbank.clear()`
   （cc:101-103；obank uniqid 归 0，vbank uniqid 归基址、create_index 归 0）。
9. `clear_call_specs()`（cc:104）。
10. `clear_jump_tables()`（cc:105）：override 表调用忠实的
    `JumpTable::clear()`（jumptable.cc:2739-2758，保留
    opaddress/maxaddsub/maxleftright/maxext/collectloads 永久域）后保留，
    非 override 表丢弃。
11. overrides 与 `laned_map` 不清（cc:106 注释；Ghidra 亦无清除调用点）。
12. `heritage.clear()`（cc:107）。
13. `merge_state.clear()`（cc:108 covermerge.clear()）。

#### 作用
主要用于以下场景：

- 重跑分析流程（restart 循环：clear 后 `is_proc_started()==false`，
  startProcessing 可再次进入 —— Ghidra ActionRestartGroup 的前提）
- 测试中复位函数容器
- 在局部失败后回退到更干净的状态
- 重新注入或重新构建函数图

#### 注意事项
“清空”不等于“回到刚创建时的裸状态”：保留域（override JumpTable、
typelock 符号、localoverride、lanedMap、processing_complete 等旗标位）
正是 Ghidra restart 语义的组成部分；两侧差集见
`tools/run_merge_clear_lifecycle_oracle.sh` 的 registered_mismatch_domains。

---

### `pub fn num_heritage_passes(&self) -> i32`

获取已经完成的 heritage pass 数量。

#### 语义
返回当前函数在 heritage / SSA 相关处理中已经执行过的轮次数量。

#### 作用
这个接口主要用于：

- 调试 SSA / heritage 过程
- 判断分析推进程度
- 记录某些多轮处理是否发生
- 辅助验证或日志输出

#### 设计含义
它反映出 `Funcdata` 不只是静态容器，还会记录“分析过程中的阶段性状态”。

---

## `Funcdata` 在当前主链路中的推荐理解方式

如果你需要快速把握 `Funcdata` 的工程角色，可以用下面这段话概括：

> `Funcdata` 是 Rudra 当前单函数分析的核心总容器。  
> 它负责承接 raw p-code 注入后的正式 IR、控制流结构、分析状态与附加语义信息，并作为后续 SSA、ActionDatabase、变量恢复、类型传播和打印输出的函数级工作上下文。

---

## 与旧架构的区别

在历史文档里，你可能会看到围绕以下对象组织的旧式描述：

- `Program`
- `analysis/`
- `codegen/`
- 直接 `Decompiler -> analyze -> generate_c_code`

这些叙述在当前工程里已经不再是最准确的主线。

相较之下，当前更贴近现状的主线是：

```text
PcodeOpRaw
  -> Funcdata
  -> PcodeOp / Varnode / Block
  -> Heritage / Actions
  -> PrintLanguage / PrintC
```

因此，`Funcdata` 的 API 文档应以“**当前函数分析容器**”为中心，而不是继续围绕旧版 `Program` 风格容器来写。

---

## 使用建议

如果你准备围绕 `Funcdata` 开发或调试，建议优先联动阅读：

- `address.md`
- `varnode.md`
- `op.md`
- `pcoderaw.md`
- `block.md`
- `heritage.md`
- `action.md`
- `printc.md`
- `../data_contract.md`

推荐顺序：

1. 先理解 `Address`
2. 再理解 `Varnode` / `PcodeOp`
3. 再理解 raw p-code 如何进入 `Funcdata`
4. 再看 `heritage` 和 `ActionDatabase` 如何消费 `Funcdata`
5. 最后看 `PrintC` 如何从函数级上下文输出结果

---

## 文档维护注意事项

后续维护本文时，请特别注意以下几点：

### 1. 不要把 `Funcdata` 写成“完整产品 API”
它是当前核心内部架构对象，更偏工程主链路，而非最终用户直接使用的高层门面。

### 2. 不要把概念对齐写成行为对齐
即使它对应 Ghidra 的 `Funcdata`，也不能直接写成“已与 Ghidra 完全一致”。

### 3. 不要把注入成功写成分析完成
`inject_raw_ops(...)` 打通的是桥接层，不代表最终变量恢复、类型恢复、输出结构化都已完成。

### 4. 如果构造流程变化，要同步更新本文
尤其是以下变化发生时：

- `new(...)` 签名变动
- `inject_raw_ops(...)` 职责变动
- `Funcdata` 不再承担当前这些主干角色
- self reference 或共享容器模型变化
- block / heritage / action 的耦合方式变化

---

## 一句话结论

`Funcdata` 是 Rudra 当前架构里最关键的函数级分析容器之一。  
它不是旧版 `Program` 的简单别名，也不是单纯的数据壳，而是当前反编译主链路中承接 raw p-code、组织图结构、支撑分析动作并服务最终输出的核心上下文对象。
### 2026-06-23（续）：test_bool_condition 搜索 BlockList

- 测试现在搜索 BlockList 内部的 BlockCondition（适配 interleaved cat）。

### 2026-06-23（续）：test_bool_condition 搜索 BlockList

- 测试现在搜索 BlockList 内部的 BlockCondition（适配 interleaved cat）。

## 2026-06-26：Funcdata P-code op 编辑 API（funcdata.hh:281-479）

新增与 Ghidra 一致的 P-code op 构造/编辑方法，解锁 ruleaction/coreaction
中需创建或改写 P-code 的 Rule/Action（此前 Rudra 仅原地改 op 字段，无法
创建新 op）。忠实对应 funcdata.hh：

- `new_op(inputs, pc)` — 分配适配层：新 op 初始位于 dead list，直到某个
  `op_insert_*` 将其接入基本块；但底层还不能表达 Ghidra 的 NULL opcode
  与固定数量 nullable input slots，因此完整函数行为仍是 **MISMATCH**。
- `new_op_with_seq(seq)` — 通过 `PcodeOpBank::create_seq` 导入显式 SeqNum；
  `(Address, time)` 保持为不可变 op 身份，并以 `time` 推进 bank 的 uniqid，
  而可变 `order` 只表示接入基本块后的块内位置。该闭包不消除复制语义差异：
  Ghidra `SeqNum` copy constructor 不复制 `order`，Rust 当前 `SeqNum: Copy`
  会复制它，因此直接观察 copied order 仍是 **MISMATCH**，不能由本次
  SeqNum 部分 fixture 推导为完整 copy-constructor `MATCH`。
- `new_unique_out(s, op)` — `Funcdata::newUniqueOut` (281)
- `new_constant(s, val)` — `Funcdata::newConstant` (283)
- `new_unique(s)` — `Funcdata::newUnique` (288)
- `new_unique_typed(s, ct)` — `Funcdata::newUnique(int4 s, Datatype *ct)` 的 typed 形（funcdata_varnode.cc:83-95）。**2026-09-24（PM-F2S）**：补齐 `ct` 参数通道——None 默认工厂 unknown base（cc:86-87），Some(ct) 经 `VarnodeBank::createUnique(s, ct)` 成为新 varnode 的数据类型（ctor `type = dt`，varnode.cc:583）。`Merge::allocateCopyTrim`（merge.cc:416/429）与 `Merge::trimOpOutput`（merge.cc:668/677）的 trim COPY 输出必须经此通道携带源 varnode 类型；缺失时 setcasts 的 castInput 会给 COPY 输入多插一个 CAST（file2string.part.0 投影 ord337 分歧根因之二）。
- `op_set_opcode(op, opc)` — `Funcdata::opSetOpcode` (463)。**2026-07-02**：对齐 `PcodeOp::setOpcode` (op.cc:276) — 清除 opcode 派生 flag 位（CALL/BRANCH/RETURNS/MARKER/CODEREF/...）后按新 OpCode 重设。修复前 CPUI_CALL 的 output 永远不带 CALL flag → ActionMarkExplicit 的 `def->isCall()` 失败 → output 未被 force-explicit → ActionMarkImplied 标 implied → printc 跳过 CALL 语句（curl 丢失约 130 处调用）。
- `op_set_input(op, vn, slot)` — `Funcdata::opSetInput` (467)，扩展 inrefs、维护 descend
- `op_insert_input(op, vn, slot)` — `Funcdata::opInsertInput`（funcdata_op.cc:308-317）：
  扩槽（`PcodeOp::insertInput` op.cc:311-318，`slot` 及之后的旧输入右移一格）后
  **经完整 `op_set_input` 路径**落位——常量去重（cc:108-115）、fresh 空槽跳过
  `opUnsetInput`（cc:118-121 NULL guard）、`addDescend` free 检查 + coverdirty
  （varnode.cc:330-340）。**2026-08-17 收编**（VARNODE-ADDDESCEND-THROW-0001 子项）：
  此前直接 `descend.push` 绕过 opSetInput，是 addDescend 同族最后一个生产者缺口
  （缺 free 检查/coverdirty/常量去重）。Rudra `Vec` 无法物化 Ghidra 的瞬态 NULL
  槽，实现将尾部 split_off 后由 `op_set_input` 追加进新槽（两步间所有 Ghidra 语句
  对 NULL 槽均为 no-op），无需分配可观察的 sentinel Varnode。
- `op_remove_input(op, slot)` — `Funcdata::opRemoveInput`（funcdata_op.cc:291）：先按
  `opUnsetInput` 擦除旧 Varnode 的一个 descendant edge，再从 Rust `Vec` 删除该槽。
- `op_insert_before(op, follow)` — `Funcdata::opInsertBefore`
  (funcdata_op.cc:345)，按 `follow` 的 `BlockBasic.ops` 定位，并把紧邻
  `follow` 的 INDIRECT 组留在原位。
- `op_insert_after(op, follow)` — `Funcdata::opInsertAfter`
  (funcdata_op.cc:373)，按块内顺序插入；非 MULTIEQUAL 会越过块首的
  MULTIEQUAL 组，INDIRECT 的 alive iop 目标会成为实际插入锚点。
- `set_input_varnode(vn)` — `Funcdata::setInputVarnode` (funcdata_varnode.cc:340)：将
  varnode 提升为函数输入（overlap 去重 + `vbank.set_input`）。**2026-07-05 新增**，
  用于 heritage rename 的 empty-stack promotion（heritage.cc:2502/2512）。委托给
  `VarnodeBank::set_input_varnode`；含 cc:363-364 属性遍与 cc:365-370 效果尾
  （unaffected/return_address 标志，经 `FuncProto::try_has_effect`）。
- `delete_varnode(vn) -> Result<()>` — inline `Funcdata::deleteVarnode`
  （funcdata.hh:294）：委托给 checked `VarnodeBank::destroy_varnode` 并传播
  `Deleting integrated varnode`/ownership 错误。用于 heritage rename 替换后的死
  varnode 清理（heritage.cc:2521/2550）。

`op_insert` 的两层状态与 Ghidra 一致：`PcodeOpBank::alivelist` 记录接入
生命周期/接入顺序，`BlockBasic.ops` 记录执行顺序。低层插入同时维护
`PcodeOp.parent`、块内 SeqNum order；插入 BRANCHIND 时设置块的
`SWITCH_OUT`。这两个容器不能互相替代。

兼容边界：部分既有 Rule 单测仍直接构造 parentless flat op bank，违反
Ghidra `opInsertBefore/After/Uninsert` 的基本块前置条件。Rudra 暂时保留
该无块域的旧 alivelist 插入/摘除分支，状态为 **MISMATCH / UNTESTED**；
有真实 `BlockBasic` parent 的有效域走上述原子插入实现，并由锁定 12.0.4
fixture `tests/oracle/op_insert_1204.*` 验证。

相邻但未纳入该 MATCH 的结构缺口：Ghidra `opUnlink/opDestroy` 会把每个
输入槽清成 NULL 而保留槽数。`RULE-MULTICOLLAPSE-0001` 已让 Rudra
`op_destroy` 通过 `destroy_varnode` 真正删除输出 Varnode，并在有 parent 时
执行 markDead + 从 `BlockBasic` 移除。（2026-09-22 更新，SB-ORD159-NULLSLOT-0001：
`op_unset_input` 现在实现 cc:98 `clearInput` 的槽内置 NULL——写入共享
`crate::op::null_slot_sentinel`（Ghidra `(Varnode*)0` 的进程级替身），槽数保留；
`op_destroy` 不再清空整个 Vec。dead op 的 `numInput()` 槽数与 NULL 槽状态
与 oracle 一致（next_url 镜像投影 ordinal 159 起 dead INDIRECT 渲染
`in=-,-` 逐字节对齐）；`op_unlink`/condexe 槽丢弃路径的 stale-Arc 泄漏同修。
唯一残留：`new_op` 创建期不预置 N 个 NULL 槽（Ghidra `PcodeOp(inputs,sq)`
ctor op.cc:71 `inrefs(s)` 预置），`PcodeOpBank::create` 只 reserve——若语料
出现"创建后未填满即被 SNAP"的形态仍会暴露 `in=-` vs `in=-,-`（登记于
SB-ORD159-NULLSLOT-0001 残差）。）
同一 OPBANK 缺口也意味着 `new_op(inputs, pc)` 当前 `num_input()==0`，并
预置 COPY opcode/派生 flags；fixture 在插入前立即设置 opcode 和所需输入，
所以本次 `MATCH` 仅证明插入族和 dead/alive 生命周期，不证明完整 newOp。

### 2026-06-26（续）：op_swap_input

- `op_swap_input(op, slot1, slot2)` — `Funcdata::opSwapInput`：交换两输入操作数。
  用于 RuleBoolNegate 翻转比较时的换序（如 `!(V < W) => W <= V`）。

### 2026-06-26（续）：op_set_output

- `op_set_output(op, vn)` — `Funcdata::opSetOutput` (`funcdata_op.cc:70`) ：
  same-Arc output 直接返回；按顺序先将 op 的旧 output 转为 free，再将 `vn`
  从它原来的 defining op 取下，然后调用 `VarnodeBank::set_def` 并消费它
  返回的 canonical Arc。最后应用 Varnode properties 并安装 canonical output，
  避免在 `BTreeSet` 内原位改动 written/def 排序键。

### 2026-06-26（续）：op_destroy / op_unset_input

- `op_destroy(op)` — `Funcdata::opDestroy`（funcdata_op.cc:203）：调用 `destroy_varnode` 删除输出及其 bank identity，按 slot 顺序断开所有输入；有 parent 时 markDead 并从原 `BlockBasic` 删除。（2026-08-23 修正：无 parent 路径也必须 mark_dead——Ghidra 后置条件是 opDestroy 后 op 恒为 dead：Ghidra 中无 parent 的 op 由 `PcodeOpBank::create`（op.cc:946）起始即 dead、在 deadlist，仅 opInsert 的 markAlive（funcdata_op.cc:157）转活；Rudra 的 create 起始即 alive，故无 parent 销毁（未插入 op 或 block Arc 已释放）需显式 mark_dead，否则无输入 alive op 滞留 ActionPool 迭代（processOp isDead 检查 action.cc:830），使读取 getIn(0) 的 Rule（如 RuleSubvarSubpiece subflow.cc:1593）panic——glob_word 修复。）（2026-09-22，SB-ORD159-NULLSLOT-0001：不再清空 inrefs Vec；`op_unset_input` 的 clearInput 写入把每个槽置为共享 null 哨兵，dead op 保留 `numInput()` 个 NULL 槽，与 oracle 的 post-opDestroy 可观测状态一致。）
- `op_unset_input(op, slot)` — `Funcdata::opUnsetInput`：断某输入的 descend 链，并执行 cc:98 `clearInput(slot)`——槽内置 NULL（共享 `crate::op::null_slot_sentinel`），槽数不变；对已断链/已置 NULL 的槽是幂等 no-op。
解锁 RuleEarlyRemoval。

### 2026-06-27（续）：op_destroy_recursive / total_replace

- `op_destroy_recursive(op)` — `Funcdata::opDestroyRecursive`（funcdata_op.cc:228）：递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source）。使用 scratch worklist 避免递归栈溢出。
- `total_replace(vn, newvn)` — `Funcdata::totalReplace`（funcdata_varnode.cc:1474）：将 vn 的所有读取引用替换为 newvn（遍历 descend 链 + op_set_input）。解锁 ActionMultiCse、constseq。

### 2026-06-26（续）：op_unset_output / new_varnode_out

- `op_unset_output(op)` — `Funcdata::opUnsetOutput` (`funcdata_op.cc:52`) ：先从
  op 取下 output，再通过 `VarnodeBank::makeFree` 将旧 output 从 written/insert
  类转为 bank-owned free Varnode，最后清除 Cover。此顺序保证 bank 的 Loc/Def
  排序键在 flags/def 变化前先移除。当 op 无 output 时不产生任何突变。
- `new_varnode_out(size, addr, op)` — `Funcdata::newVarnodeOut`
  (`funcdata_varnode.cc:104`) ：直接通过 `VarnodeBank::createDef` 以最终
  written/def 键插入 Loc/Def 树，再安装 op output 并应用已有 property
  查询。Rudra 尚未完整表达 Ghidra 的动态 AddressSpace、TypeFactory、
  `assignHigh`、laned-register 和 ScopeLocal property 边效应，这些调用闭包仍为
  **MISMATCH/UNTESTED**。
- SB-IMPLIEDWAVE-0001（2026-09-22）：`new_varnode_out` 的 split-Address
  Register-pin 适配器保持不变（无语义变化；本 lane 的临时 NVOBT 探针已随
  验证完成移除）。`new_varnode_out_full` 的完整 newVarnodeOut 序列
  （createDef→assignHigh→laned→queryProperties 尾）由 subflow 分片 builder
  （build_in_subpieces/build_out_concats）以 root 空间调用，见
  docs/api/subflow.md。
解锁 RuleLeftRight。

### 2026-06-26（续）：replace_lessequal

- `replace_lessequal(op) -> bool` — `Funcdata::replaceLessequal`（funcdata_op.cc:1029）：
  `V <= c => V < c+1`，调整常量±1并改 opcode，带溢出保护。解锁 RuleIntLessEqual。

### 2026-06-26（续）：distribute_int_mult_add

- `distribute_int_mult_add(op) -> bool` — `Funcdata::distributeIntMultAdd`（funcdata_op.cc:1073-1118）：
  `(V + W) * c => V*c + W*c`。将 INT_MULT 系数分配到 INT_ADD 的两个输入。常量输入直接乘出结果；非常量输入创建新 INT_MULT op。解锁 RuleCollectTerms 完整形式。

## 2026-06-27：CFG 重写原语（funcdata_block.cc）

新增控制流图编辑方法，解锁 jumptable.rs 的 foldInGuards/switchOver L3 缺口：

- `push_branch(bb, slot, bbnew) -> Result<(), String>`（funcdata_block.cc:404）：将 CBRANCH 转为 BRANCH（移除条件输入 slot 1），重定向 out-edge 到 BRANCHIND 块。验证源是 CBRANCH（2 out-edges）+ 目标以 BRANCHIND 结尾。
- `force_goto(pcop, pcdest) -> bool`（funcdata_block.cc:752）：遍历所有基本块，找到地址为 pcop 的最后 op，标记其指向 pcdest 的 out-edge 为非结构化 goto。
- `set_goto_branch(bl, j)`：标记 out-edge j 为 goto，对齐 Ghidra `FlowBlock::setGotoBranch`（block.cc:305-314）**三件事**：(1) edge flag（BlockBasic 用 GOTO_EDGE_0/1，结构块用 F_GOTO_EDGE），(2) source `INTERIOR_GOTOOUT`（0x400，block.hh:97），(3) target `INTERIOR_GOTOIN`（0x800，block.hh:98）。此前只做 (1)，导致 `is_interior_goto_target` 对 goto 标记的目标块失效。**2026-07-16 B4 修复**。
- `move_out_edge(bb, slot, bbnew)`：重定向 out-edge（BlockGraph::moveOutEdge 等价），更新源/旧目标/新目标的 edge 列表 + reverse_index。

## 2026-06-27（续 2）：remove_branch

- `remove_branch(bb, num)`（funcdata_block.cc:220）：`num` 是要删除的 out-edge slot；先执行 `branch_remove_internal`（必要时销毁 CBRANCH、删除该 out-edge，并按目标 incoming slot 删除 MULTIEQUAL 输入），再执行 `structure_reset`。旧文档“移除非选中边”的说法会把参数方向反转，已纠正。

## 2026-06-27（续 3）：FuncCallSpecs 集成

- `callspecs: Vec<FuncCallSpecs>` — 函数调用规格向量（Ghidra breefcall）。
- `num_calls() -> usize` — 调用点数（funcdata.hh numCalls）。
- `get_call_specs(i) -> Option<&FuncCallSpecs>` — 按索引获取（funcdata.hh getCallSpecs）。
- `get_call_specs_mut(i) -> Option<&mut FuncCallSpecs>` — 可变访问。
- `add_call_specs(fc) -> usize` — 添加调用规格。
- `get_func_proto() -> &FuncProto` / `get_func_proto_mut() -> &mut FuncProto` — 函数原型访问。

### 2026-06-27（续 2）：op_bool_negate

- `op_bool_negate(vn, op, insert_after)` — `Funcdata::opBoolNegate`（funcdata_op.cc:560）：插入 BOOL_NOT（CPUI_BOOL_NEGATE）op 取反 vn，返回输出 varnode。insert_after 控制插入位置。解锁 RuleBooleanUndistribute/RuleBoolZext 等。

### 2026-06-27（续 3）：is_type_recovery_on + flags

- `is_type_recovery_on()` — `Funcdata::isTypeRecoveryOn`（funcdata.hh:150）：检查 TYPE_RECOVERY_ON 标志。
- `set_type_recovery_on(on)` — 启用/禁用类型恢复。
- 新增 `flags: u32` 字段 + `funcdata_flags::TYPE_RECOVERY_ON` 常量。解锁 RuleBoolZext。

### 2026-06-27（续 4）：op_uninsert / op_insert_begin / op_get_slot

- `op_uninsert(op)` — `Funcdata::opUninsert`（funcdata_op.cc:164）：从
  `BlockBasic.ops` 移除、清 parent，并由 alive list 移到 dead list；输入
  descend 与输出 def 保持不变，因而可以随后重新插入。
- `op_insert_begin(op, bb)` — `Funcdata::opInsertBegin`
  （funcdata_op.cc:413）：MULTIEQUAL 插在绝对块首，其他 op 插在块首
  MULTIEQUAL 组之后。
- `op_get_slot(op, vn) -> i32` — `PcodeOp::getSlot`：返回 vn 在 op 中的输入槽位（-1 未找到）。

### 2026-06-29：spacebase() + split_uses()（底层阻塞解除）

- `spacebase()` — `Funcdata::spacebase()`（funcdata.cc:230-269）：标记映射到虚拟地址空间的寄存器（栈指针 RSP @ Register@0x20, size 8）为 `SPACEBASE` 标志。对已标记且有多后代的空间基 varnode，调用 `split_uses()` 复制定义 op 使各加法用户独立寻址。**这是 Ghidra 让 varmap/ActionStackPtrFlow 识别 RSP 为栈空间指针的规范机制**——不需要 lifter 发出 Stack-space varnode。接入主管线为 `ActionSpacebase`（coreaction.cc:5506，在 ActionHeritage 之后、infertypes 之前）。
- `split_uses(vn)` — `Funcdata::splitUses`（funcdata_varnode.cc:1540-1567）：若 vn 由 op 定义（如 INT_ADD）且有多个后代，复制定义 op 使每个读取者获得独立输出副本。允许按用户分析（如同一空间基派生指针的不同栈偏移）。**2026-09-24（PM-F2S）**：slot 计算时机修正——`slot = useop->getSlot(vn)` 必须在循环体内对**活状态**求值（cc:1554，每轮改写后重新求值），不能进循环前快照；同一 op 在多个 slot 读 vn 时（如 MULTIEQUAL 重复 RSP 输入），每轮应认领下一个尚未改写的 slot。快照版会让第二轮覆盖第一轮的安装，留下一个永不接线的新 op（file2string.part.0 投影 ord178 分歧根因）。
- **验证**：curl uVar 碎片 149→0，httpd uVar→0，while/goto 不变，776/776 测试 + curl 24/24 + httpd 29/29 gcc 审计通过。

### 2026-08-15：split_uses 对齐 VarnodeBank 转换（VARNODE-INPLACE-MUTATION-SITES-0001）

- `split_uses(vn)` — `Funcdata::splitUses`（funcdata_varnode.cc:1540-1567）两处对齐修正：
  1. **bank 转换**：新输出 varnode 由 `vbank.create_with_space`（`VarnodeBank::create`，varnode.cc:1250）以最终 (space, loc) 键创建，再经 `op_set_output`（`Funcdata::opSetOutput`，funcdata_op.cc:70-87 → `VarnodeBank::setDef`）完成 WRITTEN 置位与 def 树重键。替换旧的手写 `address_space`/`WRITTEN`/`def` 原地突变（树驻留 key 字段突变会漂移树序、破坏查找语义）。
  2. **循环边界**：Ghidra 迭代器先推进再重写（cc:1551/1563-1564），**每个**原始 descendant 都被重定向到新克隆 op；没有「最后一个读者保留原 op」特例（旧 Rudra `last_idx` break 是移植缺陷）。原 op 留给 dead-code 移除（cc:1566）。
- 验证：HEAD worktree 基线对比证明 5 个失败单测为域外既有（零新增）；E2E curl 124/124；全语料 5 连跑 sha256 一致（03d97945…）；差分 defects=0/numbering=0。

### 2026-09-24：split_uses 类型携带 + newVarnode 正典化 + find 输入空间限定（FUNCDATA-SPLITUSES-NEWVN-TYPECARRY-0001 / BANK-FINDINPUT-SPACE-0001，wt/p3batch）

- `split_uses(vn)` — cc:1556 `newvn = newVarnode(vn->getSize(),vn->getAddr(),vn->getType())`
  的新 vn 现走**完整** `Funcdata::newVarnode(s,m,ct)` 路径（funcdata_varnode.cc:148-169）：
  ①类型携带（源 vn 的 `v_type`，`ct==0` 回退工厂 unknown 基=Varnode 构造器默认）；
  ②`assignHigh`；③`checkForLanedRegister`（`s >= minLanedSize`）；④`queryProperties`
  符号尾（INVALID usepoint）。此前裸 `vbank.create_with_space` 丢全部四件携带（同类
  携带 PM-F2S 已证明可观察；spacebase 标记循环 funcdata.cc:241-262 是唯一调用点）。
- `new_varnode_typed_in_space(size, space, addr, ct)` — 新增 typed 显式空间形态的
  `Funcdata::newVarnode`（`// Ghidra: funcdata_varnode.cc:148`）；`new_varnode_in_space`
  改为委托它（`ct=None`），单一正典路径。类型非 bank 树键，插入后安装与
  `create_unique_typed`（varnode.cc:1265）同款。
- `find_varnode_input(size, space, addr)` — `Funcdata::findVarnodeInput`（funcdata.hh:324）
  的 Address 携带空间：bank 查找现带空间限定（`VarnodeBank::findInput` 见 varnode.md）。
  两消费点：ActionRestructureVarnode 参数 typelock（Register 臂）与
  ActionRestrictLocal Loop-2 unaffected 溢出槽 walk（coreaction.rs，EffectRecord.space）。
- `find_spacebase_input` — cc:298 `findInput(point.size, Address(point.space,point.offset))`
  的 `point.space` 是基寄存器的 REGISTER 空间（`stack_pointer_space`），非被指空间。
- `cse_find_in_block(op, vn, bl: Option<&…>, earliest)` — `bl` 参数改 Option 以镜像
  Ghidra 裸指针不等式（cc:1334 `res->getParent() != bl`：null `bl` 仅匹配无 parent 的
  op）；语义与调用方（RulePushMulti/RuleMultiCollapse）不变。

### 2026-06-27（续 5）：CSE 基础设施

- `cse_elimination(op1, op2) -> PcodeOpRef` — `Funcdata::cseElimination`（funcdata_op.cc:1356-1398）。
  **2026-09-22 修正（ordinal-28 selectcse 幸存者方向反转）**：旧版无视 parent 恒按
  SeqNum order 取小者；现按 oracle 全语义移植——同 parent（含双 null）比较
  `getSeqNum().getOrder()`（块内执行序，block.cc:2638 setOrder 维护）；异 parent 走
  `FlowBlock::findCommonBlock`（block.cc:736-790 mark-walk 支配树 LCA）：公共块即某 op
  的 parent 则该 op 幸存；两者皆非则 cc:1372-1386 在公共块 `getStop()` 地址新建替换 op
  （`newOp`+同 opcode+`newVarnodeOut(out.size,out.addr)`+常量经 newConstant+`opInsertEnd`），
  双方 total_replace 后销毁。
- `cse_eliminate_list(list) -> Vec<Varnode>` — `Funcdata::cseEliminateList`（funcdata_op.cc:1418-1447）：
  对 (hash, op) 列表稳定排序（sort_by_key），滑窗比较相邻同 hash 对；补 cc:1436-1437
  `isHeritaged(outvn)`（`Heritage::heritagePass = globaldisjoint.findPass(addr) >= 0`，
  heritage.hh:325；null 输出放行）守卫后消除冗余。解锁 RuleSelectCse + ActionCse。

### 2026-06-27（续 6）：op_flip_condition

- `op_flip_condition(op)` — `Funcdata::opFlipCondition`（funcdata.hh:489 逐字内联 `op->flipFlag(PcodeOp::boolean_flip)`）：仅 toggle CBRANCH 的 `boolean_flip` flag，不改 opcode。解锁 RuleCondNegate。**2026-08-23 勘误（GETSTR-ZERODIFF-A）**：旧实现对该 op 自身调 `get_booleanflip`（对 CBRANCH 返回 CPUI_MAX=74 哨兵，opcodes.cc:94-135）并赋值——RuleCondNegate 站点把 CBRANCH opcode 腐蚀为 74（IR dump 实证 GetStr SeqNum 14066:54 CBRANCH→MAX）。oracle 从不在此改 opcode（比较 opcode 改写是 opFlipInPlaceExecute 的职责，funcdata_op.cc:1280）。

### 2026-08-23：get_call_specs_of_op

- `get_call_specs_of_op(op) -> Option<Arc<RwLock<FuncCallSpecs>>>` — 对应
  `Funcdata::getCallSpecs(const PcodeOp*)`（funcdata.cc:484-497）。快路径从 input(0)
  annotation 的 typed `Weak` 升级 owner，并同时验证 owner 仍属于本 Funcdata 且
  callspec 的反向 `Weak` 以 `Arc::ptr_eq` 精确指回传入 op；回退只线性比较 exact op
  identity。当前 direct-call Iop 的数值 payload 暂时保留 entry offset，供尚未改为
  typed callspec consumer 的 legacy PrintC 使用；entry 缺失时才退化为 owner pointer
  诊断值。两者都不是 vector index 或 lookup 身份，typed `Weak` 才是唯一身份来源。
  这层兼容 shadow 不等价于 Ghidra 的 `IPTR_FSPEC` pointer codec，仍由
  `TYPEOP-FSPEC-SPACE-0001` 记为 `MISMATCH`。本 API 供 ActionInferTypes CALL 输出类型种子
  （TypeOpCall::getOutputLocal typeop.cc:720-734）等消费。

**2026-09-29（ACTIVEPARAM 速度道）：per-walk 解析 memo。**
`get_call_specs_of_op` 增加线程局部的 op→spec 解析 memo（`OpSpecMemoScope` RAII 域，
funcdata.rs）。Oracle 的快路径是常量空间指针读（funcdata.cc:486-487）、回退是裸指针
线性扫描（funcdata.cc:489-490）；Rudra 形态每次解析每 spec 付一次锁 + Weak upgrade。
参数恢复走查（`FuncCallSpecs::checkInputTrialUse` 的 trial 循环与
`ActionReturnRecovery` 的 return trial 循环）期间 callspecs 列表与所有 spec 的 op
绑定不可变（走查对 call 只读；opSetInput/newConstant 尾部只在 checkInputTrialUse
返回后执行），解析结果只依赖 op 身份——域内首次解析结果被缓存复用，观测上与重算
恒等；域外路径逐字节保持原解析逻辑。VdbeExec 实测（[APROF] 探针）：走查窗口内
gcs_steps 30.2M→5.5M（−82%），walk 形态计数（visits/desc_ops/ccdu）逐值不变。
memo 按 callspecs 索引缓存（命中时重新 clone 现列表项），防 parked-placeholder
内容差异跨域泄漏（apply 级 memo 会跨 park 舞蹈——已评估并否决）。

### 2026-06-27（会话2）：CFG 重写原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），Funcdata 新增忠实于 Ghidra funcdata_block.cc 的方法：
- `remove_from_flow_split(bl, swap) -> Result<(), String>` — `Funcdata::removeFromFlowSplit`（funcdata_block.cc:881-889）+ `BlockGraph::removeFromFlowSplit`（block.cc:1575-1590）：移除一个 2 入/2 出的空块，将每条入边重连到对应的出边。swap=true 时 In(0)->Out(1)/In(1)->Out(0)（交叉）；swap=false 时 In(0)->Out(0)/In(1)->Out(1)（直连）（funcdata_block.cc:880）。序列忠实 block.cc:1584-1589：swap ⇒ `replaceEdgesThru(0,1)`，否则 `replaceEdgesThru(1,1)`，随后 `replaceEdgesThru(0,0)`（swap 经 funcdata_block.cc:886 直传为 flipflow）。condexe execute() 用此消除冗余路径汇合。（2026-08-23 修正：旧实现的 swap 分支序列 (0,0),(0,1) 在第二次调用时越界 panic（block.rs:1613），swap=false 分支误用 flipflow=true 的交叉序列——CONDEXE-CFG-0001。）
- `structure_reset()` — `Funcdata::structureReset`（funcdata_block.cc:705）：重算循环结构 + 支配者树 + 清空 sblocks。任何 CFG 变更后调用以保持一致性。

### 2026-06-27（会话3 G3 续）：inject Phase 4 use-def linking（验证有效，暂禁用）

在 inject_raw_ops Phase 3 后验证了一个 Phase 4 use-def 链补全 pass：按线性指令序维护 (space_id, offset)→defining op 映射，为 LOAD/STORE 地址输入补上 def 弱引用（保持 SSA Arc-identity，只填 def-less 链）。**验证有效**：varmap gather_spacebase 解析出 helpf 的 10 个栈符号。

**但与 jumptable/switch 交互**（switch 表本身是 LOAD）导致 main 等函数 switch quantity 回归。为保持默认 24/24+29/29，Phase 4 暂禁用（inject_raw_ops 内详细 NOTE 记录）。重启需 jumptable/typeop 协调。实现可从 git 历史恢复。

### 2026-06-27（会话3 G3 续2）：inject Phase 4 确认禁用

inject Phase 4 全局 def-linking 确认禁用——它正确解析栈符号但扰动 typeop（struct 指针泄漏）。改用 varmap 的只读 `resolve_rsp_offset_via_bank`（作用域仅 spacebase），不扰动 typeop/copyprop。inject_raw_ops Phase 4 NOTE 已更新说明此决策。

### 2026-06-27（会话3 G5）：remove_unreachable_blocks + splice_block_basic

- `remove_unreachable_blocks() -> bool` — `Funcdata::removeUnreachableBlocks`（funcdata_block.cc:347-394）：从入口 BFS 收集可达块，标记不可达块为 dead，移除其出边，再从图移除。用于 ActionUnreachable。
- `splice_block_basic(bb) -> bool` — `Funcdata::spliceBlockBasic`（funcdata_block.cc:919-956）：拼接单出边块到其单后继（销毁 bb 的 branch op，继承后继出边，移除后继）。用于 ActionDoNothing/ActionRedundBranch case 1。

### 2026-06-27（会话3 G5续）：sync_varnodes_with_symbols

- `sync_varnodes_with_symbols(update_datatypes, unmapped_alias_check) -> bool` — `Funcdata::syncVarnodesWithSymbols`（funcdata_varnode.cc:938-989）的忠实适配：遍历 Stack-space varnodes，匹配 ScopeLocal 符号，标记为 mapped（set_direct_write）。ActionRestructureVarnode 现调用它（coreaction.cc:2281）。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-08-15（FUNCDATA-SCOPE-SYNC-0001）：sync_varnodes_with_symbols 忠实移植

旧适配体（两参数全 `_` 忽略、DIRECT_WRITE 代理、从不 updateType、从不设 nolocalalias）被完整移植替换，oracle fixture `tests/oracle/scope_sync_1204`（锁定 12.0.4 oracle，双侧 8 记录逐字节 MATCH）：

- `sync_varnodes_with_symbols(update_datatypes, unmapped_alias_check) -> bool` — `Funcdata::syncVarnodesWithSymbols`（funcdata_varnode.cc:938-989）1:1。按 loc 序遍历 scope 空间 varnode；`findOverlap` 命中符号时 `fl = getAllFlags()`（extraflags=mapped ∪ Symbol flags；`LocalSymbol.usepoint == None` ↔ Ghidra `Scope::addMap` 在 uselimit 为空时设的 addrtied，database.cc:1149-1150；typelock/namelock/nolocalalias=unaliased）；entry.size ≥ vn.size 且 updateDatatypes 时 `getSizedType`（TYPE_UNKNOWN 丢弃，cc:956-960）；entry 更小时仅清 typelock/namelock 位（cc:962-969，nolocalalias 保留）；无符号时 in-scope → `mapped|addrtied`（cc:976）、否则 unmappedAliasCheck 走 `isUnmappedUnaliased`（cc:980）、否则 0。
- `sync_varnodes_with_symbol_set(ordered, index, fl, ct) -> bool`（私有）— per-set 重载 `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator&,uint4,Datatype*)`（funcdata_varnode.cc:1048-1095）1:1：mask 从 `mapped` 起，fl 无 addrtied 时并入 `addrtied|addrforce`（可清不可设），fl 有 nolocalalias 时并入 `nolocalalias|addrforce`（可设不可清），`fl &= mask` 后对同 (space,offset,size) 集内每个非 free varnode 应用；已挂 mapentry 的 varnode 用 `mask & ~mapped` 局部掩码（mapped 位保持不变，cc:1075-1082）；ct 非空时 `updateType`（typelock varnode 不被覆盖），成功时 `high->typeDirty()`；flag 写后 `high->flagsDirty()`（varnode.cc:352-374 副作用，Rudra 的 `Varnode::set_flags` 不含此传播，故在此显式调用）。
- 模块级辅助（funcdata.rs，均带 `// Ghidra:` 注释）：
  - `varnode_use_point_offset` — `Varnode::getUsePoint`（varnode.cc:696-703）。
  - `scope_local_find_overlap`（pub，2026-08-16 SCOPE-FINDOVERLAP-KEY-0001/DYNAMIC-0001 重写）— `ScopeInternal::findOverlap`（database.cc:2392-2404）的 rangemap 分区语义：`find_overlap(point,end)`（rangemap.hh:411-423）`lower_bound(AddrRange(point))` 取与查询相交的最左分区单元，单元内按 `SymbolEntry::getSubsort`（database.cc:97-107，addrtied → 最小 (0,0)，否则首 uselimit range 的 (index,offset)；同二进制代码空间下 index 一致，Rudra 以常量 1 建模）取最小者胜出，等值 subsort 按 Vec 创建序（= std::multiset 等价键插入序）。旧实现"最小 start 真重叠"在互重叠符号上与 oracle 分歧（判别 fixture `tests/oracle/scope_find_overlap_1204`：oracle 答 `narrow` 而旧实现答 `wide`）。动态条目先被过滤（`addDynamicMapInternal` database.cc:1866-1876 只入 dynamicentry 不入 maptable，`LocalSymbol.is_dynamic` 镜像）。辅助 `entry_subsort_key` 为 getSubsort 的 (u8,u64) 键形式。2026-08-30 FUNCDATA-SCOPELOCALOVERFLOW-0001：database.cc:2397 的 `addr.getOffset()+size-1` 在 oracle 的 uint8（uint64）模域求值（int4 size 经符号扩展转换，两运算符均回绕），栈空间 2^64 附近的偏移（负栈槽）合法回绕——查询端 `last` 与记录端 `sym_end` 均改为 `wrapping_add/wrapping_sub`，含入测试从 `p < first+size` 改为 oracle 的 `first <= p <= last` 形式（`p < first+size` 在 first+size 回绕到 0 时漏答顶端记录且 debug 下同样 trap）。双侧门禁 `tests/oracle/funcdata_scopelocal_wrap_1204`（顶字节/负 size/零 size 等 7 查询，字节一致）。
  - `scope_local_in_scope` — `Scope::inScope`（database.hh:597）→ rangetree 完整覆盖语义；签名保留被基类忽略的 `usepoint` 参数（funcdata_varnode.cc:974 的实参调用形态，SCOPE-USEPOINT-WARNING-0001）。2026-08-30 FUNCDATA-SCOPELOCALOVERFLOW-0001：address.cc:484 的同一 `addr.getOffset()+size-1` 模域表达式同步改 wrapping（与 findOverlap 同一 debug-trap 面）。
  - `scope_local_is_unmapped_unaliased` — `ScopeLocal::isUnmappedUnaliased`（varmap.cc:494-502）。
  - `local_symbol_sized_type`（2026-08-24 TYPEFACTORY-EXACTPIECE-CALLERS-0001 重写）— `SymbolEntry::getSizedType`（database.cc:151-162）的 LocalSymbol 形式：`off = inaddr - sym.start`（whole-map entry offset 为 0），piece 查找委托 Architecture-owned TypeFactory 的 canonical `TypeFactory::get_exact_piece`（type.cc:4090-4117，经 funcdata_varnode.cc:957 的 entry→scope→arch 链到达同一工厂；Rudra 侧由 `sync_varnodes_with_symbols` 从 `self.get_arch().types` 捕获并传入）。旧的 `exact_piece_arc_sub_type` 本地下钻副本已删除（无 partial 构造、丢 canonical identity）；Architecture 未接线时 fail-closed（类型投影跳过，flag 同步照常）。双侧门禁 `tests/oracle/exactpiece_callers_1204`。
- 调用闭包：`ActionRestructureVarnode`（coreaction.cc:2281-2282，false/aliasyes，count 累计）与 `ActionMappedLocalSync`（coreaction.cc:2302-2303，true/true，count 累计）。
- 已知残差：① ~~`getExactPiece` 的 partial 构造缺失~~（2026-08-24 起走 canonical 工厂，partial struct/array/enum/union 与 exact 命中同 oracle）；Architecture 未接线时类型投影 fail-closed（RUDRA-GAP，见 ARCH-0001 接线 TODO）；② Rudra `Varnode::set_flags/clear_flags` 本体不带 flagsDirty 传播（varnode.rs 端预置缺口，本移植在调用点补偿）；③ Architecture-attached 路径现保持其 factory flavor 的真实命名与 Arc identity；无 Architecture 的 legacy fallback 与不同 Ghidra frontend flavor 仍须分别登记，禁止 fixture 层把 `undefined{size}`/`xunknown{size}` 归一化成 MATCH。

### 2026-06-29（续 2）：new_extended_constant（funcdata_varnode.cc:462）
- `new_extended_constant(s, lo, hi, before_op)` — 创建可能 >8 字节的常量 Varnode。s≤8 时直接 newConstant；s>8 且 hi==0 时 INT_ZEXT(const)；s>8 且 hi!=0 时 PIECE(hi,lo)。忠实移植 Ghidra `Funcdata::newExtendedConstant`（funcdata_varnode.cc:462-484）。解锁 RuleDivTermAdd。

### 2026-06-29（续 3）：Funcdata.active_output 字段
- 新增 `active_output: Option<ParamActive>` 字段（funcdata.hh）。用于 ActionReturnRecovery 检测函数返回值。当 RETURN op 有 >1 input 时自动创建 active_output。

### 2026-06-29（续 4）：Funcdata::calc_nz_mask（funcdata_varnode.cc:856-930）【2026-08-23 已重写为 oracle 结构，见文末】
- `calc_nz_mask()` — 计算所有 Varnode 的 non-zero mask（NZM）。遍历 alive ops，根据 opcode 从输入 NZM 推导输出 NZM：COPY/ZEXT 传播、XOR/OR 合并、AND 交集、LEFT/RIGHT 位移、SUBPIECE/PIECE 等。
- 用于 RuleAndMask/RuleOrMask 位优化 + 类型推断变量范围。（初版为简化单遍实现，2026-08-23 按 FUNCDATA-CALCNZM-0001 重写为 oracle 两阶段结构。）

### 2026-06-29（续 5）：find_varnode_input
- `find_varnode_input(size, addr)` — 忠实移植 `Funcdata::findVarnodeInput`（funcdata.hh:324）。查找指定 size+address 的 input varnode。用于 ActionRestrictLocal + AncestorRealistic。

### 2026-06-29（续 6）：Stack 空间 / spacebase 配置字段
- 新增字段（对齐 cspec `<stackpointer>` + Architecture stack 配置）：`stack_space: AddressSpace`（= Stack）、`stack_pointer_space/offset/size`（= Register@0x20 size 8 = x86-64 RSP）、`stack_grows_negative: bool`（= true）。
- Funcdata 不持有 Architecture 引用（L3 缺口），这些字段用 x86-64 默认值初始化，模拟 Ghidra Funcdata 从 Architecture 拿 stack 配置。
- `spacebase()` 改为从这些字段读 stack pointer 位置（不再硬编码 0x20）。

### 2026-06-29（续 7）：new_indirect_op（funcdata_op.cc:683）
- `new_indirect_op(indeffect, stack_offset, sz)` — 忠实移植 `Funcdata::newIndirectOp`。建 `STACK:off = INDIRECT(STACK:off, iop=STORE)`：input[0] + output 在 Stack 空间（stack_offset），input[1] 是引用 causing op 的 iop 常量。op 标记 INDIRECT_STORE，插在 causing op 前。这是 Ghidra 产生 Stack 空间 varnode 的核心机制（guardStores 调用它）。
  - **2026-06-29 续**：input/output 通过 `vbank.set_def` 建（设 INSERT），output 设 `active_heritage`（对齐 guardStores heritage.cc:1554-1556）。

### 2026-06-29（续 8）：inject_raw_ops varnode 去重
- `inject_raw_ops` 创建非 Const input varnode 时，改用 `vbank.find_or_create_input_space(size, space, offset)`（替代 `create_with_space`）。这让同地址的 input varnode 共享身份（对齐 Ghidra xref 去重），descend 累积所有 reader。修复了 descend 链碎片化（RSP input 从 1 个 descend 变 64 个）。

### 2026-07-01：TYPE_RECOVERY_START flag
- `funcdata_flags::TYPE_RECOVERY_START`（funcdata.hh:90）+ `has_type_recovery_started()/set_type_recovery_started()`（funcdata.hh:151）。标记类型恢复已开始，Rule 据此决定 type-based 守卫是否生效。

### 2026-07-01：Architecture 引用 + iop-space varnode + op_undo_ptradd（解锁 cpool/funcptr/iop 依赖 Rule）
- `arch: Option<Arc<Architecture>>` 字段 + `get_arch()/set_arch()`（funcdata.hh:80/144）。Ghidra 在 ctor 从 scope 取 glb；Rudra 的 `Funcdata::new` 自 2026-08-30 起在构造尾经 `canonical_arch()` 绑定共享默认实例（funcdata.cc:48 不变式），持有真实 Architecture 的调用方仍以 `set_arch` 覆盖。`set_arch` 同时把 `arch.types` 的共享身份注入 VarnodeBank，保证后续 Varnode 默认类型来自该 Architecture。
- `new_varnode_iop(op)`（funcdata_varnode.cc:176-184）— 在 Iop 空间创建引用 op 的 varnode（Arc::as_ptr 编码）。
- `get_op_from_const(vn)`（op.hh:249）— iop-space varnode 反查回 PcodeOp。
- `op_undo_ptradd(op)`（funcdata_op.cc:579）— PTRADD 撤销为 INT_ADD/INT_MULT。
- `op_mark_cpool_transformed(op)`（funcdata.hh:485）— 标记 cpool 已转换。

### 2026-07-01（续 2）：new_indirect_creation + jump_tables + get_store_guard/load_guard
- `new_indirect_creation(op, addr, sz, possibleout)`（funcdata_op.cc:710-728）— constant 零输入 + indirect_creation flag on op/in/out。
- `jump_tables: Vec<Arc<RwLock<JumpTable>>>` 字段（funcdata.hh:89）。
- `find_jump_table(op)`（funcdata_block.cc:446）+ `remove_jump_table(jt)`（funcdata_block.cc:65）。
- `get_store_guard(op)/get_load_guard(op)`（funcdata.hh:269-270）— 转发到 Heritage。

### 2026-08-30：cast_phase_index + start_cast_phase（step 2）
- `cast_phase_index: u32` 字段（funcdata.hh:77）+ `start_cast_phase()`（funcdata.hh:183 一行式
  `cast_phase_index = vbank.getCreateIndex()`）+ `clear()` 复位（funcdata.cc:90-92）。由
  `ActionSetCasts::apply`（coreaction.cc:2728）调用。

### 2026-08-30：op_undo_ptradd 全参忠实化（PTRSUB-SWITCH-CAST-RESIDUAL-0001 step 1）
- `op_undo_ptradd_full(op, finalize)`（funcdata_op.cc:579-609）— 完整 `finalize` 语义：scale 常量原样复用为 INT_MULT 第二输入（不再伪造 8 字节常量）；offset 常量时折叠 `multSize * offset & calc_mask(size)` 并继承 read-facing 类型；乘积 varnode 取 offset 尺寸、finalize 时取 scale 类型并 `set_implied`；`multSize` 按 `int4` 截断读取 `get_offset()`（不做 is_constant 门控）。
- `op_undo_ptradd(op)` 保留 1 参形式（ruleaction.rs 调用方兼容 shim），委托 `op_undo_ptradd_full(op, false)` — 与 Ghidra ruleaction.cc:6925/7115 的 `finalize=false` 一致。

### 2026-07-01（续 3）：combine_input_varnodes + DOUBLE_PRECIS_ON + new_varnode + warning_header
- `combine_input_varnodes(vn_hi, vn_lo) -> Result<()>`（funcdata_varnode.cc:381-454）—
  校验 input/同空间连续性（按 endian 选择合并地址），PIECE→COPY，非 PIECE reader
  在入口块首造 SUBPIECE，并让新输出保留各 source 的 Address space/offset。锁定
  12.0.4 的 synthetic LE/no-effect fixture 覆盖 register PIECE、重复槽、非 PIECE
  readers、canonical combined input 与两条 LowlevelError；BE Architecture 配置、nullable
  slot、local-map/ProtoModel/high-level/lane 副作用和 raw SeqNum time/order 分离仍是残差。
- `DOUBLE_PRECIS_ON` flag（funcdata.hh:85=0x2000）+ `set_double_precis_recovery`/`is_double_precis_on`。
- `new_varnode(size, addr)`（funcdata.hh:282）— 包装 vbank.create。
- `warning_header(txt)`（funcdata.cc:135-145）— 通过 commentdb 加 WARNINGHEADER 注释。

### 2026-07-01（管线改造）：restart_pending + jumptable_recovery
- `restart_pending: bool` 字段 + `has_restart_pending()/set_restart_pending(bool)` — ActionRestartGroup 的重启信号。
- `is_jumptable_recovery_on() -> bool` — Rudra 无 jumptable 恢复，返回 false（TODO）。

### 2026-07-01（续 4）：create_new_block
create_new_block(): 创建新空 BlockBasic 并加入 bblocks（funcdata_block.cc newBlockBasic）。

### set_high_level + HIGHLEVEL_ON（2026-07-03 续）
- 新增 `Funcdata::set_high_level`（对齐 Ghidra `setHighLevel` funcdata_varnode.cc:595）：设 `HIGHLEVEL_ON` 标志（对齐 `highlevel_on` funcdata.hh:84）+ 遍历 loc_tree 给每个无 high 的 Varnode 分配 HighVariable。幂等。
- 新增 `funcdata_flags::HIGHLEVEL_ON`。

### remove_unreachable_blocks 入口检测修复（2026-07-03 续）
- 修了入口检测 bug：之前只查 `ENTRY_POINT` flag（Rudra CFG 构建从不设此 flag），回退到 block 0。改为查 `size_in()==0`（对齐 Ghidra `isEntryPoint()` block.hh:325）。
- 但发现更深的根因：Rudra 的 bblocks CFG 构建不完整——跳转表/间接分支的边没全连上，导致 BFS 从入口可达的块远少于实际（getparameter: 49/133 块被误判可达，84 块误判不可达）。启用 ActionUnreachable 会删掉大部分函数体。
- ActionUnreachable 保持禁用，注释说明根因（CFG 边不完整）+ 修复路径（CFG 构建需补全跳转表/间接分支边）。

### remove_unreachable_blocks 保守门禁 + 深度诊断（2026-07-03 续 2）
- 加了保守门禁：unreachable >= 5 且 > 5% 时跳过移除（防 CFG 不完整时误删可达块）。
- 诊断：即使只移除 1 个"不可达"块（myprogress: 13 块中 1 块），也破坏了函数体 → block 移除逻辑（branchRemoveInternal/blockRemoveInternal）或 structure_reset 有 bug。
- ActionUnreachable 保持禁用，注释说明：CFG 边不完整 + 块移除逻辑需验证。

### remove_unreachable_blocks op-destruction（2026-07-03 续 3）
- 新增 Phase 2：销毁死块的所有 op（mark_dead），从 obank.alivelist 移除。这是正确移除块的前提（之前 op 留在 alivelist → printc 打印已删块的内容 → 损坏输出）。
- 但 ActionUnreachable 仍禁用：还需要 MULTIEQUAL (phi) 修补（Ghidra blockRemoveInternal :278-294 的 opRemoveInput+opZeroMulti），否则后继块的 phi-node 引用被删块 varnode 变悬空。
- curl gcc 24/24（保持），956/956 测试。

### remove_unreachable_blocks descendantsOutside 检查（2026-07-03 续 4）
- Phase 2 改进：只 mark_dead 没有外部后代的 op（descendantsOutside 检查，对齐 Ghidra funcdata_block.cc:312）。有外部 phi-node 引用的 op 保持 alive（块标 DEAD 但 op 不删）。
- 但 ActionUnreachable 仍禁用：根因更深——Action 在 mainloop 最开始运行，此时 bblocks CFG 可能不完整（sblocks 未建），移除块破坏后续阶段状态。需 pipeline 顺序调整或 CFG 完整化后才能安全启用。

### spliceBlockBasic op-moving 修复（2026-07-03 续 5）
- 修复：spliceBlockBasic 现在把 out_block 的 ops 移到 bb 末尾（对齐 Ghidra funcdata_block.cc:940-947）。之前只重定向 CFG 边，ops 被孤立。
- 还加了 MULTIEQUAL 检查（Ghidra :936 遇 phi 抛异常，Rudra 返回 false）。
- 但仍需 setOrder（:948 重置 seq_num）——Rudra 的 BlockBasic::set_order 未实现。RedundBranch 保持禁用直到 setOrder 完成。

### BlockBasic::set_order + spliceBlockBasic（2026-07-03 续 6）
- 新增 `BlockBasic::set_order`（block.rs）——重置块内所有 op 的 seq_num.order，均匀分布（Ghidra block.cc:2638-2651）。
- spliceBlockBasic 在 op-moving 后调用 set_order（Ghidra funcdata_block.cc:948）。
- 但 RedundBranch 仍禁用：splice 移除块后，引用该块为 goto 目标的 op 留下 `goto ;` 空目标。需更新 goto 引用（重定向到拼接后的块）。

### spliceBlockBasic CFG 对齐（2026-07-03 续 7）
- 重写 `splice_block_basic` 的 CFG 边处理，忠实对齐 `BlockGraph::spliceBlock`（block.cc:1597-1620）。
- 之前：手工 `remove_edge + add_edge` 拼接，丢失 moveOutEdge 的 reverse-index 重定向，且**完全丢弃 flags**。
- 现在：
  - 读取 `fl1 = bl.flags & (UNSTRUCTURED_TARG|ENTRY_POINT)`、`fl2 = outbl.flags & SWITCH_OUT`、`szout = outbl.size_out()`
  - `remove_edge_blocks(bb, out_block)` = `removeOutEdge(0)`（block.cc:1612）
  - `for _ in 0..szout { move_out_edge(&out_block, 0, bb) }` = `moveOutEdge` 循环（block.cc:1614-1616）
  - `remove_block_arc(out_block)` = `removeBlock`（block.cc:1618）
  - `bb.flags = fl1 | fl2` = Ghidra 的 `bl->flags = fl1 | fl2`（block.cc:1619，**直接赋值非 OR**）
- `mergeRange`（funcdata_block.cc:942，旧注释误写 :953）：**已接线（2026-09-22，
  SB-HERITAGE50-BLOCKCOVER-0001）**——`splice_block_basic` 在 CFG 拼接前执行
  `bb_bb.merge_range(out_bb)`（`BlockBasic::cover` 已升级为多范围
  `RangeList`，见 docs/api/block.md 2026-09-22 节）；拼接块 `getStart()` =
  并集 cover 的最低范围首地址。
- root cause：flags 丢失导致 `f_unstructured_targ` 丢失，printc 无法解析 goto 目标 → `goto ;`。
- Alignment Evidence 见 commit message。

### 2026-07-04（续）：op_insert_end + op_mark_non_printing
- `op_insert_end(op, bb)`（funcdata_op.cc:435）：插到块末尾；若末尾是
  flow-break（BRANCH/RETURN），则插在该终结 op 之前。
- `op_mark_non_printing(op)`（对齐 funcdata.hh:519）：设置 NONPRINTING flag。

### 2026-07-04：移植高优先级缺失 Funcdata op-editing API
- `op_set_all_input(op, vvec)`（funcdata.hh:477）：一次性设置所有输入（先 unset 全部，resize，再逐个 set）。
- `op_mark_calculated_bool(op)`（funcdata.hh:486）：标记布尔输出。
- `op_mark_special_print(op)`（funcdata.hh:483）：标记特殊打印。
- `op_mark_no_collapse(op)`（funcdata.hh:484）：标记不可折叠。
- `op_mark_spacebase_ptr(op)`（funcdata.hh:487）/ `op_clear_spacebase_ptr(op)`（funcdata.hh:488）。
- `mark_indirect_creation(indop, possible_output)`（funcdata.hh:451）：把已存在的 INDIRECT op 标记为 indirect creation。

### 2026-07-04（续 2）：移植 block-graph 重写 API
- `install_switch_defaults`（funcdata_block.cc:687）：遍历 jump_tables，按槽位清除旧 default 后，通过 reciprocal reverse index 在 source out-half 与 target in-half 同步标记唯一默认边。
- `remove_do_nothing_block(bb)`（funcdata_block.cc:327）：移除 do-nothing 块（setDead + opDestroy + removeBlock + structureReset）。
- `node_join_create_block(...)`（funcdata_block.cc:779）：创建合并块（newBlockBasic + setFlag(f_joined_block) + setInitialRange(addr,addr) + removeEdge + moveOutEdge + addEdge）。
  - 2026-09-23（SB-JOINSTOP，PARSECONFIG-JOINBLOCK-STOPADDR-0001）：补齐 cc:786
    `newblock->setInitialRange(addr, addr)`——原实现误判 informational-only 跳过，join 块
    cover/getStop 保持 Address(0)；`Merge::buildDominantCopy`（merge.cc:1168）以
    `domBl->getStop()` 为新主拷贝 op 建址，缺失致 parseconfig ordinal 320 dominantcopy
    `0:903` vs `3e84:903`。补齐后 parseconfig.constprop.0 投影对 oracle pin b2ace56a
    全 MATCH（335 stages / 130099 ops）。
- 文件级 helper `find_out_index`（对应 FlowBlock::getOutIndex）。

### 2026-07-04（续 3）：移植 nodeSplit + CloneBlockOps
- `node_split(b, inedge)`（funcdata_block.cc:845）：分裂基本块，复制 p-code 到新块。
- `node_split_block_edge`（funcdata_block.cc:824）：创建 DUPLICATE_BLOCK 块，重定向入边。
  - `copyRange(b)`（funcdata_block.cc:832）已接线（2026-09-22，
    SB-HERITAGE50-BLOCKCOVER-0001）：重复块 `copy_range` 继承原块完整
    多范围 cover，getStart/getStop/getEntryAddr 与原块一致（Ghidra 语义）。
- `switch_edge(in, outbefore, outafter)`（block.cc:1489）：重定向出边目标。
- `CloneBlockOps` struct（funcdata_block.cc:962-1104）：完整 p-code 克隆逻辑：
  - `build_op_clone`：克隆 op（复制 opcode + flag 子集，跳过 branch）。
  - `build_varnode_output`：克隆输出 varnode（复制 flag 子集）。
  - `clone_block`：遍历 ops 克隆 + patch_inputs。
  - `patch_inputs`：MULTIEQUAL→COPY 转换 + 常量共享 + 克隆映射查找。
- 新增 `block_flags::DUPLICATE_BLOCK`（f_duplicate_block=0x40000）。
### 2026-07-04: Added flow module (FlowInfo reachability tracking)

### 2026-07-04（续 4）：AncestorRealistic + ancestorOpUse + onlyOpUse 移植

**AncestorRealistic**（funcdata.hh:655-724 + funcdata_varnode.cc:1997-2237）：
- `AncestorRealistic` 结构 + `ArState`（op: Arc<RwLock<PcodeOp>>, slot, flags, offset）
- `state_flags` 模块：SEEN_SOLID0/SEEN_SOLID1/SEEN_KILL
- `ar_command` 模块：ENTER_NODE/POP_SUCCESS/POP_SOLID/POP_FAIL/POP_FAILKILL
- `execute(op: &PcodeOpRef, slot, trial: &mut ParamTrial, allow_fail) -> bool`
- `enter_node` — 5 case switch：INDIRECT（isIndirectCreation/isIndirectStore/killedbycall）、SUBPIECE（overlap 检测 + minimal traversal）、COPY（internal/incidental + PIECE-following minimal traversal）、MULTIEQUAL（push + multiDepth++）、PIECE（trial_size 比较 + slot 选择）
- `upon_pop` — MULTIEQUAL 回溯（markSolid/markKill + checkConditionalExe + seenSolid/seenKill 决策树）
- `check_conditional_exe` — parent block size_in==2 + solid slot source size_out==1
- Rust 适配：trial_killed_by_call/trial_size 快照字段 + pending_ind_create_formed/pending_condexe_effect 延迟应用

**ancestorOpUse**（funcdata_varnode.cc:1917-1994）+ **onlyOpUse**（funcdata_varnode.cc:1805-1904）：
- `pub fn ancestor_op_use(fd, maxlevel, vn, op, trial: &mut ParamTrial, offset, flags, match_fc) -> bool`
- 递归 def 链遍历（INDIRECT/MULTIEQUAL/COPY/PIECE/SUBPIECE）+ only_op_use 回调；PIECE 只按
  offset 门控递归单一 piece（cc:1958-1964，least-sig at 0 / most-sig at in(1).size）；
  SUBPIECE 以 offset+newOff 前进并在 REM/SREM 旁效时 setRemFormed（cc:1965-1985）
- `only_op_use(fd, vn, opmatch, trial, flags, match_fc)` — 前向 descend BFS：BRANCH/LOAD/STORE
  → false；CALL/CALLIND → checkCallDoubleUse 可 continue；不同 RETURN：仅当持有同 slot
  varnode 才豁免，否则 res=false（cc:1849-1861，activeoutput 分支带 isAlternatePathValid）；
  PIECE/SUBPIECE 维护 CONCAT_HIGH/LSB_TRUNCATED；default 置 ACTIONALT；每个 op 的
  非 persist 输出都入队（cc:1887-1896）
- `fn is_alternate_path_valid(vn, flags)` — TraverseNode::isAlternatePathValid
  （expression.cc:28-50）1:1 端口
- checkCallDoubleUse（cc:1756-1793）：fc/matchfc 均不再重复加锁——opmatch 的 spec 由调用方
  以 `match_fc: Option<&FuncCallSpecs>` 传入（Rust 锁重入规避；op==opmatch 时两者同引用）。
  input-active 分支的 cc:1789-1790 已接通（2026-09-23，GETPARAM-ACTIVEPARAM-TRIAL-0001）：
  未 checked trial 若 `is_alternate_path_valid(vn, fl)` 为真 → return false（拒绝该 trial），
  否则 return true；checked+active → false，checked+inactive → true 不变。此前该分支
  无条件 return true（保守保留），使 killed-by-call RSI trial 误判 active。
  `fl` 参数（调用方传 BFS cur_flags）自该修复起被消费
- traverse_flags 模块：ACTIONALT/INDIRECT/INDIRECTALT/LSB_TRUNCATED/CONCAT_HIGH

**2026-09-29（ACTIVEPARAM 速度道）：走查内锁合并/免分配化（行为恒等）。**
- `only_op_use`：descendant 快照缓冲改为每次调用复用一块 `descend_buf`
  （per-visit `clear+extend`，内容/顺序与 per-visit collect 恒等；oracle 就地迭代
  `vn->descend`，funcdata_varnode.cc:1818）——VdbeExec 消除 ~4.9M 次访问的重复
  malloc/free。`opmatch_is_return`（cc:1850 裸读的 Rust 锁形式）从 per-op 循环提升到
  走查前单次读取：走查对 op 只读（不写 opcode），每次迭代观测值恒等。
- `ancestor_op_use`：INDIRECT/COPY/SUBPIECE 臂的多段 `def_arc.read()` 合并为单守卫
  快照（纯读区间锁合并，OPPPOOL 手法）；oracle 每字段裸读一次。
- `AncestorRealistic::enter_node`：栈顶 State 的两次快照（op/slot/offset 三元组 +
  pull-back 视图）合并为单次读取。
- 走查形态计数（oou_calls/visits/desc_ops/ccdu）优化前后逐值相同（[APROF] 探针，
  VdbeExec --one 1055），stdout md5 恒等。

**initActiveOutput maxPass 修正**（funcdata_varnode.cc:585-593）：
- `init_active_output` 现按 Ghidra 计算 `maxdelay = funcp.get_max_output_delay()`
  （>0 时夹到 3）；锁定 cspec 的全部模型输出条目都在 register 空间（delay=0），
  故 maxpass=0 —— 由 oracle next_url 投影 round-1 finalize（ordinal 19 裁 RDX）实证。

**新增 PcodeOp mark 访问器**：is_mark/set_mark/clear_mark（op.hh:190/234/235，flags MARK=1<<13）
<!-- annotation-pass: 2026-08-15 -->
<!-- activeparam-port: 1783158350.9624996 -->
 

### 2026-07-05: op_set_input / op_unset_input / total_replace / op_set_all_input 签名改 &mut self
- `op_set_input`(funcdata_op.cc:104): 改 `&mut self`,4 类语义全对齐(early-out / const dedup / opUnsetInput erase_descend / addDescend)。修了 placeholder bug(用 vn 当 resize 占位会触发 early-out)。
- `op_unset_input`(cc:92): erase_descend + clearInput(隐式)。
- `total_replace` / `op_set_all_input`: 改 `&mut self`(Ghidra 是 mutable)。

### 2026-08-11：ANN-E CFG/helper 注释溯源

本轮只补来源标注，不改变运行时行为。源码 oracle 固定为 Ghidra 12.0.4
commit `e40ed13014025f82488b1f8f7bca566894ac376b`。

- `find_in_index` 映射 `block.cc:579 FlowBlock::getInIndex`；Rust 用
  `Option<usize>` 表示 Ghidra 的 `-1` 未找到值。
- `has_no_code` 映射 `funcdata.hh:153 Funcdata::hasNoCode`，但当前 Rust
  仍以空 op-bank 加零 size 近似 Ghidra 的 `no_code` flag，因此该映射仍是
  已知行为缺口，不能据此声明 `MATCH`。
- `block_index_for_op_addr`、`find_jump_table_arc`、`load_fill`、
  `funcp_extrapop`、`userop_type` 是 Rust 的地址查找、Arc 所有权、
  `Result`/`Option` 或缺字段适配器；Ghidra 在 `compareCallspecs`、
  `blockRemoveInternal`、`fillinExtrapop`、`earlyJumpTableFail` 内直接执行
  对应表达式，没有这些独立的 `Funcdata` 函数。

其中 `funcp_extrapop` 恒返 unknown、`userop_type` 的缺表 fallback、以及
`block_index_for_op_addr` 用地址代替 PcodeOp 身份/顺序，都是既有差异；本轮
仅如实分类，未将其伪装为 Ghidra 映射。

## 2026-08-13：`PcodeEmitFd::dump` 输入对象创建语义

`PIPE-REACH-0001` 重新读取锁定 `funcdata.cc:878-910 PcodeEmitFd::dump` 后，修正
`inject_raw_ops_single` 的输入构造：每个 emitted operand 都创建独立 Varnode；常量走
`VarnodeBank::create_constant` 以保留 CONSTANT 状态；BRANCH/CBRANCH/CALL 的第一个
operand 走一字节 code-reference；其他 operand 以 SLEIGH 指定空间创建。每次输入创建后
立即建立 descendant 反向引用。

真实 `GetStr` raw fixture 中，Rudra 因而从旧的 197 个 Varnodes 变为与 Ghidra 相同的
272 个；全部 103 个 op 的地址、数值 opcode、输入数量和输出存在性顺序一致。
2026-08-28 复验进一步关闭了这里的旧 unknown datatype/flags 结论：272 个 ordered
raw Varnode 的 flags + complete type records 现全部 MATCH。首个剩余 raw storage
差异是 CALL 的 FSPEC address space，High/resolution/symbol 与后续阶段仍由各自 TODO
跟踪；本项仍不构成 `Funcdata` 模块 L3 证明。
 
 
 
 

## 2026-08-15：`SLEIGH-FLOW-REL-0001` — `inject_raw_ops_single` 忠实 `PcodeEmitFd::dump`

锁定 oracle：Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮
完整重读 `funcdata.cc:878-908 PcodeEmitFd::dump`、`funcdata_varnode.cc:43-233`
（`assignHigh/newConstant/newUniqueOut/newVarnodeOut/newVarnode/newCodeRef`）、
`varnode.cc:1250-1352/1411-1432`（`VarnodeBank::create/xref/createDef/replace`）、
`op.cc:941-1000`（`PcodeOpBank::create/destroy`）后重写
`Funcdata::inject_raw_ops_single`：

1. **输出先行**：有输出的 op 先经 `VarnodeBank::create_def_with_space`
   （=`createDef`：构造 flags + `setDef` 的 `written|coverdirty` + `xref` 的
   `insert`）创建输出 Varnode，再创建输入——与 dump 的
   `newOp → newVarnodeOut → opSetOpcode → inputs` 顺序一致，固定了
   `Varnode::create_index` 与 Ghidra 相同的发射序。
2. **CODEREF 语义**：仅 BRANCH/CBRANCH/CALL（typeop.cc:586/605/663 的 coderef
   opflags；BRANCHIND/CALLIND 无此 flag）的 input(0) 走 `newCodeRef`：
   一字节 annotation Varnode 落在 **SLEIGH 上报的原空间**（`Address(vars[0].space,
   vars[0].offset)`），类型为核心 "code" 类型（`sleigh_arch.cc:233
   setCoreType("code",1,TYPE_CODE,false)`）。因此 CPUID 决策树这类
   `goto <label>` 内部相对分支（slghparse.y:462，const space + j_relative +
   `resolveRelatives` 写回的 masked 偏移）保持 Const 空间；x86 机器
   `jmp/call rel`（ia.sinc:1149-1151 `export *[ram]:$(SIZE) reloc`）保持 Ram
   空间绝对地址。二者不再被互相改写。
3. **其余输入**：逐引用新建 Varnode（常量含内，无位置去重），`addDescend` 按
   slot 顺序追加并置 `coverdirty`，与 `newVarnode→vbank.create` +
   `opSetInput→addDescend` 等价。
4. 新增 `code_ref_datatype()`：构造与 `TypeFactory::getTypeCode`
   （type.cc:3692-3701）观察等价的 `{name:"code", metatype:TYPE_CODE, size:1}`
   值对象（Rudra 未把 TypeFactory 穿入该发射路径）。

真实 `0f a2 c3`（CPUID; RET）门禁结果：Rudra 与锁定 Ghidra capture 逐字节一致
（81 ops / 186 Varnodes / 33 个 Const 空间 relative 分支全部 internal 解析 /
34 blocks / 49 raw+graph edges / visited 2）。这是
`tools/run_sleigh_flow_relative_oracle.sh` 差分门禁的 `funcdata.rs` 侧证据；
Varnode 生命周期其余差异（Fspec 空间、HighVariable 分配等）仍由
`ADDR-0001`/`CALLSPEC-0001` 跟踪，本模块保持 L2/MISMATCH。

### 2026-08-15: totalReplace 快照迭代 + opUnsetInput NULL-slot 语义（FUNC-GLOBRANGE-HANG-0001）

- `total_replace(vn, newvn)`（funcdata_varnode.cc:1474-1487）：从「循环重扫
  descend 直到无 live 条目」改为 Ghidra 的迭代器语义——一次性快照 live
  descendant，逐站点在**应用时**计算首个匹配 slot（getSlot，op.hh:166，
  先前的站点改写后求值），再 `op_set_input`。Ghidra 用 `op = *iter++` 在
  opSetInput 断链前推进迭代器，因此每个原始条目恰好访问一次、到达
  endDescend() 即终止——即使 `newvn == vn` 时 opSetInput 早退（cc:107）留下
  条目也只跑一趟。旧 Rust 重扫循环在 precisely 该情形下永续自旋
  （glob_range(0x4d60) 死锁，A/B 证明：旧实现跑
  `test_total_replace_same_varnode_terminates` 30s 超时被 SIGTERM；新实现
  通过）。死 Weak 条目（Ghidra raw 指针模型不可达）无法访问即跳过；slot
  缺失（Ghidra getSlot→numInput→opSetInput throw）按漂移清理掉 stale 条目。
- `op_unset_input(op, slot)`（funcdata_op.cc:92-99）与 `op_set_input` 第 (3)
  步（cc:120-121）：Ghidra `clearInput`（op.hh:136）原地置 NULL，
  `opDestroy`（funcdata_op.cc:213-215）逐槽 `if (vn != NULL)` 守卫；Rust
  `Vec<Arc>` 不能存 NULL，stale Arc 保留在槽内，改用「op 是否仍在该 vn 的
  descend 列表」作为链路存活性判据——不在则跳过 erase，等价于 Ghidra 的
  NULL-slot no-op。重复 unset（op_unlink → op_destroy 序列，Ghidra 靠 NULL
  槽天然幂等）不再产生 `erase_descend not in descend list` WARN 风暴。
- `destroy_varnode`（funcdata_varnode.cc:277-284）：`op_get_slot` 返回 -1 时
  不再 `as usize`（usize::MAX 静默 no-op，遗留无法匹配的死条目），改为跳过
  ——Ghidra 该点越界写 UB（前置条件违规），Rudra 以保守跳过表达。
- 回归测试：`test_total_replace_same_varnode_terminates`、
  `test_total_replace_skips_dead_weak_entries`、
  `test_unlink_then_destroy_does_not_disturb_other_readers`。
- E2E：curl 全量 24/24 函数完成（glob_range 1.1s、match_url 亦完成），
  `erase_descend` WARN 1454→0；残余 340 条 `free varnode multiple
  descendants` 为揭出的真实 live 不变量违规（UPSTREAM-OUTVN-DEADWIRE-0001
  残余范围）。

### 2026-08-15：`op_heritage` 桥 + `set_self_ref` 收窄（`HERITAGE-OWNERSHIP-0001`）

- 新增 `Funcdata::op_heritage`（funcdata.hh:462 的 1:1 桥）：`mem::take`
  暂移 persistent Heritage → `heritage.heritage(self)` 单 pass（显式
  `&mut Funcdata`，零 Weak 升级、零嵌套锁）→ 原对象回写。连续调用
  pass=0→1→2→3。
- `set_self_ref` 不再回填 `heritage.fd`（该字段已删除）：Heritage 管理器
  不再持有 Funcdata 句柄，消除 HERITAGE-DRIVER-0001 审计认定的写锁
  重入死锁源。
- 证据：`tests/oracle/heritage_ownership_1204.*`（3/3 MATCH，含 phi
  自引用环三连 pass 无死锁）；生产 `ActionHeritage` 未切换（归
  HERITAGE-DRIVER-SWITCH）。

### 2026-08-15：`new_indirect_op` 忠实化 + `new_indirect_creation_in_space`（HERITAGE-CALLGUARD-0001）

- `new_indirect_op(indeffect, space, offset, sz, extra_flags)`（funcdata_op.cc:683-698）
  签名对齐 oracle：输出/输入 varnode 在调用方传入的 `(space, offset)` 而非
  写死 Stack；`extra_flags` 由调用方决定（CALL guard 传 0，STORE guard 传
  `indirect_store`）；input[1] 改用 `new_varnode_iop`（Iop 空间，经
  `get_op_from_const` 可回溯 causing op 别名）替代写死的 Const/annotation
  常量；构造器不再 `set_active_heritage`（Ghidra 的调用方
  guardCalls/guardStores 在构造后设置）。
- `new_indirect_creation_in_space(indeffect, space, offset, sz, possibleout)`
  （funcdata_op.cc:710-728）：输出 varnode 在调用方空间（如 killed-by-call
  的 RAX Register 空间）而非写死 Unique；旧 `new_indirect_creation` 保留为
  Unique 空间委托（ruleaction 的历史调用点行为不变），同样移除构造器内的
  `set_active_heritage`。
- 证据：`tests/oracle/heritage_callguard_1204.*`（锁定 12.0.4 双侧 7 case
  逐字节 MATCH：IOP 别名、parent/位置、in0 形态、out 空间/flags）。


### 2026-08-15：MERGE-PERSISTENT-STATE-0001 — 持久 merge_state 挂载点
- `Funcdata::merge_state: MergePersistentState`（新字段，funcdata.hh:96
  `Merge covermerge` 对应物）：构造器初始化为 default（对应 funcdata.cc:39
  `covermerge(*this)`），merge-family Action 经 merge.rs 的 attach/detach
  往返共享 testCache/copyTrims/存活前提。
- `Funcdata::clear()`：在 heritage.clear() 后追加
  `self.merge_state.clear()`（funcdata.cc:108 `covermerge.clear()` 对齐）。
- `set_high_level()`：每个待分配 High 的 varnode 先
  `if has_cover() { calc_cover() }`（funcdata_varnode.cc:52-53
  setHighLevel→assignHigh 的 calcCover 副作用）。此前缺失该步导致独立
  merge Action（mergerequired/mergecopy/mergeadjacent）在 null-cover 空前提
  下运行。
<!-- annotation-pass: 2026-08-15 -->

### 2026-08-16：`new_indirect_op` 规范构造（`HERITAGE-CALLGUARD-0001`）

`Funcdata::new_indirect_op`（funcdata_op.cc:683-728 对应物）：free-varnode
输入、def 承载输出、Iop alias 往返、调用方旗标、`op_insert_before` 的
INDIRECT 群回跳；构造器不再内置 `set_active_heritage`/硬编码
`INDIRECT_STORE`（对齐 oracle 的调用方语义）。供 canonical guardCalls
接线消费；生产 `ActionHeritage` 双 pass 路径不变。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`Funcdata::linkSymbol`（funcdata_varnode.cc:1156-1184 对应物）重写为逐行
对齐：proto-partial 走 `link_proto_partial`（`PieceNode::findRoot` 的
op.cc:824-852 多级 PIECE 回溯为 funcdata.rs 模块级 `piece_node_find_root`）；
high 已有 Symbol 时提前返回；`queryProperties(addr,1,usepoint)` 查询重叠
（usepoint 为 def op 地址，input 取函数基址-1，varnode.cc:696-703）；无重
叠且非 persist 时 `localmap->addSymbol("", high->getType(), addr, usepoint)`
——`local_XX` HashMap 自创名删除，golden 的 bVar/pcVar 族由此产生。
`handleSymbolConflict`（:997-1029）与 `buildDynamicSymbol`（:1283-1305）改
走 ScopeLocal 符号模型（varmap.rs），HighVariable→Symbol 关联由
`Funcdata::high_symbols` 侧表建模（variable.rs 不在本租约）。persist 无重
叠仍返回 None。`remapVarnode`/`remapDynamicVarnode` 的 symbol_table 记录
保留（GLUE，待 DB-LOCALSCOPE-MAP-0001 收编）。

### 2026-08-16（复核修正）：`linkSymbol` 链四处对齐收口（`FUNCDATA-LINKSYMBOL-TYPED-0001` 复核）

`piece_node_find_root` 的多 PIECE 平手改用忠实的 `PcodeOp::compare_order`
（op.cc:778-791 执行支配序，原为地址数值比较）；`attach_symbol_to_vn` 不再
手写 flags——经 `Funcdata::symbol_entry_cache`（LocalSymbol→database.rs
`SymbolEntry` 身份稳定桥接，动态项带 hash、静态项带单址 uselimit）调用
`Varnode::set_symbol_entry`（varnode.cc:429-439 的 mapped/namelock 腿）+
忠实 `HighVariable::set_symbol`（variable.cc:245-275 四分支 symboloffset：
整匹配 -1、部分覆盖=overlap 字节偏移），coreaction.cc:2965 的
`getSymbolOffset() < 0` namerec 门因此与 Ghidra 同判；桥接 Symbol 的名字
在命名期后由 ActionNameVars 刷新与 varmap 符号一致。fixture 新增
partial_coverage case：4 字节临时@0x70（def pc=函数基址-1）+ 1 字节
input@0x71 → soff=1、被 namerec 门排除，双侧逐字节一致。

### 2026-08-17：set_arch 绑定 Architecture default model（FUNCPROTO-MODEL-BIND-0001）

- `set_arch` 不再只赋 `arch` 字段——它镜像 Ghidra named ctor 的绑定链
  （funcdata.cc:48 `glb = scope->getArch()` → funcdata.cc:69
  `funcp.setScope(localmap, baseaddr-1)` → fspec.cc:3884
  `if (model == 0) setModel(s->getArch()->defaultfp)`）：当 `funcp` 尚无
  model 时安装 `Architecture::defaultfp` 的共享 Arc。Rudra 的 Funcdata
  构造没有 ctor 期 Scope（FUNCDATA-LOCALSCOPE-OWNERSHIP-0001），set_arch
  即 `glb` 可用时刻。效果：DWARF/PLT locked-prototype overlay 之后不再出现
  非法 `model_locked && !has_model`；callspec 克隆自 fd.funcp 时携带 model，
  `FuncCallSpecs::has_effect` 返回 cspec 声明效果而非保守 UnknownEffect。

### 2026-08-17：op_set_input 常量去重分支补全 copySymbol（VARNODE-COPYSYMBOL-FIELDS-0001）

- `op_set_input`（funcdata_op.cc:104-125）常量单读者去重分支的
  cc:112 `cvn->copySymbol(vn)` 此前只内联拷贝 mapentry，丢失
  `Varnode::copySymbol`（varnode.cc:493-505）的其余簿记：Datatype 指针
  拷贝（cc:496）与 typelock|namelock 位的清空重继承（cc:498-499，
  不含 mapped/insert）。现改为直接调用 `Varnode::copy_symbol`
  （varnode.rs，cc:496-499 字段腿），equate 锁定常量在去重后不再丢
  type/typelock/namelock。
- cc:500-504 的 high 簿记（`high->typeDirty()`；有 mapentry 时
  `high->setSymbol(this)`）按 attach_symbol_to_vn 房式（Varnode 字段腿
  + Funcdata 调用侧 high 腿）接在调用侧，因为 `copy_symbol` 的
  `&mut self` 拿不到 `HighVariable::set_symbol` 所需的 Arc-to-self。
  当前不可达：Rudra `new_constant` 未接 `Funcdata::assignHigh`
  （funcdata_varnode.cc:72 缺口，残差 R1 登记 VARNODE-COPYSYMBOL-FIELDS-0001），
  cvn.high 恒 None；assignHigh 补全后该块即生效。
- oracle fixture `tests/oracle/varnode_copy_symbol_1204.{cc,rs}` +
  `tools/run_varnode_copy_symbol_oracle.sh`（pinned base dce02f7 +
  src/funcdata.rs overlay）：locks_type / no_locks / mapentry_symbol
  （含 mapentry 指针拷贝与 mapped 位不拷贝的判别）/ identity_return
  （cc:107 早退）/ spacebase_exempt（cc:110 豁免）6 行双侧逐字节 MATCH；
  high 块 NO_ORACLE（fixture 不开 highlevel_on，双侧 cvn.high==null）。

## 测试区维护（2026-08-17）

`test_split_uses_duplicates_op` / `test_unlink_then_destroy_does_not_disturb_other_readers`
的 harness 修正（VARNODE-ADDDESCEND-THROW-0001 前置件，同 aa0b6e1 ruleaction/subflow
模式）：被 splitUses 重读（funcdata_varnode.cc:1560 对每个复制 op 重设全部输入）或
被双读者共享的 free 寄存器 varnode 经 `VarnodeBank::set_input`（varnode.cc:1358 setInput
映射）登记为 INPUT，消除 addDescend throw（varnode.cc:336 "Free varnode has multiple
descendants"）会触发的 Ghidra 不可达 harness 态。INPUT 保持 is_written/is_addr_tied
false，split_uses / op_unlink / op_destroy / op_unset_input 无 input-flag 分支，
断言与被测路径零变化；setInput 在唯一 loc 上返回同一 Arc，ptr_eq 断言原样通过。
生产代码未动。

### 2026-08-17（续）：assign_high 双向挂接 + new_* 族十处接线（FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001）

- `assign_high`（funcdata_varnode.cc:48-59）补全 Ghidra `new HighVariable(vn)`
  ctor（variable.cc:220-235）的全部副作用：`add_instance(vn)`（cc:231）、
  `vn.mergegroup = 0; vn.high = high`（cc:232 setHigh(this, numMergeClasses-1)）、
  `vn.getSymbolEntry().is_some()` 时 `set_symbol(vn)`（cc:233-234）。此前只
  返回 HighVariable Arc 由调用者丢弃，vn.high 恒 None。
- newVarnode 族十处调用面接线（全部在 funcdata_varnode.cc，任务清单原写
  funcdata.cc 系笔误，oracle 已核实）：
  | oracle 行 | 函数 | Rudra 接线 |
  |---|---|---|
  | :72 | newConstant | `new_constant` assign_high |
  | :89 | newUnique | `new_unique` assign_high |
  | :110 | newVarnodeOut | `new_varnode_out` assign_high（queryProperties 腿前） |
  | :135 | newUniqueOut | `new_unique_out` assign_high |
  | :157 | newVarnode(s,m,ct) | `new_varnode` assign_high |
  | :182 | newVarnodeIop | `new_varnode_iop` assign_high（annotation no-op 腿） |
  | :196 | newVarnodeSpace | 已有调用，本次随 assign_high 补全而生效 |
  | :212 | newVarnodeCallSpecs | 已有（annotation no-op） |
  | :231 | newCodeRef | 已有（annotation no-op） |
  | :604 | setHighLevel | `set_high_level` 重写为经 assign_high 单一真源 |
- `Funcdata` 新增 `high_level_index: u32` 字段（funcdata.hh:76）；
  `set_high_level` 补 cc:600 `high_level_index = vbank.get_create_index()` 与
  annotation 拒绝门（iop/fspec/coderef varnode 不挂 high，cc:54 guard）。
  merge.rs `wire_unique_high` house pattern 自动退化为 no-op（early return）。
- 上节 "当前不可达：cvn.high 恒 None" 已失效——highlevel_on 置位后
  `op_set_input` 去重副本的 cc:500-504 high 腿可达，
  VARNODE-COPYSYMBOL-FIELDS-0001 残差 R1 关闭（fixture dedup_high 观察）。
- oracle fixture `tests/oracle/funcdata_assign_high_1204.{cc,rs,metadata.json}` +
  `tools/run_funcdata_assign_high_oracle.sh`：20 行双侧逐字节 MATCH，覆盖
  highlevel 门（off 2 行）/ setHighLevel 扫掠（7 行：flag、index、const/written
  +cover/input/iop、instances 形状、幂等）/ on 态十处族（7 行）/ opSetInput
  dedup high 腿（R1 关闭观察）/ copySymbol typedirty 重臂 + symbol guard。
  Ghidra 12.0.4 `Varnode::getHigh()` 在 high==NULL 时 throw
  LowlevelError("Requesting non-existent high-level")（varnode.cc:92），
  fixture 两侧都读裸字段（C++ `->high` / Rust `high: Option`）对齐观察通道。
  E2E：curl + httpd stdout 与接线前零差异（Matched 123 不降、defects=0、
  numbering=0）。
<!-- annotation-pass: 2026-08-17 -->


## structure_reset 支配树重置链（block_domroot_1204，2026-08-19）

**`Funcdata::structure_reset`** — `funcdata_block.cc:704-731`
`structureReset` 的语句级镜像：清 `blocks_unreachable` →
`bblocks.structureLoops(rootlist)` → `bblocks.calcForwardDominator(rootlist)`
→ `rootlist.len()>1` 置 unreachable → 死 jumptable 消灭循环（jumpvec 保序、
`warning_header` 先于 drop、isDead 经 PcodeOp 读锁）→ `sblocks.clear()` →
`heritage.force_restructure()`。RUDRA-GLUE 尾部补
`build_dom_depth/build_dom_subtree/calc_dom_frontier` 缓存刷新（Ghidra 的
dom depth 是 Heritage::buildADT 局部计算 heritage.cc:2338，Rudra 为
per-block 缓存；不触碰 oracle 可观测状态）。LowlevelError 通道按项目既有
策略映射为 panic（与 `Varnode::add_descend` 同款，per-function worker 隔离）。

**`funcdata_flags::BLOCKS_UNREACHABLE`**（bit 6 重映射，Ghidra
`blocks_unreachable` = funcdata.hh:60 = 0x4；flags 无序列化出口，按名访问
无外部可观测差异）与 **`has_unreachable_blocks`**（funcdata.hh:149）。

**对齐证据：** `tools/run_block_domroot_1204_oracle.sh` MATCH（见
docs/api/block.md 同节）；机制 C 独立复核 APPROVE。残差：死 jumptable 的
`get_indirect_op()==None` 输入域 UNTESTED（Ghidra 无条件解引用=null 即 UB，
Rudra 防御性视为 alive，生产不可达已注释）。

## laned-map 生命周期（LANEDIVIDE-INFRA-0001）


- `check_for_laned_register`（funcdata_varnode.cc:298-309 镜像）/
  `set_laned_reg_generated`（funcdata.hh:155，minLanedSize=1000000 哨兵）/
  `lane_accesses`（beginLaneAccess/endLaneAccess 镜像）/
  `clear_laned_access_map`（funcdata.hh:399）—— Funcdata 侧 typed ordered
  lanedMap 生命周期，键序为 `VarnodeData::operator<`（pcoderaw.hh:67：space
  index → offset → size 降序）。四个 `newUnique`/`newUniqueOut`/
  `newVarnode`/`newVarnodeOut` call site（funcdata_varnode.cc:90/112/136/159）
  均接 `s >= minLanedSize` 门;`clear()`（funcdata.cc:93）重置 minLanedSize 但
  不清 lanedMap（与 oracle 一致）。
- 对拍：`tools/run_lanedivide_infra_oracle.sh` MATCH（miss/hit、排序、
  setLanedRegGenerated 抑制、clear 保留 + gate 重置、clearLanedAccessMap
  逐字节一致）；残差 LANEDIVIDE-INFRA-RESIDUAL-0001（见
  tests/oracle/lanedivide_infra_1204.metadata.json）。

## 2026-08-23：MERGE-CLEAR-LIFECYCLE-0001 — clear 持久状态生命周期对拍

- `Funcdata::clear()`（funcdata.cc:84-112）从 8 步补齐为 13 步全量对齐：
  新增 7 位分析旗标掩码复位（含 `restart_pending` bool 镜像）、
  `high_level_index=0`、localmap 建模（symbols+high_symbols+
  symbol_entry_cache+param window 标量）、`active_output=None`、
  `funcp.clear_unlocked_output()`、`clear_call_specs()`、`clear_jump_tables()`，
  并把执行顺序排成 Ghidra 语句序。
- `clear_jump_tables()`（funcdata_block.cc:43-60）：override 表由"替换为新空表"
  改为调用忠实的 `JumpTable::clear()`（jumptable.rs 既有实现，
  jumptable.cc:2739-2758），保留 maxaddsub/maxleftright/maxext/collectloads/
  opaddress 永久域；此前 fresh-replacement 会丢永久域（MISMATCH 修复）。
- 观察投影（`tools/run_merge_clear_lifecycle_oracle.sh`，
  pin-base 2f9725f + funcdata.rs/merge.rs 双 overlay，schema2）：
  构造带全部持久域的 Funcdata，双侧观察 clear 前后 6 行 stdout。
  结果 `covered_projection=4/6 projection_status=MATCH overall_status=MISMATCH`；
  两行登记 MISMATCH：`localmap_typelock_survival`（Ghidra 保留
  typelock+namelock 符号，Rudra wholesale-clear 丢弃——需 varmap.rs 侧
  忠实 clearUnlocked）、`funcproto_unlocked_output`（fspec.rs 简化版不清
  returnBytesConsumed——需 fspec.rs 侧补齐）。残差统一登记
  MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001（含 4 项 UNTESTED：window range
  重派生、clean_up/cast_phase index、merge 通道生产路径填充、
  localoverride 持久性投影）。
- 既有测试影响：`funcdata::` 42 通过、2 失败
  （test_infer_params_and_return_type / test_type_propagation）为 base
  2f9725f 上即失败的预存在残差（已用 base 文件复跑验证），与本改动无关。
<!-- annotation-pass: 2026-08-23 -->

## 极性重断言（2026-08-23，root，CONDEXE-TRUEOUT-0002 跟进）

`test_bool_condition_folding_and_pattern` 按 Ghidra 纯位置极性（block.hh:299-300，out[1]=true）重断言：双 CBRANCH 的 **false** 边合流 → `BlockCondition(Or)`（block.cc:1785）；旧 And 断言编码的是翻转前反极性。

## calcNZMask 对齐重写（2026-08-23，FUNCDATA-CALCNZM-0001）

### Funcdata::calc_nz_mask（funcdata_varnode.cc:856-926）— oracle 两阶段结构
- **Phase 1（cc:859-902）**：显式 DFS opstack 按 alive 顺序遍历。遍历到 unwritten 输入时初始化：常量 → `nzm = offset`（cc:889-890）；非常量 → `nzm = calc_mask(size)`（cc:892）；spacebase 输入额外 `&= ~0xff`（视为对齐，cc:893-894）。op 弹栈时 `outvn->nzm = getNZMaskLocal(true)`（cc:874），MULTIEQUAL 的 looping 输入边被 `isLoopIn(slot)` 裁剪（cc:882-885）。Varnode 构造初值：常量=offset、其余 ~0（varnode.cc:597/601/605）。
- **Phase 2（cc:904-925）**：清 mark，把所有 MULTIEQUAL 压入 worklist；反复用 `getNZMaskLocal(false)`（不裁剪 loop 边）重算，nzm 变化时把该输出的全部 descend 压回 worklist，直至不动点。
- 旧实现（简化单遍 + 内联 switch）已删除；旧 switch 中 INT_NEGATE/INT_2COMP 分支是自创语义（oracle 落 `default:` → fullmask），已随重写移除。

### Funcdata::pcode_op_nz_mask_local → PcodeOp::get_nz_mask_local（op.cc:547，FUNCDATA-CALCNZM-0002 合并）
- **完整 oracle switch（op.cc:547-771）已迁至 `PcodeOp::get_nz_mask_local`（src/op.rs）**：比较/布尔 → 1；COPY/ZEXT 传播；SEXT sign_extend；XOR/OR/AND；LEFT/RIGHT（含 >8 字节扩展精度分支 cc:612-630）；SRIGHT（符号位已知 0 分支 cc:639-644）；**INT_DIV**（cc:648-659，coveringmask(val) >> mostsigbit_set(常量分母)——sc6 y/64 根因修复）；INT_REM（cc:660-663）；POPCOUNT/LZCOUNT（cc:664-672）；SUBPIECE（含扩展精度 cc:673-692）；PIECE（cc:693-698）；INT_MULT（cc:699-731）；INT_ADD（进位 cc:732-739）；MULTIEQUAL（cliploop 裁剪 cc:740-757）；CALL/CALLIND/CPOOLREF isCalculatedBool→1（cc:758-765）；default→fullmask。
- **输入 NZM 读取直接访问存储字段 `nzm`**（oracle varnode.hh:231 `getNZMask() { return nzm; }`）。Rudra 的 `Varnode::get_nz_mask()`（varnode.rs）是 calcNZMask 接线前的保守近似（常量→offset、其余→calc_mask），不能用于传播——残差 TODO FUNCDATA-CALCNZM-0003。
- funcdata.rs 内的暂存副本 `Funcdata::pcode_op_nz_mask_local` 已删除（值等价迁移）；`calc_nz_mask` 的 phase-1（cc:874）与 phase-2（cc:919）调用点直接调用 `PcodeOp::get_nz_mask_local`。原 funcdata.rs 侧 RUDRA-GLUE（op.rs 租约限制）随之解除，TODO FUNCDATA-CALCNZM-0002 的 op.rs divergent 旧版（忽略 cliploop、缺 DIV/REM/POPCOUNT/LZCOUNT/MULT/CALL 臂、输入 mask 走保守近似）已被完整 switch 替换。
- 原始 `>>`/`<<` 位点（oracle 未加保护处）用 `wrapping_shr/wrapping_shl` 镜像 x86-64 移位计数掩码语义；oracle 经 `pcode_right/pcode_left`（address.hh:505-517）保护的位点按其语义（sa>=64 → 0）。

### 主管线接线核实（FUNCDATA-CALCNZM-0001）
- oracle 的 calcNZMask 唯一生产调用点是 `ActionNonzeroMask::apply`（coreaction.hh:300），注册于 universal mainloop 的 `ActionSpacebase` 之后、`ActionInferTypes` 之前（coreaction.cc:5506-5508）。`newUniqueOut` 等 funcdata_varnode.cc 构造函数 **不** 触发 calcNZMask。
- Rudra 侧对应注册已存在：src/action.rs:1196（`add!(mainloop, "analysis", ActionNonzeroMask)`，"analysis" 在默认 decompile grouplist 内），无需新增接线。
- 功能证据：新增单测 `test_nonzeromask_pipeline_wiring`（funcdata.rs）——`u1=EDI&0x3f0; u2=u1/3; STORE` 走完整 `decompile` root 后，INT_DIV 输出 nzm == 0x1ff（coveringmask(0x3f0)=0x3ff >> mostsigbit_set(3)=1），未接线时写 unique 保持构造初值 ~0 不可能得到该值。

### 2026-09-26：TESTFIX——fixture 补 defaultfp 模型（长期 1F 收口）
- 该单测自落地起长期 FAILED（各车道验收 "NNNNP/1F 预存" 的那 1F）。panic 点=`FuncProto::effect_iter`（fspec.rs）`.expect("requires a prototype model")`，调用链=默认 action 树 `localrecovery` 组 `ActionRestrictLocal::apply`（coreaction.cc:1957）Loop 2 读 `data.getFuncProto().effectBegin()`（coreaction.cc:1983）。
- **BRANAUDIT 2026-09-26 裁决**（/dev/shm/rudra-reports/LANE_BRANAUDIT_2026-09-26.md）：合成 fixture 缺 proto model，非 nzm 布线缺失（布线随 a770ed10 落地，ruleaction.rs 读 `get_nzm()`）。
- oracle 亲读定案（本 session 机制 E 回执）：`FuncProto::effectBegin/effectEnd`（fspec.cc:4243-4259）在 prototype-local effectlist 为空时**无条件解引用** `model`——oracle 无优雅路径（null 即段错误）；真实管线里 model 恒被绑定（Funcdata 具名构造尾 `funcp.setScope` funcdata.cc:69 → `FuncProto::setScope` fspec.cc:3879 的 3883-3884 `if (model==(ProtoModel*)0) setModel(s->getArch()->defaultfp)`）。Rudra 生产侧 `effect_iter` 的 `.expect`（带明确 panic 消息）即该无条件解引用的忠实镜像，**不改生产代码**。
- 修法=测试侧：fixture 在 `Funcdata::new` 后自行绑定 stand-in `defaultfp`（`ProtoModelFull::new(Some(Stack),8)` 默认构造形 fspec.cc:2339、名 "default"、空 effectlist——ActionRestrictLocal Loop 2 为 no-op，被测可观测面保持 nzm 布线）。Rudra canonical 默认 Architecture 是 cspec-less 的（`defaultfp==None`），与 oracle "Architecture 解析后 defaultfp 恒非空" 不变量的差异由 fixture 侧补齐。
- 验收：`cargo test --lib` **1747P/0F/5I**（基 efc28f4a 上全绿；5 ignored 为既有 `#[ignore]`）；canon 双语料零扰动=纯 `#[cfg(test)]` 改动 + curl E2E 差分保险亲跑。

## 2026-08-23：`FLOW-TRUNCATED-0001` partial-flow clone

`Funcdata::truncated_flow(source, flow_state)` 对应锁定 Ghidra 12.0.4
`funcdata_op.cc:792-839`。目标必须没有任何既有 op；函数按 source
`deadlist` 的链表顺序、原 `SeqNum` 克隆 raw p-code，再无条件把目标 bank 的
`uniqId` 设成 source 的下一 ID。callspec 依 source qlst 顺序克隆，并用完全相同的
call-op `SeqNum` 重绑；synthetic FSPEC 输入被新目标 callspec 注解替换，旧克隆
Varnode 随即从 bank 删除。jump table 依 source vector 顺序处理：未链接项截断，
已链接项要求能以 indirect-op `SeqNum` 找到克隆 op，随后按
`jumptable.cc:2401-2425` 复制地址/model/normalization/partial/load 状态并重置
block/label/default/consume/folded/original-model 等实例状态。最后由克隆
`FlowInfo` 完成 injection（若有）与基本块生成，成功后才置
`BLOCKS_GENERATED`。`finish_truncated_flow` 现在传播 `generate_blocks` 的
`Result`；首 raw op 缺少 `STARTBASIC` 时，克隆前缀依 Oracle 保留，但 block、op
parent/order、dead→alive、edge 等生命周期尚未开始，且该 flag 保持未设置。

同轮修正 `clone_varnode`：`funcdata_varnode.cc:252-267` 的 `Address` 包含地址空间
与 offset，且 `vbank.create(..., vn->getType())` 共享原 `Datatype` 指针；Rust 现在
用 `create_with_space` 保留完整地址并复制 `v_type`，然后只保留 oracle 允许的十类
flags。`inject_raw_ops_single` 也改为通过 `new_op` 生成 dead raw op，并在 output
之后、inputs 之前执行 `op_set_opcode`，与 `PcodeEmitFd::dump` 的生命周期/创建
顺序一致。

真实双侧 fixture `truncated_flow_1204` 的当前投影为 `MATCH`：锁住 dead-list 与
SeqNum tree 的不同顺序、`uniqId`、op flags/space/order、FSPEC 重绑及 stale
Varnode 删除、jump-table clone/reset/identity/skip，以及 nonempty、missing-table
与 missing-entry 三条异常（含 Oracle 抛出前允许的 raw clone/JT 前缀和错误后的完整
op/varnode/callspec/jump-table/block/flag 状态）。该节最初记录的“Rust callspec 没有
Ghidra 的直接 `PcodeOp *` 身份”是 D0 之前的历史结论；当前实现以 exact op `Weak`
重绑，并由 typed annotation 或 `Arc::ptr_eq` fallback 区分同地址多 CALL，这一身份切片
已为 `MATCH`。全函数 B2 仍为 `MISMATCH`：effective-extrapop/paramshift/
bad-jumptable 等字段不完整，专用 FSPEC space/numeric codec 仍不同；注入分支及完整
FlowInfo 私有状态克隆仍为 `UNTESTED`，不得据此宣称 L3。

## 2026-08-24：FLOW-SHAREDRETURN-0001 — `override_flow`

`Funcdata::override_flow(addr, flow_type) -> Result<()>` 对应锁定
`funcdata_op.cc:969-1021`。它按 `PcodeOpTree` 的 SeqNum 顺序读取给定地址的全部
op，调用 `find_primary_branch` 选择第一个符合类别的真实控制流 op，并要求该 op
仍是 dead 状态；找不到或已经形成 block 时传播精确
`Lowlevel("Could not apply flowoverride")`。

改写表与 oracle 相同：

- BRANCH override：CALL→BRANCH、CALLIND/RETURN→BRANCHIND；
- CALL/CALL_RETURN：BRANCH→CALL、BRANCHIND/RETURN→CALLIND；CBRANCH 抛
  `Do not currently support CBRANCH overrides`；
- RETURN：BRANCH/CBRANCH/CALL 抛
  `Do not currently support complex overrides`，BRANCHIND/CALLIND→RETURN；
- CALL_RETURN 额外用 `new_op(1, addr)` 建 RETURN，输入为
  `new_constant(1, 0)`，再用 `insert_after_dead` 移到 primary 后。primary 的对象
  identity/SeqNum 不变，新 RETURN 的 identity/SeqNum 也不因移动重建或重复登记。

专属双侧 fixture 的选择性数值投影在 hugehelp/progressbarinit 锁住 primary identity、SeqNum、
dead-list 紧邻顺序和 RETURN 常量，并经完整 FlowInfo 路径观察 callspec target 与
OOB 状态；myprogress 锁住精确地址 query 的负例。CALL/BRANCH/RETURN 其余改写表、
CBRANCH/complex error 与 instruction-limit 组合尚未逐分支运行，保持
`UNTESTED`。另有已确认的直接调用残差：Ghidra `overrideFlow(addr, NONE)` 因未找到
primary 而抛 `Could not apply flowoverride`，Rust 当前直接返回 `Ok(())`；生产
`processInstruction` 两侧都只在 override 非 NONE 时调用，所以不影响本切片的
shared-return 路径，但 public function 仍不能称为逐分支相同。完整行为保持
`MISMATCH`：Ghidra 地址带 RAM space，Rust 当前
`Address::new` 为 null-base（`ADDRESS-PHASE2-CLOSURE-0001`）。本节初始 fixture
曾将 callspec 的 `PcodeOp *` 身份缺口记为 `CALLSPEC-0001 MISMATCH`；下述 D0 已以
双向 typed `Weak` 和 `Arc::ptr_eq` 关闭这一身份切片，当前 shared-return fixture 对该
字段为 `MATCH`。这不消除地址域或 `FLOW-SHAREDRETURN-0001` 的整体残差。

### 2026-08-24：CALLSPEC-IDENTITY-D0 stable owner 与生命周期

- `Funcdata::callspecs` 从按值的 `Vec<FuncCallSpecs>` 改为
  `Vec<Arc<RwLock<FuncCallSpecs>>>`，是 callspec 分配的权威持久强 owner；调用方
  可持有短生命周期的 `Arc` handle，但所有反向边仍为 `Weak`。
  `get_call_specs` / `get_call_specs_mut` 返回读写 guard；
  `get_call_specs_owner` / `add_call_specs_owner` 只克隆或移动同一个 `Arc` 身份。
- `get_call_specs_of_op` 的快路径要求 input(0) 同时是 Iop annotation、携带 typed
  `Weak`、该 owner 仍属于当前 vector，并且 callspec 的反向 `Weak` 精确指回传入
  op。回退也只比较升级后的 op `Arc::ptr_eq`；不再比较 `op_addr`，也不从 raw
  constant 的数值 offset 解码 owner。
- `get_op_from_const` 是相反的 IOP→PcodeOp decoder。Ghidra 由独立的
  `IPTR_IOP`/`IPTR_FSPEC` space 保证 FSPEC 永不进入它；Rudra 共用 Iop 的过渡期
  必须先检查 `Varnode.call_spec.is_some()`（即使 `Weak` 已过期也拒绝），再解释
  numeric op pointer。专用 fixture 的 `iop_guard` case 双侧都观察到 genuine Iop
  精确 round-trip，而 live/expired typed FSPEC 都不被解析为 PcodeOp；space 终态仍由
  `TYPEOP-FSPEC-SPACE-0001` 跟踪。普通 Iop 仍沿用 Ghidra raw-pointer codec；Rust
  `Arc::from_raw` 的任意 safe-input/lifecycle soundness 是本轮未改的
  `OPBANK-0001` 残差，不能由该 kind-discriminant 投影升级为 `MATCH`。
- `sort_call_specs` 只按 Ghidra 的 `(parent block index, SeqNum.order)` 两键排序，
  排序时移动 `Arc`，不 clone/reallocate/rebind callspec；`delete_call_specs` 只删除
  exact op 对应 owner，vector 位移不会改变幸存 owner 身份；`clear_call_specs`
  只清 strong-owner vector。删除或清空后，在调用方释放临时 `Arc` 后，annotation
  与 spec 的所有反向 `Weak` 都会失效。
- `new_varnode_call_specs` 把 owner 的 typed `Weak` 绑定到 annotation；direct call 的
  Iop 数值 payload 仅作为 legacy PrintC 的 entry-offset 兼容 shadow，entry 缺失时才
  使用 owner pointer 诊断值。数值 payload 不参与 identity，也不等价于 Ghidra 的
  `FuncCallSpecs *` codec；`clone_varnode` 暂时复制 typed `Weak`；
  `truncated_flow` 按源 qlst 顺序通过 source callspec 的 exact op `Weak` 与完整
  `SeqNum` 找新 op，创建不同的新 `Arc`，并把克隆 input(0) 从旧 owner 重绑到新
  owner。源/目标 callspec 与 op 身份彼此隔离，active trial 状态由专用 clone 重置。
- `check_call_double_use` 的 owner 查找也改为 exact identity，而非同地址匹配；其
  per-input trial 映射仍是 `CALLSPEC-0001` 近似（per-slot trial-address 以
  `get_trial_for_input_varnode(j)` 解析），alternate-path 判定已于
  GETPARAM-ACTIVEPARAM-TRIAL-0001（2026-09-23）接通 input-active 分支并经
  getparameter Phase 2 投影 ord 1-64 stage-identical + next_url/match_url 全 MATCH
  实证（此前 `UNTESTED`）；本 fixture
  不把完整 consumer 算法升为 `MATCH`。D0 锁定 oracle fixture/metadata/runner 为
  `callspec_identity_lifecycle_1204`；总体仍
  `MISMATCH`，因为 `AddressSpace::Iop` 只是专用 `IPTR_FSPEC` 的临时替代，numeric
  codec 也只是 consumer-compatibility shadow（`TYPEOP-FSPEC-SPACE-0001`）；且 TypeOp
  getter、PrintC typed callspec consumer、StringManager 和其它
  callspec 字段残差均不在本阶段范围。上文“`PcodeOp *` 身份仍缺失”的历史结论
  已由本 D0 身份地基取代，但该历史 fixture 自身的其它 MISMATCH 不随之升级。

## 2026-08-25：Funcdata 符号查询通道接通 database.rs（B3-COREACTION-CONSTANTPTR-0001 a1）

Funcdata 现在可经 `arch.symboltab` 走忠实 `Database`/`Scope` 查询图，替代
`symbol_table: HashMap<u64,String>` 名称代理（C2 差异）：

- `query_container_parent_scope(addr,size,usepoint)`：
  `data.getScopeLocal()->getParent()->queryContainer(rampoint,1,Address())`
  （coreaction.cc:1151 / funcdata_varnode.cc:1207）的等价物。Rudra 的
  Funcdata 无 database.rs 局部 scope（`scope` 字段是 varmap ScopeLocal 模型），
  函数局部 scope 的父即 global scope，故查询点取 global——C++ fixture 在
  oracle 侧实测验证 `getParent() == getGlobalScope()`（setup 记录的
  `parent_is_global=1`）。返回 `QueryContainerHit`（needexacthit 判据与
  char-array 中部例外字段可表达）。无通道时 `None`。
- `query_properties_parent_scope`（database.cc:1263 消费形态）、
  `is_scope_read_only`（database.cc:1796 / ruleaction.cc:7372 形态，
  替代 RulePtrsubCharConstant 的 `string_table` 成员代理入口）、
  `query_name_parent_scope`（database.cc:1198）。
- `set_symbol_property_range(flags,range)`：属性 range 的 Funcdata 侧生产者
  （`Architecture::fillinReadOnlyFromLoader`/`decodeReadOnly`
  architecture.cc:1371/:864 的 loader→symboltab 注册通道形态）；readonly
  range 经 `query_properties` 的 `get_property` 被消费端读回。
- `link_symbol_reference` 改为真通道优先：PTRSUB 常量先走
  `query_container_parent_scope`（cc:1207-1211 的 entry 起点/offset/符号名），
  未接通道或查询未命中时回退 `symbol_table` 名称代理（driver 数据源未切换
  前保持既有输出逐字节不变——本片预期零 E2E 变化；段(a0) 给 driver 加
  .rodata DAT 条目、段(b) 重写 ActionConstantPtr 后代理退役）。
- 验证：`tests/oracle/cptr_query_channel_1204` 双侧 fixture（真实 Ghidra
  12.0.4 oracle）；`cargo check --lib` 绿。

## 2026-08-25：spacebase_constant 激活与 sz/extra/输出类型修复（B3-COREACTION-CONSTANTPTR-0001 段(b)）

死代码激活 + 两处语义错修正（funcdata.cc:360-462 逐行对齐）：

- **签名扩展**：`(op, slot, entry: &QueryContainerHit, spaceid: AddressSpace,
  rampoint, origval, origsize)` — `entry` 是 Ghidra `SymbolEntry *entry` 的
  可观察投影（`getAddr()` 供 extra、`getSymbol()` 供输出类型/typelock）；
  `spaceid` 携带解析空间（cc:363 的 `rampoint.getAddrSize()` 与 cc:370 的
  wordSize 归一都读它——legacy Address 无空间，ADDRESS-0001 残留经参数传递）。
- **sz 修正**（原 `leading_zeros` 推导恒得 8 的臆造式删除）：`sz =
  spaceid.addr_size()`（空间地址大小，x86-64 ram=8，非常量大小）。
- **extra 修正**（原硬编码 0）：`rampoint - entry.entry_addr` 后按 wordsize
  byteToAddress（cc:369-370）；≠0 时走 INT_ADD 链（cc:420-434）。
- **输出类型链**（cc:413-419）：entrytype（symbol_type，缺省 getBase(sz,
  Unknown)）→ `getTypePointerStripArray`（type.cc:3849-3858：strip + 剥一层
  ARRAY）→ `update_type_lock(ptr, typelock, false)`；typelock 取 symbol
  TYPELOCK 位、Unknown 折叠为 false。
- **spacebase_vn 类型**（cc:365-366/391-393）：`get_type_spacebase` +
  `get_type_pointer` 后 `update_type_lock(ptr, true, true)`——此前仅置
  SPACEBASE flag，RulePtrsubCharConstant 的 sbType 门恒 false。
- **COPY 复用**：`set_or_insert_input`（cc:382 insertInput(1)+opSetInput 对
  的借用安全形态，瞬时 NULL 不可观察）。
- 验证：`tests/oracle/cptr_b_1204` 双侧 fixture MATCH（17 records）。

## 2026-08-25：newVarnode 属性尾接入 INDIRECT 构造器（FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001）

R9-F2 登记的两处租约外欠应用收口：`Funcdata::newIndirectOp` /
`newIndirectCreation` 经 `newVarnode`（cc:689）/`newVarnodeOut`
（cc:692/719）创建 varnode 时，oracle 在构造器内部施加属性尾
（funcdata_varnode.cc:148-165 / 104-127：
`localmap->queryProperties(addr,size,usepoint,vflags)` → 命中符号走
`setSymbolProperties`，否则 `setFlags(vflags & ~typelock)`）。Rudra 侧
对应物为 `Heritage::apply_new_varnode_flags`（heritage.rs，guard 家族
R9 整改 7867b00 引入）：

- `new_indirect_op`：newin（cc:689 尾，invalid usepoint）与 newout
  （cc:692 尾，setOutput 接线后、usepoint=op 地址）各施加一次；
- `new_indirect_creation_in_space`（含 `new_indirect_creation` 委托）：
  newout（cc:719 尾）施加；in0 是 newConstant，无该尾（oracle 同）。

效果：persist 属性带上 CALL unknown-effect guard 的 INDIRECT in/out 带
`persist`（database.cc:1278-1279 flagbase 分支）、ScopeLocal stack 窗口内
guard varnode 带 `mapped|addrtied`（database.cc:1272-1275 in-scope 分支），
与 oracle 一致。已知残差沿用 `guard_query_properties` 的登记
（HERITAGE-GUARD-FLSYMBOL-TIEBREAK-0001 的 min-size tie-break /
use-limited 资格 / mapScope / 父链符号可见性）。

验证：`tests/oracle/funcdata_flags_tail_1204` 双侧 fixture（锁定 12.0.4
oracle，六 case 逐字节 MATCH：stack 窗口 in/out flags、persist band
in/out + 非回溯、creation possibleout 双半边、unique 控制位、
free 第二 opSetInput 异常前状态与错误文本）；`cargo check --lib` 绿。

### 2026-08-25：PRINTC-SWITCH-EMIT-0001 — test_switch_case_structuring 断言恢复

A10 把本测试的断言 3→1 绑定到 printc 租约（try_rule_switch 经
identify_internal 安装 BlockSwitch 后，emit 层把 case 体路由进 DEAD
守卫被吞）。printc 侧修复落地后恢复：`switch(`（无空格，oracle 字节）
+ `case 0:`/`case 1:` 标签 + 体 return 计数 ==2；case 体注入改为
Ghidra post-ActionReturnRecovery 形态（RETURN in(0)=间接槽 占位、
in(1)=RAX，coreaction.cc:1836）。值折叠（`return uVar0;` vs oracle
`return 10;`）属 implied/ActionReturnRecovery 域，登记于 fixture
metadata out_of_scope_gaps。

## 2026-08-25：test_type_propagation / test_infer_params_and_return_type 隔离（ACTIONTYPEINFER-VTYPE-0001）

MERGE-CLEAR-LIFECYCLE-0001（上文）记录的 `funcdata::` 2 个预存在失败
测试本轮隔离为 `#[ignore]`，全量 `cargo test --lib` 恢复 0 failed。
根因属**断言过时**（非 src 缺陷），且看板 `ACTIONTYPEINFER-VTYPE-0001`
（P0 BLOCKED）审计已明确处置边界，本提交仅为落地该审计结论：

- 两测试驱动的是 Rudra-local `ActionTypeInfer` / `ActionInferParams`
  胶水 Action（`src/coreaction.rs`，标注 RUDRA-GLUE，无 Ghidra 对应物；
  真实推断是 `ActionInferTypes`），其断言编码的是前规范 `v_type=None`
  表示。
- 规范不变量：`VarnodeBank::create` 的 `ct` 参数 "must not be NULL"
  （varnode.cc:1250，`createUnique` 同），调用方传
  `getBase(size,TYPE_UNKNOWN)` = `undefinedN` 核心 type
  （ghidra_arch.cc:349-352）；Rudra `Varnode::new`
  （src/varnode.rs:549）对应铸造 `Some(undefined{size})`，bank 创建的
  varnode `v_type` 永不为 `None`。
- 因此 `ActionTypeInfer` Rule 2 COPY/INT_ADD 的 `(Some(t), None)` /
  `(None, Some(t))` 匹配（coreaction.rs COPY 臂）与 `ActionInferParams`
  RETURN 的 `unwrap_or_else` size-based 回退（coreaction.rs，RAX→long）
  均不可再触发：`test_type_propagation` 败于 unique_1 `int *` 断言、
  `test_infer_params_and_return_type` 败于 return `long` 断言。
- 审计明确拒绝的捷径（本轮未采用）：改回 `None` / 把 `is_none` 粗换
  UNKNOWN 检查——前者违反 Ghidra 非空不变量，后者是对无 oracle 的
  胶水 Action 的又一层自创语义。
- 复活路径：`ACTION-INFERTYPES-DISPATCH-0001`（依赖
  `VARNODE-LOCALTYPE-RESOLUTION-0001` 等）落地真实
  ActionStartTypes/ActionInferTypes/ActionOutputPrototype
  （coreaction.cc:4765）fixture 后，按 oracle 行为重写断言并摘除
  ignore；届时同步删除/替换无 Ghidra 对应的旧 Action。
- 关联：`comment::test_comment_sorter_op_landmark_interleaving` 第三个
  预存失败已由 `8b8dc90b`（BLOCK-STOPADDR-FIXTURE-REGRESSION-0001，
  本分支祖先）修复，单跑与全量均通过，无本轮改动。

### 2026-08-26：mapGlobals 跨 space 组边界 + 通道分流（MAINDIFF-GLOBAL-0001）
- `map_globals`（funcdata_varnode.cc:1653-1719）内层分组循环补跨 space
  break：oracle 的 `vn->getAddr() < endaddr` 是 space-major Address 比较
  （loc 走查按 space 升序，后续 space 的 varnode 比较为 Greater 直接
  break）；Rudra 的 `Address` 不携带 space，等价 break 显式化为
  `n_space != base_space`。
- queryProperties 通道分流：RAM space 组走 Database 查询通道（global
  scope 只建模默认数据空间）；非 RAM persist 组（如锁定寄存器）在
  oracle 走 ScopeLocal 腿，仍为登记的 funcdata 缺口，走 legacy
  symbol_table 代理臂。
- 验收：curl E2E main 从 timeout（>10s 无输出）恢复收敛，全文件
  in_ram_* irregular-input 命名 66→0，差分门禁 defects=0/numbering=0
  （124 函数）。

### 2026-08-26：mapGlobals maxvn 携带修复（R-MAPGLOBALS REJECT fix-forward）
- 独立复核 R-MAPGLOBALS（机制 C）在 `map_globals` 判 REJECT：oracle
  funcdata_varnode.cc:1685-1686 `if (vn->getSize() > maxvn->getSize())
  maxvn = vn;` 携带**varnode 本体**，cc:1692-1693 的 ct 取组内最大
  varnode 的 high 类型；Rudra 侧 `maxvn` 只取组起始且从不更新
  （`max_size`/`max_addr` 标量是对的），ct 分支读了错源。
- 修复：内层循环 `if n_size > max_size` 臂同步 `maxvn = next.clone()`
  （funcdata.rs map_globals，3 行代码变更）；触发输入类为同基址双宽度
  persist varnode（loc 序 size 升序，较小者为组起始）且最大者尾 == 组尾。
- 判别 fixture：`FUNCDATA-MAPGLOBALS-MAXVN-0001`
  （tests/oracle/funcdata_mapglobals_maxvn_1204）以同基址 1+8 字节
  persist varnode 钉死 ct 取大 varnode（addSymbol 尺寸 8）与
  entry 臂 inconsistentuse 翻转（warningHeader）。
## 2026-08-25：`JUMPTABLE-PIPELINE-0001` 段2 — stageJumpTable/recoverJumpTable 分级恢复

`Funcdata::stage_jump_table(partial, jt, op, flow_state)`（funcdata_block.cc:491-548）
现为完整分级恢复：partial 首次进入时置 `JUMPTABLERECOVERY_ON` → `truncated_flow`
克隆 → "jumptable" 策略组（`ActionDatabase` 共享 `arch.allacts` 槽位或等价本地库）
reset+perform，perform 的 LowlevelError 映射 `warning + fail_normal`（cc:514-518）；
`find_op(SeqNum)` 失败/opcode/地址不符返回 `Err(Lowlevel("Bad partial clone"))`
——这是 C++ throw 的穿透通道（经 recoverJumpTable/recoverJumpTables/generateOps 直达
followFlow 调用方，cc:522-523）。`partop` dead → `success`；return-address 复制测试 →
`fail_return`（cc:527-529）。`set_load_collect` 读 `TruncatedFlowState::flags` 的
RECORD_JUMPLOADS 位（cc:532 `flow->doesJumpRecord()`）；`set_indirect_op(partop)`
顺带写 `opaddress`（jumptable.hh:599）。恢复分支（cc:534-545）：`is_partial()` →
`recover_multistage`，否则 `recover_addresses_classified`，Thunk → `fail_thunk`、
Lowlevel → `warning + fail_normal`。

`Funcdata::recover_jump_table`（cc:639-673）链接既有表（override/partial 经
stage 重试）或 trial 表分级恢复，成功后 `set_indirect_op(op)` 重链 + push
`jump_tables`。所有 stage 失败码沿 `mode` 传出，LowlevelError 走 `Result` 通道。

E2E：getparameter.constprop.0 @0x3fd5 88 条目恢复（flow 665 ops/36 块 → 1866/138），
glob_set @0x4c45 35 条目恢复；124 函数 defects=0/numbering=0。
## 2026-08-25：MAINDIFF-UNIQLEAK-0001 — linkSymbol 全局符号半边

### `Funcdata::query_global_symbol_hit`（database.cc:1263 Scope::queryProperties 全局半边）

`link_symbol`（funcdata_varnode.cc:1156）中 `localmap->queryProperties` 的
父作用域走查半边：Ghidra 的 `Scope::queryProperties`（database.cc:1263-1281）
经 `mapScope` + `stackContainer`（database.cc:943-975）从 local scope 走到
GLOBAL scope 并返回最小包含 SymbolEntry。ram 地址命中全局 Symbol
（stdin/config 等 ELF/DWARF 全局）时，`handleSymbolConflict` 早臂
（funcdata_varnode.cc:1000-1003）把 entry 挂到 Varnode 的 HighVariable，
**不**在 ScopeLocal 建符号 —— `emitScopeVarDecls`（printc.cc:2254-2276，
只走 ScopeLocal 及其子）因此永不声明它。

Rudra 通道（保真序）：
1. 真 `Database` 图（`Architecture::symboltab`），经
   `query_properties_parent_scope` 同容器语义查询；
2. driver `symbol_table` 名字代理（仅精确地址命中，无大小）。

空间门：仅 Ram varnode 查询（全局 scope 只拥有 ram 区间；Rudra SymbolEntry
地址无空间维度，不开门会跨空间碰撞）。命中时把全局符号名发布到 high
（对齐 `vn->setSymbolEntry(entry)` + HighVariable 符号解析），返回 None
跳过本地建符号臂（对齐 linkSymbols cc:2963 `sym==0` 跳过 + cc:2971
`isGlobal` 门控的 finalizeDatatype）。

修复前：main 中 37 个全局来源 heritage 输入被铸成死 `in_ram_XXXX` 声明
（golden 0）。修复后 main 声明区 163→96 行。

配套 driver：`curl_decompile.rs` worker_architecture 播种 `symboltab`
（DWARF DebugGlobalDatabase + ELF STT_OBJECT）。
### removeUnreachableBlocks 忠实重写 + descend2Undef 接线（2026-08-25，HTTPD-STRIPPREFIX-ADDDESCEND-0001）
- `remove_unreachable_blocks(issuewarning, checkexistence)` 完整对齐
  funcdata_block.cc:346-393：checkexistence 快扫（首个非入口且无 immed_dom
  的块）或缓存 `blocks_unreachable` 标志门控；`collect_reachable`
  （block.cc:2154）取不可达集；逐块 setDead（+每块头警告）→
  `branch_remove_internal(blk,0)` 清出边（销毁分支 op + 修补后继 phi）→
  `block_remove_internal(blk, true)`（descend2Undef + **全部** op 销毁）→
  `structure_reset()`。
- 删除两个自创降级：① "unreachable>=5 且 >5% 则跳过"保守门禁（Ghidra 无
  此门禁；正是 httpd ap_stripprefix/ap_ht_time/ap_update_vhost_from_headers/
  ap_getword 的 "Free varnode has multiple descendants" panic 根因——不可达
  块里的活 op 继续读 free varnode，RuleCondNegate 的 op_bool_negate 二次
  addDescend 即炸）；② "有外部后代的 op 保留 alive"的 mark_dead 近似
  （Ghidra blockRemoveInternal(true) 销毁全部 op，被搁浅的读先经
  descend2Undef 换成 0xBADDEF 常量）。
- `descend2_undef`（funcdata_varnode.cc:543-583）修死-parent 判定：改查
  块级 DEAD flag（cc:558），原 `parent.is_none()` 近似在"先全标 dead 再逐块
  删"的顺序下漏跳死块读者；MULTIEQUAL 臂经 slot 前驱块尾插 COPY、INDIRECT
  臂前插 COPY、普通 op 直插常量。
- `block_remove_internal` 不可达臂接线 `descend2_undef`（cc:304-310 的
  undef 返回值控制一次性警告），移除 RUDRA-GAP 注释。
- `descendants_outside`（funcdata_block.cc:234-241）改查读者 op 的**父块**
  DEAD flag（原查 op 自身 is_dead，删块序中恒 false → 误报）。
- `move_out_edge` 忠实重写（block.cc:1502 moveOutEdge = replaceInEdge
  block.cc:160-173）：捕获目标 in-slot i 后，对源块做
  half_delete_out_edge(rev)（成对协议），目标**保留**槽位 i 重指向新源
  （reverse_index=新源 size_out），新源 append 出边（rev=i）；原实现
  "源出边原地改指 + 新目标 append 入边 + 旧目标 Vec::remove 入边"是单侧
  滑动（其他源的 reverse_index 不修正）且仅 BlockBasic——ActionDoNothing/
  RedundBranch 的 splice 早期即污染 bblocks。

## typerecovery_exceeded 旗标（RULE-PTRARITH-ADDTREE-0001，本次新增）

`funcdata_flags::TYPE_RECOVERY_EXCEEDED`（Ghidra `typerecovery_exceeded`，
funcdata.hh:72 = 0x4000；Rudra 重映射位空间取 bit 14）+
`Funcdata::is_type_recovery_exceeded`（funcdata.hh:152）/
`set_type_recovery_exceeded`（funcdata.hh:182，只置位、函数生命周期内
不清除，`clear()` 亦不重置——与 Ghidra 一致）。置位点 =
`ActionInferTypes::apply` localcount==7 分支（coreaction.cc:5393）；
消费点 = `AddTreeState::build_tree` 的 `assignPropagatedType`
（ruleaction.cc:6502/6514）：传播循环停止后由 RulePtrArith 自己给新建
PTRADD/PTRSUB 输出盖章类型。
## switch_edge 半边重建（MYFWRITE-TEMPVAR-0001，2026-08-26）

`switch_edge`（block.cc:1489-1495 经 FlowBlock::replaceOutEdge block.cc:178-191）：
补齐旧目标的 halfDeleteInEdge（reciprocal reverse_index）、out-edge 重指向时
刷新 reverse_index 至新目标 in-edge 规模、新目标 push_back 镜像 in-edge 且
flags 随出边携带。此前仅指针改写使 nodeSplit 复制块不可达/原块 in-edge 过剩，
returnsplit 永久重入。

## `start_processing` 接入 applyDeadCodeDelay（MAIN-POSTSTRUCT-SPIN-0001，2026-08-27）

补齐 funcdata.cc:166 `localoverride.applyDeadCodeDelay(*this)` 腿
（override.cc:217-231）：遍历 override 的 deadcodedelay 表（`delay >= 0`
项），经 `AddressSpace::from_index`（`AddrSpaceManager::getSpace(i)`
替身）解析回空间，逐项 `Heritage::set_dead_code_delay(space, delay)`
（heritage.cc:2815；`delay < info->delay` panic 镜像 LowlevelError）。
Override 跨 `Funcdata::clear` 存活（funcdata.cc:106 "Do not clear
overrides"），因此 `Heritage::bump_deadcode_delay` 安装的重启延迟在下一
遍 startProcessing 生效——与 oracle 的重启遍语义一致。先拷贝表项再改
heritage（override 借 self 不可变而 heritage 可变）。followFlow 与
inline-function 头警告仍属未移植基础设施（驱动侧流生成，
PIPE-RESTART-0001）。

## `start_processing` 作为 Action 前件的测试契约（BLOCKACT-NORMALIZE-CONTINUE-TAG-0001，2026-09-24）

`test_normalize_branches_break_in_while_loop`（`#[cfg(test)]`，本文件
15100 区）此前手搓 `fd.bblocks.build_dom_tree()` 代替 oracle 管线前件：
Ghidra 里 `startProcessing`（funcdata.cc:150-168）在一切 Action 之前跑
`followFlow; structureReset;`，structureReset→`bblocks.structureLoops`
（funcdata_block.cc:711）打出 F_BACK_EDGE 标签，`ActionBlockStructure`
的 buildCopy 才能携带它们供 `orderLoopBodies`（blockaction.cc:1148）发现
自然循环。跳过该前件时 `dfs_back_edges=0`、0 个循环、无 WhileDo 结构、
`ActionNormalizeBranches` 无 loop_info——回边 jmp 永不标 CONTINUE。测试
fixture 改为 `fd.start_processing()`；生产路径无变化（ActionStart 已按
universal 序先行调用，ActionNormalizeBranches 本身被 decompile grouplist
过滤=coreaction.cc:5424-5431）。


## FlowOverride 注入期应用（GOTO-LABEL-UNPRINTED-0001 tail-call 家族，2026-08-27）

`inject_raw_ops` 在 phase-1（`oneInstruction` dump 等价物）与 phase-2
（`xrefControlFlow` 块标记等价物）之间新增 `apply_flow_overrides_raw`：
当 `localoverride.has_flow_override()` 时，按指令地址查
`Override::getFlowOverride`（flow.cc:415-418 的读取位置），在 raw 层执行
`Funcdata::overrideFlow` 的改写表（funcdata_op.cc:991-1020）：
BRANCH→CALL、BRANCHIND→CALLIND、RETURN→CALLIND；CBRANCH 不支持
（cc:1000）；CALL_RETURN 在改写后的 call 后追加常量 0 输入的 RETURN
（cc:1006-1011 `newOp`+`opSetInput`+`opDeadInsertAfter` 的 raw 层等价，
SeqNum order 取 `u32::MAX` 保证位于该指令全部真实 op 之后、地址不变以进入
同一尾块）。

主 op 选择镜像 `findPrimaryBranch`（funcdata_op.cc:929-961）：每条指令只
考虑第一个 branch-like op，BRANCH/CBRANCH 要求 in(0) 非常量（内部跳转带
常量相对目标，cc:938）。

为什么走 raw 层而不是已移植的 `Funcdata::override_flow`：Rudra 记录在案的
create-implies-alive 分歧（op.rs `PcodeOpBank::create`）使 phase-1 op 永不
`isDead()`，`override_flow` 的 dead 前置条件不可满足；且其
`insert_after_dead` 插入的 RETURN 不会进 phase-2 的 op_refs 向量，会从块图
整体丢失。raw 层改写保证 phase-2 看到与 Ghidra 相同的 op 序列。

零 override（所有未播种 localoverride 的驱动——TailCallAnalyzer 角色在
分析驱动侧）时列表原样透传：无 clone、无行为变化（curl 门禁不受影响）。
消费方：`examples/httpd_decompile.rs` 以 ELF 函数符号 ∪ call-target 集 ∪
PLT 段起点（sh_entsize 对齐）为已知函数入口，函数范围外的直接 `jmp` 目标
播种 `FlowOverride::CallReturn`。消除 httpd 的
`code_rXXXX: goto code_rXXXX;` 尾调用自环家族
（ap_set_name_virtual_host/ap_pregfree/ap_getword_nc/ap_field_noparam 两个
PLT 尾）。残余自环（main 0x2BA58、ap_update_vhost_from_headers 0x2D7F0、
ap_field_noparam 0x2DD79）为内部空块/非返回 canary 分支域，见
docs/TODO_BOARD.md GOTO-LABEL-UNPRINTED-0001 残差登记。
## 测试侧两级复合块搜索（master ac6e6795 并入注记，2026-08-26）

`bool-fold test` 的 Or-Condition 搜索从一级复合层扩为两级：Ghidra 的规则
序列在该 CFG 上为 ruleBlockOr → ruleBlockIfNoExit 包裹出口子句
（blockaction.cc:1840 第二遍）→ ruleBlockCat 合并，得到
`List[If[Condition(Or), D], C]`——Condition 位于 List 子内的 If 里，需两级
下钻才能命中。纯测试辅助代码，无运行时行为变化。

## 2026-08-28：ActionFuncLink 显式空间 Varnode 适配

`new_varnode_in_space(size, space, addr)` 是 `ADDRESS-0001` 过渡期胶水：它让
`funcLinkInput` 创建的非 stack formal 保留当前 coarse space，并继续执行
assign-high、lane check 与已接线的属性 flag 投影。锁定 fixture 只证明该
Action-specific 路径的 `(space, offset, size)`、对象顺序和基础 flags。

这不是完整 `Funcdata::newVarnode` 证明。通用 `new_varnode` 仍会把 spaceless
Address 当作 RAM，且 localmap `queryProperties`、live `SymbolEntry`、
`setSymbolProperties` 与 HighVariable symbol 反向连接尚未闭合，登记为
`FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001`；模块保持 L2。

## 2026-08-29（FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001）：newVarnode 族 symbol tail 闭合

`Funcdata::newVarnode`（funcdata_varnode.cc:148-169）在 create→assignHigh→lane
check 之后固定执行 `localmap->queryProperties(addr,size,usepoint,vflags)`，entry
命中走 `setSymbolProperties`，否则 `setFlags(vflags & ~typelock)`。本次把该尾段
落为 `Funcdata::new_varnode_symbol_tail(vn, usepoint)` 并接线到三处调用面：

- `new_varnode(size, addr)`（cc:148）— usepoint = cc:162 的 INVALID `Address()`。
- `new_varnode_in_space(size, space, addr)`（cc:239-246 `newVarnode(s,base,off)`
  委托形态）— 同 INVALID usepoint 的完整尾段，替代旧的
  `Heritage::apply_new_varnode_flags` flags-only 投影。
- `new_varnode_out(size, addr, op)`（cc:104-122）— **无条件** 以 `op->getAddr()`
  为 usepoint 的 queryProperties（cc:114-119），替代此前错误委托的
  `set_varnode_property`（setVarnodeProperties cc:25-42 是 isMapped-guarded
  getUsePoint 形态的另一个函数）。

Rudra 的 walk 组合与 Ghidra 单一 `Scope::queryProperties`（database.cc:1263-1281，
`mapScope` 空 resolvemap 返回查询 scope 自身，database.cc:3187）等价：ScopeLocal 腿
（`query_properties_ex`，parent=None）未应答时接 Database 全局腿
（`query_properties_parent_scope`/`query_container_entry_parent_scope`）。全局腿
entry 命中执行完整 `set_symbol_properties_arc`（含 HighVariable symbol 反连）；
ScopeLocal 腿 entry 命中因 DB-LOCALSCOPE-MAP-0001 分裂（ScopeLocal 无 live
SymbolEntry 对象）降级为 flags 折叠。遗留：非 RAM 空间不进 Database 腿、
newVarnodeOut 的 usepoint 以 spaceless Address 进 Database 腿恒 invalid
（ADDRESS-0001，use-limited 全局 entry 不被承认）——两项均登记为残余。

## 2026-08-29:node_join_create_block 语句序索引修正(R-NODEJOIN-CROSSREVIEW F1 整改)

复核 REJECT 的致命项:两个 `find_out_index` 此前被提前到两次 `move_out_edge` 之前求值;Ghidra
funcdata_block.cc:808-809 是语句序求值——第二个 `getOutIndex(exitb)` 在第一次 move **之后**取新鲜值。
当 swapa==swapb(规范菱形恰好命中)且首个被移边在槽 0 时,陈旧索引在 move_out_edge 的 None 分支
**静默跳过第二次边转移**(swap 保留 2 出边、newblock 只有 1)。整改:
- 两个索引各自在 move 前即时求值,缺失即 panic(响亮断言,不再静默 return);
- fixture(nodejoin_join_block_forces_heritage_restructure)补 CFG 形状断言:canonical 终态=join 块
  2 出边、两分支各 1 出边(仅 join 边)。
E2E:2911/1/0,0 panic/timeout,124/124 反编译。

## 2026-08-30:X86LIFT-FLAG-PCODE-0001 连带测试期望更新(w-iced,测试专用)

src/funcdata.rs 生产代码零改动;仅更新 `#[cfg(test)]` 内两个直接编码旧 iced
提升形态的回归测试,使其断言新的 oracle-faithful 形态(来源
src/disasm/x86_lift.rs 的 X86LIFT-FLAG-PCODE-0001 改动):

- `test_add_rax_imm_minimal_alignment_path`:`add rax,1` 期望 2 op(INT_ADD→
  uniq+COPY)改为 9 op(INT_CARRY/INT_SCARRY/INT_ADD 直写 rax/imm 规范化为
  8 字节/SF/ZF/PF popcount 链)。
- `test_add_mem_rbx_rax_rmw_alignment`:`add [rbx],rax` 期望 3 op 改为 16 op
  (逐用重 LOAD:LOAD+CARRY+LOAD+SCARRY+LOAD+INT_ADD+STORE+LOAD+SF+LOAD+ZF+
  LOAD+AND+POPCOUNT+AND+PF)。

背景:FFI_TEST_LOCK 为普通 Mutex,任一断言失败会毒化锁并级联失败后续所有持锁
测试(master 全量即有 15~18 的 flaky 窗口);这两条测试是 add 形态的确定性
失败源,更新后全量回到 17 failed(17±1 达标)。手写期望仅为 Rudra 回归信号,
非 oracle 对拍(机制 B2)。

### 2026-08-30 补充(w-iced c2):同族测试期望批量更新(测试专用)

c2 落地 logic/cmp/test/jcc 后,以下测试的旧形态断言更新为 oracle-faithful
形态(生产代码零改动):test_sub_rax_imm(9 op)、test_and/or/xor_rax_imm
(9 op:CF=0/OF=0/值 op 直写/SF/ZF/PF)、test_xor_eax_eax(11 op 含 zext)、
test_cmp_rax_rbx(9 op:LESS/SBORROW/SUB→tmp/SF/ZF/PF)、test_seq_mov_add_ret
(11 op)、test_seq_mov_and_shl_ret(13 op)、test_seq_cmp_je_multiblock
(22 op;块0=10 op)、cbranch 条件接线三测试(ZF 0x201→0x206,sla 布局)。
全量 17 failed,回到 master flaky 窗口(15~18)内。

## 2026-08-30:block_remove_internal 完整移植(HTTPD-EMPTYELSE-DONOTHING-0001)

`Funcdata::blockRemoveInternal`(funcdata_block.cc:254-320)从不完整版(无
removeFromFlow、无 MULTIEQUAL 拼接、双 removeBlock、panic)补齐:BRANCHIND 跳表
清理(cc:264-269)、pushMultiequals(cc:271)、每出块 MULTIEQUAL 输入拼接
(删除 bb 槽位 + 按 bb 入边追加 deadop 穿插输入或 deadvn 拷贝,cc:273-294)、
removeFromFlow 边重定向循环(cc:296,block.cc:1545-1560 形状:自末尾出边起,
switch_edge 双半语义重定向入边)、op 销毁(unreachable 路径 descend2Undef +
descendants 检查;cc:311-312 LowlevelError 降级为警告+跳过)、removeBlock。
`remove_do_nothing_block` 返回 bool 并接通 blockRemoveInternal。

## 2026-08-30:push_multiequals 完整移植(FUNCDATA-PUSHMULTIEQUALS-0001)

`Funcdata::pushMultiequals`(funcdata_block.cc:84-171)从检测-only stub(每个
活跃 phi 发 `push_multiequal: descendant rewrite not yet implemented` 警告、
不做任何重建)补齐为完整移植:

- 出块/死边锚定(cc:93-98):sizeOut==0 直接返回;>1 仅告警继续;outblock =
  getOut(0)、outblock_ind = getOutRevIndex(0)。
- 每 bb 内 MULTIEQUAL(cc:99-103):跳过无后代 phi;其后代扫描按 descend
  顺序快照迭代。deadEdge 判定(cc:106-116):后代若是 outblock 内
  MULTIEQUAL 且对 origvn 的所有读均经死边槽(outblock_ind),该读留给
  blockRemoveInternal 的 opRemoveInput 路径;否则 needreplace=true 即跳出。
- neednewunique(cc:118-122):origvn addrtied 且与该 phi 输出同地址 →
  替换 varnode 用 newUnique,否则 newVarnode(size, origvn addr)。
  isAddrTied = addrtied|insert 双标志(varnode.hh:250),Rudra 一致。
- 人工 MULTIEQUAL 构造(cc:131-153):branches 按 outblock 入边序,bb 边槽
  放 origvn、其余槽放 replacevn;newOp(branches.size(), outblock.start) →
  opSetOpcode(MULTIEQUAL) → opSetOutput → opSetAllInput → opInsertBegin。
- 后代重写(cc:156-169):构造完成后快照 descend(与 Ghidra cc:157 的
  titer=begin() 在 opInsertBegin 之后取相同顺序),逐 op 逐槽找 origvn 读;
  死边槽(outblock_ind + outblock 内 MULTIEQUAL)跳过,其余首个命中槽
  opSetInput(op, replacevn, i) 后 break。

验证:httpd 警告×3 消失(ap_fini_vhost_config×2/ap_pregsub×1,WARNING 行
81→78),cc:311-312 滞留 op 信号消失;ap_fini_vhost_config 声明区清除 2 个
搁浅局部(25→24 decl 行),skeleton 2277→2278(+1 为删变量后序号重排再分布,
defects/numbering 均 0);curl 骨架 3095→3091(main/myprogress/
my_get_token/parseconfig.constprop.0 仅删除 stub 警告注释,函数体逐字节
不变,defects/numbering 均 0);cargo test 全量 17 failed 与 master 基线
逐名一致。

## 2026-09-01:nodeSplit 克隆输出保地址空间(FUNCDATA-NODESPLIT-SPACE-0001)

`CloneBlockOps::build_varnode_output`(funcdata_block.cc:981-998)修复:oracle 在
cc:988 以 `data.newVarnodeOut(opvn->getSize(), opvn->getAddr(), cloneOp)` 用
**完整地址(space+offset)** 建克隆输出 — ram 空间的 persist 全局写回克隆后仍是
ram。旧 Rudra 走 `new_varnode_out` 适配器(Address 不带 space、钉死 Register),
ram:0x17510 的 persist 写回被克隆成 register:0x17510,后续
linkSymbol(`if (!isPersist())` 臂被跳过 + `query_global_symbol_hit` 只认 Ram)
无符号命中 → 打印 `register0x…` token → P23 UNLINKED-REF 回填(curl _init/
my_get_token/next_url 3 行)。

- `new_varnode_out_full(size, space, addr, op)` — `Funcdata::newVarnodeOut`
  (funcdata_varnode.cc:104-122)的保空间完整序列:createDef(真 space)→
  setOutput → assignHigh → laned check(真 space)→ **无条件**
  queryProperties 尾(usepoint=op->getAddr(),`new_varnode_symbol_tail`),
  不是 isMapped-guarded 的 `setVarnodeProperties`(funcdata_varnode.cc:25-42,
  另一函数 — 对 fresh 克隆二者 usepoint 相同但此处按 oracle 原形)。
  `new_varnode_out` 变为委托(legacy 调用者保持 Register pin,行为不变)。
- `build_varnode_output` — 读 orig 输出 (size, address_space, loc) 三元组后
  走 `new_varnode_out_full`;vflag 拷贝掩码不变(cc:990-993);**补齐缺失的
  addlflag fold**(cc:995-997:`writemask|ptrflow|stack_store`,`addlflags |=`,
  旧移植完全缺失)。
- CloneBlockOps 注解纠正(cited-line-drift):struct→funcdata.hh:630;
  buildOpClone→cc:951;buildVarnodeOutput→cc:981;cloneBlock→cc:1004;
  patchInputs→cc:1047(均指向函数定义起始行)。

双侧 fixture `tests/oracle/funcdata_nodesplit_space_1204.{cc,rs}`(27 记录,
N1/N2/N3:inedge 0/1 + 最小矩阵):克隆输出 space/offset/size、flag/addlflag
投影(含 mapped|directwrite|unaffected|ptrcheck 越掩码哨兵)、SeqNum、
MULTIEQUAL→COPY inedge 拾取、clone 输入重映射/共享/常量、原块分裂后形态、
入边计数 — 双侧 stdout 字节一致 MATCH
(tools/run_funcdata_nodesplit_space_oracle.sh)。

## 2026-09-22（返修）：流程克隆的模型 clone 调用点

`Funcdata` 流程克隆(clone for partial recovery, ~funcdata.rs:11355)中
`model.clone_model(cloned_table.clone())` 改为 `model.clone_model()`
——jump 模型已无父表回指字段,父表状态经 `JumpParentFacts` 值参数下传
(见 docs/api/jumptable.md 返修节),clone 不再需要新父 Arc。

## 2026-09-22: v2 drill 钩子(Lane AA; funcdata_op.cc 同位 #ifdef 钩子)

`op_set_opcode`/`op_set_input`/`op_set_output`/`op_unset_output`/
`op_unset_input`/`op_insert_input`/`op_remove_input`/`op_swap_input`/
`op_destroy`/`op_uninsert`/`new_varnode_iop` 入口加入
`drillobserve::mod_check`/`register_iop` 调用(镜像 funcdata_op.cc:25-33、
:52-66、:70-87、:104-141、:150-186、:203-221、:291-317 与
funcdata_varnode.cc:269-292 的 OPACTION_DEBUG 钩子位;守卫先行、变更前
触发,防幻影记录;锁纪律见 drillobserve.md)。env 门控
`RUDRA_STAGE_DRILL`,未设置时为 no-op,行为与既往逐字节一致
(验证见 docs/api/action.md 同日条目)。

## 2026-09-22：switchOverJumpTables 真身（funcdata_block.cc:678）

- `switch_over_jump_tables(fd: &Funcdata, flow: &FlowInfo)`（关联函数形态）：
  遍历 `fd.jump_tables` 逐表 `jt.write().switch_over(flow)`。原 `&mut self` stub
  （RUDRA-GAP 注释、零调用者）删除。RUDRA-GLUE：flow 跟随期唯一 `&mut Funcdata`
  由 `FlowInfo` 持有，oracle 的成员函数形态无法同时借用两侧，故取共享引用 +
  `Arc<RwLock<JumpTable>>` 写锁内变更（与 Ghidra 经 jumpvec 指针改写一致）。
  错误经 `Error::Lowlevel` 传播（followFlow 同语义）。

## 2026-09-23：inject_raw_ops_single 补 laned-register 探针（ARCH-REGISTERDATA-LANE-0001）

原始 p-code 物化器此前的输出/输入直走 `vbank.create_def_with_space`/
`create_with_space`，绕过 newVarnodeOut/newVarnode 的
`if (s >= minLanedSize) checkForLanedRegister(s,m)` 探针
（funcdata_varnode.cc:113/160）。修复 = 两处物化点后补同门检查
（输出臂对应 cc:113，输入臂对应 cc:160 的非常量路径；Const 空间无 varnode
语义，oracle newConstant 无此探针，保持跳过）。效果：movdqu 16 字节 LOAD
的 unique 输出（match_url 52c5:df `u:d700:16`）入 laned map，oracle 的
ordinal 29 lanedivide 双分裂（unique 槽 + XMM0 phi 群）在 Rudra 侧同样
2=2。min_laned_size 在 lane 记录空时为 u32::MAX（旧中性行为），装载后为
最小整尺寸 16，见 docs/api/arch.md 同日条目。

## 2026-09-23：test_seq_mov_add_ret_alignment 计数随 RET 模板更新（RET-OP3-0001 波及）

`src/disasm/x86_lift.rs` 的 `ret` 臂按锁定 .sla 模板三 op 化后（见
docs/api/disasm/x86_lift.md 同日条目），本文件 `test_seq_mov_add_ret_
alignment` 的手写回归计数随之更新（Rudra 回归测试口径，机制 B2 手写
expected 性质）：`mov rax,rdi; add rax,rsi; ret` 共 1+9+3=13 op
（旧 11），断言序列补 `op[10]=LOAD`、`op[11]=INT_ADD`，`op[12]=RETURN`
（旧 `op[10]=RETURN`），alivelist 13（旧 11），RuntimeVerifier
verify_pcode_generation 计数 13（旧 11）。生产代码零改动。

另：`test_seq_mov_and_shl_ret_alignment` 在 master 94f3bf58 即稳定失败
（父基线亲测 2/2；其期望仍为 FLAG-PCODE 之前的 6-op COPY 链形态），
非本条目引起，属 funcdata 测试债（待该域 writer 更新）。

## 2026-09-23：set_varnode_properties 补 ScopeLocal 腿（FUNCDATA-SETVARNODE-SCOPELOCAL-0001）

oracle `Funcdata::setVarnodeProperties`（funcdata_varnode.cc:25-42）的单一
`localmap->queryProperties(vn->getAddr(), vn->getSize(),
vn->getUsePoint(*this), vflags)` 调用中，`Scope::queryProperties`
（database.cc:1263-1281）的 `stackContainer`（database.cc:943-962）从查询
scope 本身——即函数的 ScopeLocal——起步：先 `findContainer`（符号命中 →
`res->getAllFlags()`，database.cc:1270），再 `inScope` "discovery of new
variable" 停走（database.cc:957-958 → 1271-1277 的
`mapped|addrtied(|persist)+property` 折叠），仅当本函数 scope 不终结遍历时
才上溯父/全局 scope。Rust `set_varnode_properties` 此前只实现了
RAM/全局父通道（`query_properties_parent_scope`）+ 旧名代理，栈 varnode
永不获 `addrtied`。

修复 = 在父通道之前插入 ScopeLocal 腿：`self.scope` 上的
`ScopeLocal::query_properties_ex(space, offset, size, usepoint, None,
&property)`（varmap 域既有接口，本改动零 varmap 改动），usepoint 取
`get_use_point` 的**有效**地址（funcdata_varnode.cc:31，区别于
newVarnode 尾的 INVALID `Address()` 形态——`new_varnode_symbol_tail`）。
本腿命中即做 flags 折叠（Rudra ScopeLocal 无活 SymbolEntry，
DB-LOCALSCOPE-MAP-0001 分裂下 entry 命中降级为同一可观测折叠，与
new_varnode_symbol_tail 本腿同款处理）并跳过父通道与名代理；未命中则
走既有 RAM/父通道 + 名代理路径（字节不变）。受益调用方：
condexe/coreaction/heritage/funcdata 内部（`new_indirect_op` 的
create_with_space+set_varnode_properties 组合此前正是符号尾 ScopeLocal 腿
的缺口暴露面）。

**A/B 验证**（同机，base=f8525d21 亲测）：next_url/match_url/
parseconfig.constprop.0 三投影 vs oracle pin **MATCH 保持**；curl E2E
**2595/0/0**（基线 2563/0/0，skeleton +32）、httpd E2E **2337/0/0**（基线
2333/0/0，+4），defects/numbering 双侧全 0——"master 无栈 addrtied 消费面
=恒等"的前置假设被实测证伪：heritage/new_indirect_op 等调用路径的栈
varnode 现取本地腿 mapped|addrtied，下游变量命名/物化面（varmap/printc
域）暴露缺口（差分明细见 commit `## Differential` 块；逐函数：
glob_word +6 / glob_set +8 / glob_range +5 / main +7 / myprogress +1 /
getparameter.constprop.0 +8 / file2string.part.0 **−3 改善**；httpd main
+3 / ap_fini_vhost_config +1），按铁律 3 以 TODO
`SETVARNODE-SCOPELOCAL-CONSUMER-0001` 登记绑定；`cargo test --lib
funcdata` 批（单线程）17 failed==master 逐字（branch 40 passed 含新增
单测）；新增单测 `test_set_varnode_properties_scope_local_leg` 钉三分支
（in-scope 折叠 / 符号 entry 命中 / 窗外无本地应答——ADDRTIED 断言取裸位，
因 `is_addr_tied()`（varnode.hh:250）另需 INSERT 位，op 挂接才授予，与本
属性遍正交）。
## 2026-09-23（BOOMATTR lane）：adjustInputVarnodes space-aware 修复

- `Funcdata::adjust_input_varnodes`（funcdata_varnode.cc:494-537）签名改为
  `(space, addr_offset, sz)`：旧实现 (a) inlist 收集无空间过滤——Ghidra 的
  beginDef(Varnode::input,addr)/endDef(endaddr) 在 Address 序（空间优先）上
  迭代，偏移界永不跨空间，旧实现会把数值落在区间内的异空间输入（如
  RSI@0x30）误收进栈容器；(b) 新合并输入经 spaceless `new_varnode` 落 Ram
  空间（打印为 auRam… 切片）。修复 = 收集按容器空间过滤 + piece 输出走
  `new_varnode_out_full`（保空间）+ 合并输入走 `new_varnode_in_space`。
- 调用方唯一：coreaction `ActionUnjustifiedParams::apply`（cc:4822，本 lane
  首次接通该调用路径——旧 unjustparams 从不触达 adjust）。
- 实测：default 模式 match_url 的 304B URLGlob 栈参数容器（DWARF 锁定
  Stack[0x8,0x138)）adjust 后不再产生 Ram 空间 auRam 巨型输入；镜像模式
  match_url 与 direct-runner golden 同 `in_stack_00000130` 形态。

## 2026-09-23（BOOMATTR lane r2，CR4 次要项）：adjustInputVarnodes 错误契约

- funcdata_varnode.cc:500-514 三处 `throw LowlevelError` 对齐：收集成员资格
  改为**起始偏移 ∈ [addr, endaddr]**（beginDef(input,addr)..endDef(input,
  endaddr) 的 Address 序语义）——起始在界内但**尾部越界**的输入保留在迭代
  中，由 cc:505-506 的 LowlevelError("Cannot properly adjust input varnodes")
  显式失败（旧实现的静默过滤删除了该错误路径）；cc:512-514 的
  `(!isInput || sa<0 || sz<=size)` 合并为
  LowlevelError("Bad adjustment to input varnode")（gather 保证 is_input 与
  sa>=0，尺寸关系为活检查）。错误经 `crate::error::Error::Lowlevel` 传播，
  与既有 "Overlapping input varnodes" 同通道。
- 实测：curl（default+MIRROR）/httpd 全语料零触发（生长环按构造仅向下扩、
  尾部固定，跨尾输入在 oracle 同样 throw——两侧对非法状态同判）。

## 2026-09-24：RESIDMAP-PRINTBATCH —— printRaw 地址渲染 + display_image_base 传输

- 新增 `print_raw_code_addr(offset) -> String`（`// Ghidra: space.cc:206
  AddrSpace::printRaw`）：ram 空间代码地址的 oracle `printRaw` 拼写——
  `"0x"` + `2*sz` 位零填充十六进制，sz 从空间地址大小（x86-64 ram=8）按
  `display>>32==0 → 4`、`display>>48==0 → 6` 收缩（space.cc:210-215）；
  wordsize>1 的 `+cut` 分支对 ram（wordsize=1）不可达，未移植。
- 新增 `display_image_base: u64` 字段 + `set_display_image_base` setter
  （`// RUDRA-GLUE` 传输层）：oracle 的 Funcdata 地址本身就是 analyzeHeadless
  装载地址，而 Rudra 管线跑 ELF 相对偏移（ADDRESS-0001），代码标签层
  （`PrintC::code_label_base`）由驱动在显示期加 0x100000 基址差。警告文本中
  嵌地址的三族（"Removing unreachable block" funcdata_block.cc:374 /
  jumptable "Could not recover jumptable at" / flow "Possible PIC construction
  at"）现经同一 delta 渲染：canon 驱动装 0x100000，ELF 相对 harness 保持 0。
- `remove_unreachable_blocks` 的警告拼写对齐 cc:372-378：`(spaceName,printRaw)`
  —— 无空间名传输打印 "ram"（代码块全在 ram），偏移走
  `print_raw_code_addr`。curl 语料 `(,2be0d)` 旧形 12 处全数转
  `(ram,0x0012be0d)` canon 同形。

## 2026-09-24：FFI_TEST_LOCK 中毒免疫 + 5 个 lifter 计数陈旧期望重钉（TESTLIB-STATE-CONTAMINATION-0001）

`#[cfg(test)]` 模块内 27 处 `FFI_TEST_LOCK.lock().unwrap()` 全部改为新的
`ffi_test_lock()` 辅助函数（`unwrap_or_else(|p| p.into_inner())`）。此前任一
持锁测试的真实断言失败（实测触发点：test_normalize_branches_break_in_while_loop）
会毒化该 Mutex 并把 `PoisonError` 级联进后续所有 CURRENT_PROGRAM 使用者——
串行 16 个确定受害者、并行 17↔27 漂移谱全由这一个毒化事件加调度顺序解释。

毒化修复暴露了 5 个被掩盖的陈旧期望，按当前锁定 oracle lifter 逐 op dump
重钉（结构锚点断言，非仅计数）：

- `test_shl_rax_imm_minimal_alignment_path`：2→**37**（ea5010e9 移位 flags
  全模板：count&0x3f 掩码、保存原值、direct INT_LEFT、CF/OF/SF/ZF/POPCOUNT-PF
  链，flag 写手 INT_OR→0x200/0x20b/0x207/0x206/0x202 索引锚定）；
- `test_shr_rax_imm_minimal_alignment_path`：2→**37**（同上，INT_RIGHT + CF=
  (原值>>(count-1))&1 经第二次 INT_RIGHT+INT_AND 锚定）；
- `test_seq_mov_and_shl_ret_alignment`：13→**50**（shl 2→37 + ret 1→3）；
- `test_seq_cmp_je_multiblock_alignment`：22→**26**（两处 ret 1→3；块预算
  block1=4、block2=12）;
- `test_xor_eax_eax_input_identity`：11→**13**（ret 1→3）。

ret 3-op 形=RUDRA-GLUE RET-OP3-0001 锁定 sla `:RET` 模板（RIP=LOAD(ram[RSP])；
RSP=INT_ADD(RSP,8)；RETURN[RIP]），x86_lift.rs 已有 oracle 探针证据。生产代码
零改动（本文件改动全部位于 `#[cfg(test)]`）。

## 2026-09-24：inject_raw_ops_single 补 PcodeEmitFd::dump 的 newVarnode 尾（Lane CURB）

`inject_raw_ops_single`（`PcodeEmitFd::dump` 的对端口，funcdata.cc:878-908）
此前对非 const 输入与输出直接走 `vbank.create_with_space`/`create_def_with_space`
裸建——丢掉了 oracle `Funcdata::newVarnode`/`newVarnodeOut`
（funcdata_varnode.cc:148-169 / 104-122）的 queryProperties 符号尾
（`localmap->queryProperties` → `setSymbolProperties`/`setFlags`）与
assignHigh。现在：

- 输出腿=`new_varnode_out_full`（createDef+setOutput+assignHigh+laned 探针+
  符号尾，usepoint=op 地址）；
- 非 const 输入腿=`new_varnode_in_space`（create+assignHigh+laned+符号尾，
  usepoint=invalid），常量输入保持 `create_constant`（符号尾对 const space
  恒 0；dump 期常量的 assignHigh 残差登记 CONST-IMPORT-ASSIGNHIGH-0001）。

符号尾是导入期的属性通道：Database flagbase 的 readonly 属性范围与
全局符号命中在此落到自由 ram varnode 上——PLTSTUB-THUNKRELRO-0001 的
`.got`（RELRO）readonly 范围经此挂上 PLT 桩 `BRANCHIND(ram:0x16e90)` 输入
varnode，`JumpBasic::findNormalized`（jumptable.cc:1212-1230）的单分支
readonly 救援随即读 GOT 槽值（驱动镜像已施加 JUMP_SLOT/GLOB_DAT 外部符号
重定位）成单元素表，`sanityCheck`（jumptable.cc:2297-2320）距离>0xffff 判
thunk → fail_thunk → 无警告 CALLIND。投影银行 8/8 MATCH、curl/httpd 全量
逐函数 0 回退实证该尾对其余函数面行为中性（这些函数的自由 ram 输入在
其 DB 环境无符号命中、属性为 0）。

## 2026-09-25：push_multiequals 替换 varnode 空间限定（HERITAGE-CROSSSPACE-MERGE-0001）

`Funcdata::pushMultiequals` cc:135 的替换 varnode
`replacevn = newVarnode(origvn->getSize(), origvn->getAddr())` 中，oracle 的
`origvn->getAddr()` 是**完整存储地址（空间+偏移）**。Rudra 无空间
`new_varnode` 适配器 **implicit-RAM**，把被 push 的 REGISTER 空间 MULTIEQUAL
输出伪造为 `Ram@register偏移`（x86-64 寄存器 0x8/0x80/0x90）——该假 RAM
varnode 进入 loc_tree 后被 heritage 当作 RAM disjoint range 处理，长出
输出/输入跨空间的 MULTIEQUAL，门控（SYMDB DB 使 mapGlobals 命中 [0,0x29000)
PT_LOAD 所有权范围）时以 `uRam0000000000000008/80/90` 兜底名打印
（ap_getparents）。修复：`new_varnode_in_space(orig_size, orig_space, orig_addr)`
——origvn 自带空间，neednewunique 臂不变。backtrace 实锤注入链：
`ActionDoNothing → remove_do_nothing_block → block_remove_internal →
push_multiequals → new_varnode(Ram@0x90)`（ci=9964-9966，双态皆现）。
行为面：register-range push（语料主路径）空间不变；验收见
docs/api/heritage.md 同日节（默认路径输出 cmp 字节恒等、门控 −42、兜底名 0）。

## 2026-09-25：op_zero_multi 零输入 varnode 空间限定（FUNCDATA-OPZEROMULTI-SPACE-0001）

`Funcdata::opZeroMulti`（funcdata_block.cc:177-187）零输入臂
`opInsertInput(op, newVarnode(op->getOut()->getSize(), op->getOut()->getAddr()), 0)`
中，oracle 的 `op->getOut()->getAddr()` 是 out varnode 的**完整存储地址（空间+偏移）**
——被清零 MULTIEQUAL 的 out 常为寄存器，新输入 varnode 落寄存器空间。Rudra 侧
（funcdata.rs `op_zero_multi`）沿用无空间 `new_varnode` 适配器 **implicit-RAM**，
把寄存器空间 MULTIEQUAL 的清零输入伪造为 `Ram@register偏移` 垃圾——与
push_multiequals 同族（HERITAGE-CROSSSPACE-MERGE 兄弟位点）。修复：
捕获 out 的 `address_space` 后改走
`new_varnode_in_space(size, out_space, out_addr)`（cc:181 完整地址构造，
与 push_multiequals cc:135 修法同构）；out 为 None 的防御臂保持 Ram 默认
（oracle 无该路径，out 解引用为硬前提）。此后 `new_varnode` 无空间适配器在
funcdata.rs 映射面仅余 double_precis.rs 调用方（另行核对的邻接位点）。

验收实证（亲父 9d839715 A/B，release 亲测）：默认路径 httpd/curl 输出与亲父
**cmp 字节恒等**；门控 RUDRA_SYMDB=1 httpd 骨架 1519→1519（逐函数 diff 亦恒等）。
临时探针实锤：op_zero_multi 零输入臂在 curl/httpd-default/httpd-SYMDB 三态
**0 次触发**（该臂需 MULTIEQUAL 失去最后一条入边；ActionUnreachable 禁用 +
ActionDoNothing 链语料未构造出零输入 phi）——位点语料休眠，恒等由
RAM 臂构造严格等价（`Varnode::new` ≡ `new_with_space(Ram,…)`，varnode.rs:550）
+ 零触发共同保证；寄存器空间 out 一旦触发即走正确空间（correct-by-construction）。
## CommittedLocal（HEADLESS-BRIDGE-V1-TYPESEED，2026-09-25；TYPESEEDARB 锁位透传 2026-09-27）
新增 `pub struct CommittedLocal { offset: i64, name: String, type_expr: String }`
与 `Funcdata::committed_locals: Vec<CommittedLocal>`（默认空）。这是 headless
正典 golden 的 `<localdb>` 传输通道载体（funcdata.cc:804-810 → Database::
decodeScope → ScopeInternal::decode → Scope::addMapSym，database.cc:1564，
每个 committed symbol 携带 ATTRIB_TYPELOCK/ATTRIB_NAMELOCK）：Java DecompInterface
在任何 action 之前把它发给 C++ 库；bare driver 契约（direct-runner golden）
没有该通道。Rudra 驱动在 opt-in 门（RUDRA_TYPESEED=1）下装载收割 manifest
（tools/harvest_local_manifest.py × tests/golden/manifests/
local_seed_httpd_1204.json），ActionRestructureVarnode 在 scope 构造点物化
（见 docs/api/coreaction.md 同日节）。默认路径字段恒空，输出与 bare load
字节恒等。oracle 侧验证：锁定库 + 种子（stage_seed_diag harness，/dev/shm/
rudra-tests/bridge1/oracle_main_seeded.c）复现 canon main 声明层
`long local_d8; long local_d0; long local_c8[4]; local_80[2]; local_70[6]`
与下标形族。

**TYPESEEDARB 增量（HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001，2026-09-27，
wt/typeseedarb）**：结构体新增 `pub typelock: bool` = `<localdb>` 逐符号
ATTRIB_TYPELOCK 位（database.cc:432-434 Symbol::decodeHeader）的 Rust 载体。
`true` = C1 锁定桥（name+type-locked 物化，clearUnlockedCategory 存活，
RangeHint::fixed 边界）；`false` = **name-only 传输**——物化为 namelock-only，
由 scope 构造尾部的 `collect_name_recs`（varmap.cc:357-381，oracle 在
ScopeLocal::decode 边界 varmap.cc:472-477 到达同一下降）降级为名字推荐，
自由 restructure 后由 ActionNameVars 把名字重挂到未锁定恢复符号
（recoverNameRecommendationsForSymbols varmap.cc:1507）。这是两个 oracle 面对
**反编译器自恢复聚合体**的传输形态：锁定库 same-seed 实验（stage_seed_diag
e40ed130 RAM 盘重建，canon-core 词表安装）证明 nameonly-agg 载荷保 canary
INDIRECT 网存活且全部 local_ 名重挂，任一 typelocked ARRAY/STRUCT 灭网
（markUnaliased varmap.cc:1376-1385 alias_block 臂），drop 载荷丢名（Rudra
A/B +50 行）。种子的 type 仍走 `type_expr`——下降后仅 (addr,usepoint,size,
name) 存活（varmap.cc:1600-1613），拼写只定 entry 字节尺寸。收割器
（tools/harvest_local_manifest.py C1 模式）按③重分类：数组声明符
typelock=false（httpd 115 条全量），标量保持锁定桥（不可触发 alias_block，
钉住封闭库无法恢复的分析器辅助 typing 层 = C1 HEAD 残差域）；curl 的
DWARF/STRUCT 通道条目全为分析器真提交，保持 typelock=true（36/36），
驱动解码缺省 true = 字节行为保持。

## 2026-09-25：push_multiequals cc:118 存储地址比较空间限定（FAMILY-AUDIT-SPACELESS-SITES-0001）

`Funcdata::pushMultiequals` cc:118
`if ((origvn->getAddr() == op->getOut()->getAddr()) && origvn->isAddrTied())`
中，`Address::operator==`（address.hh:356-358）比较 **空间与偏移双元组**——
寄存器空间 origvn 与栈/RAM 空间 MULTIEQUAL out 同偏移**不是**同一存储地址。
Rudra 侧（funcdata.rs `push_multiequals` dead-edge 臂）原为无空间偏移比较，
跨空间同偏移时错置 `neednewunique`（oracle：空间不同 → false → 走 cc:135
newVarnode 同地址替换臂）。修复：比较改为
`out.address_space == orig.address_space && *out.get_addr() == *orig.get_addr()`
双条件。探针实证（curl/httpd 默认态）：位点触发 curl 13 次/httpd 115 次，
其中 off_eq=true 且 addrtied=true 的可翻转子集 **全部同空间**（curl 4：
2 Ram/Ram+2 Stack/Stack；httpd 74：73 Ram/Ram+1 Stack/Stack），零跨空间翻转
→ 输出 cmp 字节恒等 = 等价性实证而非休眠；跨空间同偏移一旦出现即按 oracle
判 false。本文件同函数 cc:135 替换臂已由 HERITAGE-CROSSSPACE-MERGE-0001
（XCROSS lane）空间限定，本行收口该函数最后一个无空间位点。

- 2026-09-25 (FAMAUDIT integration): constructor sites merged to master; this note records the integration commit touching the module.

## 2026-09-25：inject_raw_ops_single 常量输入臂并轨 newVarnode 单臂（CONST-IMPORT-ASSIGNHIGH-0001 收口）

CURB 登记的残差"dump 期 const 输入 assignHigh 未镜像"经锁定源逐环重验后
**判决=登记前提不成立（oracle 无行为差），机制层并轨收口**。oracle
`PcodeEmitFd::dump`（funcdata.cc:904-907）对剩余输入只有**一条臂**：
`vn = fd->newVarnode(vars[i].size,vars[i].space,vars[i].offset)`——常量也
走全链。全链在 const space 上的逐环退化：

- **create**：`getConstant(val)` 就是 `Address(常量空间,val)`
  （translate.hh:532-535），Varnode 构造器按空间类型推导
  `constant` 旗标与 `nzm=offset`（varnode.cc:592-597）——与
  `VarnodeBank::create_constant`（=create_with_space(Const,…)）逐位相同；
- **assignHigh**：`highlevel_on` 门（funcdata_varnode.cc:51）在 dump 期
  恒关——唯一置位者 `setHighLevel`（cc:598-599）仅经 `ActionAssignHigh`
  （coreaction.hh:346）在 `ActionStart`（startProcessing→followFlow，即
  dump 发生地）之后运行；dump 期常量的 HighVariable 由 setHighLevel 的
  catch-up 循环（cc:603-604）统一补挂，Rudra `set_high_level` 同构镜像
  （无常量过滤——oracle assignHigh 对非 annotation 常量同样建 HighVariable，
  hasCover 对 constant 恒 false 只跳过 calcCover）；
- **laned 探针**：`getLanedRegister` **只按尺寸匹配、从不读空间**
  （architecture.cc:294-306）——lane 尺寸常量会向 `lanedMap` 记入 const
  space 存储项（oracle 真机制，`create_constant` 旧臂漏镜像）；x86-64
  pspec 带 `vector_lane_sizes`（XMM/YMM/ZMM），minLanedSize=16 探针门是
  **活的**，但语料普查 dump 期常量尺寸仅 1/2/4/8（curl+httpd 共 7321
  站点，全 highlevel_on=false）——无任何常量输入到达 16 字节门 → 现语料
  休眠；一旦出现 16B 常量，Rudra 现与 oracle 同样记入 const space
  lanedMap 项（机制恢复，ActionLaneDivide coreaction.cc:592 消费面）；
- **符号尾**：`stackContainer` 对常量地址先期返回 null
  （database.cc:950 `if (addr.isConstant()) return (const Scope *)0;`），
  flags 塌缩为 `getProperty(const addr)`=0——恒零（varmap.rs
  `query_properties_ex` 的 const 臂镜像该先期返回；parent 腿对非 Ram
  直接返回）。

修复=常量臂删除 `create_constant` 特例，与全部空间并轨
`new_varnode_in_space`（funcdata.cc:904-907 单臂形态）。mid-pipeline 的
`doLiveInject` 侧（同 emitter、highlevel_on 已开、常量即时建 HighVariable）
Rudra 未接线=既有 INJECT-0001 登记域，不在本票范围。验收：curl/httpd
默认态输出对亲父 cmp 字节恒等、三门禁双零（curl 369/0/0、httpd 872/0/0，
与亲父同值）、bank 391/391、触发普查（7321 常量站点全 highlevel_on=false、
尺寸 1/2/4/8 无一达 16 字节 laned 门）与正控制（16B 常量 const space
lanedMap 记入、post-highlevel 即时 HighVariable）见 lane 终报。

## 2026-09-26：map_globals 代理臂 entry 尺寸记录（FUNCDATA-MAPGLOBALS-PROXYSIZE-0001，Lane PIRAM2 + FWARN 移交）

FWARN 车道证伪改道喂料（已并入 master 的票据）：httpd 镜面
"Globals starting with '_' overlap smaller symbols" 7 警（30 函数门禁面）
/212 警（500 函数全语料面）的真根因在 `map_globals` 的 legacy 代理臂——
本 lane 逐行对照（funcdata_varnode.cc:1653-1719，机制 E 亲读）确认两处偏差：

1. **无尺寸自插名**：oracle 的 `discover->addSymbol(symbolname,ct,addr,usepoint)`
   （cc:1709）经 `Scope::addSymbol` → `addMap`（database.cc:1126-1151）把
   mapping 尺寸（`ct->getSize()`）记进 SymbolEntry——RULE_REPEATAPPLY
   restart 重跑 mapGlobals 时，`queryProperties`（cc:1701）读回**带尺寸**
   entry，cc:1711 扩展测试
   `(addr+ct->getSize())-1 > (entry->getAddr().getOffset()+entry->getSize())-1`
   为 false → 无 inconsistentuse、无警告。Rudra 的 `symbol_table`
   `HashMap<u64,String>` 名称代理只有名字无尺寸——cc:1711 的代理形态把
   entry 末端当 `addr` 本身（等价 size-0 entry），测试恒真 → 每次 restart
   重跑都重臂警告（FWARN 插桩：19 触发点全命中自插回退名，触发计数
   30/22/16…=restart 重跑）。
2. **比较用 max_size**：代理臂 else-if 用了组的 `max_size` 而非 `ct_size`
   （oracle cc:1711 比较的是 `ct->getSize()`）。

修复（funcdata.rs，本 lane）：
- 新字段 `symbol_table_sizes: HashMap<u64,i32>`（与 `symbol_table` 平行，
  不改其类型——printc/driver 消费面零扰动）：`map_globals` 代理臂的
  create 分支与 `cover_varnodes` 的代理回退分支插入时同步记录
  entry 尺寸（cc:1126-1151 addMap 的 ct_size/addMapPoint 类型尺寸语义）。
- else-if 改 `ct_size` 对**记录尺寸**的 entry 末端
  （`addr+recorded_size`）；driver 播种项（ELF 函数名，无尺寸记录）保持
  历史 size-0 形态；has_sym 仅来自 scope overlap 时保持 `u64::MAX`
  （无代理 entry 可扩展）。

验收（亲测，基=本 worktree 9d027a33）：
- httpd MIRROR 门禁面：警告 7→**0**，skeleton 265→**258**（−7，FWARN
  预测值精确命中），defects=0/numbering=0/matched 29/29；
- httpd MIRROR 全语料（500 函数）：警告 212→**0**，输出 diff 逐行核对=
  仅警告行及其尾随空行（212+198），**零其它行变化**；ram0x 回退
  169→169（逐地址 diff 空）；
- canon 双零回退：curl 301/0/0、httpd 862/0/0 == 基线逐值；curl MIRROR
  132/275、vsh 15/55、bank 391/391、`cargo test --lib` 1733P/1F
  （唯一失败 test_nonzeromask_pipeline_wiring=VHOST 在案预存）、gcc 审计
  curl 104/20 == STRLIT 基线。

机制 C：funcdata map_globals 实现域——CR 请求随 lane 终报（复核点=
cc:1711 比较键 ct_size/entry 尺寸、addMap 尺寸记录语义、driver 播种项
size-0 历史形态的保持理由）。

### 同轮 drill 诊断移交（FUNCDATA-PIRAM-MAPGLOBALS-0001 残差两类，均越出 funcdata 写域）

oracle drill（mapglobals_drill_1204，锁定 e40ed130 git-archive +
-DOPACTION_DEBUG，direct-runner 协议逐函数）+ Rudra 侧 RUDRA_PIRAM_PROBE
插桩（已撤）双侧对照定分：

1. **direct-runner golden 的 per-function fresh scope 事实**：
   `tools/regen_ghidra_golden.py` 的 `direct_runner_results` 走 `one` 模式
   ——每函数独立进程/独立 BfdArchitecture/global scope。同址多名
   （0xa1060: ap_calc_scoreboard_size=iRam/ap_init_scoreboard=uRam/
   ap_create_scoreboard=xRam）= 各函数 mapGlobals 用**各自** maxvn high
   类型独立发明名（printNameBase 前缀随 ct）。Rudra 的 per-Funcdata
   `symbol_table` 代理与此模型一致（piRam 6 地址/计数与 oracle 逐位兑平）。
2. **残差①（类型盲前缀）根因=符号性，非 undefined**：分歧地址
   （0xa07f0: ap_read_request/ap_recent_ctime/ap_recent_rfc822_date，
   0xa11cc: ap_add_module）双侧 mapGlobals 时点 high 类型——Rudra
   **uint4** vs oracle **int4**（probe `[PIRAM-PRE] high=uint4` vs drill
   `[VN] high=int4` 逐函数实证）→ printNameBase 'u' vs 'i' → uRam vs
   iRam。登记 `TYPEPROP-PERSIST-SIGNEDNESS-0001`（coreaction/typeprop
   域，ENVDAT 占用中）。
3. **残差②（ram0x 回退）根因=消费链，非 map_globals**：map_globals 在
   全部采样点发明了正确名字（pxRam…a1058/xRam…a88a80/iRam…a1068 逐证）；
   回退发生在 PTRSUB(ram-spacebase,const) 印刷路径——oracle 链=
   mapGlobals addSymbol → linkSymbolReference `queryContainer`
   （funcdata_varnode.cc:1207）→ `vn->setSymbolReference`
   （varnode.cc:446-452，挂到常量 high）→ `PrintC::opPtrsub` 读
   `op->getIn(1)->getHigh()->getSymbol()`（printc.cc:1058-1059）→
   pushSymbol。Rudra MIRROR 断链三处：driver 动作期不挂 symboltab
   （"bare-BFD parity" 对符号通道不成立——oracle 的 BfdArchitecture 恒有
   symboltab，mapGlobals 的创建落在真 global scope）；coreaction
   `link_spacebase_symbol` 丢弃 `link_symbol_reference` 的解析结果
   （常量 high 永不挂符号）；printc 双 spacebase 臂（RPN 3312/legacy
   13880）只查 symboltab 通道+栈 scope，不查 `symbol_table` 代理。登记
   `PRINTC-SPACEBASE-PROXY-CHANNEL-0001`（driver+coreaction+printc 域）。
   门禁面现存 11 ram0x refs（main×7/ap_fini_vhost_config×3/
   ap_set_name_virtual_host×1，地址 0xa0820/0xa0830/0xa1198..0xa11b8）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 24 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
## 2026-09-26：force_facing_type / apply_union_facet 工厂写 guard（UNIONRESOLVE-PKG-G-0001，Lane PKGG）
`force_facing_type`（funcdata.cc:974）与 `apply_union_facet`
（funcdata_varnode.cc:1637）构造 `ResolvedUnion` 时原持 `arch.types` 的
**读** guard，`with_field` 因此无法执行 oracle cc:51-55 的
`typegrp.getTypePointer` 工厂 interning，指针臂退化为结构化
`Arc::new(Datatype::Pointer(..))` 非规范 Arc——cast.cc:303
`castStandard` 的 `curtype == reqtype` 指针恒等短路与 `Arc::ptr_eq`
恒等比较族对 with_field 铸造的指针永不命中。两处（连同
unionresolve.rs `resolve_in_flow` Array/Struct 臂与 coreaction.rs
`try_resolution_adjustment` 的 `build_resolve` 调用点 ripple）统一改为
**写** guard，指针臂经 `TypeFactory::get_type_pointer`
（type.cc:3867 findAdd 规范化 + pointee 一步 getStripped）取回
工厂规范 Arc。锁纪律与 union 臂 ScoreUnionFields 的既有 interning
（getTypePointerStripArray/downChain/getTypePointer）一致；调用方
（castInput/cc:2714 与 castOutput/cc:2571 族）均不持工厂 guard，
无重入死锁面。

## 2026-09-26：MIGW1-FUNCDATA-0004 Rust 化批次一（维护面/调试面/打印面/内联壳）

车道 `W-2026-09-26-MIGW1-FUNCDATA-0004`（worktree `wt/migfuncdata`）。本批将
`UNMAPPED_DECOMPOSITION_2026-09-26.md` funcdata 簇真缺失清单中的以下定义 Rust 化
（每函数带 `// Ghidra:` 锚点；逐函数 B2 fixture 见 `tests/oracle/funcdata_*_1204.*`）：

**转发/维护面（funcdata.hh 1-liner 族，46 defs）**：`start_clean_up`（hh:186，
新增 `clean_up_index` 字段替代旧 no-op 标记）、`get_clean_up_index`（hh:187）、
`seen_deadcode`（hh:242）、`dead_removal_allowed`（hh:254）、
`dead_removal_allowed_seen`（hh:260）、`find_covered_input`（hh:303）、
`find_covering_input`（hh:310）、`find_varnode_written`（hh:333，`uniq=~0` 显式
化为 `u32::MAX`）、`begin_loc`/`end_loc` 全 6 对重载（hh:337-372；size/fl/pc
三对以谓词过滤表达同一半开区间，见 FUNCDATA-LOCSIZE-BOUND-0001）、`overlap_loc`
（hh:375，随 bank 侧 (addr,size) 适配签名）、`begin_def`/`end_def` 全 3 对重载
（hh:379-394）、`end_lane_access`（hh:398）、`clear_active_output`（hh:420）、
`clear_dead_ops`（hh:428）、`mark_return_copy`（hh:452）、`find_op`（hh:453）、
`op_dead_insert_after`（hh:460）、`op_dead_and_gone`（hh:476）、
`op_mark_start_basic`（hh:480）、`op_mark_start_instruction`（hh:481）、
`target_op`（hh:490，避免与既有查询撞名）、`begin_op_code`/`end_op_code` +
alive/dead/all/addr 四对（hh:500-527）。

**OPACTION_DEBUG 观察面（14 defs，hh:580-612 + cc:1007-1118）**：Rust 侧常开
编译、行为由 `opactdbg_on` 门控（ctor 按 cc:74-81 初始化：breakcount=-1、全部
false）；`enable/disable_jt_callback`（hh:593/594，fn 指针形态）、
`debug_activate`/`deactivate`（hh:595/596）、`debug_size`（hh:601）、
`debug_enable`/`disable`/`clear`（hh:602-605）、`debug_handle_break`（hh:609）、
`debug_set_break`（hh:610）、`debug_mod_clear`（cc:1024-1032）、`debug_set_range`
（cc:1063-1072）、`debug_check_range`（cc:1076-1098，PC 界与 uniq 界的 continue
短路逐条对齐）、`debug_print_range`（cc:1100-1118，返回字符串、sink 归调用方）。
`Funcdata::clear` 补 cc:90 `clean_up_index=0` 与 cc:110 `opactdbg_count=0` 复位。
既有 `drillobserve.rs` 全局 recorder 与该 Funcdata 成员面并存（前者是 stage-drill
传输层 RUDRA-GLUE，后者是 hh 声明的成员 1:1）。

**打印面（3 defs）**：`print_raw`（cc:209-225；空块分支逐行 `seqnum:\t<opRaw>`，
SeqNum 文本为 address.cc:32-38 形式 `seqnum_text` = `AddrSpace::printRaw`
（space.cc:206-219，`0x`+按 8/12/16 位零填充收缩宽度）+ `':'` + **十进制**
uniq；带块分支组合
block.cc:1300-1316，依赖 block.rs BlockBasic::printRaw/printHeader 缺口——残差
登记 FUNCDATA-BLOCKPRINTRAW-DEP-0001；空 obank 走 RecovError→`Error::Lowlevel`）、
`print_varnode_tree`（cc:579-591，def-tree 序 printInfo）、`print_local_range`
（cc:597-608，ScopeLocal union 窗口按 RangeList::printBounds 文本；子 scope 循环
因 Rust ScopeLocal 无 child map 为结构性缺失 FUNCDATA-LOCALRANGE-CHILDREN-0001）。
opRaw 文本经 `drillfmt::DrillFmt::op_raw`（TypeOp 分发投影）；2026-09-26 起
shortcut 表与 null 槽 `<null>` 渲染按 translate.cc:517-570 /
varnode.cc:1207-1214 修正（详见 docs/api/drillfmt.md），print_family fixture
双侧 byte-MATCH。

**内联/表达式（5 defs）**：`do_live_inject`（cc:848-876，dead-list 尾捕获 +
"Illegal branching injection" 异常路径；payload 经 `InjectPayload::inject` 的
raw-ops 返回形态）、`inline_flow`（funcdata_op.cc:853-916 全序；两处已证明
行为中性的重排序以适配 Rust 借用：testHardInlineRestrictions 前移、inlineClone
先于 jumpvec 拷贝；`FlowInfo::inline_ezclone`/`inline_clone` 为 flow.rs 结构
占位、JumpTable 无拷贝构造 → FUNCDATA-INFLOW-DEP-0001，B2 状态 NO_ORACLE）、
`compare_cse_hash`（funcdata_op.cc:1404-1408 自由函数）、
`CloneBlockOps::clone_expression`（funcdata_block.cc:1024-1040，含空表
LowlevelError）、`AncestorRealistic::mark`（hh:714-717，push 先于 setMark）。

**State 构造器（2 defs）**：`ArState::new`（hh:673-680）与
`ArState::pull_back_subpiece`（hh:685-690，SUBPIECE 回拉的 offset 累加），SUBPIECE
入栈点已改用构造器（此前内联字面量）。

**等价裁决（不逐行 Rust 化，3 defs）**：`~Funcdata`（cc:190-201）——C++ 手工
deleteScope/clearCallSpecs/delete jumpvec 在 Rust 所有权模型下由字段 Drop 吸收
（self_ref 为 Weak 无环）；`PcodeEmitFd::setFuncdata`（hh:623）——Rust 以方法
接收者绑定发射目标（`inject_raw_ops_single`），无裸指针可设；
`CloneBlockOps::ClonePair` ctor（hh:635）——`clone_list` 的 `(clone,orig)` 元组
即 pair，建对位点与 C++ push 相同。

**依赖阻塞未实现（7 defs，FUNCDATA-ENCODE-DEP-0001）**：`encode`/`decode`/
`encodeTree`/`encodeHigh`/`encodeVarnode`/`encodeJumpTable`/`decodeJumpTable`
——阻塞于 varnode.rs/op.rs 的 String 形 `Varnode::encode`/`PcodeOp::encode`（无
`&mut dyn Encoder` 重载）与 jumptable.rs 的 `JumpTable::encode/decode` 整体缺失，
均在其他车道 write-set（MIGW1-DATABASE-0005 / wave-2 marshal+jumptable 票）。

验证：`cargo check --lib` 0 error；`cargo test --lib` 1753 passed / 0 failed
（与基线一致，5 ignored 不变）。

### 批次一补丁：begin_op_code 空 range 默认臂

`begin_op_code`/`end_op_code`（hh:500/503）不再转发 `PcodeOpBank::begin_op`（其默认臂
返回完整 alivelist，与 op.cc:1158-1185 的 `alivelist.end()` 空 range 语义相悖），改为
本地实现 op.cc 的 switch：仅 STORE/LOAD/RETURN/CALLOTHER 有 per-opcode 列表，其余
opcode 空 range（FUNCDATA-OPBEGIN-DEFAULT-0001，bank 侧修复归 op.rs 租约）。

### 批次一补丁 2：oracle 差分揭示的三处 bank 级语义在转发层本地还原

`funcdata_fwd_query_1204` 双侧 fixture 首轮差分暴露三处 varnode.cc/op.cc 语义在
Rust 转发层需本地还原（bank 侧修复归 varnode.rs/op.rs 租约）：
1. `begin_loc_pc`（hh:367/371）：oracle loc-tree 比较器的 "不等" 判定用
   `SeqNum::operator!=`（**仅比较 uniq**，address.hh:150-151），而排序 `<` 是
   pc 优先（address.hh:153-157）——uniq 相同而 pc 不同的 def 视为比较器等价，
   `beginLoc(pc,uniq)` 半开区间因此比字面读更宽（`loc_pc_in_span` 谓词逐条
   编码该行为，by5020=2 双侧 byte-MATCH 验证）。
2. `begin_def_fl`/`begin_def_addr`（hh:385-394）：fl 语义是
   `Varnode::input(8)/Varnode::written(16)/0=free`，且 **written+addr 组合是非法
   输入**——oracle 抛 `LowlevelError("Cannot get contiguous written AND
   addressed")`（varnode.cc:1913-1914），Rudra 以同文 panic 镜像（fixture
   catch 双侧对拍）。
3. `begin_op_code`（hh:500）：默认臂空 range（前批已修）。
另：oracle `PcodeOpBank::target` 从命中 op 反向走 startmark（op.cc:360-370），
未标 startmark 的裸 op 会越界——fixture 按真实流形态给每条指令首 op 补
`opMarkStartInstruction`（同时覆盖该转发器）。


## 2026-09-26 SLEIGH-RUSTIFY-PHASE3-0001 (test-module decode source)

The 22 `#[cfg(test)]` X86Lifter sites decode through
`disasm::sleigh_lift::sleigh_raw_ops` (linear SLEIGH walk) instead of the retired iced
bootstrap lift. Three shape-assert families were re-derived from actual SLEIGH output:
`cmp` is the .sla's 10-op temp chain (`COPY tmp <- rm` leads; the iced lift computed flags
straight off the registers in 9 ops), `mov [rbx],rax` is the engine's COPY-to-temp + STORE
pair (2 ops vs the iced direct-register STORE), and the seq_cmp_je fixture is 27 ops.

The test module's leftover `use crate::disasm::{Disassembler, X86Lifter,
X86_64Disassembler}` import line (dead after the site migration) is removed with the
module retirement commit — the disasm module no longer exports those types.

## 2026-09-27：attempt_dynamic_mapping_late 补 cc:1373-1386 implied→CAST 对侧重定向（DYNMAP-LATE-CAST-RETARGET-0001，Lane DYNMAPLATE）

`Funcdata::attempt_dynamic_mapping_late`（funcdata.rs，Ghidra funcdata_varnode.cc:1347
`Funcdata::attemptDynamicMappingLate`）此前自注 RUDRA-GAP 跳过 cc:1373-1386 的
implied-Varnode CAST 对侧重定向。本批 1:1 移植该块：哈希命中的 vn 为 implied 且
CAST 邻接时，取"另一侧"（`vn->isWritten() && getDef()->code()==CPUI_CAST` →
`getIn(0)`；否则 `loneDescend()` 为 CAST → `getOut()`），仅当对侧 `isExplicit()`
时把符号附到对侧。oracle 语义中该重定向保住的命名中间变量（显式语句）在旧实现下
被附到 implied 侧 → 内联消失——与 CASTFUSE-A 的 −154 过度内联族症状同构。

关键语义（四类）：
- 引用/输出参数：oracle 通过 `vn = newvn` 局部重绑定后统一走 `setSymbolEntry(entry)`；
  Rust 以 `Arc<RwLock<Varnode>>` 重绑定后同一 `MAPPED` 置位 + `symbol_table` 插入。
- 遍历顺序：先 def 侧（CAST 输入臂），def 非 CAST/无 def 才走 loneDescend 输出臂
  （oracle 的 `else` 覆盖"未写"与"写但非 CAST"两种情况）。
- 计数器：无计数器；`count += 1` 在 Action 级（coreaction）不在本函数。
- 比较/守卫键：`loneDescend()` 严格要求恰好 1 个后代（0 或 >1 均返回 null）；
  retarget 终判 = `newvn != 0 && newvn->isExplicit()`。

验证：`tests/oracle/copytrim_remat_1204` C2 late_cast_retarget——oracle 侧
`after` census `c0.mapped=1/tmp.mapped=0`（附着跨 CAST 落到 explicit c0），修复前
Rudra 反接 tmp；修复后（基 master 6a458387 + 本批）双侧该 case 全行 MATCH（含 mint
哈希行，前置 DYNHASH-UNIQUE-ANCHOR-0001 已并）。metadata 不动（重钉留 MB20）；官方
runner 按钉死 crate 快照（f3499354）复跑全绿，pin 完整性保持。残余分歧仅剩
DYNMAP-SETPROPS-RET-0001 / COREACT-DYNMAP-STUB-0001 / COREACT-DYNSYM-STUB-0001
（非本票写域）。`retypeSymbol`（cc:1389-1397）维持既有 RUDRA-GAP 注记不动。
## 2026-09-27：`Funcdata::clone_block_expression` pub 桥（RULEACTION-CLONEBLOCKOPS-0001，Lane RULEADJ2）

新增 6 行公共方法 `Funcdata::clone_block_expression(ops, follow_op)`：纯委托
到模块私有 `CloneBlockOps::clone_expression`（funcdata.rs:18906+，nodeSplit
车道按 funcdata_block.cc:1024-1040 落地的既有实现）。Ghidra 侧
`CloneBlockOps` 在 funcdata.hh:630 是 public 类，ruleaction.cc:9334 直接
实例化消费；Rust 结构体私有时该 pub 桥即模块边界上的同面暴露，零行为
变化。唯一消费者=`RuleConditionalMove::construct_bool`（排序后跨块布尔
表达式克隆，ruleaction.rs）。

## 2026-09-27：`op_uninsert`+`op_insert_after` 搬移对回归钉（GETPARAM-FORLOOP-OPMOVE-0001，Lane OPMOVE）

新增 `final_transform_op_move_tests` 测试模块（funcdata.rs 尾部，2 测）：把
block.cc:3381-3396 finalTransform 的 iterate/initialize 语句迁移动作（`opUninsert`
funcdata_op.cc:164-173 + `opInsertAfter` funcdata_op.cc:373-404）钉进 Rust 回归——
①块内迁移：mid-tail 迭代语句经 uninsert（dead list + parent 解附）再 insertAfter
落到块终端位，Varnode def/descend/input 链全程保持；②跨块迁移 + MULTIEQUAL 跳越
分支（cc:391-402）：非 MULTIEQUAL op 插入前方可跳过连续 MULTIEQUAL 组落位（合成
布局钉防御分支，oracle 不变量下 MULTIEQUAL 恒块首）。纯 `#[cfg(test)]` 代码，零
生产行为变化；语料级 oracle 等价由 F8FOR canon/镜面 A/B 证据承载（见 TODO_BOARD
GETPARAM-FORLOOP-OPMOVE-0001 关账行）。

## 2026-09-27：replace_volatile 尾部 special_prop 误映射修正（VARNODE-CALLOTHER-VOLATILEOUT-0001）

`replace_volatile` 的 cc:761-762 尾部（源 varnode typelock → 置
special addlflag）此前以 STOP_TYPE_PROPAGATION(0x40) 近似 special_prop——
两旗标在 oracle 是不同语义：stop_type_propagation（op.hh:215）使
`Varnode::getLocalType`（varnode.cc:912-914）阻断后代咨询；
special_prop（op.hh:207/109，0x1）门控 volatile user-op 的 local-type
覆写（userop.cc:131/162）。Ghidra 中 typelocked volatile read **不**阻断
传播，其出口类型经 `VolatileReadOp::getOutputLocal`（userop.cc:128-141，
本批 1:1 移植）从全局符号表解析。修正为置位真 SPECIAL_PROP(0x1)。
休眠面：`replace_volatile` 的调用链需 cspec `<volatile>` → varnode
`volatil` 属性（ActionVolatile 域），五语料 cspec 无该元素，链首即断，
canon A/B 字节恒等。

## 2026-09-27：replace_volatile 读臂 hold 条件 + 错误路径对齐（FUNCDEV-VOLATILE-DEVIATIONS-0001）

两处预存休眠偏差收口（CR-VOLATILEOUT 观察项②）：

① **cc:758-759 hold 条件**：oracle `if (vr_op->getDisplay() != 0)
newop->setHoldOutput()`——`getDisplay()`（userop.hh:84-85）取
`annotation_assignment|no_operator|display_string` 位，**0 才是 functional**；
即非 functional 显示（如 print 式注记）的 volatile read 输出可能无人消费，
置 HOLD_OUTPUT 防死码消除删掉读；functional read 正常参与数据流**不** hold。
旧代码无条件置位且注释理由反向（"display is functional (1), so always
hold"）。修正为经描述符 `get_display()` 条件置位。配套：`try_register_builtin_by_id`
兼容路径的 volatile 缺省此前 flags=0（functional），与 oracle userop.cc:443-447
`VolatileReadOp(...,false)`/`VolatileWriteOp(...,false)`（→no_operator/
annotation_assignment，userop.hh:190-191/205-206）不符——修正后兼容路径与
cspec 无 format 属性的 decodeVolatile 缺省同态，hold 行为两侧 1:1。

② **错误路径形态**：cc:723（写臂 `!hasNoDescend()`）与 cc:744-745（读臂
`loneDescend()==null`）oracle 均 `throw LowlevelError`——失败即中止该反编译
路径。旧代码 eprintln+return false 是静默降级。修正为 panic! 镜像（同
funcdata.rs 既有 LowlevelError 先例 begin_def_addr，varnode.cc:1913-1914；
worker 侧 catch_unwind 边界收束）；cc:742 dead-read `return false` 是 oracle
自身的无变更出口，保持不变。

休眠面：与 VOLATILEOUT 同一触发链（锁定 cspec/pspec 无 `<volatile>` 定义，
五语料链首即断），canon A/B 字节恒等为构造性必然。

### 2026-09-28：remove_jump_table 清 SWITCH_OUT 父块旗（SWITCHOUT-CLEAR-REMOVETABLE-0001）
- `remove_jump_table(jt)`（funcdata_block.cc:64-78）补齐 cc:73-76 语义：unlink 表（retain，
  cc:70-72/77）之外，先读 `jt.get_indirect_op()`（cc:73，Ghidra 在 `delete jt` 前读），
  op 存在则对其父块 `clear_flags(SWITCH_OUT)`（cc:75-76 `op->getParent()->clearFlag(
  FlowBlock::f_switch_out)`；Rudra 侧 Weak 升级失败=父块已亡，无旗可清——Ghidra 裸解引用
  活 BRANCHIND 的前提）。清旗使被 RuleSwitchSingle（ruleaction.rs:15418，oracle
  ruleaction.cc:5456）折叠后的分派块重新可 cat-merge（ruleBlockCat 的 isSwitchOut 门，
  blockaction.cc:1290/1298/1308）；此前旗残留使结构化产出退化 `switch() { case 0: … }`
  空骨架。B2 fixture：`switchout_ruleswitchsingle_1204.cc` + 构造单目标跳表二进制
  （车道侧 /dev/shm/rudra-tests/switchout/，root 集成时按 B2 纪律挑拣入库
  tests/oracle/）：oracle 侧 [BLOCKFLAGS]/[JT-REMAIN]/C 渲染 + Rudra 镜像
  --one 9 双侧 body MATCH；修复前 A/B 显示 switch 残骸骨架=可观察差异。注解行同步修正
  为函数定义起始行 `funcdata_block.cc:64`（旧 `funcdata.cc:34` 为构造函数行，
  cited-line drift）。

## 2026-09-29：`early_jump_table_fail` 回溯窗口改 deadlist（MCENSUS4-SQLITE-FTSTYPING-0001，Lane FTSINCRMERGE）

原实现以 `obank.alivelist` 定位 BRANCHIND 起点（`position().unwrap_or(0)`），
而 oracle `iter = op->insertiter; startiter = beginOpDead()`
（funcdata_block.cc:558-559）是 **dead 表窗口**：recoverJumpTables 时刻
（FlowInfo::generateOps，flow.cc:792-814，早于 splitBasic 的 markAlive
flow.cc:1013）所有 lift op 都在 deadlist（Rudra 的 flow 阶段以
recovery-time dead-cycle 同构复现）。查错表 → 位置恒 None → 窗口空 →
恒 Success → `ud2` 的 `uniq = CALLOTHER invalidInstructionException();
goto [uniq]`（.sla 原生语义）BRANCHIND 永落 fail_normal 而非
fail_callother。修复=查 deadlist；op 不在 deadlist（oracle 调用路径不可达）
时 `unwrap_or(0)` 等价 Ghidra `iter == startiter` 的零回溯出口。

`userop_type` 的缺表 fallback（2026-08-11 节登记的适配器差异）本道保持——
gen 驱动现在经 `UserOpManage::initialize`（userop.cc:392-403）装
.sla userop 名表后，`get_op(77)` 返回真实 Unspecialized 描述符而非 fallback，
`userop_type` 语义与 oracle `glb->userops.getOp(id)->getType()` 全等。

A/B 见 docs/api/flow.md FTSINCRMERGE 节（sqlite 1479→1315，零回退）。

## 2026-09-29：`early_jump_table_fail` SPECIAL 臂补 outhit 早退（Lane FTSFIX，CR-FTSINCRMERGE F1/F2）

上节交付（668cf6a4）遗漏了 oracle SPECIAL-else 臂的第二个早退：
funcdata_block.cc:596-597 `if (outhit) return JumpTable::success;`——
"Some special op (CPOOLREF, NEW, etc) generates address, don't assume
failure"。STORE 早退（:595）之后，若被检 special op（LOAD/MULTIEQUAL/
INDIRECT/CPOOLREF/NEW——均带输出，SPECIAL 精确分类）的输出与当前 vn
相交，oracle 立即 Success 进入 stageJumpTable；该早退缺失时 Rudra 继续
回溯（special 臂不更新 vn，两侧同），若窗口内更早存在未注入 CALLOTHER
且其输出与原 vn 相交（子范围/laned 重叠形态），误判 FailCallother →
错误 noreturn-void 截断——五语料（1385+810+74+29+71 函数）零触发的
潜伏缺陷，CR-FTSINCRMERGE §3 F1 判 MISMATCH。修复 = STORE 检查后补
`if outhit { return RecoveryMode::Success; }`（对位 cc:596-597）。
同 commit 更正函数头注释的生命周期描述（F2）：follow-flow 驱动走
`FlowInfo::generate_ops`、httpd 线性注入驱动走
`recover_jump_tables_injected` 的批量 dead-cycle（原文引用了不存在的
`generate_ops_from_path`），并把 `iter/startiter` 行号引用修正为
funcdata_block.cc:558-559。五面门禁 + 五受测函数 --func 零漂移
（delta 口径，见 /dev/shm/rudra-reports/LANE_FTSFIX_2026-09-29.md）。

## 2026-09-30：op 链消费迁移 + GLUE 分支链手术（PERF-ARENA-FLIP-0001 (b)）

`begin_op_code/end_op_code/begin_op_alive/end_op_alive/begin_op_dead/
end_op_dead` 桥接返回类型从 `std::slice::Iter` 换 `OpChainIter`（链序=原
Vec 序）；`op_insert_before`/`op_insert_after`/`op_uninsert` 的 legacy
GLUE 分支从 alivelist 位置扫描/retain/insert 改 O(1) 链手术
（`alive_prev` 反向 INDIRECT 组跳 + `alive_insert_before/after`）；
`early_jump_table_fail` 的 dead[i] 反向索引回溯改 `dead_prev` 存储链游走
（funcdata_block.cc:554 `--iter` 形态）；`do_live_inject` 位点循环保持
Vec 位置语义（`dead_at_strict` panic 对位）。canon 双 md5 字节恒等亲证。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。


## BLOCKFLIPW3（2026-10-01）edge-shadow 维护 choke（批 1 配套）

node-split 的两处边 retarget（funcdata_block.cc:165-167 形——outbl 的
in-edge point/reverse_index 改写、in_block 的 BlockBasic out-edge retarget）
在变异守卫内补 `sync_in_edge_shadow`/`sync_out_edge_shadow`（wave 3 边表
影子写侧, 见 docs/api/block.md EdgeShadow 段）。零读位迁移（本批）。


## ACTIVEPARAMb（2026-10-02）参数走查读面合并 + 走查不变量提升

**PERF-ACTIVEPARAM-READMERGE-0001**（activeparam 单极残量 ~3.1s 的行为恒等
削减——五处纯读面合并/提升,零 walk 形态位移;[APROF]/[SP2PROF] 探针钻定:
only_op_use 2.05s@12.5M op 访问 + AncestorRealistic 0.76s@5,818 execute +
ccdu 0.37s@1.62M 调用为主体,全部为 per-visit 锁/升级常数,非算法面）:

- `only_op_use`: ①输出 varnode 的 `is_persist`/`is_mark` 双读合并为单守卫快照
  （oracle cc:1889/1893 各一次裸字段读;本 walk 内唯一写者是本线程的
  setMark,isPersist 走查不变,两次加载之间不可变）——顺序保持
  persist→(res=false,break)→mark 检查;②opmatch 的 opcode+in(0) 提升为
  走查级单快照（`walk_match_code`/`walk_match_in0`）,供 `opmatch_is_return`
  与 `check_call_double_use` 的 `match_code`/CALLIND `b` 比较共用——oracle
  在 cc:1850/1763/1774 每 CALL 访问处重读裸字段,walk 对 op 只读
  （唯一写=vn/op marks+trial;opSetInput 尾部在 checkInputTrialUse 返回后
  才跑）,快照值与每次重读恒等。
- `check_call_double_use`: `op_code`/`match_code`/`match_in0` 改为参数传入
  ——`op_code` 取调用方 only_op_use 已持有的 op 读守卫（消除同锁递归读,
  1.62M 次）,`match_code`/`match_in0` 取走查快照（消除每调用 opmatch 重读
  +CALLIND 臂 in(0) 重读）。值恒等论证同上;`same_op`/`fc`/`matchfc` 解析序
  与全部早退序未动。
- `AncestorRealistic::enter_node`: ①`mark`/`written` 对与 unwritten 分支
  四 flag（input/unaffected/persist/direct_write）合并单守卫读（oracle
  cc:2040-2051 逐字段裸读;该 vn 的首次写是其后的 mark()）;②opcode 派发与
  各臂字段读（INDIRECT/SUBPIECE/COPY/PIECE 臂的第二守卫）合并为单
  `op_def` 守卫（cc:2031-2132;walk 对 op 只读,各臂值与分别重读恒等）;
  ③COPY 臂 minimal traversal 链步:opcode 测试与 in(0)/in(1) 跟随合并单
  `nd` 守卫读（cc:2090-2108;链上只读,无 PIECE 时的 break 条件保持原序）。

行为恒等证明链（全部亲测,基=master bc58664c）: VdbeExec --one 1055 双面
md5 钉值字节恒等（canon 20920e63/mirror 0668b234）+ ACTIONSTATS 双面五值
恒等（917/302/5,825,839/28,722,524/63,713）+ walk 形态计数器逐值恒等
（19 次 apply × 8 计数器 base/opt 探针对拍 diff 空——specs=830/trials=23,659/
oou_calls=19,275/visits=4,911,503/opvisits=12,716,619/ccdu=1,641,551 聚合
逐值精确相等——探针口径）+ corpus 双面钉值字节恒等（canon 1743cb2f·5,280,382B/
mirror 9aaf3cfd·5,285,971B,1385/1385）+ canon curl f903372a（124F
defects=numbering=0）/httpd 3617ecc3（34F 0/0）+ 镜面五面恰钉值
（curl 11/httpd 0/vsh 0/sq 41/sqlite 180,stale-guard digest 亲验）+
tests 2045P/0F/5I==基线。性能: activeparam 单极探针口径 3.097s→2.725s
（−12%,同负载窗,walk 计数不变）;VdbeExec 总量与 corpus wall 在 load 44-64
共享窗内 A/B 为 wash（−0.3s 量级效应低于 ±1.5s 噪声底,如实记）。

## 2026-10-03：inrefs 直读形态（PERF-ALLOCFLOOR-0001 session 2 簇①）

- `op_destroy_recursive`（funcdata_op.cc:228-247）——内层输入走查逐槽短守卫 +
  单句柄克隆（oracle cc:237-238 每槽 `op->getIn(i)`）。
- `block_remove_internal` 拼接臂（funcdata_block.cc:284-286）——逐 j 短守卫读
  `deadop->getIn(j)`（oracle 每次迭代新鲜读，op 与 deadop 不同块互不相等）。
- `op_destroy_raw`（funcdata_op.cc:253-261）——逐槽短守卫（cc:256-257）。
- `split_uses`（funcdata_varnode.cc:1540-1567）——复制循环内逐槽读
  `op->getIn(i)`（cc:1559-1560），不再预快照整 Vec；def op 守卫不跨
  opInsertBefore/opSetInput。
- `cse_elimination` 共同块臂（funcdata_op.cc:1378-1383）——逐槽新鲜读
  `op1->getIn(i)`（oracle 即为活读），快照元组去 inrefs。
