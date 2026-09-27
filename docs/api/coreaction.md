# `coreaction.rs` API Reference

## 2026-09-27：isOpIdentical / ptr_input_reqtype typedef 通道切换（Lane TYPEDEFIMM，wt/typedefimm）

- `ActionSetCasts::is_op_identical`（coreaction.cc:2469-2481）的 typedef 剥离
  （cc:2476-2479）从工厂名字侧表（`get_typedef_target(name)`，需要线程化
  `Option<&TypeFactory>` 参数）切换到 per-type `typedef_imm` 通道
  （type.hh:196/244）——与 oracle 一致地不需要工厂句柄，且消除名字键的
  假剥离面（外部铸造的同名类型不再被错误剥到 typedef 根）。签名去参，
  调用点 cc:2566 `force = !isOpIdentical(...)` 同步收缩；测试改通道语义
  并新增同名 look-alike 负控。
- `ptr_input_reqtype` 的 PTRSUB 臂（typeop.cc:2320-2347）补齐 cc:2337-2340
  两条剥离环：单层数组剥离后、`same_type` 比较前，reqbase/curbase 各自沿
  通道走到根（此前登记为结构性 no-op）。

## 2026-09-26：ActionPreferComplement BFS 补 BlockGoto/BlockMultiGoto 下降臂（HTTPDMAIN-F5-IFELSE-RETEST-0001 / lane F5IF）

**根因（锁定 oracle e40ed130 git-archive + F5T 仪器化 trace 双侧对照亲证）**：httpd main
configtest if/else 取向翻转（~166 skeleton 行）不是结构化规则缺口——oracle
`ruleBlockIfElse`（blockaction.cc:1416）与 Rugra `try_rule_if_else` 在该分支产出**完全
相同**的 BlockIfElse（tc=out(1)=configtest@0x2c214，fc=out(0)=normal@0x2c130，无
negateCondition，双侧 trace 逐事件一致）；golden 的 `if (iVar3==0){正常路}` 取向来自
**结构化之后**的 `ActionPreferComplement`（blockaction.cc:2140-2167）→
`BlockIf::preferComplement`（block.cc:3093-3109）：`opFlipInPlaceTest` 对
`INT_NOTEQUAL` 返回 0（规范化方向，funcdata_op.cc:1237-1240）→ 翻条件
（`INT_NOTEQUAL→INT_EQUAL`）+ `swapBlocks(1,2)` 交换 then/else 臂。oracle trace 亲证
`PREFERCOMP blk@2c109 test=0 → FLIPPED`（main 内 6 个 if/else 节点仅此一处翻转，
2be90/2beae/2bec8/2bee6/2c130 均 test=1 不翻）。

Rugra 侧机制全在（`prefer_complement`/`flip_in_place_test`/`op_flip_in_place_execute`
逐行核对 block.cc:3093/2368/funcdata_op.cc:1221/1280 忠实），但 `apply` 的 BFS 子节点
访问器 `structure_children` **对 `BlockGoto`/`BlockMultiGoto` 返回空表**——oracle 的
BFS 经 `BlockGraph::getSize()/getBlock(i)`（blockaction.cc:2154-2160）对两者**会下降**：
`BlockGoto : BlockGraph`（block.hh:547）与 `BlockMultiGoto : BlockGraph`（block.hh:573）
都是单组件复合块，wrapped 块由 `identifyInternal(ret,[bl])` 装入（newBlockGoto
block.cc:1706-1708 / newBlockMultiGoto block.cc:1736-1739），`getBlock(0)` 即 wrapped
块。main 的 configtest if/else 恰好嵌在 `BlockGoto@0x2ba58` 包裹的子树内（goto 目标
`code_r0x0002ba58:` 区），BFS 在 Goto 节点断流 → 该 if/else 从未被 offered
`prefer_complement` → 保持结构化期取向 `if (X != 0){configtest} else {正常路}`。

**修复**：`structure_children` 补两臂——`BlockGoto` 返回 `[wrapped]`、`BlockMultiGoto`
返回 `[wrapped]`（镜像 getSize()==1/getBlock(0)），BFS 恢复与 oracle 同构的下降。修后
Rugra 亲证（RUGRA_F5_TRACE）：main 的 prefer_complement 访问集与 oracle 逐节点一致
（2be90/2beae/2bec8/2bee6 test=1，**2c109 test=0 翻转**，第二趟管线 pass 2c109 test=1
=翻转粘性，与 oracle 同形）；输出 `if (iVar2 == 0){正常路} else {configtest}` 与
mirror golden L3325 逐字一致。

**验收（fast-release 亲测，基=master 641994a6）**：httpd canon **590→436**/0/0，
`--func main` **232→78**（−154，带内 ~70±20）；逐函数 delta **仅 main 变化**（其余
33 函数字节恒等，零回退、零附带翻转）；curl canon **267/0/0 == 基线**逐数恒等；
镜面棘轮三门禁/bank 391/391/cargo test 见车道终报。残余 78 行归因：F4 char\* stamp
~15 + F6 串模型 ~8 + F7 `__s1` 推荐 ~6 + F8 for↔while ~2 + F3 双重 cast 1 + RETADDR
硬地板 2 + F5 残余（翻转后块交换 churn 内的变量名/类型派生行），全部在归因报告已登记
族内，零未登记差异。

## 2026-09-26：13 处 union facing 退化读换 fd-aware 孪生（UNIONRESOLVE-PKG-A-0001 / lane PKGA）

审计底稿 `docs/alignment_audit/UNION_CONSUMER_AUDIT_2026-09-26.md` §一 coreaction 表的
13 处 divergent 消费点，全部换为 `unionresolve.rs` 的 fd-aware 孪生
（`vn_type_read_facing`/`vn_type_def_facing`/`vn_high_type_read_facing`/
`vn_high_type_def_facing`，consult `fd.union_map`），fd 均在调用点域内：

- **`is_pointer`**（`// Ghidra: coreaction.cc:1070`）3 处：cc:1077 头门
  `vn->getTypeReadFacing(op)`（slot=参数 slot——union-with-ptr-field 常量 resolved
  为 TYPE_PTR 字段时走直解门而非启发式门）、cc:1120 INT_ADD 臂
  `outvn->getTypeDefFacing()`（def-facing slot -1）、cc:1122 对侧指针判定
  `op->getIn(1-slot)->getTypeReadFacing(op)`（slot 1-slot）。
- **`mark_explicit_unsigned`**（`// Ghidra: cast.cc:38`）2 处：cc:47
  `vn->getHighTypeReadFacing(op)` 与 cc:55 `firstvn->getHighTypeReadFacing(op)`——
  签名加 `fd: &Funcdata`（调用点 cast_input 域内；测试同步传 fd）。常量 high 型
  resolved 为 uint 族字段时 oracle 强制 unsigned 打印，退化形 union metatype 不
  强制（COREACTION-INTSUFFIX-FIRE-0001 的两个读点）。
- **`subpiece_output_token`**（`// Ghidra: typeop.cc:2142`）2 处：cc:2147
  `in0->getHighTypeReadFacing(op)`——**slot 0 键**（in0 真实槽位）先 consult 再
  findTruncation（人工 slot 1 键保持 cc:2150 原样）；此前退化形恒 raw union，以
  人工 slot 1 键查 map（typeprop 建的是 slot-1 条目），两键命中集不同——field 为
  struct 时 oracle 可下钻子字段、退化形落 def-facing。签名改收
  `op_ref: &PcodeOpRef`（视图内派生）。cc:2155 `outvn->getHighTypeDefFacing()` 同
  换 def-facing 孪生。
- **`cast_output` LOAD 臂**（typeop.cc:475/484）2 处：in1 read-facing（slot 1）+
  输出 def-facing。
- **`cast_output` 移位族臂**（typeop.cc:1521/1561/1611）1 处：in0 read-facing
  （slot 0）。
- **`cast_output` PIECE 臂**（typeop.cc:2067）1 处：输出 def-facing。
- **`ptr_input_reqtype`**（`// Ghidra: typeop.cc:2320/2250`）2 处：cc:2325
  `reqtype=getTypeReadFacing(op)` 此前为**裸 `v_type`**（连 needsResolution 检查都
  无，注释自认 residual ACTION-INFERTYPES-DISPATCH-0001——随修关闭该 residual 陈述）
  与 cc:2326 `curtype=getHighTypeReadFacing(op)`。签名加 `fd`；union-ptr 基座
  map-hit 时 oracle curtype=field 指针，same_type/下钻一层判定随之。
- **`cast_output` 头注清理**：cc:2545-2548/2553-2557/2610-2613 的 union
  needsResolution 臂 "remain registered residuals" 陈述已过时（6844/6847/6968/6971
  已 fd-aware），改为现状陈述。

**伴生（datatype.rs，同 lane）**：`TypeStruct::score_single_component`
（`// Ghidra: type.cc:1893`）LOAD/STORE 指针臂 cc:1908
`vn->getTypeReadFacing(op)`——签名改收 `(fd, op_ref)`（原 `&PcodeOp` 视图），换
`vn_type_read_facing`（slot 1 键）。此臂直接决定 `resolve_in_flow` Array/Struct 臂
的 field 选择（union-ptr 地址 resolved 为 field 指针时比较 FIELD 的 pointee 而非
raw union-ptr 的 pointee）。唯一调用点 unionresolve.rs resolve_in_flow 同步。

**行为影响面**：needsResolution 型（union/ptr-to-union/size-1 数组/单字段满幅
struct/partial-union）在 map-hit 边上从 raw 退化为 resolved field；map-miss 边上
Array/Struct/PartialUnion 的 findResolve miss 臂（element/field[0]/stripped）也与
退化形不同。非 resolution 型行为恒等（孪生短路返回原 Arc）。

## 2026-09-25（LOCKFIX）：三处 op 读守卫跨"被调方再锁同一 op"窗口收紧（CURLWIRE-CR-F1）

- **形态**：外层 `PcodeOp` 读守卫（binding 形）存活期间，被调函数经自身路径再取
  同一 op 的读锁（`std::sync::RwLock` 读读递归在写者排队时死锁——单线程 Action 段
  无害，eu-stack 类并发入口为真风险；MIRROR2 车道 down_chain_pointer 已实证同形
  真死锁）。修法 = 先在临时守卫内读 opcode（或先 `drop`），释放后再调；各臂按需
  重取局部守卫。行为恒等证明 = 双语料与亲父 5e6aad2b 输出 cmp 字节恒等。
- **`call_input_cast`**（`// Ghidra: typeop.cc:295 TypeOp::getInputCast`）：
  CALLIND 臂 `get_input_local_in_fd → Funcdata::get_call_specs_of_op`
  （funcdata.rs `op.0.read()` 再锁）在原外层守卫内——现 opcode 提升为临时守卫读
  后释放再分派；CALL 臂自取新守卫传 `&PcodeOp` 视图。oracle 型虚分派读一次稳定
  opcode、全程无锁、同序。
- **`cast_output`**（`// Ghidra: coreaction.cc:2532 ActionSetCasts::castOutput`）：
  tokenct 分发的 `op_rg` 守卫横跨 CALL/CALLIND 臂的 `fd.get_call_specs_of_op(op)`
  再锁——现 opcode 临时读 + 各 token 臂（PTRSUB/PTRADD/算术族/LOAD/移位族/
  SUBPIECE）重取局部 `op_rg`，CALL/CALLIND 臂无守卫化。臂内读序与字段逐行保持。
- **`propagate_constant`**（`// Ghidra: coreaction.cc:4383 ActionConditionalConst::propagateConstant`）：
  MULTIEQUAL 臂 `op_r` 守卫横跨 `Self::test_alternate_path`（cc:4349 形,自身
  `op.read()` 再锁）——现 `drop(op_r)` 后再调（非 MULTIEQUAL 路径既有同款
  drop 位点先例）；守卫窗口内 oracle 只记录 `phiNodeEdges`（cc:4414），重接在
  handle_phi_nodes 之后，零突变窗口。
- **顺手项**：castInput 注释 `(typeop.cc:295)` → `:299`（isAnnotation null 返回行，
  CURLWIRE-CR-F2）。
- **域外移交**：flow.rs `FlowInfoSnapshot::snapshot`（`operation` 守卫横跨
  `find_rel_target` 再锁）同形位点登记 CURLWIRE-CR-F1-A1，不在本 lane 写域。
- **验证**：curl/httpd 双语料 ×2 跑 md5 全等（curl=3095b16e…, httpd=0ee08247…）；
  golden 差分 defects=0/numbering=0；bank 391/391；`cargo test --lib` 1725P+1 预存
  败（funcdata::tests::test_nonzeromask_pipeline_wiring,亲父 5e6aad2b 干树同名同败,
  非本改动）；死锁探针旧形 timeout/新形 exit 0（/dev/shm/rugra-tests/lockfix）。

## 2026-09-25：castInput 的 CALL/CALLIND 分派臂（CURLWIRE-SIGLOCK-WIRING-0001）

- **缺口**：`cast_input` 的 opcode 分发（原 :5432 区）没有 CPUI_CALL/CALLIND 臂——
  CALL 落入通用 metain 回退（`input_metatype(CPUI_CALL)=None` → ct 恒 null → 只有
  markExplicit 路径），被调 callspec 上已装载的 TYPE_LOCKED 参数槽永不驱动实参
  cast。oracle 链：coreaction.cc:2662 `op->getOpcode()->getInputCast(op,slot,strategy)`
  虚分派——TypeOpCall（typeop.cc:660）/TypeOpCallind（typeop.cc:738）**均不覆写**
  `getInputCast`，落基臂 typeop.cc:295-303：reqtype=
  `op->inputTypeLocal(slot)`（虚分派到 TypeOpCall::getInputLocal typeop.cc:687-718 /
  TypeOpCallind::getInputLocal typeop.cc:745-773——callspec 的 typelocked 参数
  slot-1，CALL 侧非 VOID 且 size<=输入，CALLIND 侧仅 VOID 守卫）、curtype=
  `vn->getHighTypeReadFacing(op)`、`castStandard(req,cur,false,true)`。
- **新增 `call_input_cast`**（`// Ghidra: typeop.cc:295 TypeOp::getInputCast`）：
  reqtype 经已移植的 `TypeOpCall::get_input_local`（typeop.rs:2006，callspec 从
  slot-0 fspec 注解解析）/`TypeOpCallind::get_input_local_in_fd`（typeop.rs:2201，
  经 `fd.get_call_specs_of_op`）；curtype 链 `vn_high_type_read_facing → v_type →
  get_base(in_size,Unknown)`（Ghidra 的 getHighTypeReadFacing 不返回 null）；
  `cast_standard_full(&req,&cur,false,true)`。op 读锁限定在 reqtype 查找内
  （read-facing 需自取同 op 锁——写者等待时 std RwLock 读读递归无保证）。
  分发臂在 metain 回退前（CALL|CALLIND → call_input_cast）。
- **curl 效果**：默认脸 487→**417**（−70 骨架行，defects/numbering 双零）——
  getparameter 121→53、my_get_line 10→6、main 104→102、hugehelp 6→0（配合驱动侧
  DAT 标签 1 字节 undefined 类型修正，cast.cc:374 指针→unknown 不 cast 规则恢复）。
  残差归因：parseconfig +4 = DAT_LAB 族（Rugra 把 `%s%s%s` 符号化为字面量而 canon
  保持 &DAT，canon 的 `(Configurable*)&DAT` cast 位移到 Rugra 的两个
  `getparameter(...,(Configurable *)in_RCX)` 位点——臂对给定类型态的行为与 oracle
  一致，类型态差异先存）。
- **httpd 效果**：默认脸 **908/0/0 与基线逐函数恒等**（同臂两语料共享；配套
  examples/httpd_decompile.rs 的 char 元类型 Uint→Int 修正——canon char=INT 元类型，
  字符串常量 char* 与 libc 锁定参数 char* 相等则 cast.cc:304 无 cast；原 Uint 元
  类型使 peel 后 INT vs UINT 触发 24+ 位点 `(char *)` 假 cast，+117 行）。
- 验证：curl/httpd 双跑字节恒等；bank 391/391 MATCH；mirror 门拒绝日志+双跑恒等；
  gcc 审计 104 OK/20 FAIL 同基线同名集；`cargo test --lib` 1713P/1F（nonzeromask
  预存）。

## 2026-09-25：语料名字表清除（EXPEL-CORPUS-TABLES-0001 / AUDIT-CORPUS-MARKERS-GATE-0001）

- **删除** `known_param_count` / `known_param_types` / `is_known_function`
  （原 :1990/:2084 区，2026-06-23 bootstrap 遗留）：按函数名硬编码的元数/类型表，
  含 curl/httpd 语料内部条目（hugehelp/getparameter/match_url/SetHTTPrequest/
  glob_*/ap_*/curl_easy_*/my_*/parseconfig/...）、libc 条目与 `_ => 6` 伪造默认。
  oracle 的 coreaction.cc **无任何名字查表**：调用点参数知识只经被调者自身
  FuncProto 拷贝（`ActionDefaultParams::apply` cc:2321-2330
  `fc->copy(otherfunc->getFuncProto())`）或平台签名数据（Rugra 等价数据面 =
  `debugproto::LibcSignatureTable`，经驱动 callspec link 装载）进入；
  本函数自身形参只来自 trial 推导（`ActionInputPrototype::apply`
  cc:4707-4761，无按自名补齐/截断）。
- **删除** `ActionCallParams`（struct + 两个 impl）：表在调用点侧的唯一消费者，
  且为**死代码**——从未在 `universal_action`（action.rs）注册、全仓无构造点；
  其 `_ => 3` 调用点默认随表一并消失。`SYSV_ARG_REGS` 保留（ActionInferParams
  的候选寄存器索引仍在用）。
- **ActionInferParams 收敛为纯推导**：类型优先级降为 `ptr_param_offsets >
  size-based`（原 `known_param_types` 顶级删除）；按自名的补齐/截断臂
  （原 supplement/truncate 块）整体删除。libc 知识现只走
  `LibcSignatureTable`（24 条 curl 锁定导入，glibc ABI 声明逐字）与 DWARF 通道。
- **A/B（fast-release 双二进制，清除前=HEAD 2eaed4a6）**：curl
  默认/MIRROR/裸态 与 httpd 默认/PARAMID/MIRROR 六态 stdout **逐字节恒等**
  （sha256 见 lane 证据）；`cargo test --lib` 1713P/1F 同名失败；bank 391/391；
  curl gcc 审计 104/20 同基线。零回退归因：表的两个消费面——死代码
  ActionCallParams 与 proto_db 预扫计数（仅经 `external_prototypes`
  `contains_key` 被 ActionDeindirect 消费，值不进输出）——均不在主管线输出路径。
- **常驻门禁**：`tools/check_corpus_markers.py`（入 `.githooks/pre-commit`）：
  生产区域（首个 `#[cfg(test)]` 前）语料函数名/二进制名/语料地址 grep，
  注释剥除 + 标识符边界（`curlast` 类子串不误报）+ TODO 绑定白名单。
  首跑全仓 0 violation（printc.rs `[FOUND-0x17520]` 探针为白名单唯一条目，
  移除登记 PRINTC-CORPUS-PROBE-0001）。
- 历史小节（2026-06-23 系）保留为过程记录，以本节为准。

## 2026-09-24：SUBPIECE/PIECE 输出 token 覆写臂（MYPROGRESS-SETCASTS-ORD399-0001 / FV2）

- `cast_output`（cc:2532-2616）token 分发补 **CPUI_SUBPIECE** 臂：新增
  `subpiece_output_token`（`// Ghidra: typeop.cc:2142
  TypeOpSubpiece::getOutputToken`）逐段镜像——①`find_truncation`（in0
  read-facing 高类型、typeop.cc:2195-2207 的复合字节偏移 = 小端 lsb/大端
  inSize-outSize-lsb、人工 slot 1、union 臂只读消费 `fd.union_map`
  =TypeUnion::findTruncation type.cc:2185），字段类型尺寸与输出相等时即
  token；②否则输出 DEF-facing 高类型（非 UNKNOWN）；③否则 factory INT
  基型。**SUBPIECE 的 token 永不为 `undefinedN`**（覆写优先于 TypeOpFunc
  构造器的 UNKNOWN 输出基 typeop.cc:2117），此前的
  `output_metatype(SUBPIECE)=Unknown` 泛化臂让 implied SUBPIECE 输出走进
  castOutput 的 cc:2569-2571 `updateType(undefined)` 降级臂，摧毁后续读点
  的比较 cast 判定（myprogress ord399 `3519:99 INT_SLESSEQUAL` in1 多出
  `3519:5fe CAST`，setcasts count 5v6）。
- 同分发补 **CPUI_PIECE** 臂（`typeop.cc:2063
  TypeOpPiece::getOutputToken`）：输出 DEF-facing 为 INT/UINT 时即 token，
  否则 factory UINT 基型——同样不走 Unknown 泛化臂。
- `output_metatype` 表保持不变（PIECE/SUBPIECE 由新臂拦截，INSERT 仍走
  Unknown 泛化臂=TypeOpInsert 无覆写）。
- 验证：myprogress 投影 **MATCH**（402 stages/84249 ops，首分歧 399 清零
  非后移）；next_url/match_url/parseconfig 四投影全 MATCH；curl E2E
  3994/0/0（对 9458a61b 亲测基线：6 函数 42 行文本 delta 全部
  undefined→具体类型的 golden-closer 拼写升级，skeleton 总数不变）；
  httpd E2E 与基线**逐字节恒等**；gcc 审计 101OK/21FAIL、6OK/23FAIL
  ==基线；双跑字节恒等。

## 2026-09-23：五 Action count 收割族覆盖（ACTION-COUNTHARVEST-FAMILY-0001 / FD）

FA2（GETPARAM-SWITCHNORM-0001，4e79535d）普查的五个"member count 无收割"残差，
逐一对照 oracle 源码后按各自**真实形态**落地——并非五件同形横切：一件纯增覆盖、
三件双桥收敛、一件自增删除。语义要点：Rust `Action::perform` 的两条 sanctioned
count 桥（action.rs:338 `take_count_delta` 收割 + :344 正返回值并入）是**相加**
关系，apply 不得同时走两条；Ghidra action.cc:319-329 只读成员，apply 正返回值
被丢弃。

1. **ActionUnreachable**（coreaction.cc:3457）：apply 已是"member+=1; return 0"
   形态，仅缺收割 → 新增 `take_count_delta`（`std::mem::take`，与
   ActionSwitchNorm/ActionPreferComplement 同款）。唯一累计点 cc:3461。
   此前投影 result/count/apply 恒 0。
2. **ActionMarkExplicit**（cc:3237）/ **ActionMarkImplied**（cc:3416）/
   **ActionReturnSplit**（blockaction.cc:2264）：此前"member+=N 且 `Ok(N)` 返回"
   双桥并存——返回路径已把 N 计入 ActionState，member 是死重复，未来误加收割即
   双计。收敛为 Ghidra 正典单桥：apply 恒 `return 0`（cc:3271/3454/2323），count
   只走 member 收割（新增 `take_count_delta`）。state.count/warning/count_apply/
   STATUS_END 逐字段不变（数学恒等：旧=返回 N+收割 0，新=收割 N+返回 0）。
3. **ActionStructureTransform**（blockaction.cc:2110-2115）：**oracle apply 从不
   碰 count**（函数体仅 finalTransform+return 0，零计数点；该 Action 定义在
   blockaction.cc 而非 coreaction.cc）——普查清单"五件均有 count+= 需覆盖"的
   前提对此件不成立。Rugra 侧的 `self.count += 1` 系自创累计，若收割必与 oracle
   恒 0 分歧（正是"harvest 后翻转 MATCH"风险的唯一真实来源）。按铁律 1.5 删除
   自创增量，member 恒 0=oracle，不加 `take_count_delta`；
   `test_structuretransform_detects_for_loop` 改由 for_init/for_iter+NONPRINTING
   见证（原 count==1 断言锁的是非 oracle 行为）。

**验证**（基线=亲父 c790ae1b 本 worktree 亲测）：curl E2E **2511/0/0** 与 httpd
E2E **2282/0/0** 均与基线逐字节 cmp 恒等；getparameter/next_url/match_url/
parseconfig 四投影与基线逐字节 cmp 恒等（gp 首分歧保持 ord186=
GETPARAM-TABLEADDR-0001 pre-existing；其余三投影 MATCH 保持）；五 Action 投影
count 字段前后对照全 diff 为空（markexplicit gp 2277/next_url 104/match_url 77/
parseconfig 251 与 markimplied 98/83/54/36 逐字段不变；unreachable/returnsplit/
structuretransform 恒 0=oracle，当前语料纯潜伏）；coreaction 单测 58/58。

## 2026-09-23：castInput double-cast 臂锁卫生（HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0002 / EW）

- **现象**：stage-projection/mirror 模式（`RUGRA_MIRROR=1 RUGRA_STAGE_PROJ=1
  RUGRA_STAGE_FUNC=main`）httpd main 确定性死锁——输出冻结于 76745763B（两轮合并态
  逐字节复现），CPU idle（600s wall / 3.1s user），stderr 终点
  `[BLOCKSTRUCT] main finalize_structure: 89 -> 12`；default 模式同树 main <1s 完成。
  gdb 双采样（setsid+gdb-as-parent 绕 ptrace_scope=1）定格：worker 线程阻塞于
  `RwLock::write_contended` ← `Funcdata::op_set_input` ← `ActionSetCasts::cast_input`。
- **根因（Rugra 侧锁卫生，非 Ghidra 语义差异）**：cc:2680-2684 臂的
  `if let Some(prev) = in_vn.read().unwrap().def...` 以 if-let **scrutinee 临时值**持
  `in_vn` 读锁贯穿整个臂体；臂体内 `fd.op_set_input(op_ref, vnin, slot)`（cc:2682 的
  opSetInput）在 `op_set_input` 第 (3) 步（funcdata_op.cc:120-121 的 opUnsetInput /
  eraseDescend）**写锁 OLD slot 输入——恰为 `in_vn` 本身**，futex RwLock 同线程
  读→写自死锁。Ghidra 单线程裸指针无锁，cc:2680-2682 先完整读
  `vn->getDef()->getIn(0)` 再 opSetInput，无此问题。default 模式此前不触发仅因
  inject 路径+无 cspec 的类型形态从未进入该臂；链侧 RC2（fb935792 cspec 挂载，bisect
  实锤：RC1 b00bf54d 单独 6s 完成、RC2 起 20s 冻结）首次让 httpd main 的
  implied-CAST×ct 匹配形态到达此臂。
- **修复形态**：prev 提取改为 `let prev_cast_input = ...; if let Some(prev) =
  prev_cast_input`——读锁在 let 语句末释放，臂体内 op_set_input 的写不再撞自持读锁；
  读序仍镜像 cc:2680（先完整读 def 输入再 opSetInput），语义零变化。
- **验收（Lane EW，wt/emitterhang@736982f2+本修）**：emitter 模式 httpd main 3s 完成
  （294 @BEGIN，`stage emitters done`，78MB 投影）；default curl 语素**逐字节等于**
  修复前树（eq2_curl_r2.c cmp 零差异，2512/0/0）；default httpd 逐字节等于修复前树
  （eq2_httpd_r2.c，2539/0/0）；三投影 next_url/match_url/parseconfig 非 META diff=0
  全 MATCH。coreaction 属机制 B 白名单，差分门禁双零通过。

## 2026-09-23：union 逐边解析管线接线（UNIONRESOLVE-PIPELINE-WIRING-0001 / EN2）

`fd.union_map` 生产方全链接通——`ActionSetCasts`/`ActionInferTypes` 三个 oracle 调用点
（coreaction.cc:2499/2556/5083）从"登记残差"变为 1:1 移植，`(char **)` 形态落地：

1. **`resolveUnion`（cc:2490-2524）**：apply 循环每 slot 先于 `cast_input` 调用
   （cc:2759）——annotation 早退 → `vn.high.type` needsResolution 门 →
   `dt != vn.type` 时 last-chance `resolve_in_flow(op,slot)` → `get_union_field`
   咨询 → `field_num >= 0` 分三臂：TYPE_PTR 且 `cast_standard(req,res,true,true)`
   仍需 cast 时不解析，否则 `insert_ptrsub_zero` + 把 resUnion 挂到新 PTRSUB 的
   def 边（-1）；implied 非 PTR 臂在 write/read resolution 同 field 时返回 0，
   其余 `setImpliedField()`（cc:2519 生产半，Lane SETIMPLFIELD 接线——flag 由
   PRINTC0004 交付的 `varnode.rs::set_implied_field` 落位，消费端
   `printlanguage.cc:527` → `PrintC::pushImpliedField` printc.rs 已在）。
2. **`tryResolutionAdjustment`（cc:2424-2459）**：`castInput` else-if 链第 4 臂
   （cc:2699）——in/out high type 任一 needsResolution 时
   `find_compatible_resolve` 互配（in 先，out 以 `get_depend(in,inResolve)` 或
   inType 为参），两侧 `ResolvedUnion::with_field` + `set_union_field`（locked
   失败即 false）。
3. **`insertPtrsubZero`（cc:2630-2644）**：PTRSUB(vn,#0) 占位插入，输出 implied +
   `update_type(ct)`；被 resolveUnion（读侧）与 castInput TYPE_PTR+testStructOffset0
   臂（cc:2692-2698，PTRSUB0 修复同轮落地）共用，后者的 needsResolution high
   继承 `inherit_resolution(newop,0,op,slot)`（cc:2695-2696）。
4. **`castInput` CAST 后记账（cc:2713-2717）**：ct needsResolution →
   `force_facing_type(ct,-1,newop,-1)`；vn high needsResolution →
   `inherit_resolution`。
5. **`castOutput` 三处（cc:2545-2557/2610-2613）**：tokenct typeEqual + needsResolution
   → `set_union_field(tokenct,op,-1,ResolvedUnion(tokenct))`；outHighType
   needsResolution 且 `!= outvn.type` → last-chance `resolve_in_flow(op,-1)`，
   out_high_resolve 改由 `find_resolve`（def-facing）；新 CAST/PTRSUB 后
   `force_facing_type`/`inherit_resolution` 对偶记账。
6. **`propagateTypeEdge`（cc:5081-5084）**：incoming temp type needsResolution 时
   `resolve_in_flow(op,inslot)` 先于 backtrack 检查执行（"Always give incoming
   data-type a chance to resolve"——backtrack 边也产生 union_map 写入这一可见
   副作用）；调用链 `propagate_one_type`/`propagate_across_returns`/
   `propagate_ref`/`propagate_spacebase_ref` 透传 `&mut fd`。
7. **fd-aware read-facing 咨询替换**：`load/store/copy/ordering/extension/shift/
   divrem_input_cast` 及 metain 回退臂的 `get_high_type_read_facing`/
   `get_high_type_def_facing` 全部改走 `crate::unionresolve::vn_high_type_read_facing`/
   `vn_high_type_def_facing`（varnode.cc:626-672 的 union_map 感知孪生；varnode.rs
   本体仍为退化实现，EJ2 写域）。op 读锁在派发前释放，由各臂自取。

**验证**：curl ②行 `glob.pattern[8].content.Set.elements = (char **)in_stack_…fd90`
== golden 746（124 函数唯一文本变化，main skeleton 588→584）；三门禁 curl
**2589/0/0**（亲父 dd22aba5 2593，-4）、httpd **2335/0/0** 字节级恒等；
next_url(335/96457)+match_url(340/80385)+parseconfig(335/130099) 三投影 MATCH。

## 2026-09-23：NodeJoin count 适配器 + ConditionalConst phi 路径忠实接通（PARSECONFIG-CONDCONST-PHI-0001）

parseconfig.constprop.0 Phase 2 投影对拍（oracle e40ed130 pin sha256=b2ace56a…，335
stages/130099 ops）逐层定位并修复三层缺口（首分歧 ordinal 81 → 320，配 funcdata 域一行
登记项后 **MATCH**）：

1. **ActionNodeJoin 补 `take_count_delta` 适配器**：`apply` 忠实递增结构体 `count`
   （=Ghidra 继承 protected `Action::count`，blockaction.cc:2355），但未像其它 15 个
   leaf Action 那样经 `std::mem::take` 收割进 `ActionState.count`，投影层
   result/count/apply 恒报 0（ordinal 81 假分歧；双侧探针证明 join 本体已逐字节同执行，
   cb1=3e84:237/cb2=3d20:9b，join 3e78+3ce0 与 3da8+3de1 完全一致）。
2. **ActionConditionalConst 移除两道 Rugra 专有门**：`use_multiequal = false` 硬覆盖
   与 `cond_const_done` 每函数一次门。二者共同压制了 oracle 的 MULTIEQUAL/phi 节点
   路径（coreaction.cc:4401-4426 MULTIEQUAL 臂 + handlePhiNodes cc:4299-4337 →
   placeCopy + opSetInput），即 ordinal 83 的 condconst firing
   （`3ebd:8e9 COPY u:10000243=c:0` + BUILD 3ec0:46e slot 重写）。useMultiequal 门改为
   忠实语义：`Heritage::num_heritage_passes(stack_space) > 0`（coreaction.cc:4522
   per-space delay 语义，heritage.cc:2779-2788；原 `fd.num_heritage_passes()` 裸
   pass 忽略 Stack delay）。历史收敛担忧（12/24 curl 超时）未复现：curl/httpd E2E
   全函数完成、零超时零 panic。
3. **`place_copy` 补 `opInsert` 挂块**：原实现只 `obank.alivelist.push`，新 COPY 无
   parent（SNAP 恒 d=1）；忠实版按 cc:4204-4218 选位（空块→endOp+备选 op 地址；
   尾 op 是分支→分支前；否则 endOp）+ `fd.op_insert` 挂块（cc:4223）。

**验收**：curl E2E 2636/0/0（基线 2665/0/0，−29：parseconfig 126→99、my_get_token
66→64，均向 golden 收敛——golden my_get_token 正含 `pcVar3=(char*)0x0` 零初始化、
golden parseconfig 正含 `char *line; char *nextarg;` 声明；逐函数零回退）；httpd
2333/0/0（基线 2331，+2=httpd main phi 路径 placeCopy 同族机制，缺陷/编号零）；
next_url+match_url 投影双 MATCH 保持；gcc 审计 81OK/26FAIL==基线；funcdata:: 批测
17 失败==master 逐字（单跑通过，全量批跑 18↔20 波动为既有跨模块共享态噪声，master
侧同样存在）。**登记（funcdata 域占线，只登记未写）**：
`PARSECONFIG-JOINBLOCK-STOPADDR-0001` — `node_join_create_block` 跳过
`setInitialRange(addr,addr)`（funcdata_block.cc:786），join 块 stop=0，
`buildDominantCopy`（merge.cc:1168 `domBl->getStop()`）把主拷贝建到地址 0 而非
cbranch 地址（ordinal 320 `0:903` vs `3e84:903`）；临时诊断补丁实测投影 **MATCH**
（parseconfig.rugra_diag.proj）。

## 2026-09-22：ActionInferTypes 补齐 propagateSpacebaseRef/propagateRef（VARGROUP-ABSORB-0001 / INFERTYPES-SPACEREF-0001）

补上 `ActionInferTypes::apply` 缺失的收尾两步（coreaction.cc:5407-5410）：
`findSpacebaseInput(stack)` 后 `propagateSpacebaseRef`（cc:5258-5306）——遍历 SP 输入寄存器的
直接后代 COPY/INT_ADD/PTRSUB/PTRADD（常量偏移），把输出临时类型为指针（指向已知类型）的
地址经 `TypeSpacebase::getAddress` 折算后交给 `propagateRef`（cc:5208-5256）——后者对
[addr, addr+sizeof(pointee)) 内同空间 varnode 逐个 `getExactPiece` 建临时类型（跳过
annotation/无后代/typelock/已挂符号），`typeOrder` 改善时 setTempType +
`propagateOneType`。这是 Ghidra 给栈区 varnode（含 heritage MULTIEQUAL 影写链）打
TypePartialStruct 类型的来源，进而门控 RuleSubRight 的 special-print 分支
（ruleaction.cc:7256）与 printc opSubpiece 字段打印。Rugra 实现按 TempTypes 侧表，
getExactPiece 在 TypeFactory 写锁短临界区内完成。实测（curl main）：SPACEREF 每次
infertypes 派发 40 个 INT_ADD，但当前各 ADD 输出临时类型为 Int 非指针——上游
"锁定调用点参数 → LOAD 反向传播指针类型"链仍未接通，本函数为忠实移植的接收端。


## 2026-09-22：ActionDominantCopy 过期注释更正 + 域确定性归因（DETERM-DOMINANTCOPY-0001）

- 结构体/apply 的注释原声称 `process_copy_trims` 是 "faithful no-op、
  copyTrims 永不填充（缺 snip 子系统）"——已过期：snip 链路
  （unify_address/eliminate_intersect/snip_reads/allocate_copy_trim）
  2026-07-04 已接入 `merge_addr_tied`，`copy_trims` 有真实填充。
  更正为实际语义：Ghidra `ActionDominantCopy::apply`（coreaction.hh:1008）
  即 `data.getMerge().processCopyTrims(); return 0;`；Rugra 侧临时
  `Merge` attach `fd.merge_state.copy_trims` 持久通道，标准管线中
  merge 阶段（`merge_all` step 6，同一 oracle 调用点）先消费，故独立
  apply 通常见空表。
- AZ drill 的 "universal:dominantcopy 工作集逐进程漂移" 与 AX 的输出
  bimodal 同根因：`process_copy_trims` 内 HashMap 迭代序随机（修复在
  merge.rs，见 merge.md 同日条目 DETERM-COPYTRIM-0001）。本文件无容器
  行为变更，只更正误导性注释。

**状态**: 已核对（当前有效）  
**源代码路径**: `src/coreaction.rs`

## 2026-08-30：castInput 双层 double-cast guard 臂序（CASTINPUT-ARMORDER-0001 / F3）

- `cast_input` 的 double-cast guard 恢复 oracle 的**两层嵌套**（cc:2673-2686）：外层
  `isWritten && def==CAST`（cc:2673）无论 implied 与否都占用该臂；只有内层（cc:2674）
  判 `isImplied`。def=CAST 且非 implied 时整条 else-if 链（常量臂 cc:2687 /
  PTRSUB0 / tryResolutionAdjustment）被跳过，vnin 保持 vn 直接落穿 CAST 插入。
  此前 Rugra 把两层合并成 `def==CAST && isImplied` 单条件（合并臂序缺陷），使
  "def=CAST 非 implied + isConstant" 误入常量臂（原地 retype、无插入）。
- 单测 `test_cast_input_def_cast_non_implied_constant_skips_const_arm`：手工 wiring
  （绕过双侧 bank 对 const 输出的同构拒绝，镜像 Ghidra `PcodeOp::setOutput +
  Varnode::setDef`——setDef 设 WRITTEN flag）构造 CAST 产出的非 implied 常量空间
  varnode，断言常量臂未触发（类型保持 ptr）+ 落穿插入 CAST（其输入经
  `opSetInput` 的 const dedup（funcdata_op.cc:108-115，双侧同构）为同值复制）。
- fixture：`ptrsub_switch_cast_1204` 新增 `cast_arm_fork` case，19→21 records
  与锁定 oracle 字节一致（负控：合并形态下 constC 被常量臂 retype 成 int8 且
  无 CAST 插入，与 oracle 分叉）。

## 2026-08-30：isOpIdentical typedef 链剥离（COREACTION-ISOPIDENTICAL-TYPEDEF-0001 / F2）

- `is_op_identical`（cc:2469-2481）新增第三参数 `Option<&TypeFactory>`，在双 PTR 同步
  下探（cc:2472-2474）之后、身份比较（cc:2480）之前，逐侧独立执行
  `while(getTypedef())` typedef 链剥离（cc:2476-2479）。Ghidra 的 `typedefImm` 是
  Datatype 实例字段（type.hh:244）；Rugra 经 TypeFactory 的 typedef 表
  （`get_typedef_target(name)`，typefactory.rs，`get_typedef` 建立的 name→stripped
  映射）解析同一链，对 factory-interned 类型与对象身份等价（名字碰撞由
  `get_typedef` 的 find_by_name 检查 panic 拒绝，链无环）。detached Funcdata（无
  arch factory）保持裸指针比较（RUGRA-GLUE 防御；Ghidra 恒有 factory）。
- 语义顺序：typedef-of-pointer 在 PTR 下探中丢失别名；typedef pointee 保留下探后
  剥离。typedef 输入下 `cast_output` 的 typelock force 判定（cc:2566）由误真
  （多插 CAST）修正为 Ghidra 的不插。
- 单测 `test_is_op_identical_strips_typedef_chain` 锁定：alias↔base、链式 typedef、
  指针下探优先序、distinct base 负例、无 factory 退化负例。
- fixture：`ptrsub_switch_cast_1204` 新增 `typedef_typelock` case（implied+typelock
  的 typedef 输出走 force 判定），17→19 records 与锁定 oracle 字节一致（负控：
  修复前该 case 双侧分叉——Rugra 误插 CAST）。

## 2026-09-23：ActionSetCasts 类型读路径/token 工厂化/shift metain（MATCHURL-SETCASTS-337-0001）

- `cast_output`（cc:2532-2616）类型读全部改走忠实 getter：LOAD token 臂的
  in1 用 `get_high_type_read_facing(&op,1)`（typeop.cc:473）、outHigh 用
  `HighVariable::get_type()`（cc:2543）——配合 varnode.rs 的
  update_type→typeDirty 修复，同 Action 内的 updateType 立即可见；插入路径
  的 `vn->updateType(tokenct)`（cc:2596）与 castInput 的
  `vnout->updateType(ct)`（cc:2706）从裸 `v_type =` 写改为 `update_type`
  调用。
- `cast_output` token 工厂化：fallback 臂与 CALL/CALLIND 臂的
  `base_type_for`（未 interned 的 "long"/"ulong" 名）改为经
  `TypeFactory::get_base`（typeop.cc:261-265 的
  `tlst->getBase(size,metatype)`）——SLEIGH 核心表下得到 interned
  `int8`/`uint8`/`undefined8`，token 参与 interned 身份比较
  （coreaction.cc:2544）与 oracle 一致；detached fixture 无 factory 时
  保留 base_type_for 兜底。
- `output_metatype` 表补齐 TypeOpBinary/Unary/Func 构造器注册的
  metatype（typeop.cc:925-2566）：XOR/AND/OR/DIV/REM/NEGATE/ZEXT →
  Uint，FLOAT 算术族 → Float，PIECE/SUBPIECE/INSERT → Unknown
  （此前 `_ => Int` 全部按有符号处理）。
- 新增 shift 族输出 token 臂：INT_LEFT/INT_RIGHT/INT_SRIGHT 的
  `getOutputToken` 覆写（typeop.cc:1518/1558/1608）= in0 high
  read-facing，bool 降级为 factory int 基型——不走 metatype 表。
- `shift_input_cast`（typeop.cc:1543-1566/1589-1606）reqtype 从硬编码
  Int 改为按 op metain（INT_RIGHT=TYPE_UINT cc:1528、
  INT_SRIGHT=TYPE_INT cc:1568，`op->inputTypeLocal(slot)` 语义）。
- `load_input_cast`/`store_input_cast` 的 req/cur 读改走
  `get_high_type_def_facing`/`get_high_type_read_facing`
  （typeop.cc:444/446/525/527）。
- 验证：match_url Phase 2 投影 **MATCH**（340 stages/80385 ops，
  首分歧 337→全量一致）；next_url 投影 MATCH 保持。

## 2026-08-30：castOutput 完整臂 + castInput guard/const/explicit（PTRSUB-SWITCH-CAST-RESIDUAL-0001 steps 3+4）

- `cast_output`（cc:2532-2616）：token 分发补 PTRADD 臂（typeop.cc:2244 = in0 high
  read-facing，经真实 `TypeOpPtradd`）与算术族臂（cast.cc:394）；补 implied varnode
  三臂（cc:2559-2582：typelock+非 RETURN lone reader → `force = !isOpIdentical`；非
  指针 out → 原地 `updateType(tokenct)`；指针 out 且 pointee 非复合 → 同样重类型，
  复合 ARRAY/STRUCT/UNION 保留）；补 `testStructOffset0`（cc:2384-2413 全移植：struct
  首字段 offset==0 / array 下探一层 + 双侧 array 剥离 + VOID 拒绝 + castStandard
  (req,cur,true,true)==null 判定）→ PTRSUB(#0) 形态（cc:2586-2588/2605-2607）。刷新
  用 `refresh_out_high_resolve`（Rugra 的 typeDirty 为 no-op 的单实例投影，登记残差）。
- `cast_input`（cc:2655-2720）重构为 oracle 臂序：ct=null → `markExplicitUnsigned`
  /`markExplicitLongSize`（cast.cc:38-105 全移植，含 inheritsSign/
  inheritsSignZero/shiftOp 的 addlflags 集合与 mostsigbit 阈值）返回计数；double-cast
  guard（cc:2673-2686：implied CAST 输出 lone-descend 原地重类型 / 回接更早 varnode）；
  常量臂（cc:2687-2691：updateType 成功即计 1，锁定常量跌落到 CAST 插入）；插入用
  `vnin`（可能是更早 CAST 的输入）。
- fixture `ptrsub_switch_cast_1204` 全部 17 条记录与锁定 oracle 字节一致（13 条
  known_raw_differences 全部撤销，见重钉提交）。

## 2026-08-30：ActionSetCasts::apply 的 PTRADD/PTRSUB fit preflight（PTRSUB-SWITCH-CAST-RESIDUAL-0001 step 2）

- `apply` 开头调用 `fd.start_cast_phase()`（coreaction.cc:2728 / funcdata.hh:183，Rugra 新增
  `Funcdata::cast_phase_index` 字段 + `clear()` 复位）。
- PTRADD preflight（cc:2740-2746）：in0 的 read-facing HIGH 类型非指针、或 ptrTo 的
  `align_size != addressToByteInt(scale, wordsize)` 时，`op_undo_ptradd_full(op, true)` 原地
  撤销（implied INT_MULT / 常量折叠）。scale 按 `int4` 截断读 `get_offset()`（cc:2741）。
- PTRSUB 降级（cc:2747-2756）：in0 read-facing 类型 `isPtrsubMatching(offset,0,0)` 不成立时，
  offset==0 → 删 slot1 + COPY，否则 INT_ADD；复用 Rugra 的
  `pointer_is_ptrsub_matching`（type.cc:1123 投影）。
- 撤销/降级后按**当前** opcode/numInput 继续本 op 的 castInput/castOutput（Ghidra 的
  `numInput()`/虚分派在循环条件处活读）；resolveUnion/checkPointerIssues 仍是登记残差。
- 效果：fixture `globform|post`/`swexpr_post` 双侧字节一致（count 7 对齐）；curl E2E
  3110/0/1 保持基线。

## 2026-08-28：GetStr read-facing char 子图

`ActionInferTypes` 的 GetStr 聚焦路径现在按 `Varnode::getLocalType` reader 顺序建立
local type，`ActionSetCasts` 按 op 顺序处理 input/output，并通过 Action count bridge
保留 raw `apply()==0`。这使 `INT_NOTEQUAL(char,char)` 不插入额外 cast。该证据只覆盖
GetStr 字符比较子图；`CPUI_MULTIEQUAL` 传播、flow resolution、type recommendations、
spacebase propagation、union/pointer preflight 等仍是登记中的 `MISMATCH/UNTESTED`。
bridge 本身没有 Ghidra 对应方法，状态为 `NO_ORACLE`；完整
`ActionSetCasts::apply`/`Action::perform` 生命周期不能据此宣称 MATCH。

## 2026-08-28：真实 BlockCopy 的结构变换调用闭包

`ActionStructureTransform::apply` 现对子块树做 child-first/postorder 遍历，
通过 `BlockCopy::subBlock(0)` 取得真实 basic loop head，并以
`BlockWhileDo::has_overflow_syntax()` 执行 oracle 的 overflow 守卫；配套测试从
真实 CFG 经 `build_copy` 构造嵌套 WhileDo。`ActionRedundBranch` 与
`ActionDeterminedBranch` 传给 `Funcdata::remove_branch` 的参数现统一解释为
“要删除的 out-edge slot”。

这不是完整函数 `MATCH`：Ghidra `finalTransform` 的 init/iterate op 移动、
moveability/alias 检查、identity 与错误路径尚未由锁定 oracle fixture 覆盖；
本切片保持 `MISMATCH/UNTESTED`，不能据 unit test 升级模块。

## 2026-08-25：STOP seal + PTRSUB downChain 接线（VARNODE-STOPUP-FLAGS-0001 / TYPE-PTRSUB-PTRSUB-0001）

以下是 `stop_ptrsub_wire_1204` 已覆盖的历史窄投影，曾消除
progressbarinit 的「Type propagation algorithm not settling」警告与 7 层
`->total` 嵌套；它不是四个完整映射函数的 1:1 声明：

1. **`build_localtypes` 的 needsBlock 窄投影（coreaction.cc:5020-5031）**：Rust
   目前遍历 loc_tree，并直接从 defining op 的 `stop_type_propagation` 近似计算
   `needs_block`；为真则 `set_stop_up_propagation()`。它没有调用完整
   `Varnode::getLocalType`，也没有 oracle 的 SymbolEntry/getExactPiece 分支，
   因而整体继续绑定 `ACTION-INFERTYPES-DISPATCH-0001`。
2. **`propagate_type_edge` 补 cc:5093**：`outslot >= 0 &&
   stops_up_propagation()` 时拒绝传播（sealed varnode 作为输入槽目标被封禁；
   以 op 输出为目标的边不受影响——正因如此 downChain 字段指针仍能流入
   RulePtrArith 封禁的 PTRSUB 输出）。
3. **`propagate_type` 四臂拆分（原 INT_ADD|INT_SUB|PTRADD|PTRSUB 合并臂 +
   sibling 传播删除）**：PTRSUB（typeop.cc:2366-2378）/PTRADD（:2268-2281）
   指针只走 input→output 且经 `TypeOpIntAdd::propagate_add_in2out`（typeop.rs，
   typeop.cc:1215）的 downChain 字段消耗变换；INT_ADD（:1181-1201）int 路径
   仅 slot-1 常量放行、`outvn->isConstant()` 透传；INT_SUB→`None`（基类
   typeop.cc:317-321）。非 const 兄弟 input 的指针正向传播（Ghidra 无此路径）
   已删除。`type_factory: Option<&Arc<RwLock<TypeFactory>>>` 参数沿
   apply→propagate_across_returns/propagate_one_type→propagate_type_edge→
   propagate_type 下传（Ghidra 经 TypeOp 的 `tlst` 成员隐式可达）。
4. **`ActionInferTypes::reset` override（coreaction.hh:975）**：按函数清零
   `local_count`（原缺失导致跨函数泄漏、误触 7-pass cap）。

配套修正（同一根因暴露的既有缺陷）：

- **`ptr_input_reqtype` 改为 `TypeOpPtrsub::getInputCast`（typeop.cc:2320-2347）
  / `TypeOpPtradd::getInputCast`（:2250-2266）已实现的非 resolution 窄路径**：reqtype=输入
  varnode 自身（read-facing）类型、curtype=其 HIGH 类型，PTRSUB 剥一层共享
  array 后比较基类型、PTRADD 比较 align_size——**从不咨询 op 的 output
  类型**（旧启发式用 output 指针类型，ActionInferTypes 给 PTRSUB 输出
  PointerRel 形态后会插出 `( )bar` 空 cast）。`cast_input_ptr` 相应去掉
  二次 castStandard 门（Ghidra castInput 对 getInputCast 非空返回直接插
  CAST，cc:2672-2675；testStructOffset0/tryResolutionAdjustment 为登记残差）。
  read-facing 的 resolveInFlow（needs-resolution 类型）仍缺
  （ACTION-INFERTYPES-DISPATCH-0001）；typedef 剥层为结构性 no-op。
- **`build_localtypes` 两处 v_type 播种过滤 Unknown 占位类型**：VarnodeBank
  建新 varnode 时预置 unknown-N，Ghidra 的 getLocalType
  （varnode.cc:918-934）除 typelock 早退外从不读 v_type——占位 unknown
  顶掉 sized-int 回退会使未封禁 INT_SUB/PTRSUB 输出停留 unknown（双侧
   fixture case C/q 抓出）。

## 2026-08-27：PTRSUB output-token 的真实生产消费者（TYPEOP-PTRSUB-FIELDCAST-0001）

PTRSUB 字段 token 不在 `build_localtypes` 播种；oracle 的 PTRSUB output-local
请求 `getBase(output-size, TYPE_INT)`，本 fixture 的 8-byte 输出为 canonical int8，
而 oversized local 闭包仍受 `TYPEFACTORY-LOCALTYPE-CACHE-0001` 约束。真实
消费点是 `ActionSetCasts::castOutput`（coreaction.cc:2532-2616）：Rust 在该
阶段派发 `TypeOpPtrsub::get_output_token`。token 与 output High 类型相同的 case
保持原 PTRSUB/output 不变；普通非 implied、非 resolution 的类型失配 case
插入 CAST，并按 oracle 顺序执行
`opSetOutput(newop,outvn) → opSetInput(newop,vn,0) →
opSetOutput(oldop,vn) → opInsertAfter(newop,oldop)`。

24-record fixture 的 selected cast graph 子投影为 MATCH：action 前两条 PTRSUB
顺序不变；equal case 零突变；mismatch case 得
`[ptrsub@6000,ptrsub@6001,cast@6001]`、一个新 implied 中间 Varnode、PTRSUB→mid、
CAST(mid)→原 output 的所列 def-use/type 状态。该声明仅覆盖 fixture 列出的图
字段，不是完整 bank/High/SeqNum/flags 状态。

整体仍为 MISMATCH，但旧的 raw-return 差异已经关闭：双侧两次 raw apply 都返回 0，
并把 inherited/leaf `count` 从 0 累加到 1。Rugra 的 `take_count_delta` 会读出 1、
清零后再读出 0；这是执行器胶水，Ghidra 没有对应映射函数，所以该 adapter 只能记
`NO_ORACLE`，也不能替代完整 `Action::perform` 生命周期证据。完整闭包还包括
Architecture CastStrategy（当前硬编码 `CastStrategyC::new(4)`）、全部 canonical
identity 比较、无效 PTRADD/PTRSUB 预重写、resolveUnion、checkPointerIssues、
needs-resolution、implied/typelock、PTRSUB(0)、forceFacingType/inheritResolution、
多 block dominance、repeat/perform lifecycle 与错误路径。这些已知/未测残差继续
绑定 `PIPE-ACTION-COUNT-0001C`，不能把 selected graph 外推为完整 MATCH。

同一 fixture 的 infer_pre/infer_post 运行一遍 production
`ActionInferTypes::apply`。unlocked SPACEBASE PTRSUB 的 base/out 均从 unknown8
变为 int8，output STOP、PTRSUB 定义边和 Architecture TypeFactory canonical int8
identity 均为 MATCH。`build_localtypes` 已改为 Varnode loc-set 顺序并调用映射的
`Varnode::get_local_type`；旧的两轮 loc-tree + op walk hybrid 已删除。该 selected
canary 不覆盖完整 SymbolEntry/getExactPiece 变体、descendant competition、非 PTRSUB
派发、repeat apply、精确 DFS path/state 和错误路径，故 selected 投影为 MATCH，
完整 `buildLocaltypes`/`ActionInferTypes` 仍由
`ACTION-INFERTYPES-DISPATCH-0001` 保持 MISMATCH/UNTESTED。

release E2E 以 2026-08-27 pre-PTRSUB fresh baseline stdout
`4404af6da658cc912b84070acb6354073c4649f3b266751e1be6cb81bd1bdc8e`
对 2026-08-28 formal stdout
`f04dee502dc0131b27b41acb5ec412c0e413515aecf3f29e0e2532b304912a73`；
formal stdout 连续两次 2281 行/59995-byte 逐字节一致；该确定性不外推 stderr。
全量仍为 124/124、
76 decompiled、0 timeout/panic/worker/protocol failure，canonical compare 为
defects=0、numbering=0、skeleton 2822→2820。该净改善只来自
`progressbarinit` 15→13，目标字段清零现与 golden 的
`*(undefined4 *)&bar->field_0x1c = 0;` 逐字一致。

raw A/B 不是单行：`diff -U3` 为 12 grouped hunks/7 functions，`diff -U0`
为 33 atomic hunks、42-/42+。其余六个函数的 golden skeleton 数均不变；main
的 `"--"` literal 虽比旧 pointer arithmetic 精确，仍不等于 oracle 的
`&DAT_001062f8`；glob_set switch cast 两版都未恢复 oracle 的 `switch(cVar3)`；
其余多数行是 alpha-renaming。更重要的是 main/getparameter/glob_word/glob_set/
next_url/match_url 新增六个无类型 concrete-pointer 声明。gcc pass/fail 总数仍为
28/123 与 95 FAIL，但诊断分类从 `{other:1101, undeclared:75, syntax:73}` 变为
`{other:1113, undeclared:79, syntax:73}`。该实质语法回归绑定
`PTRSUB-TYPED-DECL-RESIDUAL-0001`；上游 golden identity 闭包仍由
`ACTION-INFERTYPES-DISPATCH-0001`、`TYPE-UNKNOWN-0001` 与
`PRINTC-SYMBOL-DECL-0001` 跟踪。glob_set 新增 outer/nested cast churn 单列
`PTRSUB-SWITCH-CAST-RESIDUAL-0001`；main `"--"` 与 golden 的剩余差异继续由
`TYPEOP-PTRSUB-FIELDCAST-0001` 承担。上述 raw 扩散不能作为
production closure MATCH 或模块升级证据。

## 2026-08-24：build_localtypes 的 CALL/CALLIND input 播种（TYPEOP-LOCALTYPE-DISPATCH-0001 D2）

`build_localtypes` 的 `CPUI_CALL | CPUI_CALLIND` 臂在保留 output 播种之外新增
**input 播种循环**，全部经 TypeOp local dispatch（`TypeOpCall::get_input_local` /
`TypeOpCallind::get_input_local_in_fd`），禁止内联参数锁语义：

- **循环范围**：遍历 op 的每个输入 slot，跳过 annotation 输入（CALL slot0 的
  fspec 常量——buildLocaltypes 的 `vn->isAnnotation()` 过滤，coreaction.cc:5018；
  CALLIND slot0 是真实 code-pointer varnode，照常参与，其种子恰为
  `TypeOpCallind::getInputLocal(op,0)`，typeop.cc:752-756）。
- **merge 语义 = typeOrder-min**：新 helper `merge_min_type_order`
  （varnode.cc:926-931 的 descendant 竞争）：`ct.type_order(incumbent) < 0`
  才替换，平局保留先播者。output 臂同次统一改用该 helper（原为 `insert`
  覆盖式）。
- **fallback = canonical UNKNOWN**：dispatch 的 fallback 由 Architecture
  TypeFactory 出 `getBase(size, TYPE_UNKNOWN)`（typeop.cc:271-275），未锁参数
  的实参以 UNKNOWN 参与 typeOrder 竞争，`IntTypes::sized` 的 INT/UINT 兜底
  不再触达该路径（case8 判别）。
- **锁语义分派**：CALL 的 type-lock（nonvoid + `param.size <= in.size`，
  typeop.cc:705-708）/ this-pointer（PTR→STRUCT）与 CALLIND 的不对称（仅
  VOID、无 size 检查，typeop.cc:762-765）全部住在 typeop.rs 覆写内。

双侧 fixture `tests/oracle/infertypes_callinput_local_1204.{cc,rs,metadata.json}`
+ `tools/run_infertypes_callinput_local_oracle.sh`：8-case 矩阵（locked 播种、
size 拒绝、this-ptr、VOID、CALLIND 无 size 检查、多 use typeOrder-min、
stop-up→UNTESTED 注记、未锁 fallback）+ locked output 臂 + 直分派探针 +
pass1/pass2 演化，观察面为 writeBack 后 v_type + descend/block 序 + callspec
identity 投影。锁定 oracle 与 Rugra 双侧 stdout **字节一致**
（bilateral diff exit 0）。结论限定为 "CALL-input 播种路径 MATCH"：stop-up
三层链（case7）`UNTESTED` 绑 `VARNODE-STOPUP-FLAGS-0001`；op 中心 vs varnode
中心的结构差异、其余臂（差异表 #7-10）、exact-piece 分支、NULL local type
异常仍绑 `ACTION-INFERTYPES-DISPATCH-0001` / `VARNODE-LOCALTYPE-RESOLUTION-0001`。

## 2026-08-24：ActionInferTypes 的 LOAD/STORE 解引用宽度门禁

`ActionInferTypes` 的 production driver 原先在 `propagate_type` 内直接把
pointer pointee 克隆到 LOAD output 或 STORE value，绕过了
`TypeOp::propagateFromPointer` 的访问宽度条件。现在两个 pointer→value 分支都以
真实 target Varnode 的大小调用 `typeop::propagate_from_pointer`：固定长 pointee
只有在 `pointee.size == target.size` 时传播；因此 `ProgressData(32) *` 经 4-byte
或 16-byte LOAD/STORE 不再把完整 32-byte 结构类型写入 target，32-byte 精确访问仍
保留原 pointee 对象身份。value→pointer、PTRSUB、STOP_TYPE_PROPAGATION、DFS 顺序和
7-pass 上限均未改动。

锁定 fixture `action_infertypes_ptrwidth_1204` 使用真实 `Funcdata`、同一
`BlockBasic`、production op bank/def-use API 和一个共享的 `INPUT|TYPELOCK`
`ProgressData *`，按 `L16,L4,L32,S16,S4,S32` 顺序构造六个独立 target，并运行
`ActionInferTypes` 两轮。宽度决策、target 类型身份、source/slot alias、block 与
descendant 顺序、def/descend 图、named flags、成功返回和第二轮稳定性投影为
`MATCH`；异常注入与异常阶段仍为 `UNTESTED`。

完整状态仍为 **MISMATCH**，不能据此升级模块：Ghidra `getBase(16/32,
TYPE_UNKNOWN)` 按 `max_basetype_size=10` 产生 unknown-byte array，而 Rugra 当前
`TypeFactory::get_base` 兼容入口仍产生 flat UNKNOWN（`TYPE-UNKNOWN-0001`）；
`build_localtypes` 的手写
LOAD/STORE arms、value→pointer 的 factory/wordsize/target pointer width、DFS/mark
遍历、Action reset、STOP flag 消费和 PTRSUB downChain/PointerRel 均绑定
`ACTION-INFERTYPES-DISPATCH-0001`，enum/PointerRel canonical exact-piece 绑定
`TYPEFACTORY-EXACTPIECE-0001`，Ghidra/Rugra 的 `TypeField::ident` 表示差异绑定
`TYPEFIELD-IDENT-REPRESENTATION-0001`；它们都在本切片分母之外。fixture 保留双方 raw
metatype 差异并只对上述 width projection 做字段级比较，metadata 的
`overall_status` 固定为 `MISMATCH`。

## 2026-08-17：`build_full_pipeline_actions` 移除 ActionSetCasts（HERITAGE-FLAGFREE-SSA-0001）

- **Ghidra 结构事实（复核 coreaction.cc:5462-5738 全文）**：
  `ActionDatabase::universalAction` 的 root（ActionRestartGroup "universal"）
  head 仅 8 个直接子 action（:5477-5485：Start/Constbase/
  [NormalizeSetup 被注释 :5481]/DefaultParams/ExtraPopSetup/PrototypeTypes/
  FuncLink/FuncLinkOutOnly），随后才是 `actfullloop`（:5690 加入 root）。
  `ActionSetCasts("casts")` 在全文**唯一**出现于 :5735——位于 fullloop
  之后、NameVars(:5734) 之后、FinalStructure(:5736) 之前的尾部序列。
- **缺陷**：`build_full_pipeline_actions` 的 extras 幸存条目会被
  `set_default_actions`（action.rs）注册为 root 直接子节点，执行位置在
  fullloop/mainloop(heritage) **之前**。extras 里的 `ActionSetCasts` 因此
  对 pre-SSA IR 跑 CAST：`cast_input` 的 `op_set_input(cast, in_vn, 0)`
  （coreaction.rs，镜像 coreaction.cc:2702-2712）给翻译期 SLEIGH BOOL
  flag/字节寄存器 free 读（唯一读者=BOOL_NEGATE/BOOL_OR/BOOL_AND/
  BOOL_XOR）加第二读者 → E2E 351 条 `multiple descendants` WARN
  （Ghidra varnode.cc:330-338 在该状态 throw；oracle 管线中 heritage 先行
  SSA 化全部 free 读，该状态不可达）。
- **修复**：extras 删除 `ActionSetCasts` 一项注册。其唯一注册留在
  `set_default_actions` 的 :5735 oracle 位置（action.rs，post-heritage）。
  ActionSetCasts 本体（cast_input/cast_output/apply）无任何改动。
- **测试**：`test_build_full_pipeline_actions_nonempty` 改写——断言
  extras 不含 `setcasts`，且 `build_default_pipeline` root 恰有 1 个
  `setcasts`（oracle :5735 单注册）。
- **E2E 证据（2026-08-17 当时快照，含 WARN-EMIT2 WIP）**：WARN 351→0；
  75 decompiled/0 panic/1 timeout 保持；defects=0；Matched 123 不降；
  skeleton 3147→3155；numbering 0→3（glob_url 嵌套 scope 双局部声明块，
  显式登记移交 printc/varmap 域，随其修复归零；不得在 coreaction 侧加
  守卫补偿）。

## 2026-08-30：ActionDeadCode 无 spec CALL 的 in(0) consume 保护（COREACTION-CALLIN0-CLOBBER-0001）

- **根因**：`inject_raw_ops` 路径的 CPUI_CALL 出生即带静态 `has_callspec` flag
  （op.rs TypeOpCall 静态 flags，对齐 typeop.cc:663），但没有任何 FuncCallSpecs 对象
  （flow-time 锚定缺口 CALLSPEC-DRIVER-0001）。`ActionDeadCode::apply` 的
  `is_call_without_spec` 判定（flag 位组合）因此永远为 false，跳过 cc:3968-3971 的
  全量 pushConsumed；`fd.callspecs` 为空又使 `mark_consumed_parameters`（cc:3840）
  一次都不跑——CALL in(0) 在 consume 重置为 0 后没有任何 push，consume 保持 0。
  第二个 mainloop 迭代（heritage pass>0）中 `ActionVarnodeProps::apply`
  （cc:1282-1342）分支 3 `nzmask & consume == 0` 命中，`totalReplaceConstant(vn,0)`
  把 CALL 的 coderef 目标换成 `const:0` —— httpd 63 处 FUN_0 调用症状
  （DECOMPILE prefix 18→19 bisect，w-push88 移交）。
- **Ghidra 语义**：Ghidra 里每个 CALL 在 flow 期由 `FlowInfo::setupCallSpecs`
  （flow.cc:683-690）无条件挂 FuncCallSpecs 并把 in(0) 换成 fspec 注解 varnode
  （funcdata_varnode.cc:205；varnode.cc:599 给 IPTR_FSPEC 置 `Varnode::annotation`
  → cc:1294 `isAnnotation()` continue 第一层保护）；随后
  `markConsumedParameters` 第一句 `pushConsumed(~0, callOp->getIn(0))`
  —— coreaction.cc:3846 注释原文 "**In all cases the first operand is fully
  consumed**" —— 第二层保护。typeop.cc:663/741 的静态 has_callspec flag 使
  cc:3968 的 `isCallWithoutSpec()` 分支对 CALL/CALLIND 实际不可达。
- **修复**（src/coreaction.rs）：`ActionDeadCode::apply` 的 call 分支新增
  `op_has_attached_callspec(fd, op)` registry 查询（Weak 指针对比
  `fd.callspecs[*].op`）；无实际 spec 的 CALL/CALLIND 对 in(0) 执行
  `push_consumed(u64::MAX)`——恢复 cc:3846 的首操作数全量消费保证。
  `pushConsumed` 是单调合并（`val | consume`，cc:3556-3568），对真实带 spec 的
  调用与 mark_consumed_parameters 幂等，不改变其行为。
- **验证**：curl E2E 字节级不变（3095/0/0 精确保持）；httpd FUN_0 63→0 清零，
  指标 2231/3/0 不变（77 行文本变化全部为调用目标恢复 uRam<realaddr>/符号名）；
  cargo test 失败集与基线逐名相同（funcdata flaky 家族 15-20 波动）。
  双侧 fixture `tests/oracle/coreaction_callin0_clobber_1204.*`
  （curl my_fwrite @0x3460：oracle followFlow 自然挂 spec vs Rugra inject 形态）。
- **上游缺口移交**：真正的 1:1 根因修复是在 inject 路径补 flow-time 锚定
  （funcdata/flow 域，已登记 CALLSPEC-DRIVER-0001）；本修复在 DeadCode 层恢复
  同一管线级可观测（call target 存活），不引入 Ghidra 没有的行为。

## 2026-08-14：ActionDeadCode consume 闭包与自环 MULTIEQUAL

- `push_consumed` 现在逐句实现锁定 Ghidra 12.0.4
  `coreaction.cc:3556-3568`：合并并按 Varnode 大小截断 consume mask；即便 mask 没变化，
  首次传播仍设置 `VAC_CONSUME`；以 `LIS_CONSUME` 按对象身份去重，只把 written Varnode
  压入 LIFO worklist。`propagate_consumed` pop 后先清 LIS，再覆盖
  `coreaction.cc:3576-3800` 的完整 opcode 分支。
- `apply` 的 seed 边界恢复为 `coreaction.cc:3972-4010`：call-without-spec、无输出 op、
  RETURN、BRANCHIND 分别处理；普通 assignment 只 seed auto-live 输入，随后只在 output
  本身 auto-live 时 seed output。它不再把“output 有 descendants”等同于“所有 input
  全量消费”。callspec 参数、返回值 mask、last-chance LOAD、VAC/consume 两类删除路径及
  per-space `seen_dead_code` 也接入真实闭包。
- 所有会写 Varnode 的调用都发生在 `PcodeOp`/input/output 快照读锁释放之后。循环头
  `MULTIEQUAL` 可以合法地让 output 同时出现在 back-edge input 中；该 self edge 仍按原
  input slot 顺序传播，由 VAC/LIS 状态机自然收敛，绝不跳过。
- 锁定 fixture `action_deadcode_selfloop_1204` 覆盖普通 assignment、重复 self input、
  两个 PHI 互环、auto-live 输入/输出、call/LOAD 及 worklist 状态。当前模块仍为 **L2**：
  Rugra `Funcdata` 尚未持有 Ghidra 的完整 `AddrSpaceManager`，因此 apply 从 Varnode bank
  中已有空间按数字 space-id 排序，并用 enum 映射 `doesDeadcode`；未出现的自定义空间及
  Rust 无法表达的 nullable op input 仍不在本 fixture 的 MATCH 分母内。

## 2026-08-13：ActionStart/ActionStop 恢复主管线生命周期调用

- `ActionStart::apply` 现在严格执行 Ghidra 12.0.4
  `coreaction.hh:41-42` 的单一突变：调用共享 `Funcdata` 上的
  `start_processing()`，并返回 `NO_CHANGE`（Ghidra 的 `0`）。
- `ActionStop::apply` 现在严格执行 `coreaction.hh:53-54`：调用
  `stop_processing()`，因此设置 processing-complete、清空 dead-op bank，并在非
  jump-table recovery 模式下进入 datatype-warning 路径；Action 自身仍返回
  `NO_CHANGE`。
- 两个 Action 层均无容器遍历、计数器或排序键；对应遍历与排序全部属于被调用的
  `Funcdata::startProcessing/stopProcessing`。引用语义为就地修改同一个 `Funcdata&`，
  没有复制或输出参数。

当前模块仍为 **L2**。`Funcdata::start_processing` 尚缺 Ghidra
`funcdata.cc:150-168` 中的 `followFlow`、inline header warning、精确
`ScopeLocal::clearUnlocked` 和 `localoverride.applyDeadCodeDelay`；Action wrapper
对齐不代表完整 lifecycle 已 MATCH。

锁定 fixture `tests/oracle/pipeline_lifecycle_1204.{cc,rs,metadata.json}` 在同一
`examples/curl` 指纹、`x86:LE:64:default`、`gcc` compiler spec 与 `GetStr`
入口上运行两个 Action。包装层可观察字段为 `MATCH`：返回值、started/complete
flags、heritage info 初始化、prototype lock 状态，以及插入一个 dead
`CPUI_COPY` 后由 `ActionStop` 清理。完整突变仍为 `MISMATCH`：Ghidra 的
`followFlow` 产生 103 个 alive/all ops、272 个 Varnode、6 个 basic blocks、2
个 calls，Rugra 均为 0。`tools/run_pipeline_lifecycle_oracle.sh` 同时锁定两端
stdout 与稳定 diff 哈希，并把该已登记差异作为预期门禁结果。

### `ActionPrototypeTypes` 阻塞审计（PIPE-LIFECYCLE-0001）

锁定 oracle 的 `coreaction.cc:4609-4699` 在 input-locked 分支按参数索引
`0..numParams` 顺序执行：以参数的**完整 storage Address（含 AddrSpace）**创建
Varnode，调用 `setInputVarnode`（精确重叠时复用、部分重叠时报错），设置
`locked_input`，在入口块调用 `extendInput`，并仅在 truncated code space 下按
pointer type 设置 `ptrflow`。`extendInput` 又必须通过当前 `FuncProto`/`ProtoModel`
的 `assumedInputExtension`，转调 input `ParamList::assumedExtension`，决定
COPY/PIECE/INT_SEXT/INT_ZEXT 以及完整容器。

Rugra 当前 `ProtoParameter.address` 是不含地址空间的标量 `Address(u64)`，
`FuncProto` 仅保存 calling-convention 名称而不持有解析后的 `ProtoModel/ParamList`，
也没有 `assumed_input_extension` 调用面；`Funcdata::new_varnode` 还会默认创建 Ram
Varnode。因此无法区分 register/stack 同 offset，也无法为小参数决定扩展类型。
本轮没有加入 SysV 硬编码或“从现有 Varnode 猜空间”的局部实现；依赖 DAG 必须先补
Address-space-bearing parameter storage → resolved model ownership →
`assumedInputExtension` → property-aware `newVarnode/setInputVarnode`，之后才能完成
`ActionPrototypeTypes` 的真实 oracle fixture。

## 2026-08-12：Rugra 兼容参数 pass 尊重 FuncProto lock

`ActionInferParams` 是 Rugra 现有的兼容 pass，并非 Ghidra 的独立 Action。
它现在遵守锁定 Ghidra `ActionInputPrototype::apply`
（`coreaction.cc:4707-4763`）与 `ActionOutputPrototype::apply`
（`:4765-4782`）的突变边界：input locked 时不写参数列表，output locked 时
不替换返回类型。它仍是 `PARAM-RECOVERY-0001` 下待删除的启发式兼容层，
不能作为参数恢复对齐或 L3 证据。

`build_full_pipeline_actions` 同样不再把 group=`normalanalysis` 的
`ActionNormalizeSetup` 平铺进默认 decompile 路径；完整 Action group 机制仍归
`PIPE-0001`。

**状态**: 🔧 L2；2026-07-27 记录已由上方 2026-08-27 oracle fixture
纠偏。`ActionSetCasts` ordinary PTRSUB output-token no-op/CAST graph 以及 raw
apply/count 子投影为 MATCH；`ActionInferTypes` canary 的 shape/STOP/canonical
output identity 子投影也为 MATCH。Rugra-only count bridge 为 `NO_ORACLE`，完整
castOutput/apply/buildLocaltypes 闭包仍为 MISMATCH，未覆盖分支另记 UNTESTED。
**源代码路径**: `src/coreaction.rs`
**2026-07-16**: 测试构造的 BlockWhileDo 加 `overflow_syntax: false` 字段（配合 printc P7-overflow_syntax，对齐 Ghidra hasOverflowSyntax block.hh:692）。

## 模块说明 (Module Doc)

Core analysis actions for the decompiler

Corresponds to Ghidra's `coreaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionHeritage`

Action for performing SSA construction (Heritage)

Corresponds to Ghidra's `ActionHeritage`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionDeadCode`

Action for removing dead P-code operations

Corresponds to Ghidra's `ActionDeadCode`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionConstantPtr` (2026-08-25 B3-COREACTION-CONSTANTPTR-0001 段(b) 重写)

Action for identifying constant pointers and replacing them. Iterates the
constant-space varnodes, infers the pointer space (`selectInferSpace` over
`inferPtrSpaces`), runs `isPointer`'s op-shape / pointer-range /
`bit_transitions>=3` / container-query gates and rewrites hits into
`PTRSUB(spacebase, offset)` chains via `Funcdata::spacebase_constant`.
Faithful to `coreaction.cc:957-1217` (searchForSpaceAttribute /
selectInferSpace / checkCopy / isPointer / apply). Known projections (both
documented in-source): the pointer-space attribute of TYPE_PTR is not
modeled (TYPE-0001 residual) and `rampoint.getAddrSize()` rides an explicit
`spaceid` parameter because legacy `Address` is spaceless (ADDRESS-0001).

### `pub fn new() -> Self`

构造镜像 coreaction.hh:188；`localcount` 初值 0（Ghidra 的该成员由
`reset()` 零化，coreaction.hh:194 — Rust 构造即置零）。

### `fn search_for_space_attribute(vn, op) -> Option<AddressSpace>`

Ghidra: coreaction.cc:957。3 步数据流遍历（INT_ADD/COPY/INDIRECT/
MULTIEQUAL）找 LOAD/STORE 的空间常量；尾段扫描全部后代。**R-RAWQUAR
F2 修复（2026-08-25）**：追链中 `lone_descend()==None` 时 cc:984 是
`break` 跳出到尾段（且 cc:972 已把 vn 前移到输出），尾段扫描**该输出**
的全部后代——首版 `?` 从整个函数提前返回 None 跳过了 epilogue（仅
多候选空间可观测，x86-64 单 ram 候选不触发）；现以 labeled `break
'chase` 忠实镜像。

### `fn select_infer_space(vn, op, space_list) -> Option<AddressSpace>`

Ghidra: coreaction.cc:1005。TYPE_PTR 空间属性（未建模，恒走列表）→
`inferPtrSpaces` 顺序扫描，尺寸门（minSize==0 要求 ==addrSize）；
第二候选触发 `searchForSpaceAttribute` 消歧后 break。

### `fn check_copy(op, fd) -> bool`

Ghidra: coreaction.cc:1041。COPY 喂 lone RETURN 且输出锁定：PTR/UNKNOWN
放行，否则拒绝；其余跟随 `infer_pointers`。

### `fn is_pointer(spc, vn, op, slot, rampoint, full_encoding, fd) -> Option<QueryContainerHit>`

Ghidra: coreaction.cc:1070。显式 TYPE_PTR 臂（未建模，走通用门）→
op 形状门（CALL/CALLIND 锁定参数类型、COPY、PIECE/比较、INT_ADD、
STORE slot 2）→ calcScaleMask 指针范围门（0x1000/high-0x1000）→
bit_transitions>=3 → resolveConstant（translate.cc:637-641 无 resolver
默认路径）→ `query_container_parent_scope(rampoint,1,Address())`；
char-array 中部例外（cc:1153-1159）与 needexacthit（cc:1161-1162）。

### `fn apply(&mut self, fd) -> Result<i32>`

Ghidra: coreaction.cc:1167。`hasTypeRecoveryStarted` 门 + `localcount>=4`
早退；常量空间 locset 快照迭代（新造 varnode 或 offset 0 或已
PtrCheck，等价于 Ghidra 的迭代中插入容忍）；命中走
`spacebase_constant(op, slot, &entry, rspc, rampoint, fullEncoding, size)`
+ INT_ADD slot==1 的 `op_swap_input(0,1)`；`count` 经
`take_count_delta` 外化（cc:1213）。

### `pub struct ActionCse`

Action for performing Common Subexpression Elimination (CSE)

Corresponds to Ghidra's `ActionCse`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionRestructureVarnode` (2026-06-26 新增)

Restructure the local-variable scope from stack varnodes. Faithful to
`ActionRestructureVarnode` (coreaction.cc:2274).

- `apply(&mut fd)`: **2026-09-23 SB-MATCHURL-ORD70-0001 起 scope 跨趟持久**：
  首趟构造 `crate::varmap::ScopeLocal`（播种 input-locked 参数符号、
  `set_arch_lookup`、funcdata.cc:70 生命周期点的 `reset_local_window`）存入
  `fd.scope`，此后每趟复用（Ghidra 的 ScopeLocal 是 per-Funcdata 对象，
  funcdata.cc:63-71 构造一次跨所有 pass 存活——持久化保住了
  `markNotMapped` 的窗口窄化（buildInputFromTrialls fspec.cc:5737 的
  outgoing-param 槽 + ActionRestrictLocal 的 saved-reg 槽），下一趟
  `add_range` 的 `range.inRange` 门（varmap.cc:902）才能丢弃这些槽的
  hint）。每趟调用 `restructure_varnode(fd, aliasyes)` 后跑
  `fd.sync_varnodes_with_symbols(false, aliasyes)`。
  **2026-09-24 VARMAP-STACKBOUNDARY-0001 起每趟发布活跃局部图**：在
  `fd.scope = Some(scope)` 之后调用 `fd.publish_scope_to_spacebase()`
  （Ghidra getMap type.cc:2935-2945 动态解析 `fd->getScopeLocal()` 的
  所有权镜像）——把重构后的 ScopeLocal 发布进工厂缓存 stack spacebase
  类型的共享句柄，使后续 `TypeSpacebase::get_sub_type` local-frame
  查询（oppool2 ptrarith `calc_subtype` 的 extra 喂入）读到活跃图；
  myprogress 投影首分歧 150→399。
  **2026-09-23 VARMAP-PARAMSTORAGE-BLOB-0001 起参数符号按真实存储落位**：
  播种时逐参携带 `ProtoParameter::address_space`——INTEGER 类照旧
  Register 空间（寄存器偏移+寄存器宽度），MEMORY 类按值参数（match_url
  的 304B `URLGlob glob`）落 **Stack 空间**（模型偏移 8 = entry_rsp+8 起
  整类型宽度），与 oracle localdb 参数符号的 per-space SymbolEntry
  （database.cc:1848-1851 maptable per spaceid）一致；旧实现硬编码
  Register+整类型宽度的 blob 条目使 `find_container_entry` 的
  [start..start+size) 包含判定（database.cc:2269）错误吞掉无关指针寄存器
  （rax）而真栈槽读反查不到。寄存器参数的 varnode typelock 支腿现按
  `space == Register` 门控；栈参数的 typelock 走
  `sync_varnodes_with_symbols` 的 stack-space 步进 +
  `SymbolEntry::getSizedType` 字段投影（funcdata_varnode.cc:947-960），
  与 oracle 同路。
  **2026-09-23 SETVARNODE-SCOPELOCAL-CONSUMER-0001 起参数符号 usepoint 按
  ProtoStoreSymbol::setInput 落位**（fspec.cc:3153, 3166-3169）：bootstrap
  现先执行 `reset_local_window`（funcdata.cc:66-70 生命周期——oracle 的
  ScopeLocal 在 Funcdata 构造时建好窗口，localdb 符号后到），再逐参计算
  usepoint——存储落在窗口树（localRange ∪ paramRange，varmap.cc:441-458）
  内的 MEMORY 类栈参数保留 INVALID usepoint（`discoverScope` 命中本 scope，
  fspec.cc:3167），寄存器参数（无 scope 认领）回退
  `restricted_usepoint` = baseaddr−1（funcdata.cc:69，fspec.hh:1288）。
  经 `add_symbol` → `add_map_entry_with_property` 的 addMap 规则
  （database.cc:1149-1150）：栈参数 empty uselimit → **addrtied 符号**
  （与旧行为一致），寄存器参数 one-point uselimit {fd−1} → **非 addrtied**
  且条目仅在函数入口点应答（`entry_in_use` ↔ `SymbolEntry::inUse`，
  database.cc:114-120）——EE 并入 ScopeLocal 腿后，寄存器空间参数槽上的
  后续 op 输出（调用实参算术等）不再折叠条目 flags（`set_varnode_properties`
  的 mapped|addrtied 折叠），下游 `ActionMarkExplicit` 的 addr-tied 强制
  explicit（coreaction.cc:3022-3048）与 `ActionNameVars::linkSymbols` 的
  `handleSymbolConflict` 早臂（funcdata_varnode.cc:1000-1003）不再误触发。
- `aliasyes = (numpass != 0)`（coreaction.cc:2279）已穿透：第 0 趟跳过
  `mark_unaliased`/`check_unaliased_return`（varmap.cc:1280-1282）；
  `annotate_raw_stack_ptr` 不受门（cc:1284-1285）。

测试：`coreaction::tests`（3 个）验证 scope 被构建、get_name 正确、
参数符号 usepoint/addrtied 分野（`test_action_restructure_param_symbol_usepoint`
钉 fspec.cc:3166-3169 三观察面：regp usepoint=Some(fd−1) 非 addrtied 且
条目仅在 fd−1 应答；stkp usepoint=None addrtied）。


### `pub struct ActionStart`

Start of the analysis process

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeRequired`

Action for merging required varnodes (e.g., tied to the same address)

Corresponds to Ghidra's `ActionMergeRequired`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeAdjacent`

Action for merging adjacent varnodes

Corresponds to Ghidra's `ActionMergeAdjacent`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeCopy`

Action for merging COPY varnodes

Corresponds to Ghidra's `ActionMergeCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeMultiEntry`

Action for merging MULTIEQUAL entry varnodes

Corresponds to Ghidra's `ActionMergeMultiEntry`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeType`

Action for merging varnodes by datatype

Corresponds to Ghidra's `ActionMergeType`

`apply` mirrors coreaction.hh:414 exactly: it runs the same-type
speculative pass `Merge::merge_by_datatype` (Ghidra
`data.getMerge().mergeByDatatype(data.beginLoc(),data.endLoc())`) and
nothing else. It must not re-enter the required-merge sequence —
`Merge::merge_addr_tied`/`merge_range_must` only ever run inside
ActionMergeRequired (coreaction.cc:5718), which is sequenced BEFORE
ActionMarkImplied, so `Merge::merge_test_must` never observes an implied
Varnode (MERGE-FORCEMERGE-PANIC-0001).

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionSimplify`

Algebraic simplification of P-code operations

Folds redundant expressions:
- `x ^ x` → `COPY 0`
- `x & x` → `COPY x`
- `x | x` → `COPY x`
- `BOOL_NOT(BOOL_NOT(x))` → `COPY x`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionTypeInfer`

Iterative fixed-point type inference engine

Infers and propagates types across P-code IR varnodes using a multi-pass iterative
dataflow approach (up to 100 iterations until convergence). Implements 5 core rules:

1. **Opcode-driven**: Comparison/boolean ops → `bool` output
2. **COPY propagation**: Bidirectional type flow across `CPUI_COPY`
3. **Pointer arithmetic**: `INT_ADD`/`INT_SUB` with pointer → output inherits pointer type
4. **Phi node**: `MULTIEQUAL` inputs/output type unification (prefers pointer types)
5. **LOAD/STORE dereference**: Bidirectional pointer↔pointee type propagation

After convergence, a post-pass assigns size-based defaults (`byte`/`short`/`int`/`long`)
to remaining untyped varnodes.

Corresponds to Ghidra's `ActionInferTypes` iterative type recovery pass.

### `pub fn new() -> Self`

*暂无代码注释*

 
### 2026-06-23：参数指针类型检测

- `ActionInferParams` 现在扫描所有 LOAD/STORE 的地址输入（input[1]），若该 varnode 是 INPUT 参数寄存器，则把对应参数类型从 size-based scalar 提升为 `long *` 指针。对齐 Ghidra 的 `ActionActiveParam` 指针恢复逻辑。

### 2026-06-23（续）：函数签名与 known_param_count 同步

- `ActionInferParams` 现在在推断参数后，如果当前函数在 `known_param_count` 数据库中有记录，用它的值裁剪推断的参数数。修复函数定义签名与调用处参数裁剪不一致导致的 `too few/many arguments` 错误。
- `ap_strcmp_match`/`ap_strcasecmp_match` 从 1 参数修正为 2 参数。

### 2026-06-23（续）：__vfprintf_chk 参数数修正

- `__vfprintf_chk` 从 5 参数修正为 4 参数（`fp, flag, format, va_list`），与其它 `__*_chk` 可变参数函数区分。

### 2026-06-23（续）：类型传播引擎实验

- 尝试了 COPY chain 追踪 + INT_ADD 指针算术检测 + CALL 参数指针推断。所有模式都太激进——破坏 gcc 通过率（51-52/53）。
- 根因：精确类型传播需要双向类型约束求解（Ghidra ActionTypePropagate），不是简单的使用模式匹配。参数 + 常量可能是数组索引（非指针），CALL 参数可能传值（非指针）。
- 回退到原始的直接 LOAD/STORE 地址检测。53/53 维持。

### 2026-06-23（续）：参数数量对齐 Ghidra

- 修正 known_param_count 中多个函数的参数数，对齐 Ghidra 推断：
  - helpf 1→仍1（Ghidra 2，但 helpf 实际 2 参数，留待后续）
  - SetHTTPrequest 3→2
  - parseconfig 2→4
  - getparameter 3→5
  - file2string.part.0 移除（Ghidra 推断 0，但实际有参数）
  - progressbarinit 加入 1 参数组
- curl 参数差 13→11（-2）。gcc 53/53 维持。

### 2026-06-23（续）：函数名规范化 + 参数数对齐

- known_param_count 现在规范化函数名（`.` → `_`），让 `.constprop.0`/`.part.0` 后缀匹配下划线版。
- helpf 从 1 改为 2（`const char *fmt, ...`）；glob_range 从 5 改为 2；glob_url 保持 2。
- my_get_token/my_get_line 加入 1 参数组。
- curl 参数差 11→8（-3）。gcc 53/53 维持。

### 2026-06-23（续）：known_param_types 源代码签名类型传播

- 新增 `known_param_types()` 返回已知函数的参数类型签名（"ptr"/"int"），基于 curl/httpd 源代码。
- ActionInferParams 用 known_param_types 覆盖默认 size-based 类型推断。
- 效果：my_fwrite 从 `(long, long, long, long)` 改进为 `(void*, long, long, void*)`；SetHTTPrequest 从 `(long, long)` 改进为 `(int, void*)`。
- 禁用了 myprogress/glob_* 签名（优化二进制中类型冲突）。

### 2026-06-23（续）：参数补充 + is_known guard

- 当 known_param_types/known_param_count 的参数数 > 推断数时，从 ABI 寄存器列表（RDI/RSI/RDX/RCX/R8/R9）补充缺失参数。
- 加 is_known guard：只有已知函数才补充/裁剪参数，避免影响测试中的未知函数。
- 效果：getparameter 从 3 参数补充到 5（对齐源代码），parseconfig 从 1 补充到 2。
- gcc 53/53，175/176（1 预存失败）维持。

### 2026-06-23（续）：保守化 httpd 签名

- 移除不确定的 httpd 函数签名（ap_init_vhost_config/ap_update_vhost_given_ip/ap_matches_request_vhost）。
- 只保留确定正确的（ap_fini_vhost_config/ap_parse_vhost_addrs）。
- httpd 参数差 25→21。

### 2026-06-23（续）：移除不确定 httpd 签名

- 移除所有不确定的 httpd ap_* 函数从 known_param_count（ap_get_server_built/ap_pregcomp/ap_pregfree/ap_strcasestr/ap_stripprefix/ap_os_is_path_absolute/ap_is_matchexp/ap_field_noparam/ap_regcomp/ap_regfree/ap_mpm_query/ap_update_vhost_from_headers/ap_vhost_iterate_given_conn/ap_open_stderr_log/ap_setup_prelinked_modules/ap_show_mpm/ap_get_local_host/ap_set_name_virtual_host/ap_init_vhost_config 等）。
- 只保留标准库函数 + 确定的 curl/httpd 函数。
- httpd 参数差 21→16（低于初始 17！）。

### 2026-06-24：保守 ActionTypePropagate（≥2 不同小偏移）

- 新增 `src/analysis/type_infer.rs`：P-code 级保守类型传播。
- 只标记被 ≥2 个不同 8 字节对齐小偏移（<256B）访问的 varnode 为 `_struct *`。
- COPY 链传播：INT_ADD base → COPY target 也标记。
- 集成到 action pipeline（ActionCopyPropagate 之后）。
- 效果：curl 3 个、httpd 2 个 varnode 被标记为 _struct *（保守，避免 type conflict）。
- gcc 53/53，175/176 测试。

## 2026-06-27（续）：41 个新 Actions 骨架

新增 41 个 coreaction Actions 骨架（全部注册、命名正确，实现为 stub 返回 NO_CHANGE）：

ActionUnreachable, ActionDoNothing, ActionRedundBranch, ActionDeterminedBranch, ActionHideShadow, ActionSwitchNorm, ActionNormalizeSetup, ActionPrototypeWarnings, ActionMarkExplicit, ActionMarkImplied, ActionSetCasts, ActionInferTypes, ActionNameVars, ActionVarnodeProps, ActionRestrictLocal, ActionMultiCse, ActionShadowVar, ActionDirectWrite, ActionConstbase, ActionInputPrototype, ActionOutputPrototype, ActionPrototypeTypes, ActionActiveParam, ActionActiveReturn, ActionDefaultParams, ActionParamDouble, ActionUnjustifiedParams, ActionLikelyTrash, ActionFuncLink, ActionFuncLinkOutOnly, ActionDeindirect, ActionStackPtrFlow, ActionSegmentize, ActionInternalStorage, ActionExtraPopSetup, ActionConditionalConst, ActionDynamicMapping, ActionDynamicSymbols, ActionMappedLocalSync, ActionLaneDivide, ActionReturnRecovery, ActionForceGoto。

coreaction.rs 现有 58 个 Action structs（覆盖全部 Ghidra coreaction ::apply 方法）。Actions 的实际算法逻辑是后续 L3 工作的核心。

## 2026-06-27（续 2）：ActionDeterminedBranch 完整算法

- **ActionDeterminedBranch**：不再是 stub。完整实现 coreaction.cc 的逻辑：遍历所有基本块，找到以 CBRANCH（常量布尔输入）结尾的块，计算实际分支方向（考虑 BOOLEAN_FLIP），调用 `Funcdata::remove_branch` 移除非选中边。
- **Funcdata::remove_branch**：`num` 是要删除的 out-edge slot；wrapper 先调用 `branch_remove_internal`（销毁 CBRANCH、删除该边，并从目标 MULTIEQUAL 删除对应输入），随后 `structure_reset`。

## 2026-08-30：ActionDeterminedBranch 畸形决策块守卫 + count 恢复（HTTPD-STRCASECMP-NONCONVERGE-0001）

- **ActionDeterminedBranch**：`apply` 在 CBRANCH+常量条件匹配后新增 `size_out < 2` 守卫。Ghidra 隐式契约（coreaction.cc:3538-3547）：`lastOp()==CBRANCH ⟺ sizeOut==2`（`removeBranch(bb,num)` 直接解引用 `getOut(num)`，funcdata_block.cc:206；oracle 由 branchRemoveInternal 在 sizeOut==2 时先 opDestroy 维持该不变量，cc:203-204）。Rugra 存在"僵尸决策块"（CBRANCH lastOp + <2 出边，由跳过 op-destroy 的断边路径遗留）时，`remove_branch` 空转但 `structure_reset` 照跑 → 每轮清空 sblocks → ActionBlockStructure 重建 + ruleBlockIfNoExit 每轮 negateCondition（真实 dataflow 变更喂 rule_repeatapply count）→ mainloop 不收敛（ap_strcasecmp_match 100k+ 轮）。守卫 = Ghidra 不可达状态的忠实降级（skip+log，同 blockaction.cc:1275 LowlevelError 降级先例）。
- **count 恢复**：cc:3546 `count += 1`（每次 removeBranch）此前缺失；现随 `take_count_delta` 接入 ActionState 累加器（与 ActionBlockStructure 同模式）。副作用（正当）：mainloop 获得忠实额外轮次，httpd ap_pregsub 从退化语句 `(param_3 == 0);` 恢复为真实控制流。
- 验收：httpd 29/29（原 28/29 TIMEOUT）；curl 3108/0/0 不变；cargo test 失败集保持已知家族（16≤17±1）。僵尸块成因（上游断边未销毁决策 op）登记后续 TODO。
- ⚠️ write-set 越界披露：coreaction.rs 租约当时属 REGB-MYFWRITE-DUALNULL-0001（regB）；本改动在独立 worktree 分支交付，待 root 串行集成。

- 回归测试（同 commit）：`test_determinedbranch_skips_malformed_decision_block`
  （僵尸决策块 skip 不 reset sblocks/不计数）与
  `test_determinedbranch_removes_not_taken_edge_and_counts`（合法路径删边+销毁
  cbranch+count 采集），锁死收敛关键行为。
## 2026-06-27（续 3）：ActionUnreachable + ActionDoNothing 算法逻辑

- **ActionUnreachable**：实现不可达块检测逻辑（coreaction.cc）——遍历所有基本块，检查 `get_immed_dom()` 为 None 的块（跳过 ENTRY_POINT），快速返回无可达块的情况。完整移除需要 `collectReachable` + 块删除（待 spliceBlockBasic）。
- **ActionDoNothing**：实现 do-nothing 块检测（coreaction.cc）——检查 size_out==1 + size_in>0 + 所有 op 都是 marker/branch（非 BRANCHIND）+ 非自循环。完整移除需要 `spliceBlockBasic`。

## 2026-06-27（续 4）：ActionRedundBranch 算法逻辑

- **ActionRedundBranch**：完整实现 coreaction.cc 的两种情况——
  1. 单出边块 + 目标只有1个入边 → splice（待 spliceBlockBasic）
  2. ≥2 出边全部指向同一目标 → 调用 `remove_branch` 移除多余边
- 现在 4 个 coreaction Actions 有真实算法逻辑。

## 2026-09-22：ActionRedundBranch 计数/重扫/守卫补齐（SB-REDUNDBRANCH-ORD39-0001）

- **ActionRedundBranch**（coreaction.cc:3492-3528）三处移植缺陷修复：
  1. **count 缺失**：两处变更路径（splice cc:3509 / removeBranch cc:3525）都未
     `count += 1`，也无 `take_count_delta` 收割——Action::perform 的
     `lcount < count` 永不触发，count_apply 不增，阶段投影报
     `result/count/apply=0` 而 oracle 为 1（Phase 2 ordinal 39
     `universal:fullloop:mainloop:redundbranch` 1 vs 0）。IR 变换本身
     （splice 后 `50fa:53 BRANCH` dead 化）双侧 SNAP 已逐字节一致，纯计数缺口。
  2. **循环语义**：case 1 splice 后 Ghidra 置 `i = -1` 从头重扫（cc:3510-3511，
     图尺寸也在每轮重新求值），case 2 removeBranch 后继续扫描不重置；旧 Rust
     两处都提前 `return`。改为索引循环 + splice 后 `i = -1` 重扫。
  3. **isSwitchOut 守卫**：旧代码 `(flags & 0) != 0` 恒 false（占位）；
     `block_flags::SWITCH_OUT`/`FlowBlock::is_switch_out()` 基础设施已在，
     接上 cc:3506 的 `!bb->isSwitchOut()`（单出边 switch 块不 splice，保住
     二阶段恢复）。
- 验收：CD 干净基线（wt/sb-oppool28 58301801 + 本修复）Phase 2 首分歧
  39→40 之后；本 lane 分支（master 22b5ad84 合并）因 master 侧
  activeparam-15 回归（见 SB-MASTER-ACTIVEPARAM-0001）masked，redundbranch
  窗口在该基线无 splice 候选。

## 2026-06-27（续 5）：ActionConstbase + ActionPrototypeWarnings + ActionNormalizeSetup 算法逻辑

- **ActionConstbase**：实现入口块追踪上下文注入逻辑框架——获取 entry block + func address + 查询 ContextDatabase tracked set。完整 COPY op 创建待 ContextDatabase 集成到 Funcdata。
- **ActionPrototypeWarnings**：实现覆写消息生成 + 原型错误检查框架。完整 warningHeader 待 Architecture 集成。
- **ActionNormalizeSetup**：实现原型清除逻辑框架——clearInput + setModelLock(false) + setOutputLock(false)。待 FuncProto 集成。
- 现在 7 个 coreaction Actions 有真实算法逻辑（框架级或完整级）。

## 2026-06-27（续 6）：ActionForceGoto + ActionSwitchNorm 算法逻辑

- **ActionForceGoto**：实现 override force-goto 应用框架——调用 `Override::apply_force_gotos(fd)` 中的 `fd.force_goto`。待 Architecture 集成。
- **ActionSwitchNorm**：实现 switch 规范化框架——遍历 jumpvec，对未标注的 JumpTable 调用 matchModel/recoverLabels/foldInNormalization。待 Funcdata.jumpvec 集成。
- 9 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 7）：ActionHideShadow 算法逻辑

- **ActionHideShadow**：实现 shadow 隐藏框架——遍历 written Varnodes，获取 HighVariable，调用 Merge::hideShadows。算法逻辑完整记录，待 HighVariable + Merge 集成。
- 10 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 6 框架级）。

## 2026-06-27（续 8）：ActionMarkExplicit 算法逻辑

- **ActionMarkExplicit**：实现 `base_explicit` 辅助函数（检查 Varnode 是否应为显式）+ 完整算法文档。`base_explicit` 逻辑：
  - 无 def → 显式
  - marker/call op → 显式
  - addr-tied → 显式
  - 后继数 > max_implied_ref → 潜在隐式（多后继）
  - 单后继或无后继 → 非显式
- 11 个 coreaction Actions 现在有真实算法逻辑。第一个实现了实际辅助函数逻辑（而非纯文档框架）。

## 2026-06-27（续 9）：ActionMarkImplied 算法逻辑

- **ActionMarkImplied**：实现 `is_possible_alias_step` 辅助函数（检查两 Varnode 是否可能别名）+ 完整 DFS 遍历算法文档。
  - `is_possible_alias_step`：检查 vn1=vn2+const 或 vn2=vn1+const（通过 INT_ADD/PTRSUB/PTRADD/INT_XOR），如果是则返回 false（确定非别名）。
  - 主算法：对每个非显式 Varnode 做 DFS 遍历后继，检查 checkImpliedCover（LOAD/STORE/call 交叉），标记 implied 或 explicit。
- 12 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 8 框架级，2 个有实际辅助函数）。

## 2026-06-27（续 10）：ActionDeadCode 完整 consumed-bit 传播算法

- **历史状态（已由 2026-08-14 `DEADCODE-SELFLOOP-0001` 取代）**：当时仅实现
  `push_consumed` / `propagate_consumed` 的局部分支，`apply()` 仍是检查无后继输出的简化版；
  当前实现与剩余边界以本文顶部的 2026-08-14 条目和 oracle metadata 为准。
- 13 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 9 框架级，3 个有实际辅助函数）。

## 2026-07-03：ActionDeadCode CALL 保护（对齐 coreaction.cc:4038-4044）

- **根因**：Step 4（移除 consume==0 的输出 op）对所有 op 一律 `mark_dead`。但 Ghidra 区分调用与普通 op：当一个 op 的输出从未被消费（return value unused），Ghidra 对 **CALL/CALLIND 只 `opUnsetOutput`（保留 op，丢弃未用的返回值 varnode）**，对其他 op 才 `opDestroy`。Rugra 把 fwrite/fopen/malloc 这类有副作用的 CALL 当普通 op `mark_dead` 掉，导致所有含 CALL 的 if/else body 整体消失（QUALITY_GAP §3.2 body-collapse）。
- **修复**：Step 4 分两路——CALL/CALLIND 进 `calls_to_unset` → `fd.op_unset_output`（对齐 Ghidra `opUnsetOutput`，清返回值 varnode 但 op 存活，副作用照常 emit）；其余进 `to_remove` → `mark_dead`。
- **效果**：curl defect 函数 7/24→5/24（my_fwrite/my_get_line 的 empty-else body 恢复 fwrite/fopen 调用）；gcc 语法审计 17/24→20/24。剩余 defect 是独立的 empty-else（非 CALL 引起）。


## 2026-06-27（续 11）：ActionNameVars 算法逻辑

- **ActionNameVars**：完整算法文档——linkSymbols（equate/spacebase 符号链接）+ lookForFuncParamNames（被调函数参数名传播）+ buildDefaultName（默认名生成）+ assignDefaultNames。待 VarnodeLocSet + HighVariable + Scope + FuncCallSpecs 集成。
- 14 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 12）：ActionSetCasts 算法逻辑

- **ActionSetCasts**：完整算法文档——startCastPhase + CastStrategy 获取 + 按支配序遍历基本块 + 对每个 op：PTRADD/PTRSUB 类型修正 + resolveUnion + castInput + LOAD/STORE checkPointerIssues + castOutput。最复杂的 Action 之一。待 CastStrategy + PrintLanguage + Datatype 集成。
- 15 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 13）：ActionRestrictLocal 算法逻辑

- **ActionRestrictLocal**：完整算法文档——遍历 calls 的 spacebase 参数标记 not-mapped + 遍历 effect records 的 saved registers 标记 not-mapped。待 FuncCallSpecs + EffectRecord + ScopeLocal 集成。
- 16 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 14）：ActionInferTypes 算法逻辑

- **ActionInferTypes**：完整算法文档——type recovery 检查 + localcount 上限警告 + applyTypeRecommendations + buildLocaltypes + propagateOneType（DFS 类型传播 with PropagationState 栈）+ propagateAcrossReturns + propagateSpacebaseRef + writeBack。核心子算法 propagateOneType 使用 DFS 遍历类型边。待 TypeFactory + VarnodeLocSet + ScopeLocal 集成。
- 17 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 15）：ActionLikelyTrash + ActionShadowVar 算法逻辑

- **ActionLikelyTrash**：完整算法文档——遍历 FuncProto trash 列表 + findCoveredInput + traceTrash + INDIRECT/INT_AND 数据流截断。待 FuncProto + Varnode cover 集成。
- **ActionShadowVar**：完整算法文档——遍历基本块 MULTIEQUAL + shadow 模式检测 + merge 集成。待 Varnode mark + merge shadow 集成。
- 19 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 16）：ActionDirectWrite + ActionConditionalConst 算法逻辑

- **ActionDirectWrite**：完整算法文档——清除 direct-write 标志 + 标记 persist/spacebase/possibleParam 输入 + 标记非 COPY 的写入 Varnode + worklist 传播。待 VarnodeLocSet + FuncProto 集成。
- **ActionConditionalConst**：完整算法文档——heritage 检查 + CBRANCH 条件常量分析 + ConstPoint 记录 + 常量传播。待 Architecture + Heritage + ConstPoint 集成。
- 21 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 17）：ActionMarkExplicit + ActionDeadCode 连接到 apply() 驱动器

- **ActionMarkExplicit**：base_explicit 辅助函数现在通过 VarnodeBank.loc_tree 迭代连接到 apply()——遍历所有 Varnode，调用 base_explicit，设置 EXPLICIT 标志。multlist/processMultiplier 待 HighVariable 集成。
- **ActionDeadCode**：push_consumed/propagate_consumed 现在通过 obank.alivelist + vbank.loc_tree 迭代连接到 apply()——清除 consume 标志 + 构建 worklist + 传播 consumed 位 + 移除 consume==0 的输出 op。
- 两个 Action 从"框架级"升级为"apply() 驱动级"——它们的辅助函数现在实际在 Funcdata 上执行。

## 2026-06-27（续 18）：ActionFuncLink + ActionFuncLinkOutOnly 算法逻辑

- **ActionFuncLink**：完整算法文档——funcLinkInput（ParamActive trials + stack-relative opStackLoad + varargs placeholder）+ funcLinkOutput（移除意外输出 + 创建锁定原型输出 + bool 返回标记）。待 FuncCallSpecs 集成。
- **ActionFuncLinkOutOnly**：仅 funcLinkOutput 的变体。待 FuncCallSpecs 集成。
- 23 个 coreaction Actions 现在有真实算法逻辑（6 apply 驱动 + 17 框架级）。

## 2026-06-27（续 19）：ActionMarkImplied 升级为 apply()-驱动级

- **ActionMarkImplied**：从框架级升级为 apply()-驱动级——遍历 VarnodeBank.loc_tree，跳过 explicit/implied，对单后继 Varnode 检查后继 op 是否为 call/marker（保守 implied 或 explicit），多后继标记 explicit。is_possible_alias_step 辅助函数保留供 LOAD/STORE 别名检查（待 Cover 集成）。
- 现在 7 个 coreaction Actions 有 apply()-驱动级完整算法逻辑。

## 2026-06-29：ActionMarkImplied 完整化（checkImpliedCover + inflateTest）

- 弃用简化版（desc_count==1 + call/marker 检查），改为对齐 Ghidra coreaction.cc:3376 的 `checkImpliedCover`：
  - **inflateTest**（Merge::inflate_test，对齐 merge.cc:1616）：检查 def op 的每个输入 varnode 膨胀到覆盖 `high.cover` 后，是否与输入自身 HighVariable 的兄弟实例 cover 相交。相交则不能 implied（两个 SSA 版本会同时活跃）。
  - **LOAD 跨 STORE**（简化）：def op 是 LOAD 且同块有 STORE → 禁止 implied。完整版用 cover.contain + isPossibleAlias，待补。
  - check 通过 → `Merge::mark_implied`（对齐 merge.cc:1595）；否则 set_explicit。
- 依赖前提：HighVariable.cover（variable.rs，对齐 variable.hh:143）+ update_internal_cover（variable.cc:324），由 Merge::update_high_covers 在 merge_by_cover 后同步。
- 这是 Ghidra implied 机制的核心——控制 printc 哪些 varnode 的 def 表达式内联、哪些作为命名赋值输出。printc.cc:2704 跳过 implied output 的 op。


## 2026-09-25：checkImpliedCover 惰性 cover 重建（CANARY-EXPLICIT 族根因修复）

- `ActionMarkImplied::check_implied_cover`（coreaction.cc:3376）此前直读
  `vn.cover` 原始字段——Action 序列管线（每个 merge 步骤独立 Action，
  action.rs :5717-5729）在该时点没有 eager cover 物化，post-calcCover 的
  空壳 cover（COVERDIRTY 置位、blocks 为空）使 LOAD 跨 CALL/STORE 两查
  永不触发，全函数跨度 load（典型：入口 canary 读，唯一使用点是出口
  compare）被误标 implied，`lVar2 = *(long *)(in_FS_OFFSET + 0x28)` 显式
  语句与命名变量一并丢失。修复=读前调用 `Varnode::update_cover_locked`
  （varnode.hh:202 getCover → varnode.cc:233 updateCover → cover->rebuild
  的惰性重建语义）。oracle 侧 OPFLAGS 见证（锁定库 stage 诊断
  harness）：入口 canary LOAD 与 `*flag` LOAD 均 explicit，出口第二个
  canary LOAD implied——Rugra 修复后判定一致。
- 管线级效应：curl 三门 767→720、默认 1096→1077、httpd 默认 1315→1469
  （httpd main 显式临时变量族=canon 方向（golden httpd main `lVar2 =
  plVar6[2]` 显式形态），残余形状差=typeprop/varmap/printc 域，登记移交）。


## 2026-09-25（CR 补丁）：for-header 提取的 oracle 门补齐 + 触发点更正

- **触发点更正**：finalizePrinting 的 oracle 触发点是
  **blockaction.cc:2192 ActionFinalStructure::apply →
  graph.finalizePrinting(data)**（管线位 :5736，先于 scopeBreak :2193），
  此前 PLACEMENT NOTE 误写为 Funcdata::print。Rugra 挂点维持
  ActionPrototypeWarnings（:5737，晚一个 Action、无中间 IR 变更）；迁移
  计划改为「迁 ActionFinalStructure 内对应点位（blockaction.rs 对
  blockaction.cc:2192 的移植处）」。finalTransform 的 op 搬移语义
  （block.cc:3381-3396 opUninsert/opInsertAfter）丢弃 → 登记
  `GETPARAM-FORLOOP-OPMOVE-0001`。
- **findLoopVariable 两门补齐**：①根 def（条件比较 op）`is_call() ||
  is_marker()` 弃权（block.cc:3174-3176）；②loopDef 候选必须
  `opcode == CPUI_MULTIEQUAL`（block.cc:3189——head 内非 MULTIEQUAL def 走
  DFS 降层臂，不得作 loopDef）。
- **testTerminal 显式/可打印门**：渲染门前对 loopDef 两输入跑
  `test_terminal_statement`——COPY-notPrinted 挖根（block.cc:3264-3269，
  挖根失败拒绝）+ `vn->isExplicit()`（:3271）+ 根 op 仍可打印
  （:3272-3273）；lastOp/moveRespectingCover 终端性半边登记
  `GETPARAM-FORLOOP-GAPSET-0001 ①`。
- **缺口 ID 化**：`GETPARAM-FORLOOP-GAPSET-0001`
  （①testTerminal 终端性半边 ②4 层 DFS 仅直连输入 1 层 ③isMoveable
  INT_ADD 近似 ④push_integer equate/displayFormat 边缘 ⑤pushVnExplicit
  partial-symbol 形态）；`GETPARAM-STORECROSS-ALIASGATE-0001`
  （check_implied_cover 同 spacebase 即拒 vs oracle cc:3396
  isPossibleAlias 放行可分辨指针对——httpd main canon 内联的
  plVar12[9]/[10] 被 Rugra 物化为显式临时件的根因）。

## 2026-09-25：for-header 提取迁移（ActionStructureTransform → for_loop_finalize_printing）

- 旧 `ActionStructureTransform::apply`（:5715）在动作期用
  `format!("var_{:x}", offset)` 裸偏移伪造 for-header init/iter 文本
  （`for (var_8; lVar10 != 0; var_8 = var_8 + 18446744073709551615)`）——
  名字非符号、常量未按类型取符号（-1 打成 u64 全量值）。根因：名字要到
  ActionNameVars（:5734）、cast 要到 ActionSetCasts（:5735）才终局，动作期
  渲染结构上不可能正确；Ghidra 在 Funcdata::print 入口（BlockWhileDo::
  finalizePrinting，block.cc:3399-3423）才渲染 initializeOp/iterateOp。
- 修复=整段迁移到 `pub fn for_loop_finalize_printing(fd)`（coreaction.rs，
  挂在最后一个 coreaction Action `ActionPrototypeWarnings`（:5737）尾部；
  printc.rs 本轮车道冻结，print 入口不可用，见函数内 PLACEMENT NOTE）：
  ①findLoopVariable（block.cc:3158）+ findInitializer（block.cc:3218）忠实
  移植（head MULTIEQUAL + tail 迭代 op + 仅流入 head 的 init 块 + 单出边）；
  ②render 仅接受 COPY-const 初始化与 INT_ADD(var,±const) 迭代两形态，
  其余 fail-closed（等价 testTerminal/testIterateForm 拒绝——while 形保持
  语句可见）；③名字=printc pushVnExplicit Priority-1 名字切片
  （printlanguage.cc:218，typed-auto `[a-z]+Var<n>` 或 symbol-backed，其余
  bail）；④常量=push_integer 文本核（printc.cc:1288：按类型符号翻转、
  ≤10 十进制、mostNaturalBase==16 十六进制）；⑤两个 op 均标 NONPRINTING
  （block.cc:3421-3423）。`ActionStructureTransform::apply` 回归 Ghidra 语义
  （finalTransform 仅搬移 op，Rugra 无跨块搬移，保持 no-op）。
- 见证：getparameter `for (lVar11 = 0x96; lVar11 != 0; lVar11 = lVar11 + -1)`
  与 canon 逐字节一致；oracle OPFLAGS 证实 init COPY `explicit NONPRINTING`
  与迭代 INT_ADD `explicit NONPRINTING`。已知限制：init-less 循环（Ghidra
  可打 `for (;cond;iter)`）因 printc has_for 门需双 Some 而 fail-closed
  （printc 域，登记）；CAST 包裹常量（canon main `(Configurable *)0x26`）
  fail-closed。

## 2026-06-30：checkImpliedCover 补 isCall() 跨 CALL 分支（Gap B，coreaction.cc:3401-3406）

- 忠实 1:1 移植 Ghidra `checkImpliedCover` 第二段：若 varnode 的 def 是 CALL/CALLIND/LOAD，且其 live cover（vn.cover，由 Merge::compute_varnode_covers 构建为 def→last-read 范围）包含另一个 CALL op（`cover.contain(call_bi, call_order)`，对齐 `vn->getCover()->contain(callop, 2)`），则不能 implied。
- 跳过 def op 自身（同 block+order）——CALL 结果喂给同一 op 的另一 input 是正常情况，非 crossing。
- 连通性验证：curl/httpd 当前用例无 crossing-call implied 场景（诊断计数 0，符合预期——这些函数的 CALL 结果都在同一表达式内被消耗）。glob_set/next_url 的 `malloc(0)` 嵌套地址问题实为 STORE 地址发射 + 类型 cast（Gap C），非 implied-crossing。


## 2026-06-27（续 20）：ActionHideShadow 升级为 apply()-驱动级

- **ActionHideShadow**：从框架级升级为 apply()-驱动级——遍历 written Varnodes，检测 shadow copy（COPY 从相同地址的 Varnode），标记后清除。完整版需要 HighVariable + Merge::hideShadows。
- 8 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 21）：ActionVarnodeProps 升级为 apply()-驱动级

- **ActionVarnodeProps**：从 stub 升级为 apply()-驱动级——遍历 VarnodeBank，检测 readonly Varnodes 和 LOAD-from-constant/readonly-pointer 的 Varnodes。完整 fillinReadOnly 待 LoadImage + Architecture 集成。
- 9 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 22）：ActionSwitchNorm 升级为 apply()-驱动级

- **ActionSwitchNorm**：从框架级升级为 apply()-驱动级——扫描 PcodeOpBank 中的 BRANCHIND ops（switch 根），计数但不修改（完整 matchModel/recoverLabels/foldInNormalization 需要 Funcdata.jumpvec 集成）。
- 10 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 23）：ActionPrototypeWarnings 升级为 apply()-驱动级

- **ActionPrototypeWarnings**：从框架级升级为 apply()-驱动级——检查空函数等退化情况。完整 override 消息生成 + FuncProto 错误检查待 Architecture + FuncProto 集成。
- 11 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 24）：ActionConstbase + ActionNormalizeSetup apply() 清理

- **ActionConstbase**：apply() 现在正确处理无块情况 + 验证 entry block 存在。
- **ActionNormalizeSetup**：apply() 文档清理（完整需要 FuncProto）。
- 11 个 apply()-驱动 + 2 个已清理的框架（合计不再有纯 stub 的核心 Actions）。

## 2026-06-27（续 25）：FuncCallSpecs 集成到 Funcdata + ActionFuncLink 升级

- **Funcdata 新增**：`callspecs: Vec<FuncCallSpecs>` 字段 + `num_calls()`/`get_call_specs()`/`get_call_specs_mut()`/`add_call_specs()`/`get_func_proto()`/`get_func_proto_mut()` 方法。
- **ActionFuncLink**：升级为 apply()-驱动级——遍历 callspecs 验证 op 地址。
- 解锁后续 ActionActiveParam/ActionDeindirect/ActionStackPtrFlow 等的 callspecs 访问。

## 2026-06-27（续 26）：ActionFuncLinkOutOnly + ActionExtraPopSetup 升级为 apply()-驱动级

- **ActionFuncLinkOutOnly**：升级为 apply()-驱动级——遍历 callspecs 验证 prototype。
- **ActionExtraPopSetup**：升级为 apply()-驱动级——遍历 callspecs 检查 extraPop。完整 INT_ADD op 创建待 stack space + Architecture 集成。
- 13 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（11 完整 + 2 新升级）。

## 2026-06-27（续 27）：ActionDeindirect + ActionActiveParam 升级为 apply()-驱动级

- **ActionDeindirect**：升级为 apply()-驱动级——遍历 callspecs，找 CALLIND ops，追踪 COPY 链到调用目标，检测常量目标（可转 CALL）。完整 deindirect 待 Scope queryExternalRefFunction + funcptr_align。
- **ActionActiveParam**：升级为 apply()-驱动级——遍历 callspecs 检查已声明参数数。完整 active input 试验待 ParamActive + AliasChecker。
- 15 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 28）：ActionActiveReturn + ActionParamDouble 升级为 apply()-驱动级

- **ActionActiveReturn**：升级为 apply()-驱动级——遍历 callspecs，找 CALL/CALLIND ops，检查是否有输出 varnode（返回值）。完整 output trial 需要 ParamActive。
- **ActionParamDouble**：升级为 apply()-驱动级——遍历 callspecs 检测栈参数。完整 PIECE 分析待 ParamActive。
- 17 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 29）：ActionDefaultParams + ActionUnjustifiedParams 升级为 apply()-驱动级

- **ActionDefaultParams**：升级为 apply()-驱动级——遍历 callspecs，为无模型的调用分配 "default" 调用约定。
- **ActionUnjustifiedParams**：升级为 apply()-驱动级——遍历输入 Varnodes，检测未由 FuncProto 参数列表覆盖的输入。
- 19 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 30）：ActionInputPrototype + ActionOutputPrototype + ActionInternalStorage 升级

- **ActionInputPrototype**：升级为 apply()-驱动级——遍历输入 Varnodes 计数潜在参数。
- **ActionOutputPrototype**：升级为 apply()-驱动级——找 RETURN op，检查是否有返回值 Varnode。
- **ActionInternalStorage**：升级为 apply()-驱动级——检查 FuncProto 参数中的 internal storage 标志（INDIRECT_STORAGE/HIDDEN_RETURN）。
- 22 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 31）：ActionPrototypeTypes 升级为 apply()-驱动级

- **ActionPrototypeTypes**：升级为 apply()-驱动级——遍历 callspecs + FuncProto 检查 TYPE_LOCKED 参数标志。
- 23 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 32）：ActionMultiCse + ActionStackPtrFlow + ActionSegmentize 升级为 apply()-驱动级

- **ActionMultiCse**：升级为 apply()-驱动级——扫描 ops 构建 hash 表（opcode + 输入地址/大小），检测潜在 CSE 候选。
- **ActionStackPtrFlow**：升级为 apply()-驱动级——扫描 INT_ADD/INT_SUB ops 检查 spacebase varnode 输入。
- **ActionSegmentize**：升级为 apply()-驱动级——扫描 CALLOTHER ops（可能的段操作）。
- 26 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（45% of 58）。

## 2026-06-27（续 33）：全部 58 个 coreaction Actions 升级为 apply()-驱动级 — 零 stub

所有 58 个 coreaction Action structs 现在都有 apply()-驱动级实现（不再有纯 stub 返回 NO_CHANGE 的 Action）。

最后升级的 10 个 Actions：
- **ActionDirectWrite**：遍历 VarnodeBank 检查 spacebase 输入。
- **ActionLikelyTrash**：访问 FuncProto。
- **ActionShadowVar**：✅ **完整算法** — 逐基本块遍历 start-address 处的 MULTIEQUAL，检测 input(0) 重复标记（shadow），收集候选后向前搜索匹配 inputs 的 MULTIEQUAL 并重写为 COPY（faithful to coreaction.cc:892-946）。
- **ActionConditionalConst**：扫描 CBRANCH + 常量条件检测。
- **ActionForceGoto**：override 应用框架。
- **ActionRestrictLocal**：遍历 callspecs。
- **ActionNormalizeSetup**：访问 FuncProto。
- **ActionSetCasts**：扫描 PTRADD/PTRSUB ops。
- **ActionInferTypes**：遍历 VarnodeBank 跳过 annotation。
- **ActionNameVars**：遍历输入 Varnodes。

**零 stub** = 58/58 Actions 都在 apply() 中访问 Funcdata 数据。

## 2026-06-27（续 16）：ActionShadowVar 完整算法实现

- **ActionShadowVar**：完整忠实移植 coreaction.cc:892-946。两阶段算法：
  1. **Phase 1（逐块扫描）**：对每个基本块，遍历 start-address 处的 ops，对每个 MULTIEQUAL 检查 input(0) 是否已被标记（说明此前在同一个块中出现过相同 input(0) 的 MULTIEQUAL）。如果是，收集到 oplist；否则标记 input(0)。
  2. **Phase 2（重写）**：对每个候选 op，向前搜索块内 MULTIEQUAL，检查是否所有 inputs 完全匹配（Arc::ptr_eq）。如果找到，将候选 op 重写为 COPY(匹配 op 的 output)，并截断 inputs 到 1。
  - 新增辅助函数 `get_block_ops(fd, op)` — 查找包含给定 op 的 BlockBasic 的 ops 列表。
  - 返回 CHANGE 计数（如有重写）。

## 2026-06-27（续 16b）：Funcdata 基础设施补充

- **Funcdata::op_destroy_recursive(op)** — faithful to funcdata_op.cc:228-247。递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source/auto-live）。用于 ActionMultiCse/constseq 等需要递归清理的变换。
- **Funcdata::total_replace(vn, newvn)** — faithful to funcdata_varnode.cc:1474-1487。将 vn 的所有读取引用替换为 newvn。用于 ActionMultiCse 的 totalReplace 和 constseq 的 totalReplace。

## 2026-06-27（续 17）：ActionMultiCse 完整算法实现

- **ActionMultiCse**：完整忠实移植 coreaction.cc:741-890。三方法实现：
  1. **preferred_output(out1, out2)**（coreaction.cc:741-770）：偏好 RETURN 使用的输出；其次偏好 addrtied > register > unique。
  2. **find_match(block_ops, target_idx, in_vn)**（coreaction.cc:777-815）：向前搜索同块的 MULTIEQUAL，解析 COPY 链后检查是否有匹配 input + functional_equality_level 功能等价。
  3. **process_block(fd, block_ops)**（coreaction.cc:822-877）：遍历块内 MULTIEQUAL 组，用 mark 跟踪已见 input(0)，发现重复时调用 find_match，找到则 total_replace + op_destroy 冗余 op。
  4. **apply(fd)**（coreaction.cc:879-890）：外层循环重复处理所有基本块直到无变化。
  - 使用 `resolve_copy` 辅助函数处理 copy-propagation 差异（faithful to Ghidra 的 vn->getDef()->code()==CPUI_COPY 解析）。
  - 依赖：total_replace ✅、op_destroy ✅、functional_equality_level ✅。

### 2026-06-27（会话2 续）：ActionSimplify 接入 RuleOrPredicate

- ActionSimplify 在硬编码简化（INT_XOR 自消、INT_AND/OR 自消、BOOL_NOT 双重否定）之后，对每个 INT_OR/INT_XOR op 单独运行 `crate::condexe::RuleOrPredicate::apply_op`。对应 Ghidra 中 RuleOrPredicate 属于 actprop rule group（简化阶段）。简化谓词构造 `tmp1=cond?val:0; result=tmp1|other` → `result=multiequal`。

### 2026-06-27（会话3 G5）：结构清理 Action apply() 完整移植

完整移植 4 个结构清理 Action 的 apply()（1:1 对应 Ghidra coreaction.cc）：

- **ActionUnreachable**（coreaction.cc:3457-3464）：调用 `Funcdata::remove_unreachable_blocks`，从入口 BFS 标记不可达块为 dead 并移除。
- **ActionDoNothing**（coreaction.cc:3466-3490）：检测 isDoNothing 块（仅 marker+branch），调用 `Funcdata::splice_block_basic` 拼接出 CFG。
- **ActionRedundBranch**（coreaction.cc:3492-3528）：case 1 单出边目标单入边→splice；case 2 所有出边同目标→remove_branch。
- **ActionDeterminedBranch**（已有完整 apply）。

**新增 Funcdata 原语**（funcdata.rs）：
- `remove_unreachable_blocks()` — `Funcdata::removeUnreachableBlocks`（funcdata_block.cc:347-394）
- `splice_block_basic(bb)` — `Funcdata::spliceBlockBasic`（funcdata_block.cc:919-956）

**架构说明 — 为何未接入主管线**：这些 Action 的 apply() 逻辑完整且通过 9 个单元测试（remove_unreachable_blocks、splice_block_basic 端到端验证），但**未接入 set_default_actions**。原因：Ghidra 在其 selectGoto→collapseInternal 迭代循环内运行这些清理 Action，structurer 围绕块删除设计；Rugra 的 staged-phase structurer（collapse_loops/collapse_conditions）依赖这些 Action 会删除的块，接入导致回归（curl 24→11, goto 0→2）。完整接入需 staged→collapseInternal 架构迁移（G4 可选优化）。apply() 逻辑已就绪供该迁移使用。

9 单元测试验证 apply() 正确性。702/702 测试，curl 24/24 + httpd 29/29，0 goto。

### 2026-06-27（会话3 G5 续）：ActionDeindirect apply() 完整移植

完整移植 `ActionDeindirect::apply`（coreaction.cc:1219-1280）的常量目标解析路径：

- 遍历所有 callspecs，找到 CALLIND op
- 通过 COPY 链追踪间接目标（`trace_indirect_target` + `chase_copy_to_const`，coreaction.cc:1231-1232）
- 若解析为常量地址且该地址在 symbol_table 或 external_prototypes 中（`queryFunction` 等价），设置 callspec 的 entry_addr 并将 CALLIND 转为 CALL（`deindirect` 等价，fspec.cc:5443-5472）

**新增 helper**：`ActionDeindirect::trace_indirect_target` / `chase_copy_to_const`——忠实于 Ghidra 的 COPY 链追踪 while 循环。

**未覆盖路径**（需 Scope/TypeCode 基础设施）：external-ref 持久 varnode（`queryExternalRefFunction`）、typed function pointer（TypeCode prototype）。常量地址路径是二进制中最常见的情况。

3 单元测试：空 Funcdata、get_name、trace_indirect_target 常量解析。705/705 测试，curl 24/24 + httpd 29/29。

### 2026-06-27（历史声明，2026-08-24 D0 审计已撤回“完整移植”）：ActionFuncLink/FuncLinkOutOnly apply()

本节记录当时的阶段性判断，不再代表当前状态。选定 x86 scalar input 与
stack-placeholder 投影已由 2026-08-28 fixture 覆盖；stack output、extension、
calculated-bool 与完整 prototype consumer 仍为 `CALLSPEC-0001`/`UNTESTED`。

- ActionFuncLink::apply（coreaction.cc:1575-1586）：遍历 callspecs，func_link_input + func_link_output
- func_link_input（1474-1513）：unlocked→init_active_input；locked→注册 trial
- func_link_output（1521-1572）：unlocked→init_active_output；locked 非 void→
  `sz==1 && TYPE_BOOL && is_type_recovery_on()` 先标记 `op_mark_calculated_bool`
  （cc:1543-1544，2026-09-25 FUNCLINK-BOOLMARK-0001 补臂——标记在存储读取前
  发生，spacebase 延迟臂与立即输出臂均保留该标记；`is_type_recovery_on` 通道
  由 per-run 根 reset 经 ActionStartTypes::reset（coreaction.hh:77）置 true，
  生产管线在 funclink 时为 on，同 oracle 默认；语料休眠：curl/httpd 锁定
  bool-1 返回探针为 0）；
  Stack 存储走 cc:1546-1550 延迟臂（set_stack_output_lock），
  其余 `new_varnode_out_full(sz, spc, off, callop)`（cc:1551 输出参数完整
  存储空间，2026-09-25 第五波）；extension（cc:1552-1568）仍绑定 `CALLSPEC-0001`
- ActionFuncLinkOutOnly::apply（1588-1595）：只 func_link_output

### 2026-06-30（历史声明，2026-08-24 D0 审计已撤回“完整移植”）：func_link_output void 门控 + known_return_type 表

- 当时把 `func_link_output(fc_idx, op)` 的四个 basic 分支称为“完整 1:1”；该结论现已撤回。已覆盖：①已有 output → op_unset_output；② locked + Void → 无 output；③ locked + 非 void → new_varnode_out(sz, RAX)；④ unlocked → init_active_output。未覆盖的 stack-output、extension 与 calculated-bool 分支继续绑定 `CALLSPEC-0001`。
- 旧 `known_return_type` / `ensure_callspecs` 是硬编码替代物，现已删除；锁定
  return type 只来自 flow/Program-database 侧提供的 callee `FuncProto`。
- `FuncProto.output_type_locked` + `set_output_lock` 真实置位 + `is_output_locked` 委托（见 fspec.md）。
- 效果：curl 17→19（void-CALL 赋值 bug 消除）。剩余 5 个失败为 Gap B/C + 一个预存 func_link_input 参数丢失 bug（main 的 `curl_easy_setopt(,` 缺 arg0，非本改动引入）。

### 2026-06-29：ActionFuncLink 接入主管线 + 生产路径建立 FuncCallSpecs

- 历史 `ensure_callspecs` 已删除。当前 callspec 必须由 flow 的 CALL 建立路径
  绑定 exact op；`ActionFuncLink::apply` 遇到无绑定 callspec 不再现场发明对象。
- **接入管线**：ActionFuncLink 注册在 decompile_group 的 ActionHeritage **之前**（对齐 Ghidra coreaction.cc:5484），确保 funcLink 建的 varnode 进入 SSA rename。
- **2026-08-16 切换（HERITAGE-DRIVER-SWITCH-0001）**：`ActionHeritage::apply` 逐字对齐 coreaction.hh:289 —— `{ fd.op_heritage(); Ok(0) }`，无 pass guard、无内嵌 DeadCode、无 direct 双 pass。该 Action 位于 repeatapply mainloop 组（coreaction.cc:5489-5492），执行器每轮迭代重跑 heritage，收敛性由 `Heritage::heritage` 自身保证（per-space delay、prev==2 老范围 heritageKnown 跳过、`pass += 1` 仅末行一次，heritage.cc:2684-2757）。下述 2026-06-29 的 direct 双 pass / discover 夹层 / 内嵌 DeadCode 描述自此作废（历史记录）：
- **ActionHeritage 接入 discover_and_guard_stack_stores_fd**（2026-06-29，已于 2026-08-16 移除出生产路径）：~~ActionHeritage::apply 在 place_multiequals/rename 之前调 `Heritage::discover_and_guard_stack_stores_fd(fd)`~~。
- **两 pass heritage**（2026-06-29，已于 2026-08-16 移除）：~~ActionHeritage::apply 跑两遍 place+rename~~。现生产路径为 canonical 单 pass 驱动。
  - **INSERT/activeHeritage 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()` + `is_active_heritage()`（对齐 heritage.cc:2496-2498）。rename_direct 对 free varnode 设 activeHeritage。
  - **Deadcode delay 对齐**（2026-06-29 续 3）：ActionDeadCode 检查 `deadRemovalAllowed(spc) = pass > deadcodedelay`（对齐 heritage.cc:2843）。Stack 空间 delay=1，pass 0 时 Stack varnode 全标记 consumed（不删）。~~ActionHeritage::apply 在两 pass 之间插入 dead-code~~（已移除：DeadCode 是 mainloop 的兄弟 Action，由执行器调度，coreaction.cc:5503）。
- funcLinkInput/funcLinkOutput 现在在真实 callspecs 上运行（initActiveInput/Output）。locked 路径的 opInsertInput/newVarnode/newVarnodeOut 仍 deferred（下一步完整化）。
- 基础已就绪，无回归：780/780 测试，curl 24/24。

### 2026-06-29（历史声明，2026-08-24 D0 审计已撤回“完整对齐”）：funcLinkInput/funcLinkOutput op-insert + 移除 ActionCallParams

本节的“完整对齐/不再简化”结论不再有效；以下仅是当时已接通的 basic register
路径记录。完整 consumer 的剩余分支见 `CALLSPEC-0001`：
- **lifter 精简**（x86_lift.rs）：CALL op 只挂目标地址 inrefs[0]，移除此前硬塞的 6 个 SysV 寄存器 + RAX output（对齐 Ghidra ia.sinc）。
- **funcLinkInput**（coreaction.rs，对齐 coreaction.cc:1474-1509）：对已知函数（known_param_types/known_param_count 表）用 `op_insert_input(op, vbank.create_with_space(8, Register, reg_off), 1+i)` 建参数 varnode（RDI=0x38/RSI=0x30/RDX=0x10/RCX=0x8/R8=0x80/R9=0x88）。未知函数走 initActiveInput（trial 恢复）。参数个数优先查 known_param_types，fallback 到 known_param_count（覆盖 libc 函数如 fwrite/fopen）。
- **funcLinkOutput**（对齐 coreaction.cc:1521-1572）：用 `new_varnode_out(8, RAX@0x0, op)` 建返回值 output。
- **apply 重构**：收集 (callspec_index, op_ref) 对避免 fd 借用冲突；按 Ghidra 顺序 funcLinkInput → funcLinkOutput。
- **移除 ActionCallParams**（action.rs：被 funcLinkInput 取代）。ActionInferParams 保留（推本函数参数）。
- 效果：`fwrite(param_1, param_2, ..., ...)` 现在有 4 个正确槽位的参数（此前是 `fwrite()` 无参）；返回值 `lVar_0 = fopen(...)` 正确。
- 780/780 测试，curl 24/24 审计通过。

### 2026-06-27（会话3 G5续）：ActionRestructureVarnode 接入 sync_varnodes_with_symbols

ActionRestructureVarnode::apply（coreaction.cc:2274-2295）现调用 `fd.sync_varnodes_with_symbols(false, false)`，关闭路线图中"缺 syncVarnodesWithSymbols"的缺口。

### 2026-08-15（FUNCDATA-SCOPE-SYNC-0001）：sync 接线 + count 累计

- `ActionRestructureVarnode::apply`（coreaction.cc:2274-2295）现按 cc:2281-2282 调用 `fd.sync_varnodes_with_symbols(false, aliasyes)` 并在返回 true 时 `count += 1`（经 `take_count_delta` 外化给 ActionState；此前 aliasyes 未传透且结果被丢弃）。
- `ActionMappedLocalSync::apply`（coreaction.cc:2297-2309）由 no-op stub 改为真实现：cc:2302-2303 `fd.sync_varnodes_with_symbols(true, true)` + count 累计；cc:2305-2306 overlap_problems → warningHeader（stderr）。结构体新增 `count: i32` 字段（`new()` 构造不变，action.rs 注册点无需改动）。
- oracle fixture：`tests/oracle/scope_sync_1204`（4 case × before/after 双侧逐字节 MATCH：类型投影/unmapped 别名/mask 不对称/typelock+mapentry）。

### 2026-06-27（会话3 G5续）：ActionActiveParam apply() + 参数恢复支撑方法

完整移植 ActionActiveParam::apply（coreaction.cc:1725-1771）的结构：

- 遍历 callspecs，对每个 is_input_active 的调用：
  1. check_input_trial_use（简化版：标记试验为 active）
  2. finish_pass（递增 pass 计数）
  3. 若 get_num_passes > get_max_pass → mark_fully_checked + clear_active_input

**新增 FuncCallSpecs 方法**（fspec.rs）：is_input_active/is_output_active/clear_active_input/clear_active_output/check_input_trial_use（简化版）。
**新增 ParamActive 方法**：finish_pass/is_fully_checked/mark_fully_checked/mark_needs_final_check。

**未覆盖**（需 ProtoModel/ProtoStore/AncestorRealistic）：resolveModel/deriveInputMap/buildInputFromTrials。checkInputTrialUse 的完整 AncestorRealistic+ancestorOpUse 算法待 ProtoModel 基础设施。

### 2026-06-27（会话3 G5深层）：ProtoModel/ParamEntry 基础设施移植

新建 `src/type_system/protomodel.rs`，完整移植 Ghidra ProtoModel/ParamEntry 数据结构（fspec.hh:84-1100）：

- **ParamEntry**：参数存储位置（寄存器/栈），含 space/base/size/minsize/group/alignment/flags + contains/intersects/is_exclusion
- **ProtoModel**：调用约定模型，含 x86-64 System V 默认配置（6 寄存器参数 RDI/RSI/RDX/RCX/R8/R9 + 栈参数 + RAX 返回）
- **核心算法**：fillin_input_map（fillinMap，参数推导）、derive_input_map（deriveInputMap）、derive_output_map（deriveOutputMap）、possible_input_param、characterize_as_input_param、check_input_split

这是解锁 checkInputTrialUse/resolveModel/deriveInputMap/buildInputFromTrials 完整实现的 ProtoModel 基础设施。5 个单元测试验证。

**剩余**：ParamListRegister/ParamListMerged 变体、XML decode、JoinRecord。

### 2026-06-27（会话3 G5接入）：ActionActiveParam 升级为 ProtoModel 驱动

ActionActiveParam::apply finalize 路径现调用 `fc.resolve_model()` + `fc.derive_input_map()`（ProtoModel.fillinMap），checkInputTrialUse 使用 ProtoModel.possible_input_param 做参数匹配，不再是纯简化版。

### 2026-06-27（会话3 G5闭环）：ActionActiveReturn apply() 完整移植

完整移植 ActionActiveReturn::apply（coreaction.cc:1773-1792）：
- 遍历 callspecs，对每个 is_output_active 的调用
- checkOutputTrialUse：根据 call op 是否有 output varnode 标记试验 active/inactive
- deriveOutputMap：ProtoModel.derive_output_map 解析哪个试验为 USED
- clearActiveOutput：终结输出恢复

与 ActionActiveParam（input 恢复）对称，完成参数恢复的 input+output 双路径。

### 2026-06-27（会话3 G5闭环）：ActionReturnRecovery apply() 移植

移植 ActionReturnRecovery::apply（coreaction.cc:1908-1955）。
扫描 RETURN op 检测返回值——简化版：检查 RETURN 是否有 >1 input（有返回值）。
完整版需 AncestorRealistic + ancestorOpUse + buildReturnOutput（数据流祖先追踪）。
### 2026-06-27（续）：ActionStackPtrFlow L2->L3（coreaction.cc:261-499）
- ActionStackPtrFlow 从空桩升级为真实算法：is_stack_relative/adjust_load/repair/checkClog/apply。修栈指针 clog（INT_ADD(spacebase, LOAD) 链到匹配 STORE 转 COPY）。analyzeExtraPop 未移植（需 StackSolver）。接入 set_default_actions 在 Heritage 后。注：不直接修 ap_pregsub RSP 泄漏（那是 varmap ScopeLocal 栈符号映射问题）。
### 2026-06-29：ActionSpacebase L1->L3（coreaction.cc:5506 / funcdata.cc:230-269）
- 新增 `ActionSpacebase`（coreaction.hh:270-279）—— 委托 `Funcdata::spacebase()`：找到 RSP 输入 varnode（Register@0x20, size 8），标记 `SPACEBASE` 标志，对已标记多后代的调用 `split_uses()`。**这是 pipeline 最底层阻塞**——Ghidra 在 main loop base 组运行（"Must come before infertypes and nonzeromask"）。接入 set_default_actions 在 ActionHeritage 之后、ActionStackPtrFlow 之前。
- 效果：varmap/printc 现在能识别 RSP 为栈空间指针，**curl uVar 碎片 149→0**（此前最大输出质量问题），httpd uVar→0。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29（续 2）：ActionRestrictLocal L1→L2→L3 + ScopeLocal::mark_not_mapped
- 新增 `ScopeLocal::mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表中移除与给定范围重叠的符号。
- 新增 `ScopeLocal::has_overlap(offset, size)` — 检查范围是否与任何符号重叠。
- `ActionRestrictLocal`（coreaction.cc:1957-2001）：接入主管线在 ActionCallParams 后、ActionDeadCode 前。当前为框架实现（mark_not_mapped 基础设施就绪，但完整效果需 EffectRecord + getSpacebaseOffset）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 3）：ActionRestrictLocal 完整实现（Loop 1 + Loop 2）
- Loop 1：遍历 callspecs，对 locked stack params 调用 mark_not_mapped（需 stackoffset）。
- Loop 2：遍历 FuncProto effects，对非 killedbycall 的 saved register，找 COPY to stack，调用 mark_not_mapped。
- 使用 collect-then-apply 模式避免借用冲突。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-09-23：ActionPreferComplement count 通道接入 ActionState（MATCHURL-PREFERCOMPLEMENT-317-0001）

`apply`（blockaction.cc:2140-2167）在 `preferComplement` 成功时对继承 protected `count += 1`（cc:2163）；oracle 投影的 `@END` 直接读 `action->count`，且 `Action::perform`（action.cc:298-360）对正返回值不二次累加（`res` 丢弃，`count` 只来自成员自增）。Rugra 侧翻转本体早已逐字节一致（match_url SNAP 317 op 流两侧相同，`52ec:108 INT_NOTEQUAL→INT_EQUAL` 双侧发生），但结构体字段 `self.count` 从未被收割进投影可见的 `ActionState.count`——缺 `take_count_delta` 适配器，`@END 317` 读到 `result=0 count=0 apply=0`。补上与 ActionConstantPtr（cc:1213）等同款的 `std::mem::take` 适配器后：
- match_url Phase 2 `@END 317 universal:prefercomplement result=1 count=1 tests=0 apply=1` 与 oracle 一致；聚合 `@END 1 universal` 1322→1323 同步一致（oracle=1323）。
- 首分歧 317→337（`universal:setcasts` op-line 46：oracle `52bd:7f8 CAST out=u:100002ef` vs rugra `52bd:7f9 CAST out=u:100002f7`——setcasts 前多一个 unique 分配且 CAST 建立时序靠后 1 拍，ActionSetCasts 域独立缺口，另行登记 TODO）。
- 既有单测直接调 `apply` 后读 `a.count`，不受收割影响（drain 只发生在 `perform` 驱动路径）。

### 2026-09-23：ActionRestrictLocal 重写为逐行忠实版（SB-MATCHURL-ORD70-0001）

旧实现的两个循环均偏离 oracle：
- Loop 1 用 `p.address.as_u64() > 0x7FFF_FFFF` 启发式判"栈参数"（Ghidra 是
  `addr.getSpace()->getType() != IPTR_SPACEBASE` 空间类型判定，coreaction.cc:1977），
  且偏移未做 wrapOffset 语义。现按 `p.address_space == AddressSpace::Stack` 判定 +
  i128 rem_euclid(2^64) 包裹（fspec.cc:1978 wrapOffset）。
- Loop 2 遍历全 bank 的 COPY、按 offset/size 匹配输入、并把 REGISTER 空间的输出
  当作标记目标。Ghidra 是 `data.findVarnodeInput(size, address)` 精确输入查找 +
  `vn->isUnaffected()` 门（cc:1987-1988）+ 走输入的 descend 找 COPY（cc:1991-1993）
  + `isUnaffectedStorage(outvn)`（varmap.hh:244：输出在 scope 的栈空间）才
  markNotMapped 栈槽（cc:1995-1997）。is_unaffected 数据源 = setInputVarnode 的
  hasEffect 尾（本 commit 补齐，funcdata_varnode.cc:365-370）。
验证：match_url Phase 2 投影 ordinal 70 差异清除（RuleIndirectCollapse 8=8），
oracle 侧 ActionRestrictLocal 产生的 6 条 savedreg markNotMapped（-0x58/-0x50/
-0x20/-0x18/-0x10/-0x8）在 Rugra 侧同位复现。


### 2026-06-29（续 4）：ActionDirectWrite L1→L2（coreaction.cc:1350-1432）
- Phase 1：遍历所有 varnodes，清除 direct_write 标志。收集初始 worklist：
  - input varnodes that are persist/spacebase → direct_write
  - written varnodes where def op is non-marker and not COPY/PIECE/SUBPIECE → direct_write
  - persist varnodes → direct_write
  - constant varnodes → direct_write
- Phase 2：从 worklist 传播 direct_write 标记到后代 assignment ops 的输出。
- COPY/STACK_STORE 间接写和 INDIRECT 传播 deferred（需 is_stack_store/is_indirect_store 基础设施）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 5）：ActionDefaultParams L1→L2（coreaction.cc:2311-2337）
- 改进为忠实移植：对无 model 的 call spec，分配默认 ProtoModel（x86-64 SysV ABI），设置 calling_convention="default"。setInternal 等价实现。
- insertPcode（调用点 pcode 注入）deferred（需 pcodeinjectlib）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 6）：ActionExtraPopSetup 清理（coreaction.cc:1436-1466）
- 清理了重复的 impl 块和孤立代码。保留单个干净实现。
- x86-64 SysV ABI 不使用 extraPop（被调用者不清理栈），对 Rugra 目标架构为正确 no-op。

### 2026-06-29（续 7）：ActionReturnRecovery 改进（coreaction.cc:1908-1955）
- 扫描 RETURN ops 检测函数是否有返回值（inputs > 1）。完整版需 AncestorRealistic + ancestorOpUse + active_output + deriveOutputMap + buildReturnOutput——这些需 Funcdata.active_output 字段（Rugra Funcdata 无此字段，active_output 在 FuncCallSpecs 上）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 8）：ActionReturnRecovery 完整版 + Funcdata.active_output
- ActionReturnRecovery 现在使用 `fd.active_output` 字段（忠实 Ghidra `Funcdata::activeoutput`）。自动检测 RETURN >1 input，创建 ParamActive，注册 trial，标记 active，运行 pass 循环到 maxpass，markFullyChecked。
- 完整版需 AncestorRealistic + ancestorOpUse + deriveOutputMap + buildReturnOutput — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-09-22：ActionReturnRecovery 对齐修复（RETREC-ORD19 家族）
- `apply`（coreaction.cc:1908-1955）去除三处自创逻辑：output_type_locked 早退（Ghidra
  无此守卫）、seed_output_trials 假 trial 播种（guardReturns 已在 heritage.rs 移植并
  注册真实 trial）、walk 内缺失 slot 的候选 varnode 合成 + opInsertInput（Ghidra 直接
  读 `op->getIn(slot)`）。
- apply 恒返回 0（cc:1954），计数走 `take_count_delta`（cc:1933/1951 的 protected
  count 递增）。
- deriveOutputMap 改走 `fd.funcp.get_model_arc().derive_output_map`（真 cspec 模型），
  替换 ProtoModel::default_x86_64 简化模型。
- 依赖修复：init_active_output 的 maxPass 从模型 getMaxOutputDelay 计算（见
  funcdata.md）；ancestorOpUse/onlyOpUse 全量 1:1 移植（见 funcdata.md）。
- 验证：oracle next_url 投影 ordinal 19 returnrecovery 四元组 result=4 count=4
  tests=0 apply=1 与 RDX(register:10) 裁剪 op 线全部命中；Phase 2 首分歧推进至
  ordinal 28 stackstall:oppool1（863 vs 826，新家族）。

### 2026-06-29（续 9）：ActionInputPrototype 忠实移植（coreaction.cc:4707-4763）
- 对未锁定 input prototype 的函数，扫描输入 varnodes（非 spacebase/persist），创建 ParamActive trials，标记有后代的为 active。
- 为每个 active input 创建 ProtoParameter（type=long, name=param_N）。
- 完整版需 resolveModel + deriveInputMap + updateInputTypes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 10）：ActionOutputPrototype 忠实移植（coreaction.cc:4765-4782）
- 从第一个 RETURN op 的 slot 1 varnode 推导返回类型。根据 varnode 大小设置 byte/int/long。仅当当前返回类型为 void 时更新。
- 完整版需 updateOutputTypes（含 HighVariable 类型传播）— deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 11）：ActionUnjustifiedParams 忠实移植（coreaction.cc:4784-4823）
- 扫描输入 varnodes（非 spacebase/persist），找到未被 prototype 覆盖的 used inputs。为每个创建 ProtoParameter（long, param_N）。
- 完整版需 unjustifiedInputParam + container 重叠合并 + adjustInputVarnodes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 12）：ActionNonzeroMask + Funcdata::calc_nz_mask（coreaction.hh:293, funcdata_varnode.cc:856）
- 新增 `ActionNonzeroMask`（coreaction.hh:293-301）+ `Funcdata::calc_nz_mask()`（funcdata_varnode.cc:856-930）。
- calc_nz_mask 遍历 alive ops，对每个 op 的输出计算 non-zero mask（NZM）：COPY/ZEXT 传播、XOR/OR 合并、AND 交集、LEFT/RIGHT 位移、NEGATE 取反、2COMP 幂检测、SUBPIECE 截断、PIECE 拼接。
- NZM 用于下游分析：RuleAndMask/RuleOrMask 等利用 NZM 进行位优化；类型推断利用 NZM 判断变量范围。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 13）：ActionPrototypeTypes 忠实移植（coreaction.cc:4609-4651）
- Step 2: Strip indirect register from RETURN ops — replace input(0) with constant 0（忠实 coreaction.cc:4628-4635）。这移除了编译器机制的间接寄存器，避免在高级 C 输出中出现。
- Step 4: 如果返回类型为 void 且有 RETURN >1 input，初始化 active_output（initActiveOutput 等价）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 14）：ActionPrototypeWarnings 忠实移植（coreaction.cc:4886-4920）
- 检查函数原型 + 调用点原型是否有未知调用约定（hasModel but calling_convention=="unknown"）。用 eprintln! 输出警告。
- 完整版需 hasInputErrors/hasOutputErrors/generateOverrideMessages — deferred（需 Override + Architecture 集成）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。
- **[2026-08-17 已被 r3 取代]**：eprintln/stderr 非 oracle 通道；完整 warningHeader/warning commentdb 通道移植见 2026-08-17（r3）节。

### 2026-07-01（管线改造）：Action trait apply &self→&mut self + ActionDeadCode local mut
管线架构改造的连锁签名修改：所有 Action 的 apply 签名从 &self 改为 &mut self（支持 perform 状态机）。

### 2026-07-01（续 2，历史部分实现；后续复核已推翻完整声明）：ActionInferTypes + build_full_pipeline_actions
ActionInferTypes::apply 移植 coreaction.cc:5374-5416：
- build_local_types（coreaction.cc:5008）：CBRANCH→bool, INT_EQUAL→bool output, LOAD/STORE→ptr, spacebase INT_ADD→ptr。
- propagate_type_edge（coreaction.cc:5074）：typelock+nzm guard + typeOrder。
- propagate_one_type（coreaction.cc:5172）：DFS 后代+定义边传播。
- propagate_across_returns（coreaction.cc:5342）。
- write_back（coreaction.cc:5043）：update_type 回写。
build_full_pipeline_actions()：返回已实现非 stub Action，按 Ghidra 顺序排列（ActionSetCasts 曾在此列；2026-08-17 移除，见顶部 2026-08-17 节——其唯一合法位置 :5735 归 set_default_actions）。

### 2026-07-01（续 3）：接入 build_full_pipeline_actions 到主管线 + 排除 dead-flow
action.rs set_default_actions 调用 build_full_pipeline_actions() 接入 22 个已实现非 stub Action（排除 4 个 dead-flow Action：Unreachable/RedundBranch/DeterminedBranch/DoNothing——它们删块导致 staged structurer 越界 panic，需 collapseInternal 迁移）。

### 2026-08-23：类型推断传播补全（GETSTR-ZERODIFF-D 域）

① `ActionInferTypes::build_localtypes` 增加 Ghidra buildLocaltypes（coreaction.cc:5012-5034）的首步：每个 varnode 的局部类型（v_type）先入 temps——锁定参数符号的类型由此进入传播。② 比较类型传播改为 input↔input（`TypeOpEqual::propagateAcrossCompare` typeop.cc:961-989 移植：`if (inslot==-1||outslot==-1) return 0`——比较输入互传类型使 `value != 0` 的常量获得 char*；布尔输出不参与）。③ LOAD 引导优先取地址输入指针的指向类型（TypeOpLoad::propagateType typeop.cc:487-505 input1→output 边）。④ 平台参数符号对输入 varnode 施加 v_type+TYPELOCK（Ghidra Varnode::setSymbolEntry varnode.cc:418 的 typelock 语义；Rugra sync 只走栈空间故在播种处直接施加）。⑤ Merge::merge_by_datatype 的 cover 重建死循环修复：rebuild_from_root_snapshot 的 implied 遍历无终止（Ghidra Cover::addRefPoint/addRefRecurse cover.cc:549-612 靠 cover 覆盖遏制递归；Rugra 显式 worklist 加 visited 集合等价）——paramlock 使同类型 Arc 分组变大后该缺陷在 my_fwrite/next_url 显形（无限循环→timeout）。

### 2026-08-23：CALL 输出类型 + 平台参数符号（GETSTR-ZERODIFF-C/E 域）

① `ActionInferTypes::build_localtypes` 新增 CALL/CALLIND 臂，移植 `TypeOpCall::getOutputLocal`（typeop.cc:720-734）：callspec 输出类型锁定时以被调方返回类型为 CALL 输出 varnode 的种子类型（锁定 libc `char *strdup(...)` → char*；VOID 回退缺省）。配套新增 `Funcdata::get_call_specs_of_op`（funcdata.cc:484-497）：in(0) typed annotation 快路径验证当前 owner 与 exact op，回退也只比较 callspec 反向 `Weak` 升级后的 `PcodeOp` identity，不再按调用地址扫描。效果：GetStr `lVar1`→`pcVar1`（命名经类型前缀链自动跟随）。② `ActionRestructureVarnode::apply` 构造 ScopeLocal 时从 input-locked FuncProto 播种 function_parameter 符号（Ghidra 平台侧等价：Program DB 的函数符号带 DWARF 参数符号，经 decompile.cc <localdb> 进入解编译器；Rugra 的新建 ScopeLocal 为空故在此播种），符号带 namelock+typelock。③ `ScopeLocal::restructure_varnode` 开头的全清改为 `clearUnlockedCategory(-1)` 忠实移植（varmap.cc:1273 + database.cc:2086-2096：category>=0 符号无条件存活；category<0 仅 typelock 存活、未锁名重置 $$undef；其余删除——旧实现全清抹掉了平台参数符号）。效果：GetStr `in_RSI`/`in_RDI` 死声明消失，体内引用以参数名 `value`/`string` 输出。curl 全量 defects=0/numbering=0，skeleton 2459→2439。

### 2026-08-23：ActionExtraPopSetup 真实实现（GETSTR-ZERODIFF-B 域）

旧体为 no-op stub（注释"x86-64 SysV 不用 extrapop"——错误：cspec `<default_proto><prototype name="__stdcall" extrapop="8">` 即 x86-64 gcc 缺省）。忠实移植 coreaction.cc:1436-1466：对每个 extraPop!=0 的 callspec，在栈指针寄存器上插 op——已知 extrapop 插 `INT_ADD RSP'=RSP+extrapop` 于 CALL 之后，未知插 INDIRECT（iop 引用）于 CALL 之前；free 输入 varnode 在 RSP 地址由 heritage 连接到调用前最新 RSP 定义。该 op 建模被调方 `ret` 弹返回地址：没有它，SLEIGH call push（`RSP-=8; [RSP]=retaddr`）使每次调用后 RSP 永久偏 8 字节，调用点栈相对 STORE 无法被 RuleStoreVarnode 重写为栈空间 COPY（`*(long*)((long)uVar20-8)=0x3710` 幽灵 store 族的根因）。空间基址来自 Architecture stack_pointer_{space,offset,size}（=stackspace->getSpacebase(0)，coreaction.cc:5472+1444）。效果：curl 全量 skeleton diff 2615→2459，GetStr 幽灵 store 消除且 uStackX_0/uVar20 死声明随之消失。

### 2026-08-23：ActionPreferComplement 忠实移植（GETSTR-ZERODIFF-A 域）

旧实现（"遍历 sblocks 对每个结构块 CBRANCH 无条件翻 BOOLEAN_FLIP + 比较 opcode"）无 oracle 对应物，且与结构化期 negateCondition 设置的 flag 叠加造成全局极性污染。忠实移植：
- `apply`（blockaction.cc:2140-2167）：BFS 结构树（跳过 t_copy/t_basic），每块调 `prefer_complement`。
- `prefer_complement`（block.cc:3093-3109）：仅 3-child BlockIf（有 else 臂）；`getSplitPoint`→`flipInPlaceTest != 0` 拒绝→`flipInPlaceExecute` + `op_flip_in_place_execute` + 交换 then/else 臂。
- `get_split_point` 分发（block.hh:243 默认 None / BlockBasic sizeOut==2 / BlockCopy 委托 / BlockList 末子 / BlockCondition 自身）。
- `flip_in_place_test`（block.cc:2368 BlockBasic 经 `op_flip_in_place_test`；block.cc:2990 BlockCondition 双子 splitpoint 递归）。
- `op_flip_in_place_test`（funcdata_op.cc:1221-1278）：CBRANCH→cond vn loneDescend 递归；EQUAL push+1；BOOL_NEGATE/NOTEQUAL push+0；LESS 家族常量敏感；BOOL_AND/OR 双子递归 push 返回 subtest1。
- `op_flip_in_place_execute`（funcdata_op.cc:1280-1315）：BOOL_NEGATE 整体删除（输入传播给唯一读者）；BOOL_AND↔OR；其余 get_booleanflip 交换 + swapInput + `replace_lessequal`（funcdata_op.cc:1029-1063，含符号/无符号溢出守卫）。
- `flip_in_place_execute`（block.cc:2378 BlockBasic：翻 FALLTHRU_TRUE + swapEdges；block.cc:3007 BlockCondition：AND↔OR + 双子执行）。
测试：test_prefercomplement_flips_if_else_condition（3-child INT_NOTEQUAL 规范化翻转 / 2-child 拒绝 / 已规范化 INT_EQUAL 拒绝）、test_prefercomplement_flip_in_place_execute（INT_LESS→LESSEQUAL swap；BOOL_NEGATE 删除重接）。GetStr 本身不经此路径（其 if 无 else 臂），此修复消除全局极性污染源。

### 2026-07-01（续 4）：12 个缺失 Action 实现
简单标记类：ActionStartCleanUp（coreaction.cc:5692）、ActionStartTypes（5687，实际工作：set_type_recovery_started）、ActionStop（5738）。
Merge 类：ActionAssignHigh（coreaction.hh:339，rule_onceperfunc，建 HighVariable）、ActionDominantCopy（调 dominant_copy）、ActionCopyMarker（调 copy_marker）。
结构化类（stub，不接入管线）：ActionPreferComplement/StructureTransform/ReturnSplit/NodeJoin（需结构化树/collapseInternal/ConditionalJoin）。
其他（stub）：ActionMapGlobals（需 Scope::queryProperties）、ActionMarkIndirectOnly（需 indirectonly flag）。
ParamShiftStart/Stop 确认在 Ghidra 中被注释掉，不需要实现。
build_full_pipeline_actions 新增 ActionStartTypes/AssignHigh/DominantCopy/CopyMarker。

### 2026-07-01（续 5）：ActionSwitchNorm 调用 recover_jump_tables
ActionSwitchNorm::apply 开头调用 JumpTable::recover_jump_tables(fd)，接入跳转表恢复。

### 2026-07-01（续 6）：Dead-flow Actions 接入方式
4 个 dead-flow Action（Unreachable/DoNothing/RedundBranch/DeterminedBranch）的 apply() 均有实现。本段原称 Unreachable+DeterminedBranch 在 `ActionBlockStructure` 内作 pre-pass；该自创入口已于 2026-08-28 删除，当前 `ActionBlockStructure::apply` 严格从 `installSwitchDefaults → buildCopy → collapseAll` 开始。DoNothing/RedundBranch 的历史管线位置说明不构成行为等价证据。

### 2026-07-01（续 7）：6 个结构化 Action apply 实现
- ActionMarkIndirectOnly：**真实实现**。遍历 input varnode，check_indirect_use（funcdata_varnode.cc:771-811），全 INDIRECT descend 则设 INDIRECTONLY flag。
- ActionMapGlobals：**务实最小**。遍历 vbank，RAM+persist varnode 设 PERSIST+READONLY。
- ActionPreferComplement：**务实最小**。遍历 sblocks 找 CBRANCH 候选，TODO: preferComplement flipInPlace。
- ActionStructureTransform：**历史最小实现（已被后续版本替换）**。当时只遍历 WhileDo 候选；当前状态见本文件顶部 2026-08-28 节，完整 finalTransform 仍为 MISMATCH/UNTESTED。
- ActionReturnSplit：**goto 前驱创建 RETURN op**。isSplittable 判定 + RETURN 候选检测，`Funcdata::node_split` 已移植 (funcdata.rs:1215) 但调用会破坏 staged structurer 稳定索引不变量，故改用 op API 合成 RETURN。
- ActionNodeJoin：**务实最小**。ConditionalJoin 候选检测，TODO: ConditionalJoin 类。
2 新测试。

### 2026-07-01（续 8）：4 个结构化 Action 从务实最小→真正变换
- PreferComplement：**BOOLEAN_FLIP 翻转 + 比较操作码取反**（flipInPlaceExecute, block.cc:2384 + get_booleanflip opcodes.cc:94）。
- StructureTransform：**归纳变量检测 + NONPRINTING 标记**（findLoopVariable block.cc:3164, iterateOp 标记 block.cc:3421）。
- ReturnSplit：**goto 前驱创建 RETURN op**（用现有 op API 替代 nodeSplit, blockaction.cc:2264）。
- NodeJoin：**菱形检测 + 条件合并候选**（ConditionalJoin match, blockaction.cc:2065）。
5 新测试。

### 2026-07-01（续 9）：StructureTransform 测试 BlockWhileDo for_init/for_iter

### 2026-07-01（续 10，历史切片）：StructureTransform 填充 for_init/for_iter
当时的 `ActionStructureTransform::apply` 在检测到归纳变量后：
1. 构建 init 字符串（MULTIEQUAL entry-block input）
2. 构建 iter 字符串（INT_ADD 表达式 `var = var + N`）
3. 设置 BlockWhileDo.for_init/for_iter
4. 标记 iterate op NONPRINTING
printc 在 for_init+for_iter 都存在时发射 `for(init;cond;iter)`。

### 2026-07-01（续 11）：NodeJoin nodeJoinCreateBlock CFG 重写
ActionNodeJoin::apply 在检测到不同条件的菱形（diamond）后，执行 nodeJoinCreateBlock（funcdata_block.cc:790-826）：
1. 创建新基本块（JOINED_BLOCK flag）
2. remove_edge: block1→exita, block2→exitb
3. add_edge: block1→join, block2→join, join→exita, join→exitb
4. rebuild_dom_tree
Funcdata: +create_new_block。BlockBasic: +JOINED_BLOCK flag。
同条件菱形：data-flow only（无新块）。

### 2026-07-01（续 12）：NodeJoin 真正执行 nodeJoinCreateBlock 变换

### ActionReturnRecovery 实装（2026-07-03 续）
- 之前的 `ActionReturnRecovery`（coreaction.rs:5721）是空桩——只在 RETURN 已有 >1 input 时记 trial，从不主动找 RAX 写入。
- 替换为功能性实现：对每个无返回值的 RETURN（num_input <= 1），扫描其所在 basic block 反向找最后一个写 RAX（Register 0x0）的 op，把那个 output varnode 挂到 RETURN 的 slot 1。fallback：扫 alivelist 在 RETURN 之前的 RAX 写入。对齐 Ghidra `buildReturnOutput`（coreaction.cc:1836-1906）的单寄存器（RAX）情况；多寄存器拼接（PIECE）和 ParamActive 多 pass 待补。
- **效果**：函数返回类型从全 `void` 恢复到正确类型——`my_fwrite`/`myprogress`/`glob_*` 等现在返回 `int`/`long`（之前是 `void`）。只有真正无返回值的（main_init/main_free/hugehelp）保持 `void`。curl gcc 24/24（保持），0 defects，956/956 测试。

### ActionAssignHigh 增强（2026-07-03 续）
- ActionAssignHigh（coreaction.hh:339）已存在并已在 build_full_pipeline_actions（:7084）注册。
- 增强：新增 `Funcdata::set_high_level`（funcdata.rs）+ `funcdata_flags::HIGHLEVEL_ON`（对齐 Ghidra `highlevel_on` funcdata.hh:84）。
  set_high_level 设标志 + 遍历 loc_tree 给每个无 high 的 Varnode 分配 HighVariable（对齐 Ghidra `setHighLevel` funcdata_varnode.cc:595 + `assignHigh` :48-59）。
  幂等：HIGHLEVEL_ON 已设则直接返回（Ghidra 同样行为）。ActionAssignHigh::apply 现委托到 set_high_level（之前是内联重复逻辑）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `build_local_types` → `build_localtypes`（对齐 `ActionInferTypes::buildLocaltypes` coreaction.cc:5008。注意 Ghidra 拼作 "Localtypes" 一个词，非 "LocalTypes"）。
- `ensure_callspecs` → `setup_call_specs`（对齐 `FlowInfo::setupCallSpecs` flow.hh:129。Rugra 签名是批量 over fd，Ghidra 是 per-op，但命名对齐）。

### 2026-07-03（续）：命名对齐 Ghidra Action 名
- `ActionMergeCopy::get_name()` "merge_copy" → "mergecopy"（对齐 Ghidra Action 名 coreaction.hh:387，Ghidra 无下划线）。
- `ActionCopyMarker::apply` 调用更新为 `mark_internal_copies`（配合 merge.rs 改名）。

### 2026-07-04：ActionMergeCopy/ActionDominantCopy 对齐
- `ActionMergeCopy::apply` 从 45 行内联逻辑改为纯委托 `merge.merge_opcode(fd, CPUI_COPY)`（对齐 coreaction.hh:392 `data.getMerge().mergeOpcode(CPUI_COPY)`）。
- `ActionDominantCopy::apply` 调用 `process_copy_trims`（配合 merge.rs 改名）。

### 2026-07-04（续 2）：ActionHideShadow 改为委托 Merge::hide_shadows_of
- 从内联地址匹配 shadow 检测改为委托 `merge.hide_shadows_of(high)`（对齐 coreaction.cc:4831 遍历 high + 调 hideShadows）。
<!-- annotation-pass: 2026-07-04 -->
<!-- fullloop-repeatapply: 1783144461.7826152 -->
<!-- delete-simplify: 1783145834.621112 -->
<!-- activeparam-port: 1783158350.9445786 -->
<!-- activeparam-integration: 1783160103.0862665 -->

### 2026-08-13：Action leaf executor flags/count（PIPE-ACTION-COUNT-0001A）

- `ActionStartTypes` 仍按 Ghidra 在 `apply` 内累计继承的 `Action::count`，并通过
  `take_count_delta` 将该增量恰好一次交给 Rust 的外置 `ActionState`。这使包含它的
  `rule_repeatapply` 组能看到首次 `startTypeRecovery()` 的一次变化并执行第二轮。
- `ActionPrototypeTypes`、`ActionDefaultParams`、`ActionExtraPopSetup`、
  `ActionFuncLink`、`ActionFuncLinkOutOnly`、`ActionInternalStorage` 暴露构造器中的
  `rule_onceperfunc` flag。第一次零变化执行后进入 `status_end`，同一函数内跳过后续
  `perform`；`reset` 后可以再次执行，同时保留累计统计。
- 锁定 12.0.4 的 `action_leaf_count_1204` oracle 只批准 StartTypes 的完整首次/重复状态
  转换，以及上述六个 leaf 的零 calls/ops/blocks 边界生命周期。它不批准这些 leaf 的
  非空数据遍历，也不覆盖 `ActionDoNothing` 或 `ActionSetCasts`。

### 2026-08-11：ANN-F provenance 分类（无行为变更）

以下三个函数在 Ghidra 12.0.4 中没有独立函数体，不能标成逐函数映射：

- `newparam_push_unique` 是 `ActionReturnRecovery::buildReturnOutput`
  (`coreaction.cc:1836-1906`) 内联 `vector::push_back` 的 Rust
  `Option<Arc<_>>` 适配器；其末项去重依赖当前非 nullable input 模型，缺口由
  `OPBANK-0001` / `FSPEC-0002` 跟踪。
- `seed_output_trials` 是因 `Heritage::guardReturns`
  (`heritage.cc:1652-1692`) 尚未接入而放到 return-recovery 阶段的 fallback；
  该阶段迁移不构成行为对齐，由 `HERITAGE-0001` / `FSPEC-0002` 跟踪。
- `derive_func_output_map` 因 Rugra `FuncProto` 尚未持有实际 `ProtoModel`，临时调用
  `default_x86_64()`；Ghidra 在 `ActionReturnRecovery::apply`
  (`coreaction.cc:1908-1955`) 直接调用当前函数原型的 `deriveOutputMap`，缺口由
  `FSPEC-0001` / `FSPEC-0002` 跟踪。

本轮只补 `RUGRA-GLUE` provenance；实现及 oracle 状态均未改变。
 
 
 
 
 
 
 

---

## 2026-08-15：PIPE-MERGETYPE-ORDER-0001 — merge 族名称/flags/计数桥修正

- `get_name` 逐字对齐 oracle 构造器名（无下划线）：
  `merge_required→mergerequired`（coreaction.hh:364）、
  `merge_adjacent→mergeadjacent`（:376）、
  `merge_multientry→mergemultientry`（:398）、
  `merge_type→mergetype`（:409）。
- 补 14 个 `get_flags → RULE_ONCEPERFUNC` 覆盖（mirrors 构造器位）：
  MergeRequired(:364)、MergeAdjacent(:376)、MergeCopy(:387)、
  MergeMultiEntry(:398)、MergeType(:409)、MarkExplicit(:440)、MarkImplied(:461)、
  NameVars(:482)、SetCasts(:330)、InputPrototype(:894)、OutputPrototype(:905)、
  HideShadow(:992)、DynamicSymbols(:1036)、PrototypeWarnings(:1047)。
  此前 executor 观察到 status=1（可重入）而 oracle 为 status_end=16。
- `ActionMarkExplicit::apply` 返回 `change_count`（Ghidra coreaction.cc:3247-3251
  每次 setExplicit 增继承 count； sanctioned Rust count-bridge，见
  `Action::perform` 文档）。
- `ActionMarkExplicit::base_explicit` 补 oracle 缺失守卫
  `if (vn->hasNoDescend()) return -1;`（coreaction.cc:3064）——悬空输出必须
  explicit，否则被 MarkImplied 置 implied 并被 mergeTestBasic 排除，
  MergeType 合并无法发生。
- `build_full_pipeline_actions` 移除 AssignHigh/DominantCopy/CopyMarker
  （已迁移至 set_default_actions 的 :5717/:5723/:5729 精确位置）。
- fixture 证据：`tests/oracle/action_merge_order_1204.{cc,rs}` 29 行观察 28 行
  逐字节一致（seq/counts/status/IR/merge_temps 全对齐）；唯一残差
  `finalstructure` count 桥在 blockaction.rs（域外）。

### 2026-08-15：`ActionReturnRecovery` 生命周期对齐（`FUNC-TYPEPROP-SETTLE-0001`）

消除 match_url/`__libc_csu_init` 的 mainloop ABA 自旋（120s 硬超时）：

- `ActionPrototypeTypes` Step 4：output 未锁时**无条件** `init_active_output`
  （coreaction.cc:4649-4651，onceperfunc），替换自创的 void+has-RETURN 门控。
- `ActionReturnRecovery::apply`：`active_output` 为 None 时早退（= oracle
  `if (active != 0)` 门，cc:1908-1955），不再在 clear 后重建容器；空 RETURN
  分支补完生命周期尾（finishPass→maxPass 判定→deriveOutputMap→clear）而非
  提前返回——循环因此可排空并恰好 clear 一次。
- 计数对齐 oracle：每个未 checked trial 处理后 +1（cc:1935）+
  clearActiveOutput 后恰好一次 +1（cc:1951）；删除自创 else 计数与
  per-RETURN build 计数。

证据：match_url 120s→102ms、`__libc_csu_init`→10.5ms（残留的一次性
"not settling" 警告=对齐 Ghidra localcount>=7 warn-once 语义）；单测
1337/6 域外不变。按机制 B2 记 **UNTESTED**（源级对齐+E2E 恢复，returnrecovery
生命周期逐函数 oracle fixture 为后继项）。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`ActionNameVars::linkSymbols`（coreaction.cc:2930-2976 对应物）修复
hasName 语义：`if (!high->hasName()) continue` 是 variable.cc:718-747 的
"可命名"谓词（coverable/非 implied/unaffected-input 规则），不再是
"已有名字"；nameRepresentative 为空时跳过（Ghidra 对 instance-less high
不可达）。`apply`（cc:2978-3000）改为 Ghidra 顺序：linkSymbols →
lookForFuncParamNames（cc:2858-2897：对 namerec 符号做
`renameSymbol(makeNameUnique(name))`，不再直写 high.name）→ namerec 的
`buildDefaultName(sym, base, vn)` 循环 → `assignDefaultNames(base)` ——同
一共享计数器贯穿。RUGRA-GLUE 桥：命名完成后把符号 display_name 发布到
`HighVariable::name`（Ghidra 打印侧只读 Symbol::getDisplayName；Rugra
printc 仍读 high.name，退役归 PRINTC-SYMBOL-DECL-0001）。
`ActionRestructureVarnode::apply` 安装 x86-64 寄存器名表（translate.hh:380
`getRegisterName` 的 ScopeLocal 站位）。

### 2026-08-16（复核修正）：`ActionNameVars` 两处对齐收口（同上复核）

`link_symbols` 的 spacebase 分支删除 `continue`——Ghidra cc:2957-2958 落入
nameRepresentative/hasName/linkSymbol 后续（unaffected RSP input 经
variable.cc:737-745 会被 linkSymbol）。内联 makeRec 对照 cc:2815-2850 补
四条：`param->isNameLocked()` 门槛（protoparam_flags::NAME_LOCKED）、
vn/param 尺寸门、implied+written 的 CAST 展开（vn→def->getIn(0)，类型置
None 降优先）、重复 high 的 tie-break 用 `Datatype::type_order`（旧类型更
specific 则保留），rec_map 值扩为 (name, Option<Datatype>)。

### 2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）：`ActionNameVars::link_symbols` 传 Architecture-owned TypeFactory

`link_symbols` 开头按 coreaction.cc:2946 `TypeFactory *typeFactory =
data.getArch()->types;` 一次性捕获 `fd.get_arch().types`，在 cc:2971-2972
的 addr-tied 分支传给 `HighVariable::finalize_datatype(&mut factory)`
（本租约内 coreaction.rs 的唯一改动；不涉及 ActionInferTypes/PTRSUB/STOP）。
Architecture/工厂未接线时 fail-closed（不做 finalize 的类型投影），不查
任何 shared-default/process-global 工厂。双侧门禁
`tests/oracle/exactpiece_callers_1204`。

### 2026-08-17：ActionDefaultParams 逐字镜像 model 绑定（FUNCPROTO-MODEL-BIND-0001）

- `ActionDefaultParams::apply` 对齐 coreaction.cc:2311-2337：
  `evalfp = arch.evalfp_called ?: arch.defaultfp`（cc:2313-2315）；对每个
  `!fc.prototype.has_model()` 的 callspec 走 cc:2327-2328 else 分支
  `fc->setInternal(evalfp, types->getTypeVoid())`（Rugra 无法解析
  per-callee Funcdata，copy 分支不可达）；`fc->insertPcode` 的 callfixup
  注入仍缺（CALLFIXUP 域）。删除旧 "unknown→default" calling_convention
  字符串种子——模型名由 `set_model` 从真实模型取（`__stdcall`）。
  RUGRA-GLUE：简化 `proto_model`（type_system）种子保留给
  `possible_input_param` 消费者（Ghidra 单 model 字段无双轨）。
  生产效果：callspec `has_effect` 从恒 UnknownEffect 变为 cspec 声明效果，
  guardCalls 的 INDIRECT 风暴（main pass0=13,462）消退。

### 2026-08-17（r2 返工）：locked 守卫 + ActionPrototypeTypes 绑定尾（FUNCPROTO-MODEL-BIND-0001）

- 集成复测两回归的返工：①`ActionDefaultParams::apply` 对 modelless +
  model-locked callspec（LibcSignatureTable/DWARF 边界，Ghidra 对应
  UnknownProtoModel 克隆，architecture.cc:1155-1166）不再走 setInternal 的
  void 输出/store 交换——只安装共享 eval model（行为克隆等价，锁定
  storage/返回类型保全）；未锁 callspec 仍走 cc:2327-2328 setInternal。
  ②`ActionPrototypeTypes::apply` 补 cc:4615-4619 绑定尾：
  `evalfp = evalfp_current ?: defaultfp`；`!isModelLocked() &&
  !hasMatchingModel(evalfp)` 才 setModel——locked 守卫逐字。配套
  `FuncProto::has_matching_model`（fspec.hh:1391 指针相等 → Arc::ptr_eq）。
  新增单测 `test_action_default_params_locked_callspec_keeps_storage`
  （locked 保 storage/返回类型、unlocked 走 void 交换）。
- fixture 新观察点（双侧 oracle 验证）：PRINTFLAG×4（setDefaultModel
  副作用 architecture.cc:323-330——默认强制不打印、非默认 true、换默认后
  旧恢复 true）与 CALLSPEC_REBIND（绑定后锁定的 callspec 二过
  ActionDefaultParams 不被触碰）。

### 2026-08-17（r3）：ActionPrototypeWarnings::apply 完整移植——warningHeader/warning 通道（UNKNOWN-PROTOMODEL-0001 warning 子项）

旧实现只在参数锁定时 eprintln 到 stderr（非 oracle 通道），且 callspec 分支发
oracle 不存在的 "call at ... has unknown calling convention"。现按
coreaction.cc:4886-4936 逐段移植，全部警告走 `Funcdata::warning_header` /
`Funcdata::warning`（funcdata.cc:135-145/119-129 → commentdb
addCommentNoDuplicate(warningheader/warning, baseaddr, ...)）：

- override 消息（cc:4889-4892）：`fd.localoverride.generate_override_messages`
  （override.cc:279-287，仅 deadcode-delay 类）逐条 warningHeader。
- 自身原型 input/output 错误（cc:4894-4900）：`hasInputErrors/hasOutputErrors`
  为 fspec.hh:1461/1464 flag 位，Rugra FuncProto 未建模（fspec.hh:1351-1352；
  唯一置位源头 = assignParameterStorage 抛 ParamUnassignedError，fspec.cc:4220-
  4222，Rugra 无该路径；另有 fspec.cc:5507-5508 `FuncCallSpecs::forceSet` 的
  error-flag 复制——纯源 proto 拷贝非独立源头，且 error_outputparam 全库无
  直接置位源头；custom_storage 的 ATTRIB_CUSTOM decode 在 Rugra 为 no-op 丢弃，
  fspec.rs:1129，系未来接线风险点）——`proto_has_input_errors/output_errors`
  镜像谓词在所有可达状态下读 false，与 oracle 可观测等价（复核方独立 grep
  验证，含 forceSet 复制点）。
- isModelUnknown（cc:4901-4909）：`"Unknown calling convention"` +
  `printModelInDecl()` 时 `": " + getModelName()` + `!hasCustomStorage() &&
  (isInputLocked||isOutputLocked)` 时 `" -- yet parameter storage is locked"`
  （custom_storage 仅 ATTRIB_CUSTOM decode 置位，fspec.cc:4724-4727，Rugra
  decoder 该属性为 no-op stub——`proto_has_custom_storage` 同上等价 false）。
- 每调用点错误（cc:4910-4934）：`FuncCallSpecs : public FuncProto`（继承）在
  Rugra 为组合，谓词读 `fc.prototype`；名字取 `prototype.name`（set_funcdata
  绑定的 display name），空名 → `"<indirect>"`（cc:4913-4920）；定位地址 =
  `call_entry_address`（fspec.hh:1686 getEntryAddress；oracle 间接调用保持
  invalid 地址，fspec.cc:4943——Rugra None 归一为 offset 0）。

新增 fixture×3（coreaction.rs tests）：locked+unknown 写入 commentdb 精确文本
`WARNING: Unknown calling convention -- yet parameter storage is locked`
（WARNINGHEADER 类型 @baseaddr，二跑 addCommentNoDuplicate 去重=1 条）；未锁
unknown 无后缀；override 消息走同通道。验证：`cargo test --lib` 1391 pass/
5 fail（与基线同集：comment/dynamic/funcdata×2/ruleaction 预存，见
RULE-SUBCANCEL-RWLOCK-0001 记录）；curl E2E Matched 123、defects=0、gcc 17
FAIL 不变；annotations/refs 门禁过。

**C 输出发射仍断链（printc/arch 域，登记 UNKNOWN-PROTOMODEL-WARN-EMIT-0001）**：
arch.commentdb 默认 None（arch.rs:523，oracle sleigh_arch.cc:244 构造即
`new CommentDatabaseInternal()`）；printc doc_function（printc.rs:5120）未调
`commsorter.setup_function_list`（oracle printc.cc:2650）也未调
`emit_comment_func_header`（printc.cc:2652；Rugra 已有实现 printc.rs:8450 但零
调用方）；且 printc.rs:570-573 的 head/instr comment mask 与
printlanguage.cc:579/582 **接反**（oracle head=header|warningheader、
instr=user2|warning）。E2E 现状：管线侧 24 PLT thunk 函数的警告已经 warning
通道产出（stderr fallback 48=24 函数×2——action.rs:912 批量与 :1085 单独
双注册 ActionPrototypeWarnings，commentdb 侧 addCommentNoDuplicate 去重所以
对接后无重复）；3 真实函数（main_init/main_free/hugehelp）被 debugproto.rs:260
DWARF overlay `fd.funcp.clone()` 保留已绑定 defaultfp 模型名阻塞（isModelUnknown
= false），属 UNKNOWN-PROTOMODEL 父项模型语义域。

## 2026-08-17：ARCH-CONTEXT-TRACKED-0001 — ActionConstbase tracked COPY 循环落地

- `ActionConstbase::apply`（coreaction.rs，oracle coreaction.cc:678-706）从 stub
  升级为逐行移植：
  - cc:681 空块早退 → `fd.bblocks.get_size() == 0` 返回 0；
  - cc:684 entry block = `getBlock(0)`（C 风格 cast，Rugra 走 trait 对象）；
  - cc:686-690 injectid≥0 腿（`getFuncProto().getInjectUponEntry()` →
    `getPayload` + `doLiveInject`）保持门控：Rugra `FuncProto` 不存 injection id
    （`set_inject_id` 为 INJECT-0001 no-op，ProtoModelFull::inject_upon_entry 仅经
    protomodel `<inject>` resolver 赋值而生产 worker 不注册），按 flow.rs
    `FuncCallSpecsExt::get_inject_id` 同款 INJECT-0001 兼容回退读作 -1；
  - cc:692 `getTrackedSet(data.getAddress())` →
    `fd.get_arch().get_tracked_set(AddressSpace::Ram, fd.get_address().as_u64())`
    （Rugra Address 无空间维，函数地址=默认代码空间 ram，同空间查找与 Ghidra
    baselist 序全等——见 arch.rs TrackedSetMap 排序 caveat）；快照 `to_vec()`
    结束不可变借用后再进变异循环（Ghidra 引用指向全局 context，循环不触其变异）；
  - cc:694-704 每 tracked ctx：`Address(ctx.loc.space,ctx.loc.offset)` →
    `ctx.loc.space` 空间直接穿参 `new_varnode_out_full(size, ctx.loc.space,
    Address::new(ctx.loc.offset), op)`（2026-09-25 第五波前为 `Address::new
    (ctx.loc.offset)` + `new_varnode_out` Register 钉——DF register:0x20a:1
    恰同值，非 register tracked loc 空间现为 exact-general 传递）
    → `new_op(1, bb.get_start_addr())`
    → `new_constant(size, ctx.val)` → `op_set_opcode(CPUI_COPY)` →
    `op_set_input(op,vnin,0)` → `op_insert_begin(op,&bb)`（多 ctx 时逆序居块头，
    与 opInsertBegin 语义一致）；
  - cc:705 无条件 `return 0`（无 change 计数器）→ `NO_CHANGE`。
- worker pspec 喂入（examples/curl_decompile.rs 与
  examples/getstr_stage_snapshot.rs 的 `worker_architecture` 镜像）：
  `restoreFromSpec` 先 `parseProcessorConfig` 后 `parseCompilerConfig`
  （architecture.cc:639→641），其 ELEM_CONTEXT_DATA 臂（:1190）→ 读
  `sleigh_specs/x86-64.pspec`、DocumentStorage 解析、每个 `<context_data>` 子元素
  经 `TreeDecoder` 喂 `arch.decode_context_data`（fixture 同款 DOM 提取，ARCH-0001
  最小接线；其余 pspec 子元素仍为 pspec 文本管线残差）。
- 生产验证：GetStr 02b 层 [CALLGUARD] 投影 18 → **20**（每 call 补第 10 个
  0x20a range，相对序 0,30,38,200,202,206,207,20a,20b,288 与 oracle 全等）；
  block0 头部 COPY out=register:0x20a:1 in0=const0（被两个 INDIRECT guard 读）。
- E2E（HEAD 004816a 干净 worktree 基线对比）：skeleton 3155→3151
  （my_get_line/helpf/file2string.part.0/getparameter.constprop.0 各消 1 行
  幽灵 `in_register_0000020a` 声明——golden 无此行，方向朝 oracle）；
  defects=0/numbering=0/Matched=123 不降；gcc audit 16 FAIL（≤16 基线内，前值 17）。
- 回归测试：`coreaction::test_action_constbase_inserts_tracked_copy_at_entry_head`
  （单侧 Rugra 断言：DF tracked_set 摄取 → COPY 居块头、out=reg:20a:1、
  in0=const0、返回 0；机制 B2：手写 expected 不升 MATCH，oracle 侧证据=
  getstr_pipeline_1204 02b 层逐对象投影）。
- 既有 fixture 影响：`heritage_callguard2_1204` runner 的 `heritage_rs_sha256`
  钉在 base 102c476，committed 漂移（heritage.rs +14/funcdata.rs +195）致其在
  干净 HEAD 同样 mismatch（本改动前已破，非本 write-set 所致；需 fixture owner
  重钉 base）。

## default 管线树重构 WIP（2026-08-22，PIPE-DERIVED-TREE-0001 / PIPE-HEAD-FLAT-ACTIONS-0001）

- 扁平 `build_full_pipeline_actions` 重构为 Ghidra 嵌套树镜像：universal 头部
  8 Action（coreaction.cc:5477-5486）、mainloop Segmentize/InternalStorage 槽位
  （:5493-5500）、stackstall 子序列 oppool1→LaneDivide→MultiCse→ShadowVar→
  Deindirect→StackPtrFlow（:5651-5656）；`find_group_recursive` 树查询。
  WIP：pipeline_tree_1204 双侧 fixture 与 stackstall count 反馈 pending；
  参考 docs/alignment_docs/PIPELINE_STAGES_1204.md。

## 精确 action 名与 ctor flags 对齐（2026-08-23，PIPE-DERIVED-TREE-0001）

- 五个 `get_name()` 修正为 Ghidra ctor 字面名：`restructureVarnode`→
  `restructure_varnode`（coreaction.hh:855）、`unjustifiedparams`→
  `unjustparams`（:920）、`mappedlocalsync`→`mapped_local_sync`（:869）、
  `funclinkoutonly`→`funclink_outonly`（:715）、`conditionalconst`→
  `condconst`（:595）。
- 三个 `get_flags()` 补齐 ctor rule flag 位：`lanedivide`→
  RULE_ONCEPERFUNC（coreaction.hh:117）、`donothing`→RULE_REPEATAPPLY
  （:504）、`normalizesetup`→RULE_ONCEPERFUNC（:630）。
- 对拍证据：`tools/run_pipeline_tree_oracle.sh` 78 节点 DFS 双侧
  字节一致（含每个节点的 name/basegroup/flags），overall=MATCH。

## stackstall 叶子 count 通道与 analysis_finished 生命周期（2026-08-23，PIPE-STACKSTALL-COUNT-0001）

- `ActionMultiCse`/`ActionShadowVar`/`ActionDeindirect` 的 apply 内部变更数
  此前计算后丢弃，现写入继承 `Action::count` 通道（`take_count_delta` 外化，
  对应 coreaction.cc:873/:945/:1240 的 `count += 1`），stackstall 的
  rule_repeatapply 不动点由此感知叶子变更（action.cc:303-350 + 506-527）。
- `ActionStackPtrFlow` 补齐 `analysis_finished`（coreaction.hh:91，reset 清除
  ：99）、`apply` 首行短路（cc:484-485）、`numchange>0 → count += 1`
  （cc:492）、干净趟 `analyzeExtraPop` + `analysis_finished=true`（cc:494-497）；
  extrapop-known 早退（cc:264-267）经 `fd.funcp.get_extra_pop()` 判定；
  未知 extrapop 的 StackSolver 路径走已有 `analyze_extra_pop`（其 callspec
  回写仍未接线，残差 PIPE-STACKSOLVER-WRITEBACK-0001）。
- 两处缺陷修复：`ActionShadowVar` 重写路径的 RwLock 死锁（`if` 条件临时读
  guard 贯穿分支体，`op_set_input` 写锁自锁——该路径首次真实执行即挂起整条
  管线）；`checkClog` 的 `constz` 取值错位（应取 LOAD 指针的栈相对偏移
  cc:473-475，而非 clog ADD 操作数偏移）。
- 对拍：`tools/run_stackstall_count_oracle.sh`（pin-base schema2，base=b40a315
  + overlay）——双侧真实派生树的 stackstall 子树经 action.cc:303-350 外部
  perform 镜像逐趟观察：run1 三趟收敛（multicse/shadowvar/stackptrflow 各
  count=1，趟2 oppool1 count=1，终值 4），run2 reset 后单趟零变更且
  stackptrflow tests 3→4（analysis_finished 复位再分析），IR 投影逐字节一致，
  stdout_sha256=0a9439b3…，overall=MATCH。残差：deindirect 变更分支
  （PIPE-DEINDIRECT-CHANGE-0001 建议）、solver 回写。

## ActionLaneDivide 完整移植（2026-08-23，ACTION-LANEDIVIDE-0001）

- `ActionLaneDivide` 不再是 no-op stub。三函数完整移植
  （coreaction.cc:509-622，coreaction.hh:107-123）：
  - `collect_lane_sizes`（cc:509-540）：descendant 先行（step 0）后 def
    （step 1）遍历；SUBPIECE descendant 贡献 `out` size，PIECE def 贡献
    `min(in0,in1)` size；仅 `allowedLane` 接受的 size 注册进 checkLanes
    （bitmask 语义）。
  - `process_varnode`（cc:558-583）：mode<2 走 collect；mode 2 用
    pointer size（`!=4 → 8` 归一化）做默认 lane；lane 尺寸按
    LanedIterator 升序逐个尝试；首个 `doTrace` 成功即 `apply` 并
    `count += 1`。
  - `apply`（cc:585-622）：先 `setLanedRegGenerated`（minLanedSize=1000000
    封死后续注册）；mode 0..2 三趟，趟内按 `VarnodeData::operator<` 序遍历
    lanedMap，每个 storage 走 `[beginLoc(sz,addr), endLoc(sz,addr))`
    （loc-tree 精确 (space,offset,size) 过滤，`VarnodeCompareLocDef` 序）；
    `hasNoDescend` 跳过；成功拆分后重算 bounds 从头再走；失败推进且记
    `allVarnodesProcessed=false`；`allStorageProcessed` 才提前 break；
    最后 `clearLanedAccessMap`。Ghidra 的活 map 迭代在 Rust 侧用每 mode
    BTreeMap 快照等价实现（apply 期间 map 可证明稳定：插入全部被
    minLanedSize 门禁封死，删除只在末尾 clear）。
- count 经 `take_count_delta` 外化（cc:578 `count += 1`）；apply 恒返回 0
  （cc:621），RULE_ONCEPERFUNC 状态机（action.cc:352-357）使第二趟 perform
  在 `status_end` 直接短路——不改 stackstall 槽位（:5652，eb8ad57 已集成）。
- 对拍：`tools/run_action_lanedivide_oracle.sh`（pin-base schema2）——
  piece 成功路径（collect 双来源 + mode 0 拆分 + count=1 + IR 投影 +
  lanedMap 1→0）、failure 路径（collect 过滤拒绝 + mode 0/1 空 + mode 2
  默认 lane 8 对 INT_MULT backward 拒绝 + 零突变 + map 清空）、
  rule_onceperfunc（re-queue 后第二趟 perform 不清 map、ret2=0、count
  不变、IR 稳定）双侧逐字节一致，overall projection=MATCH。残差见
  ACTION-LANEDIVIDE-RESIDUAL-0001（mode 1 downcast SUBPIECE 终结符、
  同 storage 多 varnode 的 bounds 重走、多 storage 迭代序、pointer=4 归
  一化分支未在 x86-64 oracle 上覆盖）。

## 2026-08-23（VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 编译适配）：v_type 读改为 v_type.get()

四处 `h.read().unwrap().v_type.clone()` → `h.read().unwrap().v_type.get()`（:3191/:3266/:3338/:3385）。`HighVariable::v_type` 缓存迁入 `TypeCell` 锁域（Ghidra variable.hh:141 `mutable` 的对应物，详见 docs/api/variable.md）；`.get()` 仍是同一共享分配的 Arc 拷贝读，且现在携带 variable.hh:174 `getType()` 的惰性 updateType 语义。

## 引用行号勘误（2026-08-24，root）

buildLocaltypes 引用 coreaction.cc:5012 修正为 5008（定义起始行）。

## ParamActive 地址空间传递（2026-08-24）

`ActionInputPrototype`、`ActionFuncLink` 的 Heritage fallback，以及
`seed_output_trials` 现在把来源 Varnode、调用参数或模型条目的已知
`AddressSpace` 显式传给 `ParamActive::which_trial_in_space` /
`register_trial_in_space`。
这保留了 Ghidra `Address` 中的真实空间身份，使仅有 offset 的过渡
`Address` 不会被 fail-closed 拒绝，也不恢复旧有的 Register 推断。此改动
只修复 caller 的空间传递；对应 action 中既有的模型硬编码与未完成恢复分支
仍按原登记残差保留。

## CALLSPEC-IDENTITY-D0 下游接线（2026-08-24）

- `ActionFuncLink::setup_call_specs` 以 exact `PcodeOpRef` 去重并创建稳定 owner，
  将 typed FSPEC annotation 绑定到同一 owner；`ActionDeindirect` 在 CALLIND
  确认直接目标后也先安装该 annotation，再改成 CALL。两处都不再用
  `op_addr`/vector index 充当身份。
- 正常 lifting 已由 `FlowInfo::setup_call_specs` 建立 callspec；
  `ActionFuncLink::setup_call_specs` 只为绕过 FlowInfo 而手工构造的 alive CALL
  保留兼容 fallback。该 fallback 不是第二套 FlowInfo，也不把未覆盖的 consumer
  闭包升为 `MATCH`，继续绑定 `CALLSPEC-0001`。
- `ActionFuncLink`、`ActionFuncLinkOutOnly`、`ActionNameVars`、
  `ActionActiveReturn`、`ActionExtraPopSetup`、`ActionInferTypes` 等调用点通过
  callspec 的 exact op `Weak` 或 `Funcdata::get_call_specs_of_op` 取回同一个
  owner。DeadCode、active trial、warning 与原型处理用短 read/write guard；需要
  随后修改 Funcdata 时先复制 entry/type/model/slot 等值并释放 guard，避免锁借用
  改变 Action 的遍历顺序或 mutation 时机。
- 这些变化只接通身份和 Rust guard 生命周期，未改变各 Action 已登记的模型、
  trial、callfixup 或类型推导残差。D0 总体仍为 `MISMATCH`：专用
  `IPTR_FSPEC` 缺失，`AddressSpace::Iop` 临时代用由
  `TYPEOP-FSPEC-SPACE-0001` 跟踪；TypeOp getter、PrintC、StringManager 不在
  本阶段 write-set，主管线 Action 及模块状态均不据此升级。
- `StackSolver::build` / `analyze_extra_pop` 的旧注释已更正：exact per-op
  callspec lookup 已存在；真正未完成的是 `effective_extrapop` 字段、从 Iop
  source op 到 owner 的消费、known-extrapop 时把真实 rhs 写入 equation（当前仍固定
  guess 4），以及 solver 的 mutating write-back。初始 stack-pointer 非 input 时的
  错误通道也未对齐：Ghidra 抛 `LowlevelError` 并由 caller 写 warningHeader，Rust 仅写
  stderr 后返回；该非 callspec 分支绑定 `PIPE-STALL-SHAPE-0001`。上述分支均未做
  双侧执行，状态为 `UNTESTED`；callspec 分支继续绑定 `CALLSPEC-0001`，不属于 D0
  identity `MATCH`。

## ActionConditionalConst propagateConstant CPUI_RETURN 特例（2026-08-25，RETURNFOLD-GAPB-CONDCONST-0001）

- `propagate_constant` 补齐 cc:4439-4448 的 CPUI_RETURN 特例：RETURN 不能直接吃
  常量输入——对被 const 块支配的每个 RETURN 后代，先 `new_op(1, ret.addr)` 建
  `copyBeforeRet` COPY，`op_set_opcode(COPY)`、`op_set_input(copy, constVn, 0)`、
  输出 varnode 落在 varVn 的精确 (space,offset,size)（cc:4445
  `newVarnodeOut(varVn->getSize(), varVn->getAddr(), …)`；Rust 侧因
  `Funcdata::new_varnode_out` 钉死 Register space，改用
  `vbank.create_def_with_space` + 内联 assignHigh/checkForLaned/
  setVarnodeProperties 腿，保留任意 space 的正确性），RETURN 的 slot 1 无条件改读
  该 COPY 输出（cc:4446 用字面 1，不用 getSlot(varVn)），最后
  `op_insert_before(copy, ret)`。此前的 Rust 把常量直接塞进 RETURN 输入槽，
  产出 oracle 永不存在的 `RETURN const` IR 形（A61 审计 GAP-B）。
- 非 RETURN 支配读仍走 cc:4449-4452 的直接槽替换；`count += 1` 对两臂一致
  （cc:4453）。Rugra-only 的值级收敛守卫保留（`already_const` 早退），RETURN 臂
  上天然空转：插入后 slot 1 持 COPY 输出而非常量，且 op_set_input 切断 varVn→
  RETURN 的 descend 链使 RETURN 不会被重访。
- 下游不变量：copyBeforeRet **不**置 `return_copy` flag（区别于 heritage
  guardReturns 的 persist COPY）；`RulePropagateCopy` 的 cc:3933
  `isReturnCopy()` 守卫保证该 COPY 输入永不被折叠进 RETURN（RETURN 本身带
  TypeOpReturn 的 return_copy flag，typeop.cc:879）。
- 双侧对拍：`tests/oracle/returnfold_gapb_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_gapb_oracle.sh`——真实 `ActionConditionalConst::apply`
  驱动 5 块 CFG（INT_EQUAL(X,5) CBRANCH、两个被支配 RETURN、一个非支配 RETURN、
  一个非 RETURN 支配读 INT_ADD），观察面含 RPO 序、X descend 序、count
  （CountProbe/`count` pub 字段 + perform-bypass 的 zeroCount 说明）、COPY
  几何（pc/out/in0/flags）、slot1 非常量不变量、二次 apply 稳定性、
  RulePropagateCopy 全扫描 hits=0；双侧 stdout 字节一致（MATCH）。残差（均
  登记 UNTESTED，见 metadata）：apply 返回值不对称（Ghidra cc:4545 恒 0 vs
  Rugra count>0，CONDCONST-APPLY-RETURN-0001）、MULTIEQUAL phi 臂
  （CONDCONST-MULTIEQUAL-GUARD-0001）、implied-boolean 臂
  （CONDCONST-IMPLIEDBOOL-0001）、打印期折叠（依赖 GAP-A/GAP-D 上游）。

## ActionPrototypeTypes output-locked 直挂分支（2026-08-25，RETURNFOLD-GAPA-PROTOTYPES-0001）

- `ActionPrototypeTypes::apply` 补齐 cc:4637-4649 的 output-locked 双分支之 locked 臂
  （此前 Rust 只有 else 臂 `init_active_output`，locked 路径什么都不做——locked 输出
  函数裸 `return;` 的根因，A61 审计 GAP-A）。忠实语句序：
  `outparam->getType()->getMetatype() != TYPE_VOID` 门（cc:4639，locked-void 如
  `exit`/`free` 不挂任何东西、也不 init activeOutput）→ 对每个活 RETURN：
  `isDead` 跳过（cc:4642）、`getHaltType()!=0` 跳过（cc:4643；op.hh:170-172 的完整
  掩码 halt|badinstruction|unimplemented|noreturn|missing）→
  `newVarnode(outparam->getSize(), outparam->getAddress())`（cc:4644，size 取类型
  尺寸非寄存器全宽）→ `opInsertInput(op, vn, op->numInput())`（cc:4645，**追加为末
  槽**——已有值输入的 RETURN 追到 slot 2，不替换既有 slot 1）→
  `vn->updateType(type, true, true)`（cc:4646，typelock+override）。
- Rust 地基桥（ANN-F，FSPEC-0001/FSPEC-0002）：扁平 `FuncProto` 无 output
  ProtoParameter，存储地址取自 `ProtoModel::default_x86_64().output_entries[0]`
  （Register 0x0），类型/尺寸取 `funcp.return_type`——与 Ghidra
  `assignParameterStorage`（fspec.cc:2429/1569-1581，setPieces→updateAllTypes→
  store->setOutput）给出的 oracle 观察地址一致（fixture 已钉死 register:0x0:4）。
  `newVarnode(s, AddrSpace, off)` 形态（funcdata.hh:284/funcdata_varnode.cc:239-247）
  因 `Funcdata::new_varnode` 钉死 Ram space，改内联其 (cc:148-169) 腿：
  `vbank.create_with_space` + assign_high + checkForLaned + set_varnode_properties
  （GAP-B copyBeforeRet 同款模式）。
- 与 GAP-B（copyBeforeRet，cc:4439-4448）协同：PrototypeTypes（onceperfunc，早期）
  先挂 locked 输出 varnode 为 RETURN 末槽，heritage 把寄存器写链到它；晚期
  ConditionalConst 的 RETURN 臂读 varVn（即该地址上的 varnode），COPY 输出落在
  varVn 精确 (space,offset,size)，`op_set_input(op, out, 1)` 替换 slot 1——两臂
  无冲突，正是 oracle 的先后链。`ActionReturnRecovery::apply` 的
  `output_type_locked` 早退（coreaction.rs apply 开头）在 Ghidra 因 locked 时
  activeOutput 必为 NULL 而冗余等价；GAP-A 后 locked 函数不再 init_active_output，
  该守卫成为唯一防线（保留并已在注释注明，GAP-C 审计结论）。
- 双侧对拍：`tests/oracle/returnfold_gapa_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_gapa_oracle.sh`——真实 `ActionPrototypeTypes::apply` 三场
  景：A=locked int（4 RETURN：裸 RETURN 挂 slot 1、带值 RETURN **追加** slot 2 且
  slot 1 不动、halt RETURN 跳过、dead RETURN 跳过；观察 nin/in_last
  register:0x0:4/def=free/typelock=1/mt=int、attach 次序、varnode 不共享、
  activeoutput 缺席）；B=locked void（不挂不 init）；C=unlocked 对照（只
  initActiveOutput，active=1）。C++ 侧走 Ghidra 原生 locked 路径（setInternal+
  setPieces→assignParameterStorage→setOutput）。双侧 stdout 14 行字节一致
  （MATCH）。残差（均 UNTESTED，见 metadata）：ANN-F 模型胶水（仅钉观察地址）、
  多输出条目模型、E2E 折叠链（依赖 GAP-D）。

## funcLinkOutput 锁定输出存储分支（2026-08-25，FSPEC-OUTPUT-STORAGE-0001）

- **Ghidra**: `ActionFuncLink::funcLinkOutput` 的 coreaction.cc:1538-1553 腿——
  locked 非 void 输出读 `outparam = fc->getOutput()`，`addr =
  outparam->getAddress()`；`addr.getSpace()->getType() == IPTR_SPACEBASE` 时
  `fc->setStackOutputLock(true)` 并**延迟**输出 varnode 到栈 heritage
  （`Heritage::tryOutputStackGuard` 在 caller 视角重建，heritage.cc:1414），
  否则 `data.newVarnodeOut(sz, addr, callop)` 立即建在记录存储上。
- **Rugra 侧**：`func_link_output` 现读 `fc.get_output_storage()`
  （fspec.rs 扁平 store 的 `outparam::addr` 站位）；`Stack`（过渡枚举的
  spacebase，与 guardCalls cc:1460 同约定）→ `set_stack_output_lock(true)`
  + return；register 等其他空间 → `new_varnode_out(sz, Address::new(off))`
  （new_varnode_out 建在 register 空间 = 登记过的过渡分歧）。无记录存储
  （Ghidra 不可达：known-prototype 路径未记录）保持 RAX 0x0 legacy 回退。
  `sz` = `outparam->getSize()` = 返回类型 size（fspec.hh:1176）。
- 仍 deferred（`CALLSPEC-0001`）：cc:1543-1544 `opMarkCalculatedBool`
  （TYPE_BOOL sz==1 + isTypeRecoveryOn）与 cc:1552-1568
  `assumedOutputExtension` → SEXT/ZEXT/PIECE 小尺寸扩展 op。
- 证据：`tests/oracle/heritage_tryoutput_1204.*` case=production_entry_guardcalls
  ——stack 存储（stacklock=1, pre_out=0, 守卫后 SUBPIECE、无 INDIRECT）与
  register 控制几何（stacklock=0, pre_out=1, INDIRECT 守卫）双侧逐字节 MATCH。
## 2026-08-25（COREACTION-BASEEXPLICIT-NUMINST-0001 + COREACTION-MARKIMPLIED-COUNT-0001）：return 折叠链第三环 GAP-D 计数修正

- **`ActionMarkExplicit::base_explicit` 补多实例规则**（Ghidra coreaction.cc:3020-3021）：
  `HighVariable *high = vn->getHigh(); if ((high!=0)&&(high->numInstances()>1))
  return -1; // Must not be merged at all`——插入点在 call 检查之后、addr-tied
  规则**之前**（oracle 顺序：def null → marker → call/NEW → **numInstances>1** →
  addrtied → mapped → protoPartial → hasNoDescend → PTRSUB maxref 放宽 →
  desccount）。多实例 High 成员（mergerequired 的 mergeAddrTied 已强制合并的
  stack cluster 等）内联会把多个 SSA 版本的合并 cover 拉过读点，必须以显式命名
  变量打印——这正是 oracle 中 `return iVar;`（显式形）与 `return <const>;`（折叠
  形）同函数并存的判定开关之一（A61 审计 §1 环节 6）。Rust 侧以
  `vn.high.as_ref() → num_instances() > 1 → return -1` 对齐；
  `HighVariable::num_instances()`（variable.rs，variable.hh:179 numInstances 的
  1:1 port）由 assignhigh/merge 路径维护。
- **`ActionMarkImplied::apply` 计数桥**（Ghidra coreaction.cc:3434 + action.cc:362）：
  oracle 的 DFS pop 分支 `count += 1; // Will be marked either explicit or
  implied` 对**每个被标记（无论 explicit 还是 implied）的候选**各 +1，apply 本身
  返回 0，`Action::perform` 尾部 `return count;` 把累计值作为 perform 结果上报
  （markimplied 构造带 rule_onceperfunc、无 rule_repeatapply，故单次 apply 后
  perform 返回 count）。Rust 侧原先两分支恒返 `NO_CHANGE`（R16 复核确认的
  MISMATCH），现改为与 `ActionMarkExplicit::apply` 相同的 sanctioned count-bridge：
  `change_count > 0 → Ok(change_count)`，perform 累计后同值返回。count 影响
  mainloop 收敛判定与 `act=markimplied|res=N` 观察面。
- **双侧 fixture**：`tests/oracle/gapd_counters_1204.{cc,rs,metadata.json}` +
  `tools/run_gapd_counters_oracle.sh`——真实 universal tree / build_default_pipeline
  驱动 assignhigh..markimplied 四子项。prestate：stack:0x200 精确位置簇
  {m2（COPY 输出，addrtied 门控）、m1（COPY 输出，raw 无属性尾）}cover 不相交
  [r0..r1]/[r2..r3]，mergerequired 强制合并出 2 实例 High；q2/q1/w1 无后继
  （hasNoDescend→explicit）；z1=INT_MULT(常量,常量) 单后继（唯一 markimplied
  候选，checkImpliedCover 全常量输入不触 cover——cover-lazy 安全观察面）。
  决定性观察：`act=markexplicit|res=5`（m1 仅由 numInstances 规则标记：at=0、
  无 mapped、有后继）、`act=markimplied|res=1`（z1 单次弹出并 implied）、post
  `m1:ex=1,im=0,at=0,hi=2`。双侧 stdout 9 行字节一致（MATCH）。负控制：HEAD
  （dc6f0bfa，修复前）跑同 fixture 得 `res=4`/`res=0` 且 `m1:ex=0,im=1`（m1 被
  错误 implied）——两缺口均被本 fixture 鉴别。注意 m2 先建（def SeqNum 较小）
  使 loc_tree 簇首为带 addrtied 的成员——规避 merge.rs `addr_tied_location_ranges`
  `first_flags` 仅取簇首成员 flags 与 Ghidra `overlapLoc` 全簇 OR 的已知表示差
  （表示层残差另行登记，不影响本 fixture 双侧同判）。
### 2026-08-25：MarkExplicit 全量 port + MarkImplied count 桥（`RETURNFOLD-GAPA-UPSTREAM-0001`）

e2e return 值折叠链的最后检验环节（GAP-A/GAP-B 已集成后的上游切片）：

- **`ActionMarkExplicit::base_explicit` 全量重写**（coreaction.cc:3007-3082，
  原 addr-tied 简化分支整体替换）：
  - cc:3020-3021 `high != null && high->numInstances() > 1 → return -1`
    （多实例 high 永不 implied——`COREACTION-BASEEXPLICIT-NUMINST-0001` 的核心
    规则；折叠/显式选择的判定开关）。
  - addr-tied 分支（cc:3022-3049）：SUBPIECE 输入 addr-tied 且
    `overlap_join(vin) as u64 == in(1).get_offset()`（cc:3026 int4→uintb 提升，
    -1 符号扩展永不匹配小偏移）→ -1；`lone_descend`：ZEXT 输出 addr-tied 且
    `contains(vn)==0` 才可继续 implied 候选（cc:3032-3036）；PIECE 经
    `piece_node_find_root`（op.cc:824-852，funcdata.rs 私有 helper 的本地镜像，
    租约边界）判定根/内部件（cc:3037-3045，根 def `isPartialRoot()` 现已真实生效:
    flag 由 RulePieceStructure(ruleaction.cc:7642)与 SplitDatatype::buildOutConcats
    (subflow.cc:2599)`setPartialRoot` 设置, root def 为 partialRoot 时整栈
    显式——SB-IMPLIEDWAVE-0001 补齐, 原"恒 false"注记作废）；其余
    lone reader → -1（cc:3046-3048）。
  - cc:3050-3063：`is_mapped → -1`（heritage 属性尾）、`is_proto_partial → -1`、
    PIECE def 且 in(0) proto-partial → -1。
  - cc:3066-3072：PTRSUB 引用常量/输入 spacebase 时 `max_ref = 1000000`。
  - cc:3073-3081 后继循环：marker reader → -1；**`desccount > maxref → -1`**
    （修复原 `return desc_count` 缺陷——超限必须是 explicit 而非 multlist 候选）。
- **新增 `multiple_interaction`**（cc:3091-3132）：bool 输出/ZEXT/SEXT/PTRADD 的
  前两输入带 mark → purgelist → `set_explicit + clear_implied + clear_mark`；
  PTRADD 只清洗 PTRADD 祖先；bool 输出祖先 `continue` 不清洗。
- **新增 `MarkExplicitOpStackElement` + `process_multiplier`**
  （cc:3136-3157/3166-3199，Rust 需模块作用域）：LOAD slot=1/slotback=2、
  PTRADD slotback=1（不遍历乘数槽）、SEGMENTOP slot=2/slotback=3；项计数
  `> max_term_duplication` 或命中已标 mark 的祖先 → explicit；spacebase 不计数。
- **新增 `check_new_to_constructor`**（cc:3205-3235）：NEW 输出喂构造器时
  `op_mark_special_print(firstuse)` + `op_mark_non_printing(new op)`
  （`PcodeOpRef` 包装经 funcdata.rs 公有 API）。
- **`ActionMarkExplicit::apply` 全量重写**（cc:3237-3272）：multlist 收集
  （desccount>1 → set_mark）、`count += multiple_interaction(multlist)`、
  processMultiplier（mark 未被清除者）、末尾统一 clear_mark；arch 缺失时
  max_implied_ref/max_term_duplication 回退默认 2（architecture.cc:1420-1421）。
- **`ActionMarkImplied::apply` count 桥**（`COREACTION-MARKIMPLIED-COUNT-0001`）：
  原 `change_count > 0` 双臂均返回 `NO_CHANGE` 的缺陷修复为返回计数增量
  （cc:3434 每完成一个 varnode `count += 1`，apply 本身返回 0 cc:3454；
  sanctioned Rust count-bridge），`rule_onceperfunc` 下 perform 观察
  lcount<count → count_apply/status_end 与 oracle 状态机一致。平坦迭代与
  Ghidra DFS 后序的标记结果与计数总量等价（常数/自由 varnode 双侧同被
  排除：Ghidra def_tree 免费段在 `beginDef(0)` 之后，isFree 跳过 cc:3426）。
- 双侧对拍：`tests/oracle/returnfold_upstream_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_upstream_oracle.sh`。四场景驱动**生产**
  `ActionMarkExplicit::perform` + `ActionMarkImplied::perform` +
  `PrintC::emitBlockBasic`/`emit_block_graph`（rpn 路径）：
  s1_fold（单实例 COPY→RETURN：implied、mi_count=1、打印 `return+lit10` 无
  独立赋值行——cc:2704-2705 跳过 + cc:526-534 递归内联）；s2_merged（双实例
  high 合并：双 explicit、me_count=2、assign 行保留 + var 返回）；s3_dup3
  （3 读超 maxref：explicit、1 assign + 3 var 返回——钉死 desccount>maxref
  修复）；s4_mult2（2 读==maxref：multlist 存活 processMultiplier、implied、
  双折叠）。双侧 stdout 22 行字节一致（sha `c1472b99…`），stderr 双空，
  diff rc=0，各 2 次确定性。残差（UNTESTED，metadata coverage）：NEW 构造器
  路径、addr-tied 子分支（需 partialroot 旗标基建）、checkImpliedCover
  LOAD/STORE/CALL 交叉（Rust 块级近似仍在）、标记次序（平坦 vs DFS 后序，
  等价性论证未钉）。
## ActionPrototypeTypes 锁定输出/模型恢复域（COREACTION-PROTOLOCKEDOUT-0001，2026-08-25）

`ActionPrototypeTypes::apply`（coreaction.cc:4607-4651）补两处：

1. **模型不变量恢复**（cc:4613-4614 前置）：Rugra 的 DWARF/PLT 锁定签名
   路径可能留下 `model=None && model_locked=true`，破坏下游一切模型查询
   （Ghidra 的 FuncProto 永远持有已解析模型，未知名在 FuncProto::decode
   映射到 createUnknownModel，fspec.cc:4697）。在 evalfp 就绪且无模型时
   安装默认模型——锁只防替换，此处是恢复不变量而非替换。
2. **Step 3 锁定输出读插入**（cc:4637-4649）：isOutputLocked 且返回类型非
   void 时，为每个存活非 halt RETURN 插入输出存储读作为最后输入
   （`opInsertInput(op, newVarnode(size,addr), numInput())` +
   `updateType(type,true,true)`）——这是返回值数据流边，heritage 把自由读
   重命名到到达定义得到 `return <value>`，并启用 ActionReturnSplit 的
   分支 RETURN。之前只移植了 else 臂（initActiveOutput），导致所有
   DWARF/PLT 锁定签名函数反编译为无值 `return;` 且产值 op 被 dead-code。
   storage 解析在 fspec.rs `locked_output_storage`（见 fspec.md）。

## ActionFuncLink::apply placeholder 尾巴（coreaction.cc:1477/1511-1513，本次新增）

funcLinkInput 尾巴：`spacebase = fc->getSpacebase()` 在模型 input 列表含
stack pentry 且无锁定 stack 参数占用 placeholder 角色时非空（Rugra 的锁定
路径仅寄存器参数，角色永不占用），对每个建模 call 追加 stack-pointer
placeholder LOAD 作为最后一个 CALL 输入（`fc->create_placeholder`）。该输入
使 CALL 满足 `usesSpacebasePtr()`，`RuleIndirectCollapse` 的 else-if 分支
（ruleaction.cc:3223）据此折叠 unknown-effect guard INDIRECT。

## 2026-08-25：ActionSwitchNorm 去自创预扫（JUMPTABLE-PIPELINE-0001 段2）

`ActionSwitchNorm::apply`（coreaction.cc:4548-4560）不再在 apply 开头做原地
`jumptable::recover_jump_tables(fd)` 预扫——那是 flow 期恢复未接线时代的自创补丁。
oracle 中所有 `data` 上的 JumpTable 均在 flow 追踪期
（`FlowInfo::recoverJumpTables` → `Funcdata::recoverJumpTable`）已恢复完毕，
该 Action 只做规范化（matchModel/recoverLabels/foldInNormalization/foldInGuards，
fold 阶段仍为 L2 登记缺口）。apply 现镜像 cc:4559 恒返 0（NO_CHANGE），
unlabelled 计数仅保留本地变量。

## 2026-08-25（ACTIONDW-COPYDEF-MARKING-0001）：ActionDirectWrite 收集段四偏差修复

`ActionDirectWrite::apply`（coreaction.cc:1350-1434）收集段对齐修复，四处真偏差（MAINDIFF-DEADSTORE-0001 诊断发现）：

1. **COPY-def 误标（cc:1381-1394）**：oracle 对 COPY 输出收集期**不**标 directwrite（isStackStore 追踪例外）；旧代码 `else if def_opc != PIECE && != SUBPIECE` 把 COPY 一起标+入队。现按 oracle 分支序：COPY 单列，仅 `isStackStore()` 时做源追踪。
2. **possibleInputParam 分支缺失（cc:1368-1371）**：非 persist/spacebase 输入若 `FuncProto::possibleInputParam` 为真则标记。新增 `FuncProto::possible_input_param`（fspec.cc:4366-4387 完整前奏：dotdotstat 短路 + voidinputlock 门 + 锁定参数 justifiedContain==0 判定；Rugra 无锁定参数状态时该环 inert，与兄弟移植 characterize_as_input_param 同一降级口径）。
3. **isStackStore 源追踪（cc:1382-1393）**：COPY 输出带 stack_store flag（RuleStoreVarnode 设置）时，追源**单层**解一层 COPY，源 def 为 marker（INDIRECT）则标记+入队；两层 COPY 链不标记（oracle 单层解开的边界）。
4. **marker(INDIRECT) 收集分支（cc:1401-1408）**：`!propagateIndirect && INDIRECT` 时，in(0) 地址≠输出地址（活动 COPY）或输出 persist → 标记但**不**入队。结构性新增 `propagate_indirect` 字段（coreaction.hh:244），protorecovery_a=true / protorecovery_b=false 双注册（action.rs 对应 cc:5497/:5498/:5680/:5681）。

Phase-2 推播门（cc:1427-1429）同步修正为 `propagate_indirect || !INDIRECT || is_indirect_store`（旧代码硬编码 false 且注释自相矛盾）。fixture `tests/oracle/actiondw_copydef_1204` 锁定全部六 case 双注册行为（24 records 字节一致 MATCH），包括 oracle 深层语义：**分支④的 no-push 标记使 phase-2 的 `!isDirectWrite` 守卫跳过 mark+push，永久阻断经该 varnode 的 taint 传播**（w_out=0 判别）。
### ActionUnreachable 参数对齐（2026-08-25，HTTPD-STRIPPREFIX-ADDDESCEND-0001）
- `ActionUnreachable::apply` 调用
  `remove_unreachable_blocks(true, false)`（issuewarning=true，
  checkexistence=false 走缓存 BLOCKS_UNREACHABLE 标志），对齐
  coreaction.cc:3460。
## ActionInferTypes setTypeRecoveryExceeded 接线（RULE-PTRARITH-ADDTREE-0001，本次新增）

localcount==7 告警分支补上 `data.setTypeRecoveryExceeded()`（coreaction.cc:5393，
此前只 warningHeader + 计数）。该旗标是 RulePtrArith buildTree 在传播
停止后自行给新建 PTRADD/PTRSUB 输出盖章（assignPropagatedType）的前提。
同轮次另确认：PTRSUB/PTRADD/INT_ADD 指针臂依赖 `fd.arch.types`
TypeFactory（`propagateAddIn2Out` downChain），E2E 驱动侧
`worker_architecture()` 现按 `Architecture::init`（architecture.cc:1398
buildTypegrp + :1269 ELEM_DATA_ORGANIZATION + :1350 setupSizes）装配
带 `<data_organization>` 解码的真实工厂——此前工厂缺失使全部指针传播臂
静默失效，RulePtrArith 因此从未触发。
## ActionInferTypes LOAD/STORE 读者派发（TRI2-STORESPLIT-WHOLESTRUCT-0001，2026-08-26）

op-centric 遍历的 `CPUI_LOAD | CPUI_STORE` 臂重写为读者派发：每个非
annotation 输入（slot 1/2；slot 0 spaceid 是 annotation 被
`is_annotation()` 跳过，对应 buildLocaltypes 的 `vn->isAnnotation()`
continue，coreaction.cc:5018）以 `merge_min_type_order` 播种
`getBase(size, TYPE_UNKNOWN)`——即 `Varnode::getLocalType`
（varnode.cc:897-936）descend 遍历 `op->inputTypeLocal(i)` 的 typeOrder
最小值在 op-centric 走向上的投影。决定性语义：

- **无 override**：`TypeOpLoad::getInputLocal`/`TypeOpStore::getInputLocal`
  在 typeop.hh:269/:279 均为注释行，两 opcode 的每个输入局部类型都是
  `TypeOp::getInputLocal` 基默认 `tlst->getBase(in.size, TYPE_UNKNOWN)`
  （typeop.cc:266-276）。超过 max_base_type_size 的值的该基类型是
  unknown1[N] 数组（type.cc:3652-3657），不是 `IntTypes::sized` 饱和的
  8 字节 long——后者令 `testDatatypeCompatibility` 的 piece 走查
  （subflow.cc:2314-2330）无法覆盖全部 outType 分量，`RuleSplitStore`
  （subflow.cc:2991-3004）便不触发整结构常量 STORE 拆分（progressbarinit
  `*bar=0` → golden 5 行逐字段清零）。
- **最小值合并**：`merge_min_type_order` 保持 varnode.cc:926-931 的
  `0 > newct->typeOrder(*ct)` 严格小于才替换——unknown 播种永不逐出更
  具体的读者播种（例如 CALL 锁定参数）；PTRSUB field token 不属于 local
  seed，而由后续 `ActionSetCasts::castOutput` 消费。wip 2647faac 的
  STORE 地址 `pointer-to-pointee` 单向 or_insert 播种（Ghidra
  buildLocaltypes 无此 op 中心播种）一并移除。
- **FILE*+8 不误拆**：字段指针 STORE 的 outType 经 `getValueDatatype` 的
  `getExactPiece`（subflow.cc:2910-2962）恢复出的分量与 8 字节标量值
  兼容性不成立时不拆分——my_fwrite `stream->_IO_read_ptr` 保持单
  STORE/LOAD。

## ActionSetCasts 类型转换输入/输出令牌 + MarkImplied cover + ReturnSplit（MYFWRITE-TEMPVAR-0001，2026-08-26）

1. **castInput 专用臂**（coreaction.cc:2662 `getInputCast` 派发）：LOAD 走
   `load_input_cast`（typeop.cc:440-470，slot 1 地址指针转换，`*(char **)stream`
   形态），STORE 走 `store_input_cast`（typeop.cc:520-555，slot 1 尺寸失配转
   指针/slot 2 castStandard 转值，`(char *)__s` 形态）。专用臂返回值即最终
   cast 决策（cc:2662-2669 不再二次门控），插入 CAST op 于目标 op 之前。
2. **castOutput LOAD 令牌**（typeop.cc:472-485 `getOutputToken`）：LOAD 的
   token 是地址输入 high 类型的 pointee（尺寸匹配输出时），否则输出自身
   high——这是 `(FILE *)stream->_IO_read_ptr` 输出转换的来源。
3. **ActionMarkImplied**（coreaction.cc:3379-3395）：LOAD 跨 STORE 判定改用
   cover INTERIOR 包含（cover.cc:413-424 max==2 形态 + boundary==0），替换
   原整块保守拒绝；同 spacebase 偏移的交叉仍保守拒绝（isPossibleAlias
   未移植）。CALL 交叉判定同步改 interior-only（尾部边界不算交叉）。
4. **ActionReturnSplit**（blockaction.cc:2280-2315）：重写为 marked-edge
   选择走 + `fd.node_split`（此前为手工合成 RETURN，破坏 staged structurer
   稳定索引不变量的替代路径已弃用）；count 经 apply 返回值承载（Action
   count-bridge 约定）。

## 2026-09-23（SETCASTS-COPYINPUT-0001）：castInput 补 CPUI_COPY 专用臂（TypeOpCopy::getInputCast）

`ActionSetCasts::cast_input` 的 `getInputCast` 虚派发镜像（coreaction.rs
cast_input 的 `match op.opcode`）此前没有 COPY 臂——COPY 落进
`input_metatype` 兜底返回 None（输入永不插 cast），golden 的 RHS 前缀
cast 整族缺失。本臂逐行镜像 typeop.cc:397-403：

- **`copy_input_cast`（Ghidra: typeop.cc:397 TypeOpCopy::getInputCast）**：
  `reqtype = op->getOut()->getHighTypeDefFacing()`（**输出**的 def-facing
  high 类型——不是基臂的 `inputTypeLocal` 基类型），`curtype =
  op->getIn(0)->getHighTypeReadFacing(op)`（覆写直接读 slot 0，忽略调用
  方传入的 slot 参数；COPY 一元），`castStandard(reqtype,curtype,false,true)`
  决策。与基臂 typeop.cc:295 的另两处差异：无 annotation 守卫（该守卫在
  Rugra 侧位于 cast_input 派发后统一应用）、无 inputTypeLocal 查询。
- **生效形态**：COPY(组符号字段件, SUBPIECE) 之间插 CAST op → printc 的
  opTypeCast 渲染 `(type)` 前缀——main 的 10×`glob.literal[i] = (char *)
  in_stack_..._X_8_;`、8×`glob.pattern[i].content = (union_5a7)auVarXX._8_16_;`
  （union 名 `union_5a7` vs oracle `anon_union_16_3_...` 是已登记的
  DWARF-ANON-TYPENAME-0001 命名残差，非本臂逻辑）。
- **配套修复（type_system/cast.rs `cast_standard_full`）**：req/cur 元类型
  先做 Ghidra 内部呈现规范化（`Enum→Int`、`PartialEnum→Uint`，oracle 依据
  type.hh:491-494/type.cc:1475，详见 docs/api/type_system/cast.md 2026-09-23
  段）——否则枚举 req/cur 落进 cast.cc:339-389 的 default 臂恒判需 cast，
  main 的 `.type` 行与 `(int)::config.httpreq` 会过cast。
- **暴露的既有类型态残差（登记 DWARF-SYMFIELD-TYPESTATE-0001，非本臂
  逻辑缺陷）**：COPY 臂按当前类型态正确插出 `(_IO_FILE *)stdout@@`/
  `(undefined8)…` 等 cast，golden 对应行因符号/字段类型态不同（stdout
  FILE* 符号类型、pattern[8].content union 字段链）无 cast 或名不同。

## 2026-08-26（TRI2-CALLOUT-ASSIGN-0001）：ActionActiveReturn::apply 完整移植（collectOutputTrialVarnodes/buildOutputFromTrials 接通）

`ActionActiveReturn::apply`（coreaction.cc:1773-1792）从简化版升级为完整链：

- **checkOutputTrialUse（fspec.cc:5661-5676）**：先 `collectOutputTrialVarnodes`
  （fspec.cc:5536-5553）——CALL 已有输出则抛 `LowlevelError`（Rugra：整 apply
  返回 `Err(Lowlevel)`，driver 侧 pipeline ABORTED 等价观察）；`trialvn` 为
  dense `Vec<Option<Varnode>>`，长度=`getNumTrials()`，`None`=null 槽位；
  以 `PcodeOp::previousOp`（op.cc:344，块内 basiciter 前驱，块首即停）回走
  CALL 前驱 op 链，遇首个非 INDIRECT break；对 `indirect_creation` 标记的
  INDIRECT，其输出经 `ParamActive::whichTrial`（fspec.cc:1982，重叠匹配+`sz<=1`
  早退 quirk）定位 trial 槽，填入 trialvn 并**即时** `setAddress(vn addr,size)`
  （fspec.cc:5550-5552——Rust 经 stable Arc owner 绕开 fd 借用分裂，保持
  Ghidra 循环内即时重置序，后续 whichTrial 读到已重置地址）。随后逐 trial：
  `trialvn[i]` 非空 → `markActive()`，空 → `markInactive()`（不调 markNoUse）；
  已 checked → `LowlevelError`。
- **deriveOutputMap（coreaction.cc:1785）**：`fc.derive_output_map()` 既有委托。
- **buildOutputFromTrials（fspec.cc:5770-5860）**：按 `curtrial.getSlot()-1`
  （registration 位置，survive sortTrials）索引 trialvn 收集 finalvn；`break`
  于首个非 used；`deleteUnusedTrials()` 重编 1..N；==1 时 def 入 deletedops +
  `opSetOutput(op, finaloutvn)`；==2 时 joinReverse 选 hi/lo（`findPreexistingWhole`
  未移植——TODO(FSPEC-OUTPUTJOIN-0001)，恒走 constructJoinAddress+SUBPIECE 对）；
  尾部统一 destroy：`opDestroy(dop)` + `deleteVarnode(in0/in1)`。
- **count 通道**：`count += 1`（coreaction.cc:1788）经 `pub count` +
  `take_count_delta()` 外化（同 ActionMultiCSE/ActionMarkImplied 约定，
  perform 的 `lcount<count → count_apply` 观察链）；apply 返回值保持 0。

**根因背景**：progressbarinit `curl_getenv` 输出丢失 = callspec proto 被错误
播种为 caller 的（DWARF 锁定）`fd.funcp` → `funcLinkOutput` 走 locked 分支跳过
`initActiveOutput()`（coreaction.cc:1571-1572）→ 无 trial → CALL 无输出 →
裸语句形 `curl_getenv(...);`。修复后 RAX trial 经 heritage guardCalls 的
KilledByCall INDIRECT 收集，CALL 输出恢复三下游（EQUAL/strtol/free），
golden 形态 `__nptr = (char *)curl_getenv("COLUMNS");` 达成。

## ActionFuncLink/ActionActiveParam 调用实参收敛（MAINDIFF-CALLPROTO-0001，master 并入）

- `func_link_input(fd, fc_idx, op)`（coreaction.cc:1474-1513 `funcLinkInput`）
  重写：`(!inputlocked)||varargs` 才 `init_active_input`（cc:1482-1483）；
  locked 路从**锁定原型**参数表构造 stub CALL 输入
  （`newVarnode(sz,param->getAddress())` cc:1507-1508，Rugra 侧保留模型分配的
  coarse register/stack 空间；stack formal 走 `op_stack_load`，非 stack formal
  走 explicit-space Varnode 创建；varargs 形参另注册
  fixed-position active trial cc:1488-1493）。硬编码
  `known_param_count/known_param_types` 表（glob_url=2 与 DWARF 3 冲突的
  根因）从本函数删除；表中残留仅 ActionCallParams/ActionInferParams 域。
- `ActionFuncLink::apply`（cc:1575-1586）：`known` 谓词（⑤）删除——
  trial 注册的唯一所有者是 `Heritage::guard_calls`（heritage.cc:1495-1509，
  heritage.rs 已移植），apply 内集中式重注册环移除；placeholder 尾
  （cc:1511-1513 createPlaceholder）保持在 apply。
- `ActionActiveParam::apply` finalize（cc:1752-1755）：callspec owner Arc
  先克隆再持写锁，使 `build_input_from_trials(fd, op)` 的 opSetAllInput 尾
  可与 `&mut fd` 共存；序列 resolveModel → deriveInputMap →
  buildInputFromTrials → clearActiveInput 与 oracle 逐行对应。
- `test_action_funclink_initializes_active` 更新为 oracle 行为：unlocked
  callee 仅 initActiveInput（0 trial），trial 由 heritage guardCalls 注册。

## ActionInferTypes STORE 值局部类型改用工厂 getBase（TRI2-STORESPLIT-WHOLESTRUCT-0001，2026-08-26）

STORE 值输入（slot 2）的局部类型种子从 `IntTypes::sized(size)`（8 字节
`long` 封顶）改为工厂 `getBase(size, UNKNOWN)`：Ghidra 的
`Varnode::getLocalType`（varnode.cc:900-936）对每个读者取
`op->inputTypeLocal(i)`，`TypeOpStore` 不覆写 `getInputLocal`
（typeop.hh:279 注释掉），走默认 `TypeOp::getInputLocal`
（typeop.cc:271-275）= `tlst->getBase(自身尺寸, TYPE_UNKNOWN)`；尺寸 16
经 type.cc:3652-3656 变为 unknown1 数组。指针→值方向的
`TypeOpStore::propagateType`→`propagateFromPointer`（typeop.cc:206-228）
只跨精确尺寸或部分枚举匹配，不会把 16 字节常量压成 8 字节整型。全宽
unknown 局部类型使 `testDatatypeCompatibility` 的分段游走
（subflow.cc:2319-2334）覆盖 outType 每个字段，RuleSplitStore
（subflow.cc:2991-3004）得以把整结构常量 STORE 拆成逐字段 STORE。
- `ActionSetCasts::cast_output` tokenct 计算补 CALL/CALLIND 臂（对齐
  coreaction.cc:2541 getOutputToken → TypeOpCall::getOutputLocal
  typeop.cc:720-735 / TypeOpCallind::getOutputLocal typeop.cc:776-789）：
  callspec 的 LOCKED 非 void 输出类型，否则 TypeOp 基类默认
  `getBase(out_size, TYPE_UNKNOWN)`（typeop.cc:261-265）。该 token 使
  unlocked（默认 proto）call 输出打印为 `__nptr = (char *)curl_getenv(...)`
  —— token undefined8 对输出 high char* → castStandard(char*,undefined8) →
  CALL 后插 CAST；locked 且类型等于输出 high（strtol→long）命中
  type_equal 短路不插。CALLIND 经 get_call_specs_of_op（slot-0 Iop 注解,
  TYPEOP-FSPEC-SPACE-0001）取 callspec，等价 typeop.cc:782 getCallSpecs。
## 2026-08-27（MAIN-POSTSTRUCT-SPIN-0001）：ActionPrototypeWarnings 空间名表接线

`ActionPrototypeWarnings::apply`（coreaction.cc:4885-4892）的覆写消息
生成从空名表改为按锁定 x86-64 语料空间表构造 9 项名字向量
（`AddressSpace::spec_space_name`，索引 0-8），再交
`Override::generate_override_messages`（override.cc:279）。
`Heritage::bump_deadcode_delay`（heritage.cc:2580）现在是生产级插入者：
match_url 触发后输出 oracle 同文的
"Restarted to delay deadcode elimination for space: register" 头注释。
此前"消息列表可证为空"的前提随 deadcode-delay override 接线失效。

## MYFWRITE-TEMPVAR exploratory (2026-08-27)

ActionActiveReturn 试验性补充了 preceding INDIRECT trial 收集与
`build_output_from_trials` 调用（oracle `coreaction.cc:1773-1792`）；
ActionMarkImplied 增加 LOAD/STORE 覆盖守卫。尚待在 BlockCopy 活委托基线
上完成 E2E 验证。

## FSPEC-CALLPROTO-LATENT-0001 R2 spacebase leg (2026-08-27)

`ActionFuncLink::func_link_input` now mirrors oracle `coreaction.cc:1494-1512`:
locked parameters in stack/spacebase storage are created through
`Funcdata::op_stack_load`; the first non-varargs stack parameter claims the
spacebase-placeholder flag, subsequent parameters are appended as loads, and
a remaining callspec spacebase creates the canonical placeholder input.
Register/non-spacebase parameters retain their coarse address-space varnodes.
The locked x86-64 GCC scalar register/first-stack, varargs, unlocked and
placeholder-slot paths are covered by `ACTION-FUNCLINK-INPUT-1204`. Full
Architecture-owned Address identity, ModelRules/non-scalars and
`func_link_output` remain outside the approved projection, so this module
stays L2.

## 2026-08-28：GETSTR-FUNCLINK-SPACE-0001 限定证据

锁定 runner `tools/run_action_funclink_input_oracle.sh` 在 Ghidra 12.0.4
`e40ed130…` 与隔离 Rust comparand 上输出 101 records / 9268 bytes，双方
stdout SHA-256 均为
`6cd6ad2eff1d290c7906c6b40cd1ce7d2c818a0939f655ef6260d16b99ef4c0f`，
raw diff 为空。批准范围仅为单 Architecture、x86:LE:64、GCC 默认模型的
coarse `(AddressSpace, offset, size)` input 可观察投影：locked
register/first-stack、locked register-only、locked varargs、unlocked、trial
flags/pass/fixed-position、natural/synthetic placeholder、CALL/bank 顺序和
placeholder 前后 trial 映射。

`ActionFuncLink::apply` 不再现场创造 callspec 或使用已知函数字符串表。
完整 `Address(AddrSpace*,offset)` 身份、generic newVarnode 属性尾、
non-scalar/ModelRules 以及 `func_link_output` 的 extension/error 分支仍为
`MISMATCH`/`UNTESTED`；fixture overall 正确保持 `UNTESTED`。

## 2026-08-29：INFERTYPES-SETTLE-0001 — temp 类型经 TypeFactory 规范化（interned-pointer 收敛契约）

`ActionInferTypes` 的 `writeBack`（coreaction.cc:5043-5060）依赖
`Varnode::updateType` 的 C++ 指针比较 `type == ct`（varnode.cc:459）判收敛。
oracle 里该比较成立的前提是**所有流经 temp 系统的 `Datatype*` 都出自
TypeFactory 的 intern**：`buildLocaltypes` 的种子来自
`getOutputLocal/getInputLocal`（终归 `tlst->getBase`，typeop.cc:264），每个
`propagateType` override 的产物也经工厂构造（`TypeOp::propagateToPointer`
终归 `t->getTypePointer`，typeop.cc:197）。Rugra 的 temp 生产线含免工厂构造
（COPY-spacebase 指针臂、`typeop::propagate_to_pointer`），裸 `Arc::ptr_eq`
跨轮永假，`writeBack` 每轮报 change，`localcount` 撞 7 触发
「Type propagation algorithm not settling」（coreaction.cc:5390-5392，
myprogress 实证：同名 `old==new` 而 Arc 指针不同）。

修复：新增 `canonicalize_temp_type`（对应 oracle 全类型经
`TypeFactory::findAdd` 规范化的事实，type.cc:3412），在两个 temp 写入
choke point 生效 —— `build_localtypes` 的 `temps.insert`（cc:5035
setTempType）与 `propagate_type_edge` 的 `temps.insert`（cc:5108）。规范化
保守：命名 Base 走 `get_base_named`（nametree name+id intern，type.cc:3667），
无名 Base 走 `get_base` 且要求 size/metatype/name 三相等；命名 Pointer 先
`find_by_name` 命中且结构相容才替换（Ghidra 侧不符会 raise
"Trying to alter definition of type"，type.cc:3423；Rugra 保守保留原 Arc，
稳定生产方 Arc 同样收敛），无名 Pointer 递归规范化 pointee 后走 `get_ptr`
（type.cc:3867-3883）。fixture：`infertypes_settle_1204`（双侧 MATCH，
8 轮 apply 的 metatype/size 表 + 实例身份稳定性逐字节一致）。

证据边界：本切片只证明 interned 收敛契约；`ACTION-INFERTYPES-DISPATCH-0001`
等完整 dispatch 闭包状态不变。

## 2026-08-29：类型推断指针构造改匿名（PTRSUB-TYPED-DECL-RESIDUAL-0001）

`make_pointer_type`、`make_ptr` 与 COPY-spacebase 指针臂（TypeOpCopy::
propagateType 的 spacebase 分支，typeop.cc:411-423）此前构造带组合名
（`"char *"`）的 Pointer。Ghidra 对应路径全部终归 3-arg
`TypeFactory::getTypePointer`（type.cc:3867-3875，空名）——推断产物的指针名
在任何 Ghidra 输出中都不可观测。组合名使这些指针成为命名单层指针，被忠实的
printc 声明渲染为 `char * pcVar5`（oracle
printc_anonymous_pointer_decl_1204 named_ptr_contrast 形），偏离 golden 的
`char *pcVar5`。三处均改 `TypePointer::new`（空名 + calc_submeta +
inheritable flags）。同批：typeop.rs `propagate_to_pointer`、debugproto.rs
`parse_c_type`/`pointer_type`/DWARF 数组（见各自 docs/api 文件）。
E2E：curl 全语料 star-blank 声明 58 → 0，compare defects=0/numbering=0。

## 2026-08-29:nodejoin 臂移除冗余 build_dom_tree(R-NODEJOIN-CROSSREVIEW 问题4)

structure_reset(twin 内)已执行 calcForwardDominator(funcdata_block.cc:712),新块为 append 索引未变;
额外的 build_dom_tree 调用对未突变 CFG 幂等且不可观测,按复核建议删除。

## 2026-08-29:NODEJOIN-F4-MATCH-GATES-0001 findDups 全门补齐

ActionNodeJoin::apply 的 match 谓词此前只查双方 last op 是 CBRANCH + 同条件短路,
不同条件菱形**无条件 join**(over-join)。新增 `nodejoin_find_dups`(coreaction.rs,
Ghidra: blockaction.cc:1912 ConditionalJoin::findDups)按 oracle 顺序补齐全部门:
1. `isBooleanFlip()` 任一 cbranch 置位即拒(cc:1920-1921,"flip hasn't propagated
   through yet");
2. `vn1 == vn2` 是**完整 match**(cc:1926-1927,见 F3);
3. 双方条件必须 `isWritten()`(cc:1930-1931)、非 `isSpacebase()`(cc:1932-1933);
4. `functionalEqualityLevel(vn1,vn2)` 必须 ∈ {0,1}(cc:1936-1938);
5. vn1 定义 op 不得为 SUBPIECE/COPY(cc:1939-1941)。
通过后返回 `MergeNeeded`(cc:1943 mergeneed 注册由 ConditionalJoin 状态承接,F2)。
测试:`test_nodejoin_finddups_gates`(booleanFlip×3/unwritten/spacebase/res<0/
res>1/SUBPIECE/COPY 全拒 + 相同 INT_LESS 正对照 join 1 次且块数 +1)。

## 2026-08-29:NODEJOIN-F3-SAMECOND-FULLJOIN-0001 同条件菱形执行完整 join

旧代码把 findDups 的 `vn1 == vn2` 快路径(cc:1926-1927)误读为 "data-flow-only",
same-cond 菱形只 count+=1 不做任何 CFG/op 变换。oracle 语义:vn1==vn2 是**完整
match**,返回 true 后调用方照样走 `ConditionalJoin::execute` 全部四步
(cc:2354-2358 match→execute→clear),仅 mergeneed 为空(setupMultiequals 无新
MULTIEQUAL、moveCbranch 的 `vn1!=vn2` 查表走 else 分支直接用 vn1)。现
`NodeJoinFindDups::SameCondition` 与 `MergeNeeded` 一样落入 nodeJoinCreateBlock
路径。测试:`test_nodejoin_counts_diamond_candidate` 追加断言(块数 4→5)。

## 2026-08-29:NODEJOIN-F2-EXECUTE-STEPS-0001 ConditionalJoin::execute 四步齐全

新增 `ConditionalJoin` 状态结构(coreaction.rs,Ghidra: blockaction.hh:234 ConditionalJoin):
mergeneed(`map<MergePair,Varnode*>`)以 Vec 按 (side1.createIndex, side2.createIndex)
有序维护 = MergePair::operator<(cc:1898-1906)的 C++ map 语义(等键覆盖/排序迭代)。

`ActionNodeJoin::apply` 的 join 路径现执行全部四步(cc:2094-2102):
1. nodeJoinCreateBlock(cc:2097,已有 twin)+ 此前按 match 顺序(cc:2079-2082)先算
   a_in1..b_in2;
2. `setup_multiequals`(cc:2023-2040):mergeneed 每对建 MULTIEQUAL(cbranch1 地址,
   side1=slot0/side2=slot1,newUniqueOut 输出)按 map 序 opInsertEnd 进 joinblock;
3. `move_cbranch`(cc:2043-2057):cbranch1 opUninsert→opInsertEnd 进 joinblock,条件
   输入换成合并输出(vn1==vn2 时保持 vn1),cbranch2 opDestroy;
4. `cut_down_multiequals` ×2(cc:1981-2019):exit 的 MULTIEQUAL 去掉 hi 槽输入、lo 槽
   换成合并输出;1 输入的 MULTIEQUAL 转 COPY 并 opInsertBegin 回块首。

match 尾部补 `check_exit_block` ×2(cc:1954-1972,cc:2088-2089):exit 里从两根块
流入不同 Varnode 的 MULTIEQUAL 对注册进 mergeneed;findDups 失败路径 condjoin.clear()
(cc:2084-2087)与 execute 后 clear()(cc:2357)同样移植。

关键发现(双侧一致):nodeJoinCreateBlock 尾部 structureReset→structureLoops→
findSpanningTree 会把块表**重排为逆后序并重索引**(Ghidra block.cc:1015-1137
`list = rpostorder`)——joinblock 不在追加位置;测试按 JOINED_BLOCK flag 定位。
测试:`test_nodejoin_execute_runs_all_four_steps`(joinblock=[ME,ME,CBRANCH] 序、
cbranch1 读合并输出、b2 cbranch2 销毁、exit [COPY,INT_ADD] 且 COPY 读 (v1,v2) 合并)。

## 2026-08-29:NODEJOIN-F5-DYNAMIC-SIZE-0001 外层循环动态 graph.getSize()

`ActionNodeJoin::apply` 外层改为 `while i < fd.bblocks.get_size()`(cc:2334
`for(int4 i=0;i<graph.getSize();++i)` 每次迭代重新求值)。join 会 append 新块
(尺寸+1)且 structureReset→findSpanningTree 重排块表(block.cc:1015-1137),冻结的
pre-loop 尺寸会漏访问 joinblock —— 而它持有移动后的 cbranch1 和两条出边,自身
可再次 join。测试:`test_nodejoin_dynamic_size_rejoins_joinblock`(三同条件菱形
→ count==2、两个 JOINED_BLOCK;oracle 侧 I_triple 同为 count=2,见
nodejoin_condjoin_1204 双侧 fixture)。

## 2026-08-29:NODEJOIN F2-F5 簇差分收尾
E2E curl(124/124,0 panic):defects=1(getparameter 空 else,他人项,不变)、
numbering=0、skeleton 2911→2884(−27,向 golden)。per-func:next_url 150→134、
getparameter.constprop.0 678→669、my_get_token 57→55,其余 121 函数零变化。
双侧 fixture nodejoin_condjoin_1204 9/9 MATCH(sha256 a5fdf6f3...)。

## 2026-08-30:ConditionalJoin match 补 cc:2076 同目标门(R-NJF234-CROSSREVIEW MISMATCH #1)

复核 REJECT 项:Ghidra blockaction.cc:2076 `if (exita == exitb) return false;` 在 Rugra 缺失。
可达性:CBRANCH 目标==fallthru 时 flow.cc:960-967 无条件登记两条同块出边(仅 BRANCHIND 去重),
构造出 sizeOut==2 且双出口同块的输入;Ghidra 拒绝一切 match,缺门则对同一边做两次
removeEdge/moveOutEdge 手术 → find_out_index panic 或 CFG 损坏。修复=计算出 exita/exitb 后
立即 `Arc::ptr_eq(&exita,&exitb) → continue`。当前语料不触发(单向加门,零新 join 路径)。

## 2026-08-30:ActionDoNothing 忠实重写(HTTPD-EMPTYELSE-DONOTHING-0001)

httpd 空 else 缺陷族根因:旧实现调 `splice_block_basic`(其自创单入守卫拒绝一切
join 目标),而 Ghidra `ActionDoNothing::apply`(coreaction.cc:3466-3490)走
`removeDoNothingBlock` → `blockRemoveInternal`(funcdata_block.cc:254-320,支持多入
目标:pushMultiequals + 出块 MULTIEQUAL 输入拼接 + removeFromFlow 边重定向)。
守卫补齐:`BlockBasic::isDoNothing` switch-target 门(block.cc:2604-2613,辅助
`block_is_do_nothing`)、自环 f_donothing_loop 置位+警告(block.hh:100)、
`BlockBasic::unblockedMulti`(block.cc:2534-2571,辅助 `block_unblocked_multi`,
MULTIEQUAL 同一性解析)。移除返回 CHANGE 镜像 count+=1,驱动 rule_repeatapply
fullloop 重跑 → mainloop → ActionBlockStructure 在 structureReset 清空后的
sblocks 上对净化 CFG 二次结构化(oracle 探桩实证:
ap_make_dirstr_prefix 第一轮 IfElse MATCH(空 fc),donothing 删 0x2e8d6/0x2e902
后第二轮 PROPERIF MATCH 单臂 if)。测试:
`test_action_donothing_removes_join_targeted_jmp_island`。
E2E:httpd defects 7→3、skeleton 2317→2257;curl 3076/0/0(基线 3089,−13)。
机制 C 白名单(主管线 Action):Cross-Review PENDING。

## 2026-09-01:ActionPrototypeTypes eval-model 门裁决(PLTSTUB-WARNLOSS-0001)

裁决(salvage regb `3d042eb` vs master c95b845 立场):**分支方向正确**。oracle
coreaction.cc:4614-4619 是单一合取——`(!isModelLocked()) &&
!hasMatchingModel(evalfp)` 才 `setModel(evalfp)`,model-locked 原型**永不**被绑
evaluation model,"locked ⇒ model 非空"的不变量由签名 decode 边界维护
(fspec.cc:4690-4698:未识别约定名 → createUnknownModel,即 UnknownProtoModel
克隆 default 行为且 isUnknown()=true;architecture.cc:1159-1166,保留名
"unknown" setPrintInDecl(false)),locked unknown 身份因此存活到
ActionPrototypeWarnings(cc:4901-4908)发射
`Unknown calling convention -- yet parameter storage is locked`。master 旧
`!has_model()` 臂(注释主张 "lock only guards replacement")是该合取的反面,
静默修复 modelless+locked 状态并摧毁 unknown 身份——已删除,回归单一合取门
(含 modelless 分解:unlocked+modelless ⇒ has_matching_model=false ⇒ 绑定,
与 Ghidra 行为一致;modelless+locked(仅 Rugra 可构造)保持身份不修)。
`set_input_lock(true)`⇒modellock 耦合已在 fspec.rs 与 fspec.cc:3924-3925
("Locking input locks the model")逐字一致,是 locked 覆盖层保持身份的承载机制。

差分:行为 delta 仅 modelless+locked 分支(不再绑默认模型);master E2E 该状态
经 set_arch named-ctor 绑定(funcdata.rs:1143-1146)+ from_model_carrier 播种
不再出现,curl E2E 3090/0/0 零漂移。**warning 51 vs 24 的剩余差集不在本 action**:
26eee4a 起 LibcSignatureTable::locked_proto 与 DebugDb::locked_proto 均以
from_model_carrier/set_pieces 把 defaultfp 模型名装进 locked 原型(PLT 24 桩 +
void-DWARF main_init/main_free/hugehelp 三函数),unknown 身份在播种层即丢,
登记 PLTSTUB-WARNLOSS-0001 残留(debugproto.rs 两处 builder 需按
fspec.cc:4690-4698 语义钉 "unknown" 约定名,行为 Arc 保留为克隆)。
fspec create_placeholder 双守卫(pltstub 9f14522)证伪:Ghidra fspec.cc:4849-4857
本体无守卫,cc:1482-1512 caller 侧门控(setplaceholder=varargs、首个 locked
stack param 置 spacebase=NULL、cc:1511 仅非空才 create)已在 master
func_link_input(coreaction.rs:9703-9774)忠实落地,再入库内守卫=非 oracle 层。

## 2026-09-22：JUMPTABLE-TABLEAPI-0001 P0-A — ActionSwitchNorm 真身接线

`ActionSwitchNorm::apply`（coreaction.cc:4548-4565）从空壳升级为忠实移植：
- 每个未 isLabelled 的 JumpTable：`match_model` → `recover_labels` →
  `fold_in_normalization`，count+=1；match/recover 的 LowlevelError 消息原样
  经 `Error::Lowlevel` 穿透 apply（Ghidra 异常传播语义）。
- 所有表（含已标注）跑 `fold_in_guards`，成功则 `get_structure().clear()`
  （重做结构）并 count+=1。
- 仍返回 0（NO_CHANGE）——Ghidra 本 action 不向框架报告状态变化。
- 跳表快照迭代（Arc clone）等价 Ghidra 按下标遍历（fold 只追加地址条目，
  不增表）。表级 API 与 foldIn* 语义修正明细见 docs/api/jumptable.md。

## 2026-09-22：ACTION-TRAVERSAL-144-0001 — gatherReturnGotos 忠实 goto 前驱检测

`ActionReturnSplit`（blockaction.cc:2264）的 goto 前驱检测从替代实现换成 Ghidra
原语义（blockaction.cc:2205-2234）：

- **删除的替代**："入边源块以 BRANCH/CBRANCH 结尾即算 goto 前驱"——把结构化
  if/else 边也当 goto 边，next_url R2 尾误开火 8 记录，余震 = R3 p8 COPY 链清理 +
  blockstructure×5 + p9 condnegate/notdistribute/boolnegate 有阻尼振荡，fullloop
  多跑第 4 轮（TRAVERSAL144 §3-§5）。
- **移植的原语义**：对 RETURN 块每条入边，源块经 `getCopyMap()` 进入结构树并走
  祖先链；祖先为 `t_goto` 且 `gotoPrints()` 成立、或为 `t_if` 且 if-goto
  `getGotoTarget()` 非空，且目标经 `while(ret->getType()!=t_basic)
  ret=ret->subBlock(0)` 下探到**原始 basic 块**后与 RETURN 块指针同一（cc:2215-
  2229；`BlockCopy::subBlock` 返回镜像原件，block.hh:524）→ 该入边入选。
- **top-down 实现**（`gather_return_gotos` + `GatherReturnGotosWalk` +
  `crate::block::next_flow_after_successors`，2026-09-22 起与 goto_prints 树遍
  历共用 block.rs 的单一事实源分表，本文件原私有副本已删）：Rugra 结构树组件
  走 typed 字段、无自底向上
  parent 链，祖先链扫描实现为等价子树扫描（入边源 copy 落在 qualifying 节点
  子树内 ⟺ 其祖先链含 marked 节点）；oracle 的 setMark/clearMark（作用域严格
  局限于单 RETURN 的 gather→select→clear，cc:2213-2306）以 walk 内
  `active_ancestors` 计数承载。
- **gotoPrints 的 mid-pipeline live 评估**：returnsplit 运行时
  `prints_precomputed` 尚未由 ActionFinalStructure 填充，`goto_prints`/
  `goto_prints_in` 亦只覆盖根图形态；故按 oracle 的虚分发表（block.cc:1335
  BlockGraph / 2899 BlockGoto / 3053 BlockCondition / 3127 BlockIf / 3341
  BlockWhileDo / 3448 BlockDoWhile / 3476 BlockInfLoop / 3639 BlockSwitch）逐父
  类型计算 `nextFlowAfter` 后继，比较 `front_leaf(target) != succ`（copy 层指针
  同一，block.cc:2884-2888）。关键语义：If/WhileDo 的 getBlock(0) 条件槽后继为
  null；WhileDo body 尾回流条件 front leaf；DoWhile/Condition 恒 null；
  InfLoop 回流 body 首 leaf；Goto 组件后继 = 目标 front leaf；Switch 无槽0
  特判（oracle 的 getBlock(0)==bl 指调度根 cs[0]，Rust 组件表不含它 —— 旧表
  把第一个 case 误当调度根，2026-09-22 修正）、非 t_goto case null、t_goto
  case 取打印序下一 case（组件序 = 发射序；真实 label 排序绑定
  JUMPTABLE-TABLEAPI-0001）。根层兄弟规则走
  `crate::block::graph_sibling_successors`（同一单一事实源）。
- **apply 骨架不变**：RETURN 快照 → isSplittable → gather → 倒序 splitedge/
  retnode 累积 → "不能全拆"pop → `fd.node_split`（count 经 apply 返回值承载）。
- 单测 `test_returnsplit_creates_return_at_goto_pred` 重写为两阶段：阶段 A
  （BRANCH 前驱 + 无 goto 结构）零分裂（替代实现的回归负控）；阶段 B
  （BlockGoto 包装 + copy map 接线）双前驱入选、pop 一条、恰好一次 nodeSplit。

## 2026-09-22：删除自造 ActionCopyPropagate（copyprop lane 判决）

- 删除 `pub struct ActionCopyPropagate`（源码零引用的死代码；注释谎称对应
  Ghidra `RuleCopyPropagate`——锁定 oracle 12.0.4 无此 Rule/Action，见
  `docs/alignment_docs/COPYPROP_LANE_VERDICT_1204.md`）。
- oracle 的 COPY 治理=merge 相位四 Action（MergeCopy/DominantCopy/HideShadow/
  CopyMarker），Rugra 均已实现并按 cc:5722/5723/5728/5729 顺序挂树；本删除
  行为零变化（curl E2E byte-identical，defects=0，numbering=0）。

## 2026-09-22：SB-ORD186-PTRARITH-0001 — MULTIEQUAL 类型传播恢复忠实（TypeOpMulti::propagateType）

`ActionInferTypes::propagate_type` 的 `CPUI_MULTIEQUAL` 分支恢复为锁死 oracle 的
忠实语义（typeop.cc:1951-1965 `TypeOpMulti::propagateType`）：

- `inslot!=-1 && outslot!=-1` → `None`（只能 input↔output 传播）；
- 源 varnode（`inslot==-1` 时为 op output，否则 `in[inslot]`，coreaction.cc:5080
  的 `invn` 选取）是 spacebase → `getTypePointer(alttype->getSize(),
  getBase(1,TYPE_UNKNOWN), defaultDataSpace->getWordSize())`，指针尺寸取
  **alttype 尺寸**、pointee 为 unknown1、ram wordsize=1（与 COPY 分支同一字面量）；
- 其余 → `Some(alttype)`（phi 透明）。

背景：2026-08-26 my_f_write 会话曾以"Ghidra 没有 TypeOpMulti::propagateType
覆写"为由把该分支改成 `None`——该前提对锁死 oracle 为假（typeop.cc:40 注册
`TypeOpMulti`，1951 行有覆写；基类 typeop.cc:317-319 的 null 默认被覆盖）。phi
不透明切断了指针类型跨 MULTIEQUAL 的传播，next_url mirror Phase 2 首分歧
ordinal 186（universal:fullloop:mainloop:oppool2，oracle result/count 4/4 vs
rugra 3/3）：`0x50db:c4 RBP(phi 0x50c0:65b) + RAX(free retval)` 的 base phi 在
rugra 侧保持 int8，RulePtrArith::applyOp 的 TYPE_PTR 槽搜索失败，第 4 次
INT_ADD→PTRADD(*#0x1) 转换未发生。恢复透明后 drill 窗口 4/4 对齐，Phase 2 首分
歧后移至 ordinal 332（universal:setcasts，33 vs 41，独立已登记缺口）。

验证：curl E2E 124 函数 defects=0/numbering=0，skeleton 3105→3049；httpd E2E
29 函数 defects=0/numbering=0，skeleton 2392→2348；`--func next_url` 0/0。该修
复不依赖 my_f_write 的旧行为——2026-08-26 同 commit 的 LOAD/STORE
`propagate_to_pointer` 截断修复才是 my_f_write 收敛的真实原因。

## 2026-09-22：SB-ORD332-SETCASTS-0001 — propagateType 覆写集合忠实化 + getInputCast 覆写臂移植（Phase 2 ordinal 332 setcasts）

Phase 2 next_url mirror 首分歧 ordinal 332（universal:setcasts，oracle
result/count 33/33 vs rugra 41/41）：rugra 的 ActionSetCasts 比 oracle 多做 8 次转换。
drill 双侧窗口分解 = **+4 多余 cast**（`507d:830 RAX=CAST(sext出)`、`5088:831
CAST(RAX)→*#0x18`、`50b8:836 RAX=CAST(call free出)`、`50c0:83e CAST(RAX)→*#0x8`）
+ **−3 缺失 EBX 输入 cast**（`507b:5a s>>`、`5077:117 INT_LESS`、`50e5:d9
INT_LESSEQUAL`）+ **7 次不可见计数**。三层根因、三个修复：

1. **`propagate_type` 自造传播臂删除**（根因主项）：旧代码有
   `INT_ZEXT|INT_SEXT → 前传 input 类型`、`BOOL_* → bool`、
   `INT_MULT/DIV/SDIV/REM/SREM/NEGATE/LEFT/RIGHT/SRIGHT + FLOAT_* → 泛型整数前传`
   三组**无 oracle 对应物**的臂。锁死 oracle 的 propagateType 覆写集合（typeop.cc
   全量枚举）只有：COPY(411)、LOAD(487)、STORE(557)、EQUAL/NOTEQUAL/LESS/
   LESSEQUAL(945/1009/1085/1109 经 propagateAcrossCompare)、SLESS/SLESSEQUAL
   (1033/1059 仅 TYPE_INT)、INT_ADD(1181)、AND/XOR(1455/1422 仅 enum 或
   floatSignManipulation 浮点)、OR(1488 仅 enum)、MULTIEQUAL(1951)、INDIRECT
   (2005)、PIECE(2074)、SUBPIECE(2161)、PTRADD(2268)、PTRSUB(2366)、SEGMENT
   (2431)、NEW(2501)；其余全是基类 null 默认（typeop.cc:317-321）。ZEXT/SEXT
   前传把 4 字节 `uint`（s>> 输出 EAX 的类型）盖到 8 字节 `RAX=sext` 输出上，
   类型尺寸错配 → setcasts 的 castStandard "尺寸不等恒 cast" 制造全部 4 个多余
   cast。本次：删三组自造臂、新增 INDIRECT/PIECE/SEGMENTOP/NEW 臂、SUBPIECE 按
   cc:2161-2186 的 getSubType 逐层下降重写（union resolveTruncation stub 保留
   residual）、AND/XOR/OR 按 enum/floatSignManipulation 门移植、SLESS/SLESSEQUAL
   从 acrossCompare 混合臂拆出（仅 INT）、FLOAT_* 比较从传播中移除、
   floatSignManipulation（typeop.cc:153-176）随臂移植。
2. **比较/移位/除余 getInputCast 覆写臂移植**（−3 缺失 cast 根因）：
   `TypeOpIntSless/SlessEqual/Less/LessEqual::getInputCast`（typeop.cc:1023/1049/
   1075/1099：checkIntPromotionForCompare 门 + castStandard care_uint_int=TRUE；
   SLESS 族 metain=INT+care_ptr_uint=TRUE，LESS 族 metain=UINT+care_ptr_uint=FALSE）、
   `TypeOpIntZext/Sext`（1131/1157 + cast.cc:126-138 checkIntPromotionForExtension
   方向匹配门）、`TypeOpIntRight/Sright` slot0（1543/1585 + UNSIGNED/SIGNED_EXTENSION
   门）、`TypeOpIntDiv/Sdiv/Rem/Srem`（1639/1659/1679/1699 同门）。旧行为走泛型
   `input_metatype` 臂 care=false，int/uint 互换自由 → LESS/SRIGHT 的 EBX(uint4)
   输入永不 cast。
3. **指针 intern 化（+6 不可见计数根因）**：`make_ptr` 原地新建非 intern 的
   `Arc<Pointer>`，而 `TypePointer` 的 `type_equal` 是 ptr_eq —
   `TypeOpStore::getInputCast` 的 cast-already-in-place 测试（typeop.cc:542-551）
   恒判"不同"→ recast → castInput 双 cast 守卫的 lone-descend retype 路径
   （cc:2675-2678）隐形 +1×6。oracle 的 `tlst->getTypePointer` 返回 intern 实例，
   内容相等即同一指针 → 返回 null。修复 = `make_ptr` 经
   `TypeFactory::get_type_pointer` intern（detached fixture 无工厂时保留原构造）；
   同族根因 `propagate_to_pointer`（typeop.rs）以 **alttype 尺寸**建指针而 oracle
   `TypeOp::propagateToPointer`（typeop.cc:186-198）以 **outvn 尺寸**为 sz — 6 个
   STORE 地址 vn 得到 ptr::1/2/4（8 字节地址！）。新增
   `typeop::propagate_to_pointer_sized(alt, sz, factory)` 忠实镜像（含
   PARTIALSTRUCT getComponentForPtr 与 unknown* 降级），coreaction.rs 的
   LOAD/STORE 传播臂改传地址 vn 尺寸。

**验证**：Phase 2 next_url mirror **全函数投影 MATCH**（335 stages + 全部 @SNAP
逐字节一致，首分歧清零——不止后移）；curl E2E 124 函数 defects=0/numbering=0
skeleton 3105→3024；httpd 29 函数 defects=0/numbering=0 skeleton 2392→2357；
config 域 main/getparameter.constprop.0/parseconfig.constprop.0/glob_set/
glob_range/glob_url/next_url 逐函数 0/0；确定性双跑（E2E stdout sha256 相等 +
投影 cmp 通过）。

残差（登记 SB-ORD332-SETCASTS-0001 行）：acrossCompare 的 PointerRel 降级臂
（cc:972-982，Rugra 无 TypePointerRel，不可达）；PIECE/SUBPIECE 的 near/far
指针 resize 臂（本 arch 无 alt pointer，不可达）；TypeUnion::resolveTruncation
无 Rust 移植（stub None）；typeop.rs 侧 `propagate_to_pointer` 旧签名调用点
（spacebase 臂族）仍以 alttype 尺寸建指针——测试路径 twin，未在本 lane write-set
内，留待 typeop 域收敛。

### 2026-09-23（GETPARAM-SWITCHNORM-0001）：ActionSwitchNorm count 外化（take_count_delta）

`ActionSwitchNorm` 补齐 `take_count_delta` 覆盖（16 个既有覆盖同一适配族）：
Ghidra `Action::perform`（action.cc:319 调 apply、327-329 检查成员增量、
361 `return count`）读取 apply 内 `count += 1`（coreaction.cc:4557 未标注臂 /
4561 foldInGuards 臂）积累的成员并作为返回值上报。Rugra 侧该成员此前无人收割
（默认 `take_count_delta` 恒 0），apply 体虽忠实执行（unlabelled 表
match_model/recover_labels/fold_in_normalization + 全表 fold_in_guards 照跑），
但 stage 投影的 result/count/apply 恒报 0——getparameter 投影 ord155
`universal:fullloop:switchnorm` oracle=2/2/1 vs rugra=0/0/0 的"缺 fire 型"分歧
即此（ET RANGEUTIL-CONSTGEN-0001 后首分歧）。修复后 ord155 逐字段
`result=2 count=2 tests=0 apply=1`==oracle（表实况:1 表 unlabelled+fold 成功
=2 计数;ord299/340 labelled+fold false=0,亦==oracle）,投影首分歧 155→186
（+31 stages;186 分歧=oppool2 新建 switch 表寻址 op 常量对 c:4f0/fb10 vs
c:4e8/fb18,pre-existing 被旧 155 掩蔽,另登记）。flags=0 → `issue_warning`
门卫短路,`check_action_break` 断点位未设——改动对 E2E 文本零影响
（curl 2511/0/0、httpd 2282/0/0 逐字节==亲父基线即为证）。

**验证**：getparameter 双投影 bisect 首分歧 155→186;`--func getparameter`
729/0/0（=8be100d9 亲父值;ET 报 743 系 CR8 基）;三门禁 curl 2511/0/0 +
httpd 2282/0/0 == 亲父 8be100d9;三投影 next_url/match_url/parseconfig
全 MATCH 保持。同族残差（本 lane 未动,登记 ACTION-COUNTHARVEST-FAMILY-0001）:
ActionUnreachable/ActionMarkExplicit/ActionMarkImplied/ActionStructureTransform/
ActionReturnSplit 的 `self.count +=` 同样无收割覆盖（ActionDoNothing 经返回
路径适配已覆盖）——当前三投影函数内 oracle 计数均为 0 故不可观测,harvest 后
不可能翻转 MATCH（计数非 0 ⇒ 快照已分歧行为先暴露）。

### 2026-09-23（VARGROUP-ABSORB-0001 §4-4）：ActionRestrictLocal 参数谓词 + ActionRestructureVarnode 持久 scope

- `ActionRestrictLocal::apply` 循环 1 的 spacebase 参数判定从 `p.address.as_u64() > 0x7FFF_FFFF`（从不命中 callee 相对偏移）修正为 `p.address_space == AddressSpace::Stack`（coreaction.cc:1974-1975 的 `IPTR_SPACEBASE` 空间类型测试）。match_url 调用点（so=fc70 + Stack:8:304）现在把 fc78..fd90 出参影子区 markNotMapped——oracle `print localrange` 的 fc78-fda7 间隙由此产生，30d6 字段件因此非 addr-tied/mapped。
- `ActionRestructureVarnode::apply` 改为复用 `fd.scope`（Ghidra 的 localmap 为 Funcdata 生命周期单一对象，funcdata.cc:69-70）；仅首趟构造 + seed 平台参数符号 + `reset_local_window`（一次性窗口安装）。此前每趟 fresh scope + 全量重装窗口，把 RestrictLocal 的窄化整体抹掉。

### 2026-09-23（LOCKHYGIENE-SCRUTINEE-FAMILY-0001）：markExplicitUnsigned lone 臂 scrutinee 读守卫提升

- `ActionSetCasts::mark_explicit_unsigned`（cast.cc:38-71；lone 臂=cc:63-66）的
  `if let Some(lone) = outvn.read().unwrap().lone_descend()` scrutinee 临时读守卫
  持有至整个 if-let 体尾——与 ER（ruleaction SubRight lump 臂）/EW（castInput
  double-cast 臂）/EM3（merge cover_dirty）同族的潜伏锁卫生缺陷：体内一旦出现对
  同一 outvn 的写锁即同线程 RwLock 自死锁（当前体内只读 lone，未触发）。
  修复形态与 ER/EW 一致：提升为语句级 `let lone_descend = ...;` 先绑定
  （lone_descend 返回 owned `Option<Arc<_>>`，读守卫随 let 语句结束释放，
  不可观测），读序不变（cc:63 loneDescend 读取 → cc:65 lone opcode 检查）。
- 新增单测 2 个：`test_mark_explicit_unsigned_lone_arm_semantics`
  （SUBPIECE lone=不继承符号→false 无 unsignedprint；INT_ADD lone→true+flag；
  注意 untyped 常量报 UNKNOWN=unsigned-family，正控场景须给另一侧 INT 类型）
  与 `test_mark_explicit_unsigned_lone_arm_guard_released_before_body`
  （10s 超时线程内以生产调用形状复现"体内写锁 outvn"——scrutinee 形态下
  该写自死锁，提升后瞬间完成）。
### 2026-09-23（HTTPD-CALL-PUSH-0001 RC3）：analyzeExtraPop 写回 + ExtraPopSetup setEffectiveExtraPop
- `analyze_extra_pop`（coreaction.cc:261-318）从"只计数骨架"升级为完整写回
  端口：cc:264-267 早退守卫现读架构 `evalfp_called`/`defaultfp` 模型的
  extrapop（与 oracle 同源；此前误用 `fd.funcp.get_extra_pop()` 投影）；
  cc:278 变量数为 0 早退；cc:287-293 的 65535 不可解解值只打一次
  `warning_header("Unable to track spacebase fully for stack")`；cc:296-309
  对 iop 挂 CALL 的 INDIRECT 定义变量按 `soln - soln2`（companion 缺席为
  0）回写 `FuncCallSpecs::set_effective_extrapop`；cc:310-315 所有可解变量
  的定义 op 经 `op_set_opcode(INT_ADD)` + `op_set_all_input([spcbase_in,
  const soln])` 重写。签名随之 `&Funcdata → &mut Funcdata`。
- `ActionStackPtrFlow::apply`（cc:495）调用点的 funcp 守卫移除（守卫回归
  oracle 位置——函数体首部）；`ActionExtraPopSetup::apply` 的已知 extrapop
  分支补 cc:1454 的 `setEffectiveExtraPop(extrapop)` 写回（调用点索引收集
  后循环外统一写，避免与 `find_call_op` 的注册表读交叉借用）。
- 行为边界（实测）：httpd/curl（defaultfp=__stdcall extrapop=8 已知）两语料
  走 cc:264-267 早退，本次写回不触达——E2E 数字不变（httpd 2137/0/0 缺
  numbering 见 TODO 板 VARMAP-DUPDECL 家族；curl 4073/0/0 优于当前 master
  4085）。未知 extrapop 平台（32 位 __cdecl 类）的写回路径当前无 E2E 语料
  覆盖，状态 UNTESTED（B2 件待后续 wave 建 fixture）。
## 2026-09-23（BOOMATTR lane）：ActionInputPrototype/ActionUnjustifiedParams 全量重写（自函数参数恢复）
- 根因（curl 镜像契约 +1488 爆炸族，SB-F2STRING-ADDRTIED-PARAMRECOVERY-0001）：
  `ActionUnjustifiedParams`（fullloop/protorecovery）旧实现是自创 raw 兜底——
  对每个"未匹配声明参数且有后代"的输入 varnode 直接造 `param_N`/long 参数；
  `ActionInputPrototype`（fixateproto）旧实现只在参数为空时把全部 used 输入
  raw 化。f2string 修复（RuleLoadVarnode 走 newVarnode 符号尾→栈 varnode 获
  addrtied）后输入面扩大，raw 兜底把 RBX/RBP/R12 等未合并 high 全部升参：
  main 19 参、next_url 4 参等。
- **ActionUnjustifiedParams::apply** 按 coreaction.cc:4784-4828 全量重写：
  def 序遍历输入 → `FuncProto::unjustified_input_param`（新增，见
  docs/api/fspec.md）判定"在参数容器内但未对齐最低有效端"→ 向前生长容器
  （cc:4798-4820 重叠环）→ `Funcdata::adjust_input_varnodes`（cc:4822，
  space-aware 修复见 docs/api/funcdata.md）→ 重启遍历（cc:4823-4825 迭代器
  失效语义）。**本 Action 永不创建参数**——参数创建是 fixateproto 的
  ActionInputPrototype 职责。
- **ActionInputPrototype::apply** 按 coreaction.cc:4707-4763 全量重写：
  cc:4714 clearCategory(fake_input) → cc:4715 clearUnlockedInput → 锁定早退 →
  def 序（VarnodeCompareDefLoc）遍历输入 + `possibleInputParam` 门 +
  ParamActive trial 注册 + hasNoDescend 判 active（cc:4717-4730）→ setScope
  fallback glue（fspec.cc:3879-3885：convention 名模型→arch defaultfp，同
  varmap func_proto_param_range 优先序）→ resolveModel + deriveInputMap
  （cc:4731-4732）→ unref&&used trial 物化新输入 varnode
  （cc:4733-4749，hasInputIntersection 折叠为 bank_has_input_intersection
  GLUE：varnode.cc:1536-1554 的 def 序 next/prev 探针）→ updateInputTypes
  （high 已开）/updateInputNoTypes（cc:4750-4753）→ clearDeadVarnodes
  （cc:4755）。
- 验收（fast-release，RUGRA_MIRROR）：curl 镜像 4071→4064/0/0（vs canonical
  golden）；vs direct-runner golden 3149→3118；default 模式 2683→2684
  （match_url +1：304B URLGlob 栈参数容器 adjust 后 in_stack_00000008[304]
  声明——oracle 同形 adjust 的符号吸附残差，登记 BOOMATTR-INSTACK-SYMATTACH
  残差）；httpd 2099/0/0（≤2104 基线）；next_url/match_url 双投影 vs
  sb-oracle 锁定 oracle 投影逐 stage MATCH（仅 META 身份行差异）；
  cargo test --lib 18 失败=基预存同集（b8031069 A/B 复核）。
## 2026-09-23（BOOMATTR lane r2，CR4 REJECT 返工）：unjustparams 遍历方向 + count 通道
- **MISMATCH-1 修正（coreaction.cc:4803-4815 逐字核对）**：oracle 重叠扩展内循环
  `iter2 = iter; while (iter2 != begiter) { --iter2; vn = *iter2; }`——iter 在
  cc:4794 `*iter++` 后指向当前 varnode 之后的下一项，`--iter2` 首次落回**当前
  varnode 自身**，随后**降序**扫到首个输入。链式跨骑（高位输入下扩 vdata.offset
  后使更低位输入变为跨骑）必须在**同一趟降序扫描**内以更新后的边界判定完成；
  前向升序不含自身的扫描在"生长后容器 rejustify 成功 break"时会永久漏掉更低位。
  修正 = `input_vns[..=idx].iter().rev()`（含自身、降序，逐字镜像 --iter2 序）。
- **MISMATCH-2 修正（coreaction.cc:4826）**：`ActionUnjustifiedParams` 增加
  `count: i32` 字段，每次 adjustInputVarnodes 后 `count += 1`，经
  `take_count_delta`（std::mem::take）外化到 ActionState 累加器——action.rs
  perform cc:338-339 的既有 count 通道（lcount<count → count_apply/repeat/
  组级变更判定）即 Ghidra `Action::count` 的等价物，apply 返回值保持 0
  （cc:4828）。
- 实测：curl default 2684/0/0、MIRROR canonical 4064/0/0、direct-runner
  3118/0/0、httpd 2099/0/0，MIRROR 输出与 r1 **逐字节相同**——本语料无
  链式跨骑场景触发（降序扫描与升序在单步扩展下行为等价），count 通道
  无行为翻转（unjustparams 无 repeatapply 旗，count 经组级聚合消费）。
## 2026-09-23（CHAINFIX lane EY2）：ActionInputPrototype 补 ProtoStoreSymbol store 副作用折叠
- **根因（EV delta_decomp ① 族）**：合并态 httpd 缺口最大族 = `in_` 参数
  寄存器命名（179 记号：RDI 48/RSI 45/RCX 17/RDX 15/R8 8/32 位变体 7/
  RAX 12/RSP 7 + in_RIP 21）。EH 车道恢复了参数发现（trials/模型门/
  unref 创建），但平铺 FuncProto store 从未把 `ProtoStoreSymbol::setInput`
  的 ScopeLocal 符号安装副作用带上——`ActionNameVars::link_symbols` →
  `Funcdata::link_symbol` 的 `queryProperties(addr, 1, usepoint)` 查不到
  function_parameter 符号（输入 varnode 的 usepoint = `baseaddr-1`，
  `Varnode::getUsePoint` varnode.cc:696-703 未写 varnode 分支），输入 high
  无符号 → 打印层落回寄存器名 `in_RDI` 族。EU 车道终报残差 ③
  （"无锁函数参数的 scope FUNCTION_PARAMETER 符号安装缺口"）即本项。
- **修复（两处折叠，均逐字锚定 Ghidra 调用点）**：
  1. cc:4715 `clearUnlockedInput` store 尾：`ProtoStoreSymbol::
     clearAllInputs` = `scope->clearCategory(0)`（fspec.cc:3233-3236，
     `ScopeInternal::clearCategory` cat>=0 分支=removeSymbol，
     database.cc:2020-2029）——在 `!is_input_locked()` 下对
     `fd.scope` 执行 `clear_category(FUNCTION_PARAMETER)`，防 action
     restart 循环下旧符号按重推导存储累积。
  2. `update_input_(no_)types` 注入 `store_install` 闭包（经 fspec 回调
     在 cc:4079/4121 调用点触发）：镜像 `ProtoStoreSymbol::setInput`
     （fspec.cc:3151-3183）——既有 slot 符号存储漂移则 removeSymbol；
     安装分支按 `discoverScope`（database.cc:1353-1365：mapScope 起向上
     walk，`inScope` 命中=本 scope range tree 拥有该存储=栈窗内 MEMORY
     类参数）决定 usepoint：命中=INVALID（空 uselimit→addrtied），未命中
     （寄存器参数）=`restricted_usepoint = baseaddr-1`（fspec.hh:1288、
     funcdata.cc:69）→ `add_symbol` + `set_category(FUNCTION_PARAMETER,
     count)`，命名折叠 `param_<count+1>`（Ghidra 传空名，默认名由
     database.cc:1777-1781 `buildDefaultName` param 分支产生同串；
     `lookForFuncParamNames` 对 input 跳过重命名，先命名无传播损失）。
     `pieces.flags==0` 使 indirect/hiddenretparm/typelock/namelock 镜像
     臂（fspec.cc:3171-3182）不可达。无 scope 的 GLUE 态折叠为空操作。
- **消费链闭环**：`link_symbol`（funcdata.rs:1448，funcdata_varnode.cc:
  1156-1184 镜像）以输入 usepoint=baseaddr-1 查中单点 uselimit 符号 →
  `handle_symbol_conflict` 对 input 直接 `set_symbol_entry` → 打印层出
  `param_N`。EK usepoint 修复（queryProperties uselimit 匹配）与 EH 参数
  恢复在合并态的交互缺口由此闭合。
- **验收（fast-release，oracle e40ed130）**：httpd 2539/0/0 → **2433/0/0**
  （−106）；curl 2512/0/0 → **2507/0/0**（−5 全为 legacy 死声明删除，
  零新增行）；`in_` 参数寄存器族 142 记号→0（RDI/RSI/RCX/RDX/R8/32 位
  变体全消），param_ 记号 243→329；残差 in_RIP 21=CHAINMERGE-INRIP-
  PRINTFAMILY-0001 域、in_RAX 12+in_RSP 7=非参数寄存器输入（RAX=返回值
  寄存器/RSP=栈指针，模型不收，基线也不发射该形态，登记
  CHAINFIX-INRAXRSP-RESIDUAL-0001 待归因）；gcc 审计 curl 82/25、httpd
  6/23 均与基线恒等；三投影（match_url/next_url/parseconfig.constprop.0）
  与 EQ2 基线字节恒等 → MATCH 结构性继承；cargo test --lib 串行 1658P/
  18F=基线逐名同集。

## 2026-09-24：ActionOutputPrototype 简表替换为 updateOutputTypes 真端口（Lane GG2）

旧实现按 RETURN 输入尺寸硬编码 byte/int/long 三臂且只在现类型为 void 时写入
——违反铁律 1.4 的简表（oracle 反例：httpd `switchD_0017766d::default`
`mov eax,0xfffffffd; ret` 打印 `undefined8 ...(void) { return 0xfffffffd; }`
而旧表打 `long`）。重写为 coreaction.cc:4765-4782 逐行端口：
`getFirstReturnOp`（returnlist 插入序，跳 dead/五旗标 halt 族）取输入 1..n 构造
triallist，交 `FuncProto::update_output_types`（fspec.cc:4136-4159）；
未锁输出 + 空表 → clearOutput（void），与 Ghidra 同。

## 2026-09-24（CR29 返工）：build_localtypes 注释锚行修正

TypeOpReturn::getInputLocal 引用随 typeop.cc 901 修正（原 883）。无行为变化。

## 2026-09-24：ActionRestrictLocal effect 迭代走 FuncProto::effectBegin 回退（PM-GLOBWORD lane）

**2026-09-24 补注（BANK-FINDINPUT-SPACE-0001，wt/p3batch）**：Loop-2 的
`fd.find_varnode_input(effect.get_size(), effect.space, …)` 现携带
`EffectRecord.space`（cc:1987 `data.findVarnodeInput(size,(*eiter).getAddress())`
的 Address 含空间；fspec.rs `EffectRecord{space,offset,size,…}` 本就带）。
同族另一消费点：ActionRestructureVarnode 参数 typelock 的 Register 臂。
语义变化仅当跨空间偏移碰撞时可见（x86-64 无碰撞=latent）。

Loop-2（saved-register 溢出槽 walk，coreaction.cc:1983-1999）此前读
`fd.funcp.effects` 原始字段——分析期 FuncProto 的本地 effectlist 恒空，
`<unaffected>`（RBX/RSP/RBP/R12-R15）记录全在解析模型的 effectlist 里，
导致 walk 永远空转：

- oracle `FuncProto::effectBegin/effectEnd`（fspec.cc:4243-4257）在本地
  列表为空时回退 `model->effectBegin()`；Rugra 的
  `FuncProto::effect_iter()`（fspec.rs，含同一回退）早已存在，本修复把
  消费点从裸字段改为 `effect_iter().to_vec()`。
- 因果链（glob_word）：push rbx/rbp/r12/r13 的溢出槽（stack:-0x20..-0x8）
  经 RuleStoreVarnode 变 COPY 后，restrictlocal 第二轮应按 unaffected
  记录 `markNotMapped(off, sz, false)`；未标记 → 槽留在 range tree →
  restructure#2 建出 8 字节符号（unaliased=false）→ sync 走符号分支 →
  输出 varnode 无 nolocalalias → RuleIndirectCollapse 拒折调用影子
  INDIRECT（stage 65 首分歧 258-vs-250）。
- 修复后：槽退出 range tree、无符号、unmapped 分支
  `isUnmappedUnaliased`（无栈参窗口恒真）置 nolocalalias → INDIRECT
  折叠 → pushmulti/propagatecopy 统一到寄存器值，与 oracle 一致。

httpd 附带收益：ap_is_matchexp 骨架 5→0（消除 cVar2/cVar3 溢出影子
双变量抖动，全函数 skeleton identical）。
## 2026-09-24：input_metatype 表按锁定 oracle ctor 重建（PM-F2S）
`ActionSetCasts::cast_input` 泛化臂的 `input_metatype(opc)` 原先把全部
INT_* 算术/逻辑/移位 ops 统一映射为 `Int`。锁定 oracle 的每个 TypeOp ctor
第 4 参（metain，typeop.cc:1168-1692）并非一致：
- INT metain（typeop.cc:1168/1319/1381/1503/1568/1618/1652/1692）：INT_ADD、
  INT_SUB、INT_MULT、INT_SDIV、INT_SREM、INT_2COMP、INT_LEFT、INT_SRIGHT。
- UINT metain（typeop.cc:1395/1409/1442/1475/1528/1632/1672）：INT_NEGATE、
  INT_XOR、INT_AND、INT_OR、INT_RIGHT、INT_DIV、INT_REM —— 注册为
  `TypeOpBinary/Unary(...,TYPE_UINT,TYPE_UINT)`。
修正前症状：INT_AND slot0 的 inputTypeLocal 基类型请求为 int8 而 oracle 为
uint8（typeop.cc:1442），trim CAST 输出类型随之错签；setcasts 下一 slot 的
markExplicitUnsigned firstvn 卫（cast.cc:53-58）读另一侧 metatype=Int 而非
Uint，未按 oracle 提前返回，多计一次 count（file2string.part.0 投影
ord337 的 29vs30 根因之三）。

## ActionRestructureVarnode：committed-local 种子物化（HEADLESS-BRIDGE-V1-TYPESEED，2026-09-25；TYPESEEDARB 锁位透传 2026-09-27）

scope 首次构造臂（fd.scope 为 None 的分支）在平台参数符号安装之后新增
`fd.committed_locals` 物化循环：每条种子经 `parse_c_type`（debugproto，
shared_default 工厂，GL 判例的类型身份域单一原则）解析后以
`ScopeLocal::add_symbol(Stack, name, dtype, wrapped_offset, usepoint=None)`
安装，并置 `typelock=true; namelock=true`。对应 oracle 生命周期 =
Funcdata 构造 → `<localdb>` decode → action（种子在 decode 期入库）；
`clearUnlockedCategory(-1)`（varmap.cc:1259）保证 typelock 符号跨 pass 存活，
`MapState::gatherSymbols`（varmap.cc:1044-1059）把它们作为 RangeHint::fixed
边界喂给 restructure——这正是 canon 声明层分区（92B auStack_9c 被种子切成
28B+16B+48B）与下标形（8B 元素 → scale-8 PTRADD）的机制。默认
committed_locals 为空 = 零行为差异（E2E cmp 字节恒等亲父）。

**TYPESEEDARB 增量（HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001，2026-09-27）**：
物化循环的 `typelock=true` 硬编码改为 **透传 `seed.typelock`**
（`scope.symbols[idx].typelock = seed.typelock; namelock 恒 true`）=
`<localdb>` 逐符号 ATTRIB_TYPELOCK 位（database.cc:432-434）的物化镜像。
typelock=false 的种子（反编译器自恢复聚合体，收割器按③重分类的 115 条
数组声明符）物化为 namelock-only，随后紧邻的 `scope.collect_name_recs()`
调用——正是 oracle ScopeLocal::decode 边界（varmap.cc:472-477）的同一下降
（varmap.cc:357-381）——把该符号类降级为名字推荐：自由 restructure 布局
栈槽、恢复未锁定数组，ActionNameVars 经
recoverNameRecommendationsForSymbols（varmap.cc:1507）按 overlap+精确地址
把 local_ 名重挂到恢复符号上。若该符号以 typelocked ARRAY/STRUCT 形态存活，
markUnaliased 的 alias_block 臂（varmap.cc:1376-1385，alias_block_level=2）
会灭 aliason 并把 sticky unaliased 传给后续 entry——httpd main 的 canary 槽
(-0x40) 即此路径：nolocalalias → RuleIndirectCollapse 放行 → INDIRECT 网折叠
→ 死 canary 语句被消。锁定库 same-seed 实验（stage_seed_diag e40ed130）
双向钉死：nameonly-agg 载荷网活、locked 载荷网死、drop 载荷丢名。落地面：
canon httpd skeleton 311→304（main 15→13 = canary ×2 精确收敛；
ap_fini_vhost_config 45→40 同族），其余函数字节恒等；RUGRA_SEEDS=0 控制臂
字节恒等；retaddr_canary_passcount_1204 fixture web_survival 翻 MATCH 重钉。

## 2026-09-25：BRIDGE1-TYPESEED-PARSEFAIL 降级声明（Lane TYPEFIX，注释级）

种子物化循环的 parse 失败臂（skip+eprintln）正式登记为声明降级
（BRIDGE1-TYPESEED-PARSEFAIL，CR-BRIDGE1 条件项，代码逻辑零改动）：
oracle 的 `<localdb>` 传输对不可解析类型没有按符号容忍——
`ScopeInternal::decode -> decodeType` 抛 LowlevelError（type.cc:4179
"Unable to resolve type"，或 TypeArray::decode 尺寸检查 type.cc:1339-1341），
整函数数据库解码失败、函数不进入 action 管线。Rust 通道保留按符号
skip+eprintln：损坏/不可解析的 manifest 条目降级为"该 local 不播种"而非
中止函数。仅 harvest 门禁外的 manifest 可观测（合法 manifest 只携带表内
拼写）；自 BRIDGE1-TYPESEED-PIDT 修复移除 parse_c_type 的静默
address_size 回退后，该臂同时是未来不可解析基拼写的指定响亮处理路径
（见 docs/api/debugproto.md 同日节）。

## 2026-09-25（SPACEFIX lane）：buildReturnOutput 两段 join 空间构造（COREACTION-JOINSPACE-0001）

CR-XCROSS 复核登记的 P2 空间钉死残留位：`build_return_output` 两段拼接臂
（coreaction.cc:1850-1868）此前自创「取 lo/hi varnode 偏移最小值 + Register
空间」并注释声明 Register space——对 oracle 是错误声明。cc:1855-1857 的
`getArch()->constructJoinAddress(translate, trialhi.getAddress(),trialhi.getSize(),
triallo.getAddress(),triallo.getSize())` 以 **trial 存储地址**（非 varnode 偏移）
进入 `AddrSpaceManager::constructJoinAddress`（translate.cc:817-860）。

新增两个自由函数（coreaction.rs，ActionReturnRecovery 结构体旁）：

- `return_join_address(arch, hi, lo)`（// Ghidra: translate.cc:817）——四分支
  1:1 镜像：①空间合法性守卫（cc:824-826 LowlevelError 臂对输出 trial 结构上
  不可达，violation 响亮记录后仍 join）；②usejoinspace（spacebase=stack 或
  默认代码空间=ram 分片迫使可映射空间合并，cc:827-830）；③连续性
  （address.cc:173 `Address::isContiguous`：同空间+wrapOffset 算术）——可映射
  空间返回最早地址（LE lo/BE hi，cc:832-835），register 空间先查覆盖父寄存器
  名（`Architecture::get_register_name` ← sleighbase.cc:144-168）有名即返回该
  分片地址（cc:837-845）；④否则 findAddJoin([hi,lo],0) → **Join 空间**
  unified 偏移（cc:848-859）。
- `join_unified_offset(hi, lo)`（RUGRA-GLUE）——unified 偏移的无状态
  splitmix64 派生：同分片四元组恒映射同一 join 地址（保留 findAddJoin
  splitset 去重对下游可观察的合并恒等语义——本函数两处触发同偏移实证），
  异分片映射到互异 16 字节对齐槽（translate.cc:708 roundsize 对齐）。**残差**
  （TODO 行登记）：oracle 偏移是进程全局 `joinallocate` 计数器顺序值；
  Rugra 生产 Architecture 无可变 join 表（`join_db` 经共享 Arc 只读），无状态
  派生兼得并行线程竞态免疫；数值差异当前不可观察（join_db 恒空，无 findJoin
  消费方可比较偏移）。

`newVarnodeOut(hisz+losz, joinaddr, newop)`（cc:1860）随之改走
`new_varnode_out_full(total, join_space, join_off, newop)`——三元组同源：
size=两 trial 尺寸和、space/offset=constructJoinAddress 结果。

- 探针实证（已回滚）：curl 0 触发；**httpd 默认+SYMDB 各 2 次触发**，均为
  `ap_vhost_iterate_given_conn` 的 RDX(0x10):RAX(0x0) 8+8 寄存器对（非连续、
  无覆盖父名 → join 空间，与 oracle 判定一致），两处触发去重为同一 join 偏移。
- 可观察效果：该函数 join 整体 var 的命名槽位从 Register@0 钉死的第 4 位
  （auVar4）移至真实 Join 空间序（所有 register var 之后，auVar8），
  存活变量编号 lVar4/plVar5/puVar6/puVar7 **与 golden 前缀逐一吻合**
  （亲父为 lVar5/plVar6 off-by-one）——向 oracle 收敛；门禁骨架计数逐函数
  恒等（httpd 1472/0/0 双方同值，ap_vhost_iterate_given_conn diff=49 双方同值），
  SYMDB 1328/0/0 不回退，curl 字节恒等。残余 auVar8[16] 打印本体是
  heritage processJoins 拆分 stub 的既有登记残差（golden 侧 join 读被拆分，
  C 文本无 16 字节 var）。

## 2026-09-25（ALIASGATE）：isPossibleAlias 判定移植接入门内（GETPARAM-STORECROSS-ALIASGATE-0001 收口）

`ActionMarkImplied::check_implied_cover` 的 LOAD 跨 STORE 臂
（coreaction.cc:3384-3399）此前在「LOAD cover interior 包含 STORE 且
STORE/LOAD 的 spacebase 偏移相等」时无条件拒绝 implied——这是 oracle
拒绝集的保守超集：oracle 在 cc:3394 偏移相等后还咨询
`isPossibleAlias(storeop->getIn(1), op->getIn(1), 2)`（fn :3303），
指针对**可分辨**（provably distinct）则放行（保持内联形）。
后果=httpd main canon 内联的 `plVar12[9]/plVar12[10]` 字段读被物化为
显式临时件（GETPARAM +154 的过度物化族分量）。

新增/接线（均带 `// Ghidra:` 行号注释）：

- **`ActionMarkImplied::is_possible_alias`（Ghidra: coreaction.cc:3303
  ActionMarkImplied::isPossibleAlias）**：完整逐行移植——vn 同一=确定别名；
  任一侧 unwritten 走常量偏移比较/`is_possible_alias_step`（oracle 对
  NEAR 常量的 FIXME 保持原样）；step 门先于 def op 比较；PTRSUB 归一为
  INT_ADD、PTRADD 归一为 INT_ADD 且乘数取 in(2) 偏移的 int4 截断
  （cc:3322-3333）；归一后 opcode 不等或 depth==0 → 可能别名
  （cc:3334-3335）；一元值透传族（COPY/ZEXT/SEXT/2COMP/NEGATE）递归
  in(0)（cc:3338-3343）；INT_ADD 双常量加数按 `mult*offset` 的 uintb
  回绕乘比较（等→递归基，不等→`!functionalEquality(基,基)`，
  cc:3347-3353）；任一加数非常量时 mult 不等→可能别名，否则四个
  functionalEquality 配对选互补槽递归（cc:3354-3362）。锁纪律镜像
  `functional_equality_level`：op 读锁在递归前释放，无跨调用 op 守卫。
- **check(1) 臂接线**（cc:3394-3397）：spacebase 偏移相等后改为
  `if (is_possible_alias(store_in1, load_in1, 2)) return false;`——
  仅指对可能同址时拒绝；in(1) 结构性缺失（Ghidra 不可能态）保守拒绝。
- `is_possible_alias_step` 的 `#[allow(dead_code)]` 预留标记移除。

管线级效应（本车道 A/B 双构建亲测，基=cb759c42）：

- curl 默认脸/裸脸（RUGRA_SEEDS=0）与基线**字节恒等**（577/948
  skeleton，defects/numbering 全零）——语料无放行路径触发。
- httpd 默认脸 **1257→1179**（main 687→609，其余 30 函数逐函数恒等，
  零回退）；裸脸 1376→1298 同款。过度物化族回收：`apr_getopt(uVar9,…)
  →apr_getopt(plVar12[10],…)`（=golden :3579 canon 形）、
  `apr_array_make/apr_pool_tag/apr_pstrdup(plVar12[9],…)` 全恢复内联。
- oracle-判决一致物化族**保持**（不回退）：FS canary 显式对
  （`lVar2 = *(long *)(in_FS_OFFSET + 0x28)`+出口 compare）、call 交叉
  物化（ap_vhost_iterate_given_conn `lVar3 = plVar6[2]`，golden 同款）。
- 残余 main 609 的形状分量（显式临时件 undefined 型裸指针形渲染+decl
  移位重配对）维持 `GETPARAM-EXPLICIT-TEMP-SHAPE-0001`（typeprop/
  varmap/printc 联合域）登记不变。

## 2026-09-25（CSPEC2 lane）：ActionNameVars 消费 badjumptable 旗标（CALLSPEC-0001 (c) 收口）

CALLSPEC 移交件三消费者之一的 (c) 落地：`lookForBadJumpTables`
（coreaction.cc:2779-2803）此前是登记 no-op（RUGRA-GAP 注释），本轮
按锁定 oracle 逐行移植，插回 `ActionNameVars::apply` 的 cc:2985 位置
（linkSymbols → recoverNameRecommendationsForSymbols(GAP) →
**lookForBadJumpTables** → lookForFuncParamNames → 默认命名环）。

- **`ActionNameVars::look_for_bad_jump_tables`（Ghidra: coreaction.cc:2779
  ActionNameVars::lookForBadJumpTables）**：按 callspec 注册序扫描；
  `fc->bad_jump_table()` 为真时取 `fc->getOp()` 的 in(0)（CALLIND 目标=
  截断残留的疑似 switch 变量），implied+written 且 def 为 CAST 时剥一层
  （makeRec cc:2822-2828 同款、单层）；随后五道门：isFree 跳过 / high 无
  符号跳过 / nameLocked 跳过（只改未锁名）/ 符号不在 ScopeLocal 跳过 /
  以上全过则 `rename_symbol(make_name_unique("UNRECOVERED_JUMPTABLE"))`。
  Rugra 侧 local 域符号通道=`fd.high_symbols`（linkSymbol attach 桥填充），
  缺项同时建模 cc:2795 的 sym==null 与 cc:2798 的 getScope()!=localmap
  （全局 database 符号走 high.symbol Arc 通道，永不进 ScopeLocal）。
  两阶段形态（先按注册序收集 sym_idx、再依序 rename）与 Ghidra 单循环
  逐个 rename 观察等价：读段五道门不读名字状态，makeNameUnique 的
  nametree 演化只由 rename 段按同序驱动。rename 后的名字经 apply 尾部的
  symbol→High 写回桥（PRINTC-SYMBOL-DECL-0001 在案）进入打印。

**触发链与休眠声明（OPZERO 判例式亲证）**：

- 生产者=flow.cc:754 `fc->setBadJumpTable(true)`（truncateIndirectJump
  默认失败臂，BRANCHIND→CALLIND + "Treating indirect jump as call" 警告）。
  httpd 语料亲证该臂活跳：ap_vhost_iterate_given_conn 0x12daeb 站点输出
  双警告行（"Could not recover jumptable at 0x0012daeb. Too many
  branches" + "Treating indirect jump as call"）——正是 golden 里
  `code *UNRECOVERED_JUMPTABLE` 参数命名的产生位置。
- **flow setter 移交（本车道未写 flow.rs）**：flow.rs:796-797 的
  TODO(CALLSPEC-0001) `_` 臂一行 setter（字段与访问器已备，fspec.hh:1701
  镜像）登记移交 FAMAUDIT 并行车道；落地前生产恒 false。
- 休眠实证：httpd 默认脸（MAX_FUNCS=30）改动前后**字节恒等**（cmp 零差，
  UNRECOVERED_JUMPTABLE 零出现）+ 双跑确定性；curl **577/0/0** 恒等
  基线——旗标恒 false ⇒ 消费者全门空转，与 oracle 构造态同判。
- 触发实证：单测
  `test_namevars_look_for_bad_jump_tables_rename_fires_on_flag`
  构造 CALLIND+spec+in(0) 高变量 ScopeLocal 符号链——旗标 false 时名字
  不动（生产休眠态），置 true（flow.cc:754 等价）后
  rename→`UNRECOVERED_JUMPTABLE` 且 high_symbols 通道完好。
  2026-09-27 CANON-REGJUNK-INRAX-LIVEVAR-0001 适配：inject_raw_ops 的
  Phase 3 输入预提升整体退役（寄存器 INPUT 仅由 Heritage renameRecurse
  晋升，heritage.cc:2499-2503），本单测在 `set_high_level` 前显式
  `set_input_varnode` 提升 CALLIND in(0)——模拟真实管线 heritage 后态
  （ActionNameVars::linkSymbols 命名的是 input 高变量），断言面不变。

**activereturn 接线核验（移交件 (d) 判词：已活跳，无需代码）**：
`ActionActiveReturn`（coreaction.cc:1773-1792 镜像）在
action.rs:2403 fullloop:protorecovery 注册位（cc:5688）恒在；stage drill
亲证 ap_vhost_iterate_given_conn 在 stage 349 `fullloop:activereturn`
内完成 buildOutputFromTrials 单输出形（CALLIND 获得 RAX 输出、
`[create]` INDIRECT 销毁、第二遍 empty=1）——返回面已是 8B `uVar3`，
与 direct-runner golden 的 8B `xVar3` 同判（CALLSPEC 报告的 ③ 桶
16B join `auVar8._0_8_` 面已被 master 演进+SPACEFIX 关闭）。
processJoins 存根残差维持 COREACTION-JOINSPACE-0001 原登记。

**ap_vhost_iterate_given_conn 残差现状（vs ghidra_httpd_1204.direct-runner
golden）**：CALLSPEC ② 桶唯余 `void(*)()param_2` vs
`code *UNRECOVERED_JUMPTABLE` 命名差——本消费者+FAMAUDIT setter 落地后
收口；类型前缀族（xunknown8/int8/int2）为全局类型脸残差在案；
Rugra 侧 `switch() {}` 空体残片为截断路径独立残差（blockaction/printc 域）。

## 2026-09-25：第五波 coreaction 三位点空间穿参（FAMILY-AUDIT-SPACELESS-SITES-0001 ⑧，Lane COREFIVE）

RUFOUR 第四波登记的 coreaction 三位点（锚点 coreaction.cc:695-705 /
1545-1556 / 1445-1460）逐处判读后，构造源 (space,offset) 三元组全部改为
与 oracle 同源穿参（先例：XCORSS/OPZERO/SPACEFIX/FAMAUDIT/RUFOUR 同构修法）：

1. **ActionConstbase::apply tracked-restore**（cc:697-699）：`Address
   addr(ctx.loc.space,ctx.loc.offset)` 的空间=tracked loc 自身空间（pspec
   `<set>` 经 register map name 臂解析或显式 space 属性）→
   `new_varnode_out_full(ctx.loc.size, ctx.loc.space, Address::new(offset), op)`；
   旧 Register 钉在 x86-64 DF（register:0x20a:1）恰同值。
2. **ActionFuncLink::funcLinkOutput**（cc:1545-1551）：`addr =
   outparam->getAddress()` 为输出参数完整存储地址（cc:1546 IPTR_SPACEBASE
   →Stack 延迟臂维持）→ `new_varnode_out_full(sz, spc, Address::new(off),
   callop)`；trial-commit 锁定路径经 set_output_parameter 记录 varnode 自身
   空间（可为 Join——SPACEFIX build_return_output 8+8 分裂返回），旧 Register
   钉对 Join 锁定输出错。无存储回退臂（decode 通道 ADDRESS-0001 残差）维持。
3. **ActionExtraPopSetup::apply**（cc:1443-1452）：`sb_addr =
   Address(point.space, point.offset)`，point=`stackspace->getSpacebase(0)`，
   其空间=栈指针寄存器自身空间 → `new_varnode_out_full(sb_size,
   arch.stack_pointer_space, Address::new(sb_offset), op)`（输入臂
   `create_with_space(sb_space,…)` 先已同源）；x86-64 RSP=register:0x20，
   旧 Register 钉恰为 oracle 真值（RUFOUR 判例警示在此侧成立）。

**触发实证**（release 默认态，探针 `[DBG] COREFIVE` 提交前已删）：三位点
全热非休眠——curl：site1 constbase 125 次（全 Register，size=1 DF）、
site2 funclink-output 113 次（73×sz8+40×sz4 全 Register）、site3 extrapop
342 次（全 Register extrapop=8 INT_ADD 臂）；httpd：site1 36、site3 361
（同形全 Register）、site2 0。x86-64 全语料空间新旧同值 →
curl/httpd 默认态输出与亲父 35ac53c8 cmp 字节恒等（92315B/55922B，
base==probe==final 三态 + 双跑确定性恒等）=等价性实证（非休眠）；
Join/Stack-delay/无存储回退臂在双语料 0 触发，correct-by-construction。

**门禁**：compare 双门禁双零（curl 124 函数 defects=0/numbering=0；
httpd 34 函数双零）；投影 bank 391/391 OK；cargo test --lib 1713P/1F
（test_nonzeromask_pipeline_wiring 预存谱系同败，fspec NZMask 路径与本
diff 零交集）；annotations/refs 全绿。coreaction 主管线域=机制 B 白名单
（Differential 块见 commit）；机制 C 单点同构+五波先例声明，独立 CR 待 root。
## 2026-09-25（CVRHOIST）：ActionMarkImplied::apply 后代先行 DFS（GETPARAM-CVAR1-HOIST-0001 收口）
`ActionMarkImplied::apply`（coreaction.cc:3416-3455）此前用扁平
loc_tree 循环逐 varnode 判定——丢掉了 oracle 的 `DescTreeElement`
varstack DFS（cc:3422-3451）的**后代先行序**：Ghidra 对每个根先把
未标记的后代输出压栈、帧的后代迭代器耗尽才 check+标记本体
（cc:3430-3443），即任何 varnode 的判定发生在其全部（未标记）后代
被标记**之后**。
该顺序是**承载语义的**，不是风格：
1. `Merge::markImplied` 会弄脏 def op 输入的 cover
   （merge.cc:1600-1604 置 coverdirty）；
2. `Varnode::getCover` 的惰性重建通过「重建时刻已 implied」的输出
   **传递扩展 cover**（`Cover::rebuild` 的 path 遍历，cover.cc:492-493）；
3. 消费者先被标 implied 后，生产者重建的 cover 经
   `Cover::addRefPoint` 对非 MULTIEQUAL 读点的**全前驱递归**
   （cover.cc:610-612）跨基本块延伸。
**canon `cVar1 = *flag;` 入口物化判决链**（锁定 oracle e40ed130
断点实测，/dev/shm/rugra-tests/cvrhoist/oracle_gp.err）：
`cmpb $0x2d,(%rbp)` @0x3f49 的 LOAD 输出被子代 INT_EQUAL@3f49 读、
INT_EQUAL 输出被 CBRANCH@3f55（`je`）读——rep movsq @0x3f52（aliases
初始化循环）不碰 flags，比较值活跨整个循环。DFS 先标
INT_EQUAL 输出 implied（弄脏 LOAD 输出 cover）→ LOAD 输出重建时
经 implied 链到达 CBRANCH@blk3 → 前驱递归填 blk2/blk1 全覆盖、
blk0 补到块尾 → cover interior 含 STORE@0x3f52/blk2 → 检 (1)
spacebase 相等 → `isPossibleAlias(store_ptr, flag_ptr)`：两侧指针
def 均为 CROSSBUILD（rep movs 循环 p-code 标记），归一 opcode 相等
落入 default 臂 → 可能别名 → 拒绝 implied → **explicit**。扁平循环
下生产者先于消费者处理，cover 永不延伸（仅 `[(0, def, IE)]`），
跨 store 查不触发 → 误 implied 内联（Rugra `if (*flag == '-')`）。
修复=按 cc:3416-3455 忠实移植 DFS：帧持有（varnode, 后代 op 快照
vec, 游标），后代 op 快照等价于活 list 迭代器（checkImpliedCover/
markImplied/setExplicit 均不变异读链）；op→getOut 链按 SSA 构造为
DAG，无环不变量与 oracle 相同；`count += 1`（cc:3434）逐帧累加保持
（菱形可达路径双计与 oracle 逐为一致）。
管线级效应（A/B 双构建亲测，基=master fdeff691）：
- curl getparameter **156→153**、全量 **577/0/0→546/0/0**
  （glob_set 44→38、glob_range 38→29、main 120→107 同族收敛；
  逐函数零回退）；`cVar1 = *flag;`+`if (cVar1 == '-')` = canon
  getparameter:27/:41 逐字形态。
- httpd 默认脸 compare 基线对拍见 LANE_REPORT（cVar1 族=同机制
  跨 store 物化族）。
- ALIASGATE 已恢复的内联族（plVar12[9]/[10] 等）不回退——DFS 只
  影响 cover 延伸形态，可分辨指针对仍由 is_possible_alias 放行。

## 2026-09-25：canonicalize_temp_type 相对指针保形（UNIONRES-RELPTR-SCOREPARITY-0001，wt/unionf2）

无名 Pointer 臂的 `get_ptr` 重建此前对**相对指针**（Ghidra `TypePointerRel`，
临时形=type.cc:4016-4022 `getTypePointerRel(parentPtr,ptrTo,off)` 经
`markEphemeral`，正式形=`is_ptrrel` 位）一律执行，把 parent/offset 状态剥掉
后换成裸指针 —— oracle 的 `propagateTypeEdge`（coreaction.cc:5104-5110）是
`setTempType(newtype)` 原样落 temp，无任何重建步；`propagateAddIn2Out`
（typeop.cc:1241）产出的临时 rel 指针因此完整存活到消费端
（`TypePointerRel::downChain` type.cc:2656 的 parent 重入、
`TypePointer::resolveInFlow`→`ScoreUnionFields` 的 whole-union trial）。
Rugra 剥壳后评分链在 (INT_ADD,slot=0) 边收到 plain 指针，whole trial 的
downChain 对 union pointee 返回 NULL，恒 0 分 —— 正是 match_url/next_url
sprintf 参数边 oracle [5,5,0,5]（whole 平局胜→不解析，canon 印
`(int8)&...content + 8`）vs Rugra [0,5,0,5]（Set 胜→过度解析印
`.content.Set + 8`）的 +5 评分差根因。

修复：Pointer 臂在 `get_ptr` 重建前置守卫 —— `pointer_rel` 状态或
`IS_PTRREL` 位的指针直接保留原 Arc。安全性论证：临时 rel 形构造即过
`findAdd` 工厂 intern（`get_type_pointer_rel_ephemeral`），结构等价类型已
共享单 Arc，本函数存在的「writeBack `Arc::ptr_eq` 收敛」目的对 rel 形自动
成立，重建是纯信息损失。验收：curl skeleton 396→377（match_url 21→19 即
+2/函数过度解析族归零、glob_set 21→16、glob_range 23→19、getparameter
53→45，124 函数零回退），httpd 896 字节恒等，defects/numbering 0/0，
bank 391/391，gcc 审计 104/20 恒等，双跑 cmp 恒等（安静机器；构建窗口内
首跑有既有 timing 噪声家族）。

## 2026-09-26：setcasts 两检查点联合体读面咨询（UNIONRES-FIELDOFF-PTRSUBNORM-0001，Lane FIELDOFF）

ActionSetCasts 主循环的 PTRADD/PTRSUB 健全性检查改 fd-aware 咨询
（coreaction.cc:2742 `op->getIn(0)->getHighTypeReadFacing(op)` 与
cc:2748 `op->getIn(0)->getTypeReadFacing(op)->isPtrsubMatching(off,0,0)`）:
- PTRADD undo 检查（cc:2740-2745）:union 基址先解析成字段指针再做
  alignSize 比较。
- PTRSUB demote 检查（cc:2747-2756）:退化形会把 AddTree 刚用解析形建好的
  PTRSUB 判成 `isPtrsubMatching(union)=false`（type.cc:1167-1171 对 union 恒
  false,注释明说 union-PTRSUB 由 resolveUnion 创建不可用于字段解析）→ 降级
  INT_ADD → 与 AddTree 咨询互为重写环的一侧。咨询后解析形 struct pointee
  走 Struct 臂 offset 匹配 → 不降级。Rust 镜像位 coreaction.rs
  `ptradd_undo`/`ptrsub demote` 两臂（unionresolve::vn_type_read_facing /
  vn_high_type_read_facing）。
## 2026-09-25：propagate_ref 恢复 beginLoc(addr) 下界（GENSMOKE-S2-TYPEINFER-METATYPE-0001 首刀，wt/s2fix）
`ActionInferTypes::propagate_ref`（coreaction.cc:5208-5254）的候选窗此前只实现
了上界 `voff < end`（endLoc(endaddr)），漏掉下界 `iter = data.beginLoc(addr)`
（cc:5224）。oracle 的 VarnodeLocSet 迭代从 `addr` 起（含），**偏移低于 addr
的 varnode 永不访问**——即使其尺寸与窗口部分重叠。Rugra 侧 `curoff =
voff.wrapping_sub(off)` 对 below-window 候选回绕成巨大无符号值，随后的
`curoff.wrapping_add(vsize)` 意外再回绕后，部分重叠候选能以**负偏移**进入
`get_exact_piece(ct, curoff as i64, vsize)`——oracle 排序下不存在的状态。
该通道把毒化符号的 exact-piece 灌进窗口下方的栈槽链（vsh probeSys 的
propref 泛洪、curl 镜像的 stack varmetatype 漂移），是 GENSMOKE-S2
metatype 过推断族的主放大器。
修复：候选过滤补 `voff < off → false`，恢复半开窗 `[addr, addr+ct_size)`。
验收（五口径 defects/numbering 全零）：vsh 镜 51→41（main 的 argc
int4/uint4 族 15→5 清零）、curl 镜 211→**143**、httpd 镜 412→386、
curl canon 388→369、httpd canon 872 恒等；gcc 审计 httpd canon 15/14 恒等；
bank 1730 pass / 1 fail（fspec 域 `test_nonzeromask_pipeline_wiring`，
master 既有，DOTFIX 94276edf 已 A/B 复现）。
**残余登记**：probeSys 26 行残余属 varmap 域符号中毒环（restructure 周期把
int8 点位喂回 `axStack_60` 数组符号 → ADD in→out `ptr→int8` → 比较交换 →
walk φ → gatherOpen int8 点位 → 符号，oracle 同信道因符号层恒 xunknown8 而
不动点在 unknown）——详见 TODO_BOARD GENSMOKE-S2 残余条目；typeprop 边逐边
对拍（oracle TYPEPROP_DEBUG 直跑 trace 已建，/dev/shm 证据目录）确认其余
臂（MULTIEQUAL 重包、INT_EQUAL 横传、LOAD/STORE backedge、metain 表）逐行
同构。

## 2026-09-26（F7NAME lane）：ActionNameVars 恢复链接线 + ActionInferTypes 类型推荐（HTTPDMAIN-F7-NAMERECOMMEND-0001 机制半）

三处接线（src 侧零算法新造，全部消费 varmap.rs 新落的存储层，详见
docs/api/varmap.md 同日节）：

- **`ActionNameVars::apply`**（coreaction.cc:2978）— cc:2984 的
  `recoverNameRecommendationsForSymbols()` 调用落地（scope take/put-back 借用
  seam），替换原 RUGRA-GAP 注释（"no name-recommendation store is ported
  yet"）。顺序保持 oracle 逐字：linkSymbols → recover → lookForBadJumpTables →
  lookForFuncParamNames → buildDefaultName 循环 → assignDefaultNames。
  lookForFuncParamNames/makeRec（cc:2815-2897）此前已移植（锁定原型参数名→
  喂参局部推荐），本票数据半（httpd 驱动 IMPORTFLIP）接通其输入。
- **`ActionRestructureVarnode`** scope 构造块尾 — `collect_name_recs()` 调用
  （varmap.cc:476 `ScopeLocal::decode` 尾调的边界镜像：committed-local seed
  materialize 之后、restructure 之前）。TYPESEED 种子全部 name+type-locked，
  故为 no-op——为未来 name-lock-only localdb 传输（oracle 的
  ATTRIB_NAMELOCK-without-ATTRIB_TYPELOCK 形态）预留忠实边界。
- **`ActionInferTypes::apply`**（coreaction.cc:5374）— cc:5398 的
  `applyTypeRecommendations()` 调用落地（localcount 门之后、buildLocaltypes
  之前，oracle 位置逐字）。存储恒空时 no-op。

验收（fast-release 亲测，基=master 641994a6 亲测 590/0/0）：机制半+数据半
（examples/httpd_decompile.rs IMPORTFLIP）联合 E2E httpd canon **590→439**
/0/0（−151，9 函数改善 0 回退，main 232→196——`long *__s1` 声明+4 使用行与
golden 逐字复现，含 oracle 的判别行为：喂 "crit" 的 (long*) cast 链局部得名
`__s1`、直喂 "alert" 的 (char*) cast 局部保默认名）；curl canon 267/0/0 恒等；
RUGRA_IMPORTSIG=0 断路==旧默认脸字节恒等（机制半全语料惰性亲证）；镜面三面
110/258/15==基线（275/460/55 棘轮未重钉）；bank 391/391；cargo test --lib
1744P/1F（nonzeromask 预存）。机制 C：coreaction/varmap 核心层白名单——CR
已请求（见车道终报）。
### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor
- 本模块 9 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
## 2026-09-26：ActionDoNothing 自环 warning 地址修复（MSTRUCT-DONOTHING-WARN-0001，Lane CORESMALL）

`ActionDoNothing::apply`（= coreaction.cc:3466-3490）自环臂的 warning 地址：
oracle `data.warning("Do nothing block with infinite loop", bb->getStart())`
（cc:3479）取 **BlockBasic 自身** 的 cover 起址（block.cc:2319-2325：first
range 的 first addr，虚分派 `get_start_addr`）。旧 Rugra 走 `front_leaf` 下降
+`unwrap_or(0)`——而 oracle `getFrontLeaf` 对 t_basic 块返回 null
（block.cc:344-348：`subBlock(0)` 为 null），故 front_leaf 恒 None ⇒ 地址
0x0 ⇒ commentdb 里该 warning 落在函数窗口之外，comment sorter 永不放置、
`do { /* WARNING: ... */ } while(true)` 面缺失（curl main+_start 两处、vsh
_start 一处）。修复=直接虚分派 `bl.read().get_start_addr()`（BlockBasic
覆写= block.rs:2755，block.cc:2319 镜像），front_leaf 下降删除。

E2E（基=efc28f4a A/B）：canon curl 267→266/0/0（_start 警告行与 golden 逐
字节）；镜面 curl 78→76、vsh 15→14（警告面两/一处转 MATCH）、httpd 恒等
（httpd golden 无该面）、sq −1（同面）；defects/numbering 全零恒定。

## 2026-09-26：try_resolution_adjustment build_resolve 工厂写 guard（UNIONRESOLVE-PKG-G-0001 调用点 ripple，Lane PKGG）
`build_resolve` 闭包（cc:2447-2457 臂，`ResolvedUnion::with_field` 调用点）
由工厂**读** guard 改为**写** guard：`with_field` 签名随本票改为
`&mut TypeFactory`，指针臂执行 oracle unionresolve.cc:54 的
`typegrp.getTypePointer` interning（type.cc:3867）。本文件仅此一处
guard 翻转，无其他逻辑变化；调用方不持工厂 guard，无重入面。

- `output_metatype` 注释同步：PTRSUB/PTRADD/COPY 的 None 表项对 castOutput
  默认臂不再可达（被前置臂拦截）。

### 2026-09-26 — F8FOR 测试夹具字段补齐（HTTPDMAIN-F8-FORLOOP-0001，Lane F8FOR）

`tests::` 内 `BlockWhileDo` 夹具构造补 `initialize_op/iterate_op/loop_def`
三字段（cfg(test) 编译修复，零行为；字段本体见 docs/api/block.md 同日节）。

## 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

## 2026-09-26：ActionConditionalConst inSlot 回边索引 + blockIsDom 前置门（SQ-STACKSPILL-TYPEWRITEBACK-0001，Lane STACKSPILL）

**find_const_compare 的 inSlot 取值**（`// Ghidra: coreaction.cc:4478 ActionConditionalConst::findConstCompare`）：
oracle cc:4511 `points.emplace_back(varVn, constVn, bl->getOut(constEdge), bl->getOutRevIndex(constEdge), blockDom[constEdge])`
——ConstPoint 的 `inSlot` 是 **`getOutRevIndex(constEdge)`**（const 块 in-edge
列表里指向本分支块的那条边的下标），不是分支块自己的 out-edge 下标。旧端口直接
传 `const_edge`（且把已传入的 `bl_out_rev_index` 参数标为 "not used"），两者只在
目标块 in-edge 排序恰好镜像分支 out-edge 编号时重合。反例（sasquatch sigwinch
@0xabd7）：`je ac39` 是 ac39 的 **in-edge 0** 却是分支块的 **out-edge 1** —— 假
inSlot 使 propagateConstant 的 immediate-edge 臂（cc:4408 `op->getIn(point.inSlot)
== varVn`）匹配到**错误的 MULTIEQUAL 槽**，经 handlePhiNodes/placeCopy 把
`piVar5→unaff_R12` 的栈溢出 COPY 链 phi 输入替换成 const-0（`unaff_R12 = 0`），
随后 RuleEarlyRemoval 销毁无读者的 `COPY R12 = RAX`@0xabe7，
ActionInferTypes 的 int4* 传播链断裂（writeBack coreaction.cc:5043 无类型可回写
→ gatherVarnodes 的 fixed hint 全 Unknown，varmap.cc:1140 `vn->getType()`）——
golden `int4 *piStack_68`/`int4 *unaff_R12` 退化为 `xunknown8`。修复 =
`in_slot = bl_out_rev_index[const_edge]`（block.rs `get_out_rev_index` 既有忠实
镜像，block.hh:303）。oracle 侧探针实证（锁定库 +condconst/ruleaction 只读
trace）：oracle 同点位 `inSlotMatch=0`（假 inSlot 下才会匹配），MULTIEQUAL 保
持 R12@copy 输入，`unaff_R12 = piVar5` 存活。

**propagate_constant 的 cc:4435 前置门**（`// Ghidra: coreaction.cc:4383 ActionConditionalConst::propagateConstant`）：
oracle cc:4435 `if (!point.blockIsDom) continue;` 在 dominates 判定**之前**把
非支配点整条跳过——既不做常量替换也**不 pushConstant**。旧端口把该门折叠进
`if (block_is_dom && dominated { … } else { push_constant }`，使 blockIsDom=false
的点（如多前驱 merge 目标）落进 else 臂——在 `COPY R12 = RAX` 这类溢出链 COPY
输出上伪造 ConstPoint，同样终结于 const-0 phi 替换。修复 = 还原三段结构：
`if !block_is_dom { continue; } if dominated { …replace… } else { push_constant }`。

E2E（基=8dbb5072 干净基线 worktree A/B 亲证）：①sq 面 D3 族收敛——sigwinch
`piStack_68`/`unaff_R12 = piVar5`（24 行残差=typedef 前导+ram 命名+CASTFUSE，
各有既有票）、progressbar_error `piStack_150/188/190`+`pxStack_d8/e0`（24）、
squashfs_opendir_1 `pxStack_170`（36）；②canon curl md5 `6af97704`、httpd md5
`d6fd730a` 双字节恒等；③镜面棘轮 curl 58/65、httpd 124/150、vsh 15/16 全 PASS
未重钉，sq 6860/7500+810/810（numbering=7 预存承重）；④bank 391/391；⑤cargo
test --lib 1749P/0F。sq 全量 skeleton 7060→6860（−200），53 函数改善
（process_extract_files −844/add_path −842/pre_scan −375 等）。

**遗留两支（登记 TODO，见车道终报）**：(a) read_inode_3/1 + LzmaEnc_CodeOneBlock
三函数 0→~850 回退——oracle 侧 condconst 探针实证这些函数的 ram 合并被
cc:4404 `varVn->isAddrTied() && 同址` 守卫拦下（oracle 探针 at(var)=1），而
Rugra 裸面 gen_decompile 无 Database（symboltab=None），ram varnode 永不携带
addrtied——CSPEC-GLOBAL-APPLY-0001 既登记残差（Architecture 收集
global_scope_ranges 但从不应用到 Database）；canon 驱动侧手补
`db.add_range(0..MAX)` 故 canon 不受影响。(b) cc:4404 的 oracle 精确形式
（去掉 Rugra 端多余的 `out.isAddrTied()` 合取项）单独验证时打破 httpd canon
字节恒等（460367b2 vs d6fd730a，ap_fini_vhost_config 等 5 函数）——旧合取项
是 canon 现状的承重补偿（Rugra 侧 ram 合并输出 varnode 缺 addrtied 旗标），
须随 (a) 的 Database 底层修复一并对齐（A/B 复测）。

**CR-STACKSPILL 合并附带（root 集成同 commit）**：cc:4404 守卫处多余的
`out.is_addr_tied()` 合取项已就地补 `// CSPEC-GLOBAL-APPLY-0001 承重补偿`
内联票引（coreaction.rs propagate_constant MULTIEQUAL 臂,合并态 ~14342）——
语义零变化,纯票引标注;同 commit 登记 **CONDACT-FROMVALUE-FLIP-PAIR-0001**
（CR 终判 F-2/F-3:apply 隐含布尔点 flip 配对互换 vs oracle cc:4539-4540
无条件三元组、CBRANCH 出边序注释勘正、链式 BOOL_NEGATE 解包超集审计,详见
TODO_BOARD 票行）。CR 条件 F-1（证据目录实验残留改名
`httpd_canon.c→httpd_canon_cc4404-experiment.c`,md5 460367b2 非 canon 锚
d6fd730a）已在 /dev/shm/rugra-reports/stackspill-evidence/ 执行。

## 2026-09-26：ActionConditionalConst phi 边排序键改 SeqNum time（PAREVAL-DETERM-HERMETICITY-0001，Lane HERMIT）

- **缺陷**：`collect_reachable`/`handle_phi_nodes` 的 `phi_node_edges` 旧表示为
  `Vec<(usize, usize)>`——元素 0 是 `Arc::as_ptr(op_arc) as usize`（op 的**裸堆地址**），
  `Vec::sort()` 按元组序=按堆地址排序。`handle_phi_nodes`（cc:4321-4330 主循环）按此
  序对每条断连 phi 边调 `place_copy`（cc:4200-4222：`newOp`+`newUniqueOut`+分支前
  `opInsert`），故**影子 COPY 的 unique temp 分配序、块内插入序、最终打印语句序全部
  由堆地址序决定**——受进程内前置反编译分配历史扰动（非单调剂量响应）+ASLR 影响
  （跨进程翻转）。sqlite3 `shell_exec` 同函数同输入两字节变体（38491B→38519B 现尺，
  两相邻零赋值 `pppppbVar20=0`/`param_2=0` 互换）即此机制；oracle 12.0.4 同剂量
  矩阵（solo×3/dose k5..k0/dose-arch）恒单变体——Rugra 侧对齐缺陷。
- **oracle 语义（亲读）**：`collectReachable`（cc:4090）`sort(phiNodeEdges…)` 的
  比较器是 `PcodeOpNode::operator<`（expression.hh:41-48）——**不同 op 按
  `op->getSeqNum().getTime()` 比较（指针只做相等性检查，永不做排序键）**，同 op 按
  slot；`binary_search`（cc:4106）成员测试用同一比较器。`handlePhiNodes`
  （cc:4299-4333）直接以排序后序迭代 `phiNodeEdges[i].op`，无存活过滤。
- **修复**：`phi_node_edges` 改 `Vec<(PcodeOpRef, usize)>`（Arc+slot）；
  `sort_by`/`binary_search_by` 按（SeqNum time, slot）——探针 time 提升出
  binary_search 闭包（外层 `op` 读守卫存活，防同锁再入）；`handle_phi_nodes`
  直接持 Arc 迭代（去掉旧 alivelist 裸指针 O(n) 线性找回，Ghidra 无存活过滤且
  push→handle 窗口内无 op 销毁——propagateConstant cc:4413/4424 push 到
  cc:4459-4464 handle 之间只读）；`place_multiple_constants`（死代码，flowTogether
  腿缺失=独立缺口 CONDACT-FLOWTOGETHER-LEG-0001）同步新类型签名，行为零变化。
- **验证**：剂量实验 k=0..5 全部恒等 fnv `4110e793…`（=变体 A=oracle 语句序
  `pppppuVar18` 先 `param_2` 后），双进程复跑一致；7 剂量 IR 全量转储归一化后
  单一 md5（完全封闭）。canon/镜面/bank/测试门禁见车道终报。

## 2026-09-26：mapglobals 单测改产线形态（CSPEC-GLOBAL-APPLY-0001 连带，Lane CSPECGLOBAL）

`test_action_mapglobals_creates_symbol_for_persistent_ram_varnodes`：自
CSPEC-GLOBAL-APPLY-0001 起每个 `Architecture` 构造即持有 Database
（architecture.cc:600 buildDatabase），Funcdata 的 canonical 默认 arch 的
空 rangetree 使 `map_globals` 忠实抛 "Could not discover scope"
（funcdata_varnode.cc:1704-1705）。测试改为自带 ram 全域 DB 的 arch（产线
parse 后形态），可观察面从 legacy symbol_table proxy 改为 DB 全局 scope 的
addSymbol（cc:1709）。生产行为零改动；cc:4404 承重补偿合取（:14342 注记）
的 A/B 摘除见同车道第二 commit。

## 2026-09-26：cc:4404 oracle 精确形还原（CSPEC-GLOBAL-APPLY-0001 第二 commit，Lane CSPECGLOBAL）

`ActionConditionalConst::propagate_constant` MULTIEQUAL 臂的守卫还原为
coreaction.cc:4404 逐字形：`varVn->isAddrTied() && varVn->getAddr() ==
op->getOut()->getAddr()`——摘除输出侧 `out.is_addr_tied()` 承重补偿合取
（裸面无 DB 时代的补偿;constructor symboltab 落地后每面 ram varnode 经同
一 newVarnode 折叠取得 addrtied,合取冗余）。A/B 三态（base d153c868 /
commit1 / commit2）: canon curl+httpd 字节恒等（md5 c33052a3/6923d6c1）,
镜面 curl 74/58/0/0、vsh 71/15/0/0、sq 810/4530/0/0、httpd 29/156/0/0
全同 commit1;1778P/0F;bank 391/391。CR-STACKSPILL 时代"单独落地打破
httpd canon(460367b2)"不再复现。
## 2026-09-27：62-clone 类级裁决登记表（WORKPKG-UNMAP-COREACT-0002 ③，Lane COREACT2）

`coreaction.hh` 中 62 个 Action 类各带一个 `virtual Action *clone(const ActionGroupList &)`
（coreaction.hh 全文件 65 处 clone 声明，类粒度去重=62）。全部为同一模板：

```cc
virtual Action *clone(const ActionGroupList &grouplist) const {
  if (!grouplist.contains(getGroup())) return (Action *)0;
  return new ActionX(getGroup());
}
```

**裁决（类级 RUGRA-GLUE，一条家族映射，不冒充 62 个独立移植）**：C++ 逐类 clone 样板
只做两件事——组员资格门 + 带组名的重建。Rust 侧等价形态已结构性存在：

- 注册即工厂：`add!(parent, "group", Box::new(ActionX::new()))` →
  `add_action_factory_in_group`（action.rs:711）把构造闭包存入 `child_factories`；
- 组门 + 重建：`ActionGroup::clone_group`（action.rs:734，镜像 action.cc:391
  ActionGroup::clone）对每个 child 先问虚 `clone_for_groups` 覆写（容器/fixture 动作用），
  缺省臂=`grouplist.contains(child_groups[i])` 门 + `factory()` 重建——恰是 62 个 C++
  样板的公共语义；叶子 Action 因组名与构造被工厂闭包一次捕获，无需逐类虚方法。

62 类全表（awk 类粒度提取自 coreaction.hh，升序；映射全部=「add! 工厂缺省臂」）：
ActionActiveParam · ActionActiveReturn · ActionAssignHigh · ActionConditionalConst ·
ActionConstantPtr · ActionConstbase · ActionCopyMarker · ActionDeadCode ·
ActionDefaultParams · ActionDeindirect · ActionDeterminedBranch · ActionDirectWrite ·
ActionDominantCopy · ActionDoNothing · ActionDynamicMapping · ActionDynamicSymbols ·
ActionExtraPopSetup · ActionForceGoto · ActionFuncLink · ActionFuncLinkOutOnly ·
ActionHeritage · ActionHideShadow · ActionInferTypes · ActionInputPrototype ·
ActionInternalStorage · ActionLaneDivide · ActionLikelyTrash · ActionMapGlobals ·
ActionMappedLocalSync · ActionMarkExplicit · ActionMarkImplied · ActionMarkIndirectOnly ·
ActionMergeAdjacent · ActionMergeCopy · ActionMergeMultiEntry · ActionMergeRequired ·
ActionMergeType · ActionMultiCse · ActionNameVars · ActionNonzeroMask ·
ActionNormalizeSetup · ActionOutputPrototype · ActionParamDouble · ActionPrototypeTypes ·
ActionPrototypeWarnings · ActionRedundBranch · ActionRestrictLocal ·
ActionRestructureVarnode · ActionReturnRecovery · ActionSegmentize · ActionSetCasts ·
ActionShadowVar · ActionSpacebase · ActionStackPtrFlow · ActionStart ·
ActionStartCleanUp · ActionStartTypes · ActionStop · ActionSwitchNorm ·
ActionUnjustifiedParams · ActionUnreachable · ActionVarnodeProps

（同族同裁决：ruleaction.hh 各 Rule::clone 同构映射到 RulePool 的工厂注册——不在本表
写域，REGEN/TYPEOP 车道域。）

**39 项清单内其余两裁决**（详见上节）：propagationDebug=TYPEPROP_DEBUG 调试脚手架，
oracle release 构建同样缺席 → 缺席即对齐，不移植；PropagationState ctor/step=
propagate_one_type 的 edges_for 内联投影（coreaction.rs:8722 锚），无独立结构体。

## 2026-09-27：WORKPKG-UNMAP-COREACT-0002 十函数落地（Lane COREACT2）

以锁定 oracle 亲读各函数全貌后 1:1 移植（排除 lookForFuncParamNames/makeRec——已移植，
REGEN 边）：

- **isCopyConstant**（cc:2174-2181）+ **isDelayedConstant**（cc:2187-2200）：
  ActionRestructureVarnode 关联函数；INT_ADD 臂保持 oracle 槽序（slot 1 先查）。
- **protectSwitchPathIndirects**（cc:2206-2258，53 行）：BRANCHIND 开关值单路径回溯——
  binary/ternary 双输入沿非 delayed-constant 侧（双侧均非→多路径 return）；unary/INDIRECT
  沿 in(0)（INDIRECT 记为 lastIndirect）；LOAD 沿 in(1)；MULTIEQUAL 特判=首个 INDIRECT 定义
  输入 set_no_indirect_collapse 后 return 不再回溯；终点常量且存在 lastIndirect →
  set_no_indirect_collapse。锁守卫逐臂 Option 化（缺失即 return，良构 IR 行为不变）。
- **protectSwitchPaths**（cc:2262-2272）：块序 0..size 扫 lastOp，BRANCHIND → 逐 op 保护；
  接入 ActionRestructureVarnode::apply cc:2284-2285 槽（`is_jumptable_recovery_on` 门，
  替换原 TODO 注释）。
- **checkPointerIssues**（cc:2349-2373）：ActionSetCasts 关联函数；LOAD→out / STORE→in(2)
  调用点插在 per-op 输入 cast 循环后、castOutput 前（cc:2762-2767，oracle 的 `opc` 局部
  于循环顶捕获——LOAD/STORE opcode 不被 preflight 变异，live 读恒等）；size 语义=非
  PTR 或 pointee size≠值宽 → "Load/Store size is inaccurate" warning；空间语义=指针带
  space 属性且 op 空间常量既非该空间也非其 contain → refers/attribute warning。
  TypeOp 元数据名小写首字母大写化（"load"→"Load"，typeop.cc:433/:513）；contain 项投影
  =enum 指针空间无虚拟空间 → getContain 恒 null（每个可表达空间的 oracle 同形）。
  双 if 结构（size 与 space 两独立判定）保持。
- **canonicalReturnOp**（cc:5311-5336）：从 propagate_across_returns 内联提取为独立函数；
  **补上缺失的 getHaltType()!=0 跳过**（HALT|BADINSTRUCTION|UNIMPLEMENTED|NORETURN|
  MISSING 五旗标，op.hh:171）——此前内联版漏此守卫；second loop（cc:5354-5371）同样补
  halt 跳过。typeOrder 严格 `< 0` 换绑（先到者平局保持）。
- **extendInput**（cc:4590-4607）：ActionPrototypeTypes 关联函数 + locked-input 物化循环
  （cc:4682-4703）整段补齐。原 RUGRA-GAP 注释（ProtoParameter 无空间/FuncProto 无
  model）已过时——两载体现已存在，删除 stale 注释。PIECE 臂经 param 类型 INT→SEXT /
  其他→ZEXT；newOp(1, topbl.getStart) + newVarnodeOut(vdata) + opInsertBegin 全链。
  cc:4653-4674 truncated 空间栈指针 ZEXT 块：生产语料恒 untruncated（oracle 同死），
  Funcdata 侧无 default-code-space 句柄，守卫投影为常 false（登记残差，修复路径=
  truncate-aware 空间管道）。
- **flowTogether**（cc:4174-4192）：ActionConditionalConst 关联函数——空 excise 的
  collectReachable 从 edge i 输出标记可达集；其余 result≠0 边命中标记 → 双双记 result=2；
  clearMarks 后返回。接入 handle_phi_nodes cc:4314-4336（alternate>1 门 + hasFlowTogether
  → placeMultipleConstants + count+=1，此前两段全缺）。
- **countMarks**（cc:2007-2030）+ **traceTrash**（cc:2047-2138，92 行）：
  ActionLikelyTrash 关联函数全量移植。countMarks=逐输入 inner for(;;)：标记即计并断、
  未写断、def==op 指针同一即计并断（绕环）、仅 INDIRECT def 沿 in(0) 上链。traceTrash=
  markedlist 索引序 BFS + per-descend 五臂开关（INDIRECT persist/indirect-store/记录；
  SUBPIECE；MULTIEQUAL/PIECE 的 countMarks==numInput 门；INT_AND 整形字节常量掩码
  `(mask<<8|16|32)&mask` 三形；default 非垃圾）；allroutes 输出未标记=未见全输入→
  非垃圾；收尾无条件双清（op 标记+vn 标记）。
- **ActionLikelyTrash::apply**（cc:2140-2170）：循环结构全量（find_covered_input/
  双锁跳过/traceTrash 门/INDIRECT→constant-0+mark_indirect_creation、INT_AND→constant-0/
  count+=1/return 0）。**trash 列表源投影**：fspec.rs decode 把 `<likelytrash>` 折叠进
  effects（既有 seam），FuncProto 无独立 trash 载体 → 迭代空表——生产 x86-64-gcc 语料
  逐字节恒等（该 cspec 无 `<likelytrash>` 元素，oracle 列表同为空；仅 32 位 x86gcc.cspec
  有）；fspec 长出独立载体后循环即活。登记 WORKPKG-UNMAP-COREACT-0002 残差项。
- **propagationDebug**（cc:4980-5002）：`#ifdef TYPEPROP_DEBUG` 调试脚手架——oracle
  release 构建同样不含该函数；按"debug-scaffolding 缺席=release 对齐"裁决不移植，
  入 62-clone 裁决表。
- **PropagationState ctor/step**（cc:5115/:5139）：已在 propagate_one_type 的 edges_for
  投影内联实装（coreaction.rs:8722 注释锚），无独立结构体——入 62-clone 裁决表（inline
  projection 形态）。

**新测试**：`test_likelytrash_count_marks_and_trace_trash`（手接 IR 锁 countMarks 的
INDIRECT 链计数 + traceTrash 三臂：INDIRECT-only 垃圾/INT_ADD 非垃圾/0xff00 掩码垃圾 +
标记清理）。

**验收**：亲父 6a458387 A/B 双语料（curl 3184 行/httpd 2293 行）**字节恒等**（diff=0）；
canon 门禁 curl **157/0/0**、httpd **311/0/0**（=任务基线，零回退零漂移）；生产中性归因=
protectSwitchPaths 恒 is_jumptable_recovery_on 门内（canon 关）、checkPointerIssues 仅
warning 通道、extendInput 恒 gcc-model COPY 早退（无 assumed extension）、flowTogether
需 alternate>1 的多 phi 边形态、canonicalReturnOp halt 剔除在 canon 语料无 halt RETURN、
trash 迭代空表（双侧同空）。

## 2026-09-27：ActionDynamicMapping / ActionDynamicSymbols 双 apply 实装（COREACT-DYNMAP-STUB-0001 + COREACT-DYNSYM-STUB-0001，Lane COREACT2）

以锁定 oracle 亲读 `coreaction.cc:4852-4884` 两 apply 全函数体 + `funcdata_varnode.cc:1314-1399`
两委托全貌 + `database.cc:1921` beginDynamic/endDynamic + `varnode.cc:410-439`
setSymbolProperties/setSymbolEntry + `action.cc:100-145` perform 状态机后，把两个注册空桩
升级为 1:1 移植：

- **`ActionDynamicMapping::apply`**（cc:4852-4867，mainloop 槽 :5504，
  restructurevarnode/infertypes 之前每 pass 跑）：遍历 `ScopeLocal` 动态条目表
  （varmap 侧=`symbols` arena 中 `is_dynamic=true` 条目，槽序=插入序=oracle
  `dynamicentry` std::list 序），逐条调 `Funcdata::attemptDynamic_mapping`
  （first_use_addr=usepoint（database.cc:122 getFirstUseAddress 的单址 uselimit 投影）/
  hash/size/category 投影），成功一次 `count += 1`（cc:4864），**返回字面 0**
  （cc:4866——count 是 Action 基类字段，只被 perform 的 lcount<count 消费）。
- **`ActionDynamicSymbols::apply`**（cc:4869-4884，双槽 :5724 merge 相 DominantCopy 后
  / :5733 MapGlobals 后 NameVars 前，rule_onceperfunc）：同一 walk，委托
  `attempt_dynamic_mapping_late`（名字级附着），成功 `count += 1`（cc:4881），返回 0。
- **`++iter` 先于调用的快照等价性**：oracle 在调 attemptDynamicMapping 前先递增迭代器
  （std::list 中途变更安全）；Rust 侧改为行前快照（借用安全），等价性论证=被移植的
  委托臂（find/attach、equate、size 门、union-facet 臂——oracle applyUnionFacet
  (funcdata_varnode.cc:1637) 只解析 union 字段不铸动态条目）都不能在 walk 中途增长
  动态表，故快照集合 ≡ 原地 walk 集合。注释里逐条登记。
- 两结构体新增 `pub count: i32` 字段 + `take_count_delta` 实现（外部化 oracle
  protected `Action::count`，perform 的 applied 判定 action.cc:346 `lcount<count` 由
  ActionState 累计器接住）；`new()` 构造与 action.rs 三处注册点（:5504/:5724/:5733，
  前序车道已注册）无需改动。
- **翻绿证据**（copytrim_remat_1204 fixture 双侧直跑，oracle stdout sha256
  = `4910bcdf…` ≡ metadata 钉定 canonical，未改 fixture/metadata——重钉留 MB20）：
  - `action_walk_level`（C4）**全 18 行 MATCH**（含 after-census `mapped=1` 翻绿、
    act `count=0|status=0` 天然对齐——oracle count=0 因 setSymbolProperties 假返回）。
  - `action_late_walk`（C5）17/18 MATCH：after-census `mapped=1` 翻绿；残差仅 act 行
    `count=1|status=1` vs `count=0|status=0`——fixture 硬编码 count 打印 + 直调 apply
    绕过 perform 状态机，属 fixture 侧重钉（MB20 集成），非实现缺口。
  - 全局分歧预算 11 行 → 4 行对（残差全部在 funcdata.rs/dynamic.rs 域：
    DYNMAP-SETPROPS-RET-0001、DYNHASH-UNIQUE-ANCHOR-0001 +
    DYNMAP-LATE-CAST-RETARGET-0001、C5 act 重钉行）。
  主管线影响面：哈希命中用点从"永不得命名"变为 mainloop 每 pass 重附着 + merge 相
  /终相两次 late 命名附着（CASTFUSE-A 链 action 级半收口）。

## 2026-09-26：ActionDeindirect 三臂全量重写（FSPEC-DEINDIRECT-TRIGGER-0001，Lane FSPECDEIN）

以锁定 oracle 亲读 `coreaction.cc:1219-1280` 全函数体后，把部分重实现升级为
逐句 1:1（TRIGFACE 车道测绘钉死：oracle fspec 两触发点——fspec.cc:5471/5503——
因缺臂而生产不可达）：

- **COPY 链追踪改忠实形态**（cc:1231-1232）：`walk_copy_chain` 返回**走链后的
  varnode**（不是只返回常量终点），臂判定用 walked vn 的
  persist/externref/constant 三性质；旧 20 跳上限与"先查常量再走链"两自创
  结构退役。
- **external-ref 臂**（cc:1233-1240）：`isPersist && isExternalRef` → 生产
  `queryExternalRefFunction`（arch.symboltab 全局 scope stack_external_ref；
  per-symbol `refaddr` 存储为 CALLSPEC-0001 seam 残差——检测可达、referral
  解析无生产通道时行为=oracle `newfd==0` 不转换）→ `deindirect` + count+=1 +
  continue。
- **constant 臂**（cc:1241-1257，`else if` 语义保真）：wordsize 取函数入口空间
  → `AddrSpace::addressToByte` 缩放 → `funcptr_align != 0` 时
  `offset >>= align; offset <<= align` 剥编码位（x86-64 funcptr_align=0 恒等）→
  生产 `queryFunction`（主=arch.symboltab 全局 scope `query_function_addr`
  FunctionSymbol 层；fallback=驱动 `symbol_table`/`external_prototypes` 通道，
  保住既有转换集）→ `deindirect`（entry/name/annotation/CALLIND→CALL/
  indirectOverride/lateRestriction 全链）+ count+=1 + continue。
- **typed-funcptr 臂**（cc:1258-1277，独立 `if`——前两臂条件成立但查询落空仍
  进入）：`hasTypeRecoveryStarted()` 门（stackstall 在 ActionInferTypes 之后，
  生产恒真）→ `op->getIn(0)->getTypeReadFacing(op)`（原始输入，非 walked vn）
  PTR→CODE → `TypeCode::proto` 存在且 `!isInputLocked()` → `force_set` +
  count+=1（isInputLocked 注释保留 oracle FIXME 语义）。
- **callee proto 生产形**：`db_default_callee_proto` = 默认构造 FuncProto（无锁/
  noreturn/参数——database.cc:557 惰性 new 的 db 函数 `funcp` 旗标面）**+ 默认
  model 绑定**（`setInternal(evalfp/defaultfp, void)`——与 `ActionDefaultParams`
  （cc:2311-2332）给 callspec 的形态一致）。绑定理由（探针实证,站点 0xead55）：
  oracle 的常量折叠收敛在 ActiveParam finalize **之后**才到达 deindirect 拷贝
  （拷贝后的 model-null deriveInputMap 在 oracle 会崩,coreaction.cc:1753→
  fspec.hh:1494——golden 存在=该状态 oracle 从不可达）；Rugra 的常量在迭代 1
  即析出（npasses=1、6 活跃 trial 时即拷贝）,model-less 拷贝把仍活跃的 finalize
  晾在简化模型 fallback 上丢光 trial（sqlite3_blob_write 调用参数丢失）。绑定
  默认 model 使拷贝 model-中性;oracle 已行使的每个门结果不变（isCompatible
  经 `this==op2` 通过,恰如 oracle null model 经 `compatModel==op2`（fspec.cc:
  2406-2411）通过;noreturn/inline/lock 门同读 false）。分歧面=非默认 model 的
  callspec（锁定单 model gcc 语料为空,登记于本票）。
- 循环内调用 `deindirect` 后**同一 op 的 opcode 已改 CALL**，后续迭代经
  cc:1229 的 CALLIND 门自然跳过（与 oracle 相同的幂等闭包）。
## 2026-09-27：propagate_across_returns 温度覆写无条件化 + halt/op 恒等守卫（COREACT-TEMPOVERWRITE-0001，Lane TEMPOVER）

`ActionInferTypes::propagate_across_returns`（coreaction.cc:5342-5372）第二循环的
覆写条件由「空或严格更次序才覆写」（`None→set` / `type_order<0→set`）对齐为
oracle 的**指针恒等判定**：

- **cc:5364** `vn->getTempType() == ct` 是裸 `Datatype*` 指针恒等（varnode.hh:198
  `temp.dataType`，未置即 NULL）。Rust 侧映射为 `Arc::ptr_eq(existing, &base_ct)`
  ——TypeFactory 的 findAdd/base_cache 结构化驻留使 Arc 指针恒等与 Ghidra
  Datatype* 恒等同构；无条目（Ghidra NULL）永不等于非空 ct，直落覆写。
- **cc:5365** `vn->setTempType(ct)` 为**无条件覆写**：现存类型与 canonical 类型
  指针不等即覆写（含「不同但非严格更次序」与「现存更优」两种旧代码跳过的
  情形），随后 `propagate_one_type` 重推数据流。

同函数两循环补齐 oracle 守卫（任务票面称 COREACT2 已补，实测该函数内缺席，
属票面事实性偏差，本车道一并 1:1 对齐）：

- **cc:5321/:5359** halt 守卫：`(flags & pcodeop_flags::HALT) != 0 → skip`
  （Rugra HALT 旗标为 Ghidra `getHaltType()!=0` 的既定代体，同
  ActionPrototypeTypes/ActionActiveReturn 既有形态）。
- **cc:5357** canonical 跳过由 varnode 恒等改判 **op 恒等**（`best` 携带
  `PcodeOpRef`，`Arc::ptr_eq(&r.0, &canonical_op.0)`）：rv==base_vn 出现在他
  op 时由 :5364 指针恒等兜底跳过，两端可观测行为等价，取字面形。
- 循环内 op 读锁改为短作用域（守卫提取后即释放），避免
  `propagate_one_type` 跨读锁遍历。

**验证（canon A/B，基=6a458387 双构建亲测）**：curl 输出 A/B **字节恒等**
（md5 51cc85d2，157/0/0）；httpd **字节恒等**（md5 f5a05fd5，311/0/0）。
构造性休眠见证（临时探针，未提交）：覆写判定位 curl 触达 **0** 次、httpd
触达 **339** 次全部 `type_order<0`（新旧语义重合的严格改进覆写），
`diverges=true`（现存非恒等且 `type_order>=0`）双语料 **0** 次——残差触发
面=「canonical 类型对现存类型非严格更优且指针不同」，canon 语料不存在该
形态。触发条件（票面登记）：多 RETURN 函数中某 RETURN 输入已有与 canonical
返回类型不同源（非同一 interning 实例）且 typeOrder 相等或更优的温度类型。


## 2026-09-27（CVAR1HOIST）：GETPARAM-CVAR1-HOIST-0001 MB20 中间态复核判决（零 src 改动）

本车道（基=master 836ae2bc，MB20 合并进行中中间态）对该票重跑双侧对照：
**票面分歧（oracle 判 `*flag` 入口 LOAD explicit 而 Rugra implied）在当前
基线不复现——已被 CVRHOIST `ActionMarkImplied::apply` 后代先行 DFS
（commit 363c9cfd，已入基）连同 gparam 084cdd1c 双修（check_implied_cover
读前 `update_cover_locked` 惰性重建 + `inflate_test` 无条件现聚合）与
ALIASGATE cb759c42（isPossibleAlias 端口）共同关闭**，四件全部在基内亲证。

- **canon 双脸实测（836ae2bc 本树 release 构建）**：`cVar1 = *flag;`
  （canon :1677 对应位，Rugra :1570）与 canary
  `lVar2 = *(long *)(in_FS_OFFSET + 0x28);`、消费者 `if (cVar1 == '-')`
  三件全数显式物化==canon 逐形；bare 脸（RUGRA_SEEDS=0）同样物化（:1549）。
  canon 门禁 curl **157/0/0**、httpd **311/0/0**（==亲父基线，零漂移）；
  `--func getparameter` = 31 skeleton 行/0 defects/0 numbering，残差全为
  decl 类型槽族（Configurable*/FILE* 声明序）与 cast 渲染族（`(FILE *)fopen`
  形）——均在他域既有登记（typeprop/setcasts/C3 系），非 explicit/implied 域。
- **决策链亲读复核（本轮亲读 oracle，铁律 1.2）**：
  `ActionMarkExplicit::apply` cc:3237-3272（baseExplicit 负 desccount 才
  预标 explicit——`*flag` LOAD 输出不在此列，显式性完全由 MarkImplied 判定）
  / `checkImpliedCover` cc:3376-3414（检 (1) interior contain+isPossibleAlias、
  检 (2) CALL 交叉 interior、检 (3) inflateTest） / `apply` cc:3416-3455
  （DescTreeElement 后代先行）/ `Merge::markImplied` cc:1595-1605（置 implied
  + 弄脏 def 输入 hasCover 者 cover）/ `Merge::inflateTest` cc:1616-1647
  （whole-interval==2 才拒、copyShadow/partialCopyShadow 豁免、piece 交叉）。
  Rugra 对应物（coreaction.rs:4882-5050/5058-5164、merge.rs:1338 族）逐段
  在位且与本判决输出一致。oracle 侧决策态由 CVRHOIST 断点 harness 钉死
  （/dev/shm/rugra-tests/cvrhoist/oracle_gp.err：LOAD#452984834@0x3f49
  markimplied 后 EXPLICIT、inflateTest 不参与）。
- **域外无移交**：merge.rs 无新缺口；本票无残差留在 explicit/implied 判定域。
  机制 C：零 src 改动，N/A。门禁全记录见
  /dev/shm/rugra-reports/LANE_CVAR1HOIST_2026-09-27.md。

## 2026-09-27（Lane TRUNCSPACE）— ActionPrototypeTypes::apply 截断空间 ZEXT 块（cc:4653-4674）

COREACT2 残差②（投影 false 注释块）被真管道取代：`apply` 第 5 步（第 4 步
initActiveOutput 之后、锁定输入物化之前）落地 oracle 的截断代码空间栈指针
ZEXT 物化——`spc = getArch()->getDefaultCodeSpace(); if (spc->isTruncated())`
→ `stackspc = getStackSpace()`（恒在）→ `topbl = getBasicBlocks().getBlock(0)`
（块表空则 None）→ `for i in 0..numSpacebase()`：`fullReg = getSpacebaseFull(i)`
+ `truncReg = getSpacebase(i)` → `invn = newVarnode(truncReg)` +
`setInputVarnode` → `newOp(1, topbl->getStart())` +
`newVarnodeOut(fullReg)` + `opSetOpcode(INT_ZEXT)` + `opSetInput` +
`opInsertBegin`。守卫/查询走 `arch.space_is_truncated(arch.
get_default_code_space())` 与 `arch.stack_space_get_spacebase(_full)`
（translate.cc:104-124 的 arch 投影，装配面见 docs/api/arch.md 同日条目）。
x86-64:LE:64 语言无 `<truncate_space>` 记录 → 生产语料双侧休眠（oracle 同死）；
单测 `test_prototypetypes_truncated_stack_zext` /
`test_prototypetypes_untruncated_no_zext` 钉两端形态。注：cc:4684 的
`ptr_size = isTruncated() ? getAddrSize() : 0` 属锁定输入物化段
（WORKPKG-UNMAP-COREACT-0002，wt/coreact2 交付），合并时该段应以本车道的
`arch.space_addr_size(arch.get_default_code_space())` 接线。

## 2026-09-27：castOutput CALLOTHER token 臂（PRINTC-STRDATA-TYPELOCK-0001）

`cast_output`（`// Ghidra: coreaction.cc:2532 ActionSetCasts::castOutput`）的
tokenct 分发补 **CPUI_CALLOTHER** 臂（此前落入 `output_metatype` 的
`_ => Int` 泛型臂，产出工厂 `int8`）：

- oracle 链（亲读）：`TypeOp::getOutputToken`（typeop.cc:282-285）默认即
  `op->outputTypeLocal()` → `TypeOpCallother::getOutputLocal`
  （typeop.cc:865-872）——按 in(0) 常量选 `UserPcodeOp` 描述符：
  `InternalStringOp::getOutputLocal`（userop.cc:361-364）返回
  **out varnode 自身（typelocked）类型**；`DatatypeUserOp`（userop.cc:70-73）
  返回注册 outType；元数据缺失时基类默认 `getBase(out.size, TYPE_UNKNOWN)`
  （typeop.cc:261-265）——**永非有符号 Int 基**。
- Rugra 实现直接复用 `crate::varnode::op_output_type_local`（该函数本批同步
  补齐 InternalStringOp 覆写，见 docs/api/varnode.md 同日节）；无工厂的
  detached fixture 回退 `base_type_for(size, Unknown)`。
- 症状链（探针实证，RUGRA_DBG_STRDATA per-action 快照）：泛型臂给 STRINGDATA
  CALLOTHER 的 token=int8 → `tokenct != outHighType` 短路失效 →
  implied+typelock force 臂（cc:2559-2562）触发 cc:2595-2609 替换序列
  （`newUnique` + `updateType(tokenct)` + `opSetOutput(op,vn)`）→ STRINGDATA
  出口 vn 被换成未锁 int8 新 unique → printc display_string（printc.cc:701-714）
  非指针臂 `"badstring"` + setcasts 因 int8-vs-char* 补 `(char *)` cast
  （双症状同根）。修复后 token=char*（出口 vn 自身类型）→ cc:2544-2548
  `tokenct == outHighType` 短路命中，零 cast 零替换，typelock 存续至 `stop`。

## 2026-09-27：build_localtypes 接通 symboltab 线程（VARNODE-CALLOTHER-VOLATILEOUT-0001）

`build_localtypes` 新增从 `fd.arch.symboltab` 提取
`Option<Arc<RwLock<Database>>>` 并透传给 `Varnode::get_local_type`（签名
+1 参数，插在 userops 之后）——oracle 的
`VolatileReadOp::getOutputLocal`（userop.cc:128-141）经描述符
`glb->symboltab` 边查全局 scope（cc:136
`getGlobalScope()->queryProperties` → cc:138 `getSizedType`），Rust 侧
`UserOpManage` 无 glb 反链，故沿 userops Option-thread 同型先例显式传参。
纯线程改动：无 volatile CALLOTHER 在飞时（五语料 cspec 无 `<volatile>`，
链首即断）行为零变化；canon A/B 字节恒等见车道终报。callother 域的
setcasts token 面不动（本票非 STRDATA 域）。
## 2026-09-27：RETURN 遍历接 begin_op(CPUI_RETURN)（Lane NORMGUARD2，COREACT-RETTABLE-TRAVERSAL-0001）

canonical_return_op（cc:5317-5318）与 propagate_across_returns 第二循环
（cc:5354-5355）两处 `obank.alivelist.iter().filter(opcode ==
CPUI_RETURN)` 投影改接 `obank.begin_op(CPUI_RETURN)`（op.rs:1937-1945，
op.cc:1158-1174 忠实镜像返回 returnlist 切片）。returnlist 序=
addToCodeList push_back（op.cc:881）的转换/插入时序；markDead 不摘表
（同 Ghidra，摘除在 destroy），故 isDead()/getHaltType() 跳过保持在
循环内（cc:5320-5321/cc:5358-5359，先 dead 后 halt 顺序不变），与
oracle 完全同构。零行为（CR-TEMPOVER 判据）：语料上 RETURN 同一插入
事件进两表序恒等，filter 隐含 dead 排除被循环内 isDead() 跳过包含——
canon 双语料 A/B cmp 字节恒等亲证（md5 51cc85d2 / 04b3b014）。

## 2026-09-27：HALT-only 守卫归五并集字面形（Lane NORMGUARD2，COREACT-HALTGUARD-NORM-0001）

全库 HALT-only 单旗标守卫清点（grep `pcodeop_flags::HALT`）后，剩余两处
归一为 op.hh:171 `getHaltType()` 逐字五旗标并集字面形：

### 守卫位清点表（grep `pcodeop_flags::HALT` 全库 5 个使用点）

| # | src/coreaction.rs | 所在函数 | oracle 锚点 | 归一前形态 | 归一后 |
|---|---|---|---|---|---|
| 1 | :9244 | `canonical_return_op` | cc:5321 | 五并集（CR-TEMPOVER 已归一） | 保持 |
| 2 | :9325 | `propagate_across_returns` 第二循环 | cc:5359 | 五并集（CR-TEMPOVER 已归一） | 保持 |
| 3 | :11759 | `ActionOutputPrototype::apply`（getFirstReturnOp 投影） | funcdata_op.cc:640 | **HALT-only** | **本票归一五并集** |
| 4 | :11957 | `ActionPrototypeTypes::apply` Step3 | cc:4637-4649 | 五并集（前期已归一） | 保持 |
| 5 | :16768 | `ActionReturnRecovery::apply`（单快照喂 cc:1921/cc:1943 两循环） | cc:1924/cc:1947 | **HALT-only** | **本票归一五并集** |

归一判据：op.hh:171 `getHaltType()` 逐字五旗标并集（halt|badinstruction|
unimplemented|noreturn|missing）；分歧集构造性空集（CR-TEMPOVER 证明——
语料无可达 RETURN 携四卫星旗标而不携 halt），故本票=纯防未来旗标启用的
语义漂移面收敛，零行为变化（canon 双语料 A/B cmp 字节恒等亲证，
md5 51cc85d2 / 04b3b014）。:3269 行的 getFirstReturnOp 陈述同步更新。

## 2026-09-27 — CALLSPEC-COPY-0001（ActionDefaultParams copy 臂生产化，Lane CALLSPEC）

**机制**：`ActionDefaultParams::apply`（cc:2311-2337）此前登记为
FUNCPROTO-MODEL-BIND-0001 残差——"copy-from-callee 分支不可达"。本次把
cc:2321-2330 的三分支臂 1:1 落地：

- **COPY 臂**（`fc.callee_proto()` 为 Some，即 queryCall 边界已存被调恢复
  原型——`FuncCallSpecs::set_callee_proto`，fspec 侧的
  `getFuncdata()/getFuncProto()` 可观察切片）：`fc.copy_proto_from(&callee)`
  （fspec.cc:3789 `FuncProto::copy` 全量转移）+ cc:2325
  `(!isModelLocked() && !hasMatchingModel(evalfp)) → setModel(evalfp)`；
- **NOFUNC 臂**：无被调 → 既有 `setInternal(evalfp, void)` 路径（含
  UNKNOWN-PROTOMODEL-0001 locked-guard 补偿）原样保留；
- 驱动 `link_call_specs` 在 libc/DWARF 两半安装调点原型的同时 `set_callee_proto`
  存档被调原型（canon 现行面仍由预管线安装定义——copy 臂被 `!hasModel()` 门
  控为惰性，canon A/B 字节恒等亲证）。

**验收**：双侧 fixture `tests/oracle/callspec_copy_1204.{cc,rs}`（锁定 oracle
e40ed130 手动构建 + Rust 侧经真实 `ActionDefaultParams::apply`）24 记录
**字节恒等 MATCH**（COPY/COPY_LOCKEDMISMATCH/NOFUNC 三臂：参数
typelock+namelock、寄存器存储 0x38/0x30、锁字、模型保留/绑定、调点名存活）；
canon curl 157/0/0 md5 51cc85d2 恒等 + httpd 恒等；单测
`callspec_copy_tests` 3 例。

**CAST-A 残差再归因（车道关键结论，非本机制可收敛）**：canon 探针实证
fgets/fclose 调点的 libc 表参数**已 typelocked**（`TypeOpCall::getInputLocal`
req=*FILE 解析成功），缺 cast 的直接原因是**参数位 facing 类型强度差**——
Rugra 把 DWARF 类型强定型到实参 varnode（req 与 cur 同对象 →
`castStandard` 早退），oracle 在这些位点的实参类型更弱。类型身份分裂实验
（libc 宇宙 vs DWARF 宇盟两 FILE 对象）被 golden 三组对照证伪
（`__stream = stdin`/`__stream = fopen` 双 nocast 与
`my_get_line((FILE*)__stream)` cast 不能同时成立）——A/B净 −18/回归 +6，
已回退。收敛责任移交 CURLCANON-PROTOCAST-INPUTS-0001（stage drill 钉
my_get_line/fgets 位点的首个类型状态分歧）。

## 2026-09-27：castInput 的 RETURN 分派臂——TypeOpReturn::getInputLocal 通道（Lane PROTOCAST，wt/protocast 基 wt/callspec bab71bc6）

- **缺口**：`cast_input` 的 opcode 分发没有 CPUI_RETURN 臂——RETURN 落入通用
  metain 回退（`input_metatype(CPUI_RETURN)=None` → ct 恒 null → 只有
  markExplicit 路径），锁定/恢复的函数输出类型永不驱动返回值侧 cast。oracle
  链：coreaction.cc:2662 `op->getOpcode()->getInputCast(op,slot,strategy)` 虚
  分派——`TypeOpReturn`（typeop.cc:898）**不覆写** `getInputCast`，落基臂
  typeop.cc:295-303：reqtype=`op->inputTypeLocal(slot)`（虚分派到
  `TypeOpReturn::getInputLocal` typeop.cc:901-922——slot 0 不定标记走基默认
  `getBase(size,TYPE_UNKNOWN)`；slot≥1 取**所在函数当前输出类型**
  `fp->getOutputType()`，cc:917 的 isOutputLocked 门在 12.0.4 **被注释**，仅
  VOID/尺寸不匹配回退基默认）、curtype=`vn->getHighTypeReadFacing(op)`、
  `castStandard(req,cur,false,true)`。
- **新增 `return_input_cast`**（`// Ghidra: typeop.cc:901
  TypeOpReturn::getInputLocal`，pub 供双侧 fixture 驱动）：reqtype 经既有
  `TypeOpReturn::get_input_local_in_fd`（typeop.rs:3292，ActionInferTypes
  buildLocaltypes 已用的同一实现）；curtype 链
  `vn_high_type_read_facing → v_type → get_base(in_size,Unknown)`；
  `cast_standard_full(&req,&cur,false,true)`。分发臂在 metain 回退前
  （RETURN → return_input_cast）——canon 效果：my_get_line
  `return (char *)__dest;`（golden:1344 形）收敛，canon curl
  157→**155**（−2，defects/numbering 双零，其余 124 函数字节恒等）；
  httpd 字节恒等。
- **`store_input_cast`/`call_input_cast` 转 pub**：双侧 fixture
  （`tests/oracle/protocast_facing_1204.rs`）直接驱动生产臂，与
  CALLSPEC-COPY 先例同形态（私有静态的 fixture 可达性）。
- **双侧 fixture `tests/oracle/protocast_facing_1204.{cc,rs}`**（锁定 oracle
  e40ed130 手动构建，真实 BfdArchitecture + followFlow'd my_fwrite
  Funcdata 上的真实 getInputCast 虚分派）：**17 记录字节恒等 MATCH**
  （sha bf5ee514…）。钉死的三面决策语义：
  1. **对象身份臂**（cast.cc:304 `curtype==reqtype` / cc:329
     `curbase==reqbase` 剥层后）：oracle 对**同形不同对象**的 struct 指针
     （DWARF 宇宙 FILE vs clib 宇宙 _IO_FILE）cast，对同对象 nocast
     （call_locked_distinct/call_conf_vs_file/store_distinct vs
     call_locked_same/store_same）——castStandard 从不比较名字；
  2. **RETURN 值臂**（本修）：ret_distinct → `char *`（canon my_get_line
     `return (char *)__dest;` 的种子）；
  3. **castOutput 翻转角色**（coreaction.cc:2585-2592
     `castStandard(outHighResolve,tokenct)`，cast 目标=OUTPUT HIGH）：
     call_out_distinct → `Configurable *`（canon getparameter
     `V = (Configurable *)fopen(...)` 的决策投影；castOutput 为私有静态，
     Part B 逐字转录 3 行翻转，CALLSPEC-COPY 先例同口径）。
- **CAST-A 家族残差再归因（车道核心结论）**：决策臂语义经双侧 fixture
  钉死为 1:1（给定类型对象态，Rugra 与 oracle 逐记录恒等）；canon 站点
  （`fgets(buf,LIT,(FILE *)fp)` 族 main 31/getparameter 9/parseconfig 2/
  file2string 1 + my_get_line fgets 2）的分歧在**决策上游的类型对象态**——
  canon 探针实证 Rugra 的 DWARF 通道与 libc 表把 FILE 铸成**同一工厂对象**
  （req==cur → castStandard 早退），oracle 持两宇宙（DWARF FILE vs
  clib _IO_FILE，golden 三组对照互斥约束下的唯一自洽模型：stderr/stdin 与
  libc 原型同宇宙 nocast，`::config.errors`/DWARF 局部跨宇宙 cast）。
  该宇宙分配是**驱动数据层**（examples/curl_decompile.rs 的 DWARF/GLIBCPROTO
  种子通道）职责，不在本车道写域（src/fspec.rs+src/coreaction.rs）——
  收敛责任登记驱动侧票（见 TODO_BOARD PROTOCAST 行再归因注记）。

MB25 merge-resolution note (PROTOCAST × SETIMPLFIELD test-module union): the
two lane test additions landed at the same end-of-module position; the merged
file retains both `test_resolve_union_sets_implied_field` (SETIMPLFIELD,
master side) and `test_cast_input_return_arm_casts_to_function_output_type`
(PROTOCAST, branch side). diff3 had aligned both parents' final `}` as common
suffix, so the junction needed one explicit fn-close restoration — behavior
of both tests unchanged.
