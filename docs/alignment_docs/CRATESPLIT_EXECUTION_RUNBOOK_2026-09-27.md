# CRATESPLIT 执行手册 —— 窗口一开即认领即跑的机械执行清单（CRATEPREP 车道交付）

> 车道: CRATEPREP（docs-only，零 src 零 tools 改动）· 2026-09-27 · 基=master `6a458387`（MB19 收口后）
> 性质: 把既有蓝图翻译成可机械执行的 WP 清单。**本文不新设架构裁决**；一切结构结论
> 引用自下列权威链，冲突处如实标注留 root 裁决（§8）。
>
> **权威链（冲突时以靠前者为准）**:
> 1. `docs/alignment_docs/LANE_HHMIRROR_2026-09-26.md` —— A2 压测终判（SCC[60]→24 冻结 +
>    环棘轮，12+4 边逐边亲核）。蓝图 §7 明文"与其冲突处以该报告为准"。
> 2. `docs/alignment_docs/CRATESPLIT_MIGRATION_BLUEPRINT_2026-09-26.md`（含 §7 A2 修订节）——
>    crate 目标形态、基础设施迁移清单 ①-⑰、Phase B 设计。
> 3. `tools/cycle_ratchet.py` + `tools/verify_cycle_ratchet.sh` + 
>    `docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md` —— 环棘轮工具与白名单账本（维护红线载体）。
> 4. 本手册 —— 仅执行编排（WP 切分/顺序/门禁/回滚），从属上三者。

---

## 0. 执行窗口约束（置顶，先读）

### 0.1 触发判据（root 持有，缺一不启；蓝图 §4.4 + §7.5）

| # | 判据 | 自检方法 |
|---|---|---|
| ① | 对齐收敛：canon 双语料（curl/httpd）零未解释差异（defects=0/numbering=0，全部残差绑定在案票） | `python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only` + httpd 同款 |
| ② | 零待并分支：无任何在飞/待并 worktree 分支 | `git branch | grep -c '^ *wt/'` 期望 0（2026-09-27 实测 30 支在飞，判据未满足） |
| ③ | wave 边界：当前 wave 收尾、主管线集成 commit 完成、看板活动票最少化 | root 目视 TODO_BOARD |
| ④ | （仅 Phase B / WP-15 B3 追加）SLEIGH 换装（✓ 已完成，2fa1c792）+ **TFSINGLE step-2 落地**（`PAREVAL-TF-PERARCH-WIRING-0002`，2026-09-27 时点仍 OPEN） | 票状态 |

### 0.2 当前排期

**窗口 = MB20 合并后开启**（root 派发口径）。MB20 合并是判据②③的清场动作；窗口开启时
root 在 WP-01 完成判据四项终验并拍板窗口形态（单窗/双窗，见 §5 末尾）。

### 0.3 并行度总则

- **串行主干**：凡编辑 `src/lib.rs` 的 WP（全部带归位 WP + 卫星拆分 + crate 抽出）按
  铁律 6 单 writer 串行，一次只有一道在飞。
- **并行口袋**（与主干无文件交集时）：C1 副本清理（WP-09）、runner 级联内部（4-5 道）、
  审计/文档/只读复核任意时刻可并行。
- 建议并发：常态 2-3 agent（1 主干 + 1-2 口袋），级联期峰值 5。
- 全程在 `/dev/shm/rugra-worktrees/<lane>` 建 worktree（AGENTS 惯例）；**禁 git stash**；
  每改动单元立即原子 commit，显式 `git add <owned files>`。

### 0.4 维护红线（违者停线）

1. **环棘轮白名单只进不漏**：任何新增环边禁止直改 `cycle_ratchet.py` 的 `FROZEN_*` 常量；
   必须先按 HHMIRROR §2 方法逐边定性（亲核 Rust 字段/trait 签名 + Ghidra .hh 对应行），
   登记 `docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md` 账本，再 `--emit-freeze --accept-new`
   重新冻结。改善方向（边消失/模块出环）不 FAIL，但重冻结必须走同一账本流程。
2. **宣称零环 = 机制 D 红线**：本程序的目标表述固定为"压缩无环 + 冻结核心 SCC（≤24 模块）
   + 环棘轮"（HHMIRROR §7.2 条件 1），任何 commit message / 文档不得宣称模块图零环。
3. **canon 字节恒等即停线**：任何 WP 后 canon curl/httpd A/B 输出非逐字节恒等 → 停线、
   回滚该 WP、root 归因后再续（§6）。
4. 注释锚不受影响：`// Ghidra:` 注解键控 Ghidra file:line，代码跨文件移动不破坏锚
   （HHMIRROR §4(c) 亲核）；移动 commit 零注解改动，违反即审。

---

## 1. 基线快照（2026-09-27 @ master 6a458387 实测，窗口开启时以 WP-01 重测为准）

| 项 | 值 | 来源 |
|---|---|---|
| src/ .rs 文件总数 | **96**（73 顶层模块 + lib.rs + 22 子目录文件） | 本车道 `find src -name "*.rs" \| wc -l` |
| 与蓝图 97 的差 | −1：SLEIGH 换装后 disasm/{x86_64,x86_lift}.rs 退役、sleigh_lift.rs+frontend.rs 新增（净 −1）。**蓝图 §2.3 的 97 计数已过期，以本表 96 为准** | 蓝图 §1.2 vs 现树 |
| 冻结核心 SCC | **24 模块** @ master 9ac04ade：action arch block cover cpool database drillobserve fspec funcdata heritage jumptable merge op options pcodeinject pcodeparse prefersplit transform type_system unionresolve userop variable varmap varnode | cycle_ratchet.py FROZEN_SCC |
| 冻结 solo 基线 | 56 模块（v3 折叠粒度；HHMIRROR "74/98" 为 v2 每文件粒度，并存非矛盾） | 同上 FROZEN_SOLO |
| intra-SCC 白名单 | 86 边对 / 186 证据键（`form\|item\|anchor` 粒度） | 同上 FROZEN_EDGES |
| runner 总数 / tree-pin / overlay | **249 / 36 / 28**（233→249 漂移，36/28 恒定） | 本车道 grep 实测 |
| docs/api 顶层 .md | 76（+ 子目录 align/analysis/bin/binary/codegen/disasm/examples/pcode/translator/type_system 既有镜像） | 本车道 ls |
| lib.rs 私有 mod | `mod error;`(:127) `mod types;`(:128) `mod utils;`(:129) | 本车道实测 |
| examples | 20 个 .rs（蓝图 28 已过期，深层引用面 WP-12 重测） | 本车道 ls |
| 镜面五面基线 | curl 56/74 · httpd 94/29 · vsh 16/71 · sq 7500/810 · sqlite 26665/1385 @ `1a41d6ad`（MB19 重钉） | tools/mirror_gate_baselines.tsv |
| 机制 B canon 口径 | 数字以 WP-01 冻结记录为准（MB17 档案口径 curl 200/0/0 · httpd 255/0/0，MB19 后可能已移） | 蓝图 4.0 + MB 台账 |
| pub(crate) 总盘 | 蓝图基点实测 54 处（WP-01 重测为准） | 蓝图 §5.2 |

---

## 2. 目标形态

### 2.1 Stage 1 终态（单 crate 内，A2 形态；HHMIRROR §7.3 草图 + 本手册落全 96 文件）

```
src/
  foundation/     ← 9 文件（全 solo）  opcodes crc32 error rangemap types space
                        marshal compression sleigh_ffi        [未来 rugra-foundation + rugra-sleigh]
  pcode/          ← 17 文件            address pcoderaw varnode◆ op◆ variable◆ block◆ jumptable◆
                        cover◆ dynamic transform◆ prefersplit◆ unify opbehavior float_emulate
                        constseq rangeutil translate
  types-db/       ← 10 文件            type_system/{mod,cast,datatype,typefactory,protomodel}◆
                        database◆ cpool◆ comment stringmanage userop◆
  arch-hub/       ← 11 文件            arch◆ action◆ varmap◆ fspec◆ options◆ pcodeinject◆
                        pcodeparse◆ context loadimage capability modelrules
  funcdata-hub/   ← 5 文件             funcdata◆ heritage◆ merge◆ override_rs unionresolve◆
  impls/          ← 浮顶层 9+5 文件    typeop coreaction ruleaction double_precis paramid signature
                        drillfmt drillobserve◆ callgraph
                        + 卫星拆分产物: heritage_impl merge_impl dynamic_impl unionresolve_impl
                          override_impl（WP-03 生成）
  structure/      ← 6 文件             blockaction condexe subflow flow graph tracedag
  print/          ← 5 文件             printc prettyprint printlanguage grammar expression
  emulate/        ← 2 文件             emulate memstate
  frontend/       ← 6 文件             binary/ disasm/{mod,sleigh_lift} debugproto ffi frontend
  align/ analysis/← 不动（13 文件）
  （root）        lib.rs utils.rs bin/rugra.rs
```
（◆ = 冻结 SCC-24 成员；组内 SCC 成员间互引合法——它们是同一冻结分量，分层只对 solo 生效。）

**机制 = `#[path]` 保模块路径**（蓝图 §2.2）：文件进组目录，lib.rs 一行
`#[path = "pcode/op.rs"] pub mod op;` 使模块路径保持 `crate::op` —— 零 use 搅动、零
examples 搅动、零公共 API 破坏、`pub(crate)` 可见性不变。卫星拆分新模块为顶层平铺
`crate::heritage_impl` 形（HHMIRROR §1 先例），同样经 lib.rs `#[path]` 声明。

### 2.2 Stage 2 终态（crate 化；蓝图 §2.4 三条实测无环切割线）

```
crates/
├── kuna-{base,num,sleigh,slacomp}   # 既有 vendor 四件，不动
├── rugra-foundation/  8 文件（foundation 组减 sleigh_ffi；error/types 升 pub mod；
│                       根包 pub use shim 保 crate::error 等内部路径可达）
├── rugra-sleigh/       1 文件（sleigh_ffi.rs DTO；依赖 kuna-sleigh——C++ FFI+build.rs
│                       已随 2fa1c792 退役，无构图可迁，蓝图 R2 修正）
├── rugra-core/         冻结 SCC-23(24−drillobserve 出环后) + Funcdata/Architecture 字段
│                       闭包 solo + impls 浮顶层 + print/emulate/frontend/structure 带
│                       （精确成员 = WP-12 B0 审计冻结，本手册不预列——诚实边界）
└── （root rugra 包）   门面：lib.rs 再导出 + bin/ + examples/ + align/ + analysis/
                        + ffi + debugproto + frontend.rs（upper 带居民）
                        + 可选 B4: rugra-emulate/rugra-frontend/rugra-verify（默认不排期）
```

依赖方向规则（蓝图 §5.1）：`foundation ← sleigh ← core ← {门面, upper}`；禁向上边/横向边；
每步 `cargo tree --workspace` + 断言工具核验。

---

## 3. 全局验收门禁

### 3.1 G0 —— 每 WP 通用（全绿才可 commit；任何一项红 = 停线）

```bash
# 1) 快速编译反馈（编辑期反复用）
cargo check --lib
# 2) 库构建 + 单测（失败集与基线"逐名相同"，不得新增失败）
cargo build --profile fast-release --lib && cargo test --lib
# 3) canon A/B 字节恒等（A=本 WP 开工前 HEAD 构建，B=本 WP 终态构建；两侧先入库落档）
cargo run --profile fast-release --example curl_decompile   > /tmp/opencode/wp_<id>_curl_after.c
cargo run --profile fast-release --example httpd_decompile > /tmp/opencode/wp_<id>_httpd_after.c
cmp /tmp/opencode/wp_<id>_curl_after.c   <基线A档>   # 必须零差
cmp /tmp/opencode/wp_<id>_httpd_after.c <基线A档>   # 必须零差
# 4) 差分口径不漂（defects/numbering 与 WP-01 冻结记录相同）
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
# 5) 环棘轮 checkpoint（每 WP 必跑；PASS 才过，INFO 登记入 WP 验收记录）
tools/verify_cycle_ratchet.sh
# 6) 静态门禁（pre-commit 自动执行，此处显式列出让执行者预期）
python3 tools/check_ghidra_annotations.py --all
python3 tools/check_ghidra_refs.py --all --strict
python3 tools/check_doc_sync.py --all
python3 tools/check_corpus_markers.py --all
python3 tools/check_gate_health.py
```

**canon 基线纪律**：WP-01 冻结基线 A 档（curl/httpd canon 输出 + sha256 + compare 数字 +
`cargo test --lib` 失败集名单）落 `/dev/shm/rugra-reports/cratesplit-window/`；每 WP 的
B 档与**前一 WP 的 B 档** cmp（链式恒等，等价于与 WP-01 基线恒等）。

### 3.2 G1 —— 阶段边界全量门禁（WP-11 前置、WP-16 终验）

G0 全部 + 以下（数字基线 = WP-01 冻结值，改善方向允许、恶化即停）：

```bash
cargo build --release                       # 双 profile 终验
cargo run --release --example curl_decompile   | cmp - <fast-release 档>   # 双 profile 恒等
cargo run --release --example httpd_decompile  | cmp - <fast-release 档>
tools/verify_mirror_gate.sh                 # 镜面五面（curl/httpd/vsh/sq/sqlite）
tools/verify_projection_bank.sh             # 投影 bank（391 面，数字以现基线为准）
tools/verify_cycle_ratchet.sh               # 棘轮终态
```

### 3.3 棘轮 checkpoint 协议（每 WP）

1. `tools/verify_cycle_ratchet.sh` 退出码 0 = PASS。
2. 出现 `[INFO] improvement`（边消失/模块出环/白名单边对减少）→ 记入该 WP 验收记录
   （预期轨迹见各 WP 行）；**不当场重冻结**，统一在 WP-10 走账本流程。
3. 出现 FAIL（新成员入环/白名单外边证据/solo 掉环）→ 停线：按 §0.4-1 定性登记后由
   root 裁决，禁止为过门禁而改 `FROZEN_*`。

---

## 4. WP 分解（16 个工作包）

> 工时单位=车道日（单 agent 全天）。"写域"列出该 WP 允许触碰的全部路径（铁律 6 租约面）。
> 除标注"并行口袋"外全部串行（lib.rs 写点）。每 WP 一个或多个原子 commit（移动+镜像
> docs/api+.md 同 commit，蓝图 R9）。

### WP-01 预检、冻结与棘轮连续性升级 —— `CRATESPLIT-WP01-PREFLIGHT-0020`

- **前置**: 窗口开启（root 完成判据 ①②③ 终验 + 拍板单窗/双窗形态）。
- **内容**:
  1. **棘轮 `#[path]` 模块映射升级（硬前置，不动它则第一笔 git mv 就打碎棘轮）**:
     `cycle_ratchet.py` 的 `module_of()` 目前按文件路径首段折叠（src/pcode/op.rs → "pcode"），
     任何带归位后模块名全变、断言 (a) 必 FAIL。升级 = 解析 lib.rs 生产文本的
     `#[path = "..."] (pub )?mod NAME;` 声明，建 文件/目录前缀→模块名 映射，优先于路径
     启发式；目录声明（如 `#[path = "types-db/type_system"]`）覆盖其下全部子文件。
     **连续性证明**: 现树（零 `#[path]`）升级前后输出逐字节相同（SCC-24/86 边对/56 solo
     恒等）+ 重跑变异测试 M2（solo 拖入 SCC）与 M4（白名单边对新增字段 anchor）仍 FAIL。
  2. 五份冻结清单落档 `/dev/shm/rugra-reports/cratesplit-window/`:
     (a) runner 级联名单（36 tree-pin + 28 overlay，按当期 grep 重 derive）;
     (b) 带归属 96 文件表（本手册 §2.1 + root 对 §8 差异项的裁决结果）;
     (c) pub(crate) 全量审计表（54 处基点重测 + 带内归属定性——同带保持 pub(crate)、
         跨带被引用项为 B 阶段升 pub 候选）;
     (d) 卫星拆分可见性放宽表（HHMIRROR §4(a): Merge 5 私有字段/DynamicHash 8/Varnode
         self_ref/PcodeOpBank 等——impl 移兄弟模块后须升 pub(crate) 的逐字段清单）;
     (e) canon 基线 A 档（§3.1 纪律）。
  3. 看板清扫：残留活动票 write-set 路径改写为带路径（判据③保证近零）。
- **写域**: `tools/cycle_ratchet.py`（仅 module_of 映射）、`docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md`（连续性证明记录）、TODO_BOARD、/dev/shm 计划档。
- **工时**: 1 日。 **门禁**: G0 全套（棘轮升级前后双跑均 PASS 且输出恒等）+ 变异测试。
- **棘轮**: 升级不改变冻结基线语义（零 #[path] 时映射空转）。 **回滚边界**: 单 commit revert。

### WP-02 foundation 带归位 —— `CRATESPLIT-WP02-FOUNDATION-0021`

- **文件清单**（9 → `src/foundation/`）: opcodes.rs, crc32.rs, error.rs, rangemap.rs, types.rs,
  space.rs, marshal.rs, compression.rs, sleigh_ffi.rs
- **操作**: `git mv` ×9 → lib.rs 9 行改 `#[path = "foundation/X.rs"]`（types 保持私有 mod，
  仅路径变）→ docs/api 顶层 9 个 .md 移入 `docs/api/foundation/` → `tools/generate_api_docs.py`
  写入路径字串随动（蓝图 ④，1 行）→ corpus 清单内核对 foundation 项的字面路径改写（蓝图 ⑫）。
- **pub/use 改动**: **零**（`#[path]` 不动可见性；marshal↔space 微环组内消化，不处理）。
- **工时**: 0.5 日。 **门禁**: G0。 **棘轮**: 预期零变化（模块名未变）。
- **回滚边界**: 单 commit（mv+lib.rs+镜像）revert 即恢复。

### WP-03 impls 带脚手架 + 卫星 types/impl 五拆 —— `CRATESPLIT-WP03-SATSPLIT-0022`

- **前置**: WP-02（lib.rs 写点让渡）。
- **内容**（HHMIRROR A2.1"卫星先行"——最高风险内容改动最先做，fail-fast）:
  对 5 个卫星文件执行 types/impl 两分（types 留原模块，算法 impl + 自由函数 + 无人持有的
  分析器 struct 移入新顶层模块 `<name>_impl`，文件落 `src/impls/`，lib.rs 加
  `#[path = "impls/heritage_impl.rs"] pub mod heritage_impl;`）:

  | 卫星 | types 留守（下沉面） | impl 浮出面 |
  |---|---|---|
  | heritage.rs | Heritage/HeritageInfo/LoadGuard/LocationMap 等 struct 定义（HHMIRROR §3 逐字段核验干净） | 全部算法 impl（`use crate::funcdata` 仅出现在方法体，:7） |
  | merge.rs | Merge/MergePersistentState struct 定义 | 算法 impl（attach/detach 已消除 fd 字段） |
  | dynamic.rs | DynamicHash struct（8 字段） | unique_hash_vn 族签名 impl |
  | unionresolve.rs | ResolvedUnion/ResolveEdge | **ScoreUnionFields（:351-365 `pub fd: &Funcdata` GLUE 字段）+ Trial 整体浮顶** |
  | override_rs.rs | Override struct（BTreeMap×4 面） | 1 处 Funcdata 签名 impl |

  同时建 `src/impls/` 目录。**可见性放宽**（非纯移动，HHMIRROR 条件 2）: 按 WP-01 (d)
  表逐字段升 `pub(crate)`（Merge 5 私有字段、DynamicHash 8 等）——编译期可见性放宽，
  零运行时行为变化。
- **写域**: src/{heritage,merge,dynamic,unionresolve,override_rs}.rs、新 src/impls/*.rs ×5、
  src/lib.rs（+5 行）、docs/api 镜像、CYCLE_RATCHET 账本（ vanished 边登记）。
- **工时**: 1 日（串行；5 拆各 ~1.5h）。**并行度=1**（lib.rs 单写点；若拆 5 子票并行，
  lib.rs 5 行必须由主干 agent 串行落）。
- **门禁**: G0 + 卫星域既有 oracle runner 抽查 3 面（heritage/merge/unionresolve 各一，
  注意 runner overlay 此时已 stale——抽查用 pinned-commit 家族面，live 面留 WP-11）。
- **棘轮预期**: `unionresolve→funcdata`（ScoreUnionFields.fd）从 intra-SCC 视图消失 →
  INFO improvement；新模块 `*_impl` 为图源点（无入边）不入环。
- **回滚边界**: 每卫星一 commit，按卫星 revert。

### WP-04 pcode 带归位 —— `CRATESPLIT-WP04-PCODE-0023`

- **文件清单**（17 → `src/pcode/`）: address.rs, pcoderaw.rs, varnode.rs◆, op.rs◆,
  variable.rs◆, block.rs◆, jumptable.rs◆, cover.rs◆, dynamic.rs, transform.rs◆,
  prefersplit.rs◆, unify.rs, opbehavior.rs, float_emulate.rs, constseq.rs, rangeutil.rs,
  translate.rs
- **操作**: 同 WP-02 模式（git mv + lib.rs `#[path]` ×17 + docs/api 镜像 + corpus 清单）。
- **pub/use 改动**: 零。E7 互持组（op↔varnode↔variable↔block）整体同带下沉，接受合并
  节点（HHMIRROR A2.2"接受合并节点"）。
- **工时**: 0.5-1 日。 **门禁**: G0。 **棘轮**: 零变化预期。

### WP-05 types-db 带归位 —— `CRATESPLIT-WP05-TYPESDB-0024`

- **文件清单**（10 → `src/types-db/`）: type_system/ 整目录（mod.rs, cast.rs, datatype.rs,
  typefactory.rs, protomodel.rs）◆, database.rs◆, cpool.rs◆, comment.rs, stringmanage.rs,
  userop.rs◆
- **操作**: 同上模式；type_system 目录整体
  `#[path = "types-db/type_system"] pub mod type_system;`（目录内相对路径随目录走，无陷阱）。
- **pub/use 改动**: 零（TypeFactory OnceLock shim 随文件走；TFSINGLE step-2 门只约束 WP-15）。
- **工时**: 0.5 日。 **门禁**: G0。 **棘轮**: 零变化预期。

### WP-06 arch-hub 带归位 + E12 GLUE 修复 —— `CRATESPLIT-WP06-ARCHHUB-0025`

- **文件清单**（11 → `src/arch-hub/`）: arch.rs◆, action.rs◆, varmap.rs◆, fspec.rs◆,
  options.rs◆, pcodeinject.rs◆, pcodeparse.rs◆, context.rs, loadimage.rs, capability.rs,
  modelrules.rs
- **E12 GLUE 修复**（HHMIRROR E12 行，A2 唯一登记在案的 GLUE 内容改动）:
  action.rs:341 `crate::drillobserve::activate()` 位于 Action trait 默认方法体（:309
  perform）内，默认体随 trait 下沉会把 drillobserve 拖入下层。修法 = 调用移出默认体
  （或 cfg 门控），Ghidra OPACTION_DEBUG 是 `#ifdef`（action.hh 无此引用）。
  **属主管线 Action 域 → 机制 C 强制独立复核**（commit 附 `## Cross-Review` 块）。
- **工时**: 0.5-1 日（移动 0.5 + GLUE 修复+复核 0.5）。 **门禁**: G0 + Action 域
  oracle runner 抽查（action_perform 族）。
- **棘轮预期**: `action→drillobserve` 边消失 → drillobserve 出环 → SCC 24→23，
  INFO improvement ×2（本手册 §2.2 的 SCC-23 记法由此而来）。

### WP-07 funcdata-hub 带归位 —— `CRATESPLIT-WP07-FUNCDATAHUB-0026`

- **文件清单**（5 → `src/funcdata-hub/`）: funcdata.rs◆（11k+ 行枢纽独居）, heritage.rs◆,
  merge.rs◆, override_rs.rs, unionresolve.rs◆（后四者为 WP-03 拆分后的 types 半边；
  impl 半边已在 src/impls/ 不再动）。
- **操作**: 同上模式。 **pub/use 改动**: 零。
- **工时**: 0.5 日。 **门禁**: G0。 **棘轮**: 零变化预期。

### WP-08 其余 solo 带归位 —— `CRATESPLIT-WP08-SOLOBANDS-0027`

- **文件清单**（28 文件分四带）:
  - `src/structure/`（6）: blockaction.rs, condexe.rs, subflow.rs, flow.rs, graph.rs, tracedag.rs
  - `src/print/`（5）: printc.rs, prettyprint.rs, printlanguage.rs, grammar.rs, expression.rs
  - `src/emulate/`（2）: emulate.rs, memstate.rs
  - `src/frontend/`（6）: binary/ 整目录, disasm/ 整目录（mod.rs + sleigh_lift.rs）,
    debugproto.rs, ffi.rs, frontend.rs
  - `src/impls/` 补齐（9）: typeop.rs, coreaction.rs, ruleaction.rs, double_precis.rs,
    paramid.rs, signature.rs, drillfmt.rs, drillobserve.rs◆, callgraph.rs
- **要点**: typeop 整体浮顶（HHMIRROR E1/E2/E6: TypeOp trait 无人持有——TypeOpManager
  无生产持有者；`as_printc_mut` Any-downcast 是自由函数随 impl 浮动，C2 自动完成）。
  printc 在机制 B 白名单内——canon 门禁即差分门禁，无需额外动作。corpus 清单内
  printc 等字面项随带改写。
- **工时**: 0.5-1 日（可按带分 2-3 commit）。 **门禁**: G0。 **棘轮**: 零变化预期
  （solo 带移动不改模块名）。

### WP-09 C1 错置副本清理（E5）—— `CRATESPLIT-WP09-C1DUP-0028`（并行口袋）

- **前置**: WP-04（address.rs 已归位）。**与 WP-05/06/07 文件零交集，可并行。**
- **内容**（蓝图 C1，A2 框架下唯一维持的 C 票）: 删 address.rs:2010
  `functional_equality`（level-0 简版副本），10 处调用（全在 ruleaction.rs
  :3525/:3625-3626/:3722-3723/:17238-17267）改调 `crate::expression::functional_equality`
  （expression.rs:732 正主，expression.cc:520-526 唯一正主；GETPARAM 车道已证实正主既有）。
- **写域**: src/pcode/address.rs、src/impls/ruleaction.rs（若 WP-08 已落）或 src/ruleaction.rs、
  docs/api 对应、本票行。
- **工时**: 0.5 日。 **门禁**: G0 + expression 域既有 fixture 回归（B2 面）+ 机制 B
  差分（ruleaction 在机制 B 白名单——defects/numbering 与基线相同，任何新差异须
  `## Differential` 块逐处归因）。
- **棘轮**: use 图 address→varnode 边消失（types 图本就无此边——functional_equality 是
  函数不是字段），棘轮零变化预期。
- **回滚边界**: 单 commit revert。

### WP-10 棘轮终态重冻结 + CI 强制接线 —— `CRATESPLIT-WP10-RATCHETCI-0029`

- **前置**: WP-02..09 全落（含并行口袋 WP-09）。
- **内容**: 汇总全窗口 `[INFO] improvement`（预期: `unionresolve→funcdata` 消失、
  `action→drillobserve` 消失、drillobserve 出环、SCC 24→23；若有超出预期的 vanished/
  fallen 逐条按 HHMIRROR §2 定性）→ 登记账本 → `python3 tools/cycle_ratchet.py
  --emit-freeze` 产出新基线字面量 → 粘贴回工具 + 账本记录新指纹（预期 23 SCC +
  solo 集 +drillobserve）→ `tools/verify_cycle_ratchet.sh` 接入版本化 CI
  （`.github/workflows/alignment-gates.yml`，A2.5 收口：CYCLERATCHET-TOOL-0001 票
  "Phase A/A2.0 预检步启用强制门禁"条款兑现）。
- **工时**: 0.5 日。 **门禁**: G0 + 棘轮 PASS（新基线）+ 变异测试复跑。
- **回滚边界**: 基线字面量 commit 独立，可单独 revert（revert 后回到旧基线仍 PASS——
  改善方向的边在旧白名单里只是 vanished，不违约）。

### WP-11 runner 级联批 —— `CRATESPLIT-WP11-RUNNERREPIN-0030`

- **前置**: **本窗口全部树移动动作的最后一次之后**（位置见 §5 执行序；若 B 阶段在窗内，
  则排在 WP-14/15 之后）。
- **内容**（蓝图 ⑤ 主导成本 + HHMIRROR §4(d)"28 overlay 是重建非改名"）:
  1. 36 个 `rugra_base_src_tree` pin 重钉：基=移动后 master 的 src/ 整树 tree hash；
     双形态纪律（rev-parse blob id + sha256 文件哈希，AGENTS 实操备忘）。
  2. 28 个 overlay runner 重建：卫星拆分后 overlay 路径集合与 metadata comparand
     （文件 sha256 表）按新文件清单**整组重写**（heritage.rs 拆两文件 → overlay 必须同时
     覆盖 types+impl 两件），禁只改名。
  3. 逐 runner 重跑到绿才算重钉完成（~10-20 分/个，4-5 并行）。
- **写域**: tools/run_*.sh（36-40 个）+ 对应 tests/oracle/*.metadata.json。
- **工时**: 2-3 日（4-5 并行）。 **门禁**: 每 runner exit 0 且 stdout sha256 与语义基线
  一致；GLOBREPIN 族预存红面"红→红"记录不修（在案惯例）。
- **并行度**: 4-5（每 runner 独立缓存目录）。 **回滚边界**: 每 runner 一 commit。

### WP-12 B0 审计 + crate 骨架 + 依赖断言工具 —— `CRATESPLIT-WP12-B0AUDIT-0031`

- **内容**（蓝图 B0）:
  1. pub(crate) 全量审计落到 item 级（54 处重测值 × 跨 crate 引用交集 = 升 pub 候选名单冻结）;
  2. **rugra-core 精确成员清单冻结**: 冻结 SCC-23 + Funcdata/Architecture 字段闭包 solo
     （HHMIRROR §5: 闭包 36 模块含 24 SCC——出环后重算）+ impls 浮顶层 + print/emulate/
     frontend/structure 带；upper 带居民（align/analysis/binary/callgraph?/disasm::sleigh_lift/
     emulate/ffi/graph/memstate/modelrules/paramid/signature/protomodel/unify/debugproto/
     frontend.rs 中归门面者——按蓝图 §5.2 reach-in 51 对逐一归属）落档;
  3. crate manifest 骨架（crates/rugra-{foundation,sleigh,core}/Cargo.toml）;
  4. `cargo tree --workspace` + 自写偏序断言扫描器（解析各 crate [dependencies] 做方向
     校验，蓝图 §5.1）进 CI;
  5. 基础设施多根扩展: check_ghidra_annotations/refs（①② SRC_DIR→多根）、
     .zcode/align_gate.py 谓词扩 `crates/*/src/`（③ 静默失效风险）、
     check_alignment_evidence 路径形态（⑪）、select_fixtures 谓词（⑬）——全部带回归测试。
- **工时**: 1 日。 **门禁**: G0 + 断言工具自测（对现树断言零违例）。
- **回滚边界**: 工具与清单分 commit。

### WP-13 B1 抽 rugra-foundation —— `CRATESPLIT-WP13-B1FOUNDATION-0032`

- **文件清单**（8: `src/foundation/` → `crates/rugra-foundation/src/`）: opcodes.rs,
  crc32.rs, error.rs, rangemap.rs, types.rs, space.rs, marshal.rs, compression.rs
- **pub/use 改动**: `mod error`/`mod types` 私有升 `pub mod`；根包
  `pub use rugra_foundation::{...}` 再导出 shim 保 `crate::error` 等内部路径可达
  （marshal 1 处 pub(crate) 为唯一跨界待审项，WP-12 名单裁决）；Cargo.toml workspace
  依赖登记（members glob `crates/*` 自动入，零 members 编辑）。
- **棘轮配套**: cycle_ratchet 升级多根支持（`--src` 多目录或按 crate 分别跑；跨 crate
  引用视为外部不入图；foundation 全 solo → core 视图 SCC-23 不变）+ 账本登记口径变更。
- **工时**: 1-2 日（含门禁）。 **门禁**: G0 + examples 零改动编译 + annotations/refs/
  evidence 三工具多根形态全绿（WP-12 产物）。
- **回滚边界**: 单 commit（mv+manifest+shim+工具多根）。

### WP-14 B2 抽 rugra-sleigh —— `CRATESPLIT-WP14-B2SLEIGH-0033`

- **文件清单**（1: `src/foundation/sleigh_ffi.rs` → `crates/rugra-sleigh/src/`）。
- **pub/use 改动**: crate manifest + kuna-sleigh path 依赖声明；根包再导出 shim。
  无 C++ 构图可迁（R2 修正）。
- **工时**: ≤0.5 日。 **门禁**: G0 + examples 零改动编译。
- **回滚边界**: 单 commit。

### WP-15 B3 抽 rugra-core —— `CRATESPLIT-WP15-B3CORE-0034`

- **前置（硬门，蓝图 §5.3）**: **TFSINGLE step-2（PAREVAL-TF-PERARCH-WIRING-0002）已落地**
  ——去 shim 后 types 组边界无全局静态隐耦合；step-2 未落地本 WP 禁启动（触发双窗形态，§5）。
- **文件清单**: WP-12 冻结的 core 成员清单（≈ SCC-23 + 闭包 solo + impls 带 + print/
  structure 带 + emulate/frontend 带中归 core 者；数量级 60-70 文件）从 src/ 各带整体
  `git mv` → `crates/rugra-core/src/`（带内目录结构保留）；根包变门面
  （`pub use rugra_core::*` 族 + upper 带居民 + bin/ + examples/）。
- **pub/use 改动**: WP-12 名单执行（upper 引用的 pub(crate) 项升 pub）；examples
  ~600 处深层引用（20 个 example 重测面）零改动编译 = 门面完整性验收。
- **工时**: 3-5 日。 **门禁**: G0 + G1 全量（本 WP 是阶段边界）+ examples 零改动 +
  `cargo tree` 偏序断言零违例。
- **回滚边界**: 分批 commit（按带分组搬移，每批 G0 绿）；整 WP revert 须连同
  Cargo.toml/workspace 回滚。

### WP-16 收尾与终验 —— `CRATESPLIT-WP16-CLOSEOUT-0035`

- **内容**: fixture_registry path_epoch 裁决执行（蓝图 ⑤b：250 处历史 src 引用默认
  **不改写**——证据不可变，root 拍板确认）；CURRENT_STATUS/ALIGNMENT_ROADMAP 状态行；
  G1 终验双 profile；result/ 回流（cp /tmp/<run>.log result/curl_cur.c 惯例）；/dev/shm
  车道资源回收。
- **工时**: 0.5 日。 **门禁**: G1 全量。

---

## 5. 执行序与窗口形态

```
WP-01 ──► WP-02 ──► WP-03 ──► WP-04 ──► WP-05 ──► WP-06 ──► WP-07 ──► WP-08 ──► WP-10
                                     │                              │
                                     └─► WP-09（并行口袋，汇于 WP-10 前）┘
     [判据④ TFSINGLE step-2 已落地?]
     ├── 是（单窗）: WP-12 ──► WP-13 ──► WP-14 ──► WP-15 ──► WP-11 ──► WP-16
     └── 否（双窗）: WP-12 ──► WP-13 ──► WP-14 ──► WP-11 ──► WP-16a（轻收尾）
                     ……下一窗口: WP-15 ──► WP-11b（第二轮级联 +2-3 日）──► WP-16b
```

- **级联位置铁则**: WP-11 永远排在本窗口**最后一次 src/ 树移动之后**（B1/B2/B3 都会再
  改 src/ tree hash）；排错位置 = 双倍级联（HHMIRROR §4(d)）。
- **双窗代价**: 第二轮全量级联 +2-3 车道日 + 36 pin 二次失效。root 在 WP-01 拍板形态。
- **总工时**: 串行关键路径 ≈ **16.5-20 车道日**（Stage1 7.5-8 + 棘轮/级联 2.5-3.5 +
  Stage2 5.5-8.5 + 收尾 0.5）；2-3 agent 并行墙钟 ≈ **3-4.5 周**。与蓝图 §4.5（4-5 周
  单车道）自洽：蓝图 Phase A+A2 同窗 10-12 车道日 ≈ 本手册 Stage1+级联。
- **每 WP 结束动作**: 门禁全绿 → 原子 commit → TODO_BOARD 票行状态更新 → 链式 canon
  基线档前滚。**任何 canon 非恒等即停**（§0.4-3）。

---

## 6. 回滚程序（WP 级边界）

| WP 类 | revert 边界 | 程序 | 注意 |
|---|---|---|---|
| 纯移动（02/04/05/07/08 及 06/13/14/15 的移动批） | 该 WP 单 commit（mv+lib.rs+镜像同 commit） | `git revert <commit>` → G0 复跑 | revert 后 docs/api 镜像随 commit 自动复原；禁 `git restore`/`checkout` 裸操作（并发纪律） |
| 内容改动（03 各卫星/06 GLUE/09 C1/10 重冻结） | 每内容单元一 commit | revert → G0 + 该域 runner 抽查复跑 | E12 GLUE 与 C1 revert 后须在账本记回滚原因 |
| 级联（11） | 每 runner 一 commit | 只 revert 出问题的 runner 面 | 已绿 runner 不动；禁整批回滚 |
| crate 抽出（13/14/15） | 单 commit（13/14）/分带批（15） | revert 须连同 Cargo.toml/lock/workspace/工具多根改动 | examples 编译面随 revert 自动复原 |

通用纪律: 回滚后必须复跑 G0 并把 canon 基线档指针退回前 WP；跨 WP 连环回滚（>1 WP）
须 root 批准。禁 `git stash`（worktree 纪律）；所有回滚在 /dev/shm worktree 内完成并
立即 commit 回滚 commit。

---

## 7. E13-E16 阻断边处置（逐边解阻路径 / 永久豁免裁决建议）

> 四边全部是 HHMIRROR 亲核的 (c) 类真阻断（被持有 trait 签名环 / 字段级反转环），全部
> 有 Ghidra 前置声明承载的 oracle 本体对应（.hh include 图对编译器隐形的完整类型环）。
> **共性**: 破任一边 = B2 门禁语义改动（签名收窄/字段重构），收益只作用于"core 内部再
> 分层"这一默认不排期的目标，对三条 crate 切割线（foundation/sleigh/core）零收益。

| 边 | Rust 证据 | Ghidra 证据 | 解阻路径（若未来要做） | 本手册裁决建议 |
|---|---|---|---|---|
| **E13** Action/Rule trait 签名→funcdata | action.rs:100 `apply(&mut self, fd: &mut Funcdata)`、:495 `apply_op(..., fd, ...)`；trait 被 ActionDatabase/ActionPool `Box<dyn>` 持有 ← Architecture.allacts ← Funcdata.arch | action.hh:102/120 `perform(Funcdata&)`（fwd decl 经 include 闭包传递自 varnode.hh:31 可见） | C6 trait 反转：上下文 trait 参数化或签名收窄（kuna EngineTranslate 手法先例）；B2 门禁 + Action 域 fixture + 机制 C 复核；0.5-1.5 日/项；SCC 24→~15 的组成部分 | **永久豁免**：留在冻结 SCC + 白名单；破边=偏离 oracle 签名形态，纯语义风险零 crate 收益。仅当未来立项"core 内部按草案层再拆 crate"时随 C6 重开 |
| **E14** ArchOption 签名→arch | options.rs:51 `apply(&self, arch: &mut Architecture, ...)`；OptionDatabase 持 `dyn ArchOption` ← Architecture.options_db | options.hh:27 `class Architecture;` fwd decl（.hh 图 L0-3 上行 12 层） | C7 同款 trait 反转 | **永久豁免**（同上理由；options.hh 在 .hh 图最底层却上行 12 层，是 fwd-decl 红利最典型案例——Rust 物化后不可无语义消解） |
| **E15** JumpModel 签名→funcdata | jumptable.rs:1518-1520 `recover_model(&mut self, fd: &Funcdata, ...)` + build_addresses/fold_in_*/sanity_check 共 7 签名；JumpTable 持 `Box<dyn JumpModel>` ← Funcdata.jump_tables | jumptable.hh:249-260 纯虚签名族（L12→L16 上行 4 层） | C8 同款（7 签名一次收窄，面最大） | **永久豁免**（同上） |
| **E16** type_system 反转环 ×2 | ① datatype.rs:4328 `TypeSpacebase.fd: ScopeLocal` + varmap.rs:2499 `ScopeLocal.arch_lookup: Architecture` + arch `Architecture.types: TypeFactory`（字段级 3-环）；② datatype.rs:3697 `TypeCode.proto: FuncProto` + fspec.rs:2773 `FuncCallSpecs.proto_model: ProtoModel`（2-环） | type.hh:725 `Architecture *glb`（L5→L15 上行 10 层）、:696 `FuncProto *proto`（L5→L12）、:155-158 前置声明块；database.hh:473/917 | 字段重构：call_spec 侧表化（varnode→fspec GLUE 同族）/TypeSpacebase/TypeCode/ScopeLocal 持有链改 Weak 或 lookup——发散性重构，"丢 C++ 类形状"成本（HHMIRROR §6） | **永久豁免**：重构使 Rust 类型形状偏离 oracle 字段语义（B2 面极大且逐字段证明义务）；冻结环 + 白名单即终态 |

**豁免的执行含义**: 四边永久留在 FROZEN_SCC/FROZEN_EDGES；其上的任何**新增**证据键
（新字段/新签名引用）仍触发断言 (b) FAIL，走 §0.4-1 账本流程——豁免≠放弃执法。
同族附带裁决: `varnode→fspec`（Varnode.call_spec Weak GLUE）与
`unionresolve→funcdata`（ScoreUnionFields.fd GLUE，WP-03 后已出环）同列永久豁免登记，
RUGRA-GLUE 偏离理由在案（HHMIRROR §2 尾注/§3）。

---

## 8. 与蓝图的差异清单（如实标注，留 root 裁决——本手册不自作主张改蓝图）

| # | 差异 | 蓝图出处 | 本手册处理 | 裁决点 |
|---|---|---|---|---|
| D1 | 文件总数 97→96（SLEIGH 换装树演变） | §2.3 计数校验 97 | 以现树 96 为准逐文件落 WP 清单 | 确认采纳现树口径 |
| D2 | 带组成采用 HHMIRROR 层组（pcode/types-db/arch-hub/funcdata-hub/impls）而非蓝图 §2.3 十组（pcode/types/struct/actions/database/arch/…）——varmap 入 arch-hub、database/cpool/userop 入 types-db、block/jumptable 入 pcode、coreaction/ruleaction/typeop/paramid/signature/callgraph 入 impls 浮顶层 | HHMIRROR §7.3 vs 蓝图 §2.3（蓝图 §7 明文"冲突以 HHMIRROR 为准"） | 从 HHMIRROR；两案差异文件逐一列表于 WP-01 (b) 冻结单 | root 终验带归属（带边界是导航性选择，不影响切割线） |
| D3 | loadimage 归属：HHMIRROR 草图列 arch-hub，蓝图列 pcode 组 | HHMIRROR §7.3 vs 蓝图 §2.3 | 从 HHMIRROR（权威链 1），WP-01 可复议 | 二选一，零语义影响 |
| D4 | B3 core 成员=SCC-23+闭包（A2 后口径），蓝图原文"60 文件 SCC[60]"系 A2 前口径 | 蓝图 §2.4 vs §7 修订 | 以 WP-12 审计冻结清单为准，本手册不预列 | 确认 A2 后口径 |
| D5 | examples 28→20、runner 233→249（基点漂移） | 蓝图 §1.1/⑨ | 全部以 WP-01/WP-12 重测为准 | 无（登记性） |
| D6 | B1 foundation crate 含 sleigh_ffi 与否：蓝图 §2.4 图把 sleigh DTO 画独立 crate 但 foundation 组 9 文件含 sleigh_ffi | §2.3 vs §2.4 | Stage1 同带（9 文件），Stage2 拆 B1(8)+B2(1)——与蓝图一致 | 无（澄清性） |
| D7 | 棘轮 `#[path]` 映射升级是本手册新增的硬前置（蓝图/HHMIRROR 均未指出 tool 的路径启发式会被带归位打碎） | —（两权威文档的隐含缺口，本车道实测 module_of 逻辑推出） | WP-01.1 执行 + 连续性证明 | 确认为 WP-01 硬前置 |
| D8 | 环棘轮多根支持（B 阶段）同为新增工具项 | 蓝图 ③ 只提 align_gate 谓词 | WP-13 配套 | 确认 |

---

## 9. TODO_BOARD 登记

`docs/TODO_BOARD.md` CRATESPLIT 节下新增 **CRATESPLIT-WP 系列票（-0020..-0035，16 票）**，
每票含稳定 ID/write-set/验收命令/依赖（见该节）。与既有票的收敛映射:

| 旧票（-0002..-0019） | 归宿 |
|---|---|
| A0-PREFLIGHT-0002 | → WP01-0020（吸收，旧票由 root 收敛指针） |
| A1..A8-0003..0010 | → WP02/04/05/06/07/08（带组成按 HHMIRROR D2 重分；A9 前移至级联位） |
| A9-RUNNER-REPIN-0011 | → WP11-0030（位置从"Phase A 尾"改为"窗口最后一次树移动后"） |
| A10-CLOSEOUT-0012 | → WP16-0035 |
| B0..B4-0013..0017 | → WP12..15；B4 维持默认不排期 |
| C0..C5-0018 | C1→WP09；C0/C2/C3/C4/C5 作废（HHMIRROR §7.4 裁定在案） |
| R7-CAPABILITY-0019 | 维持 OPEN（capability.rs 随 WP-06 归 arch-hub 带文件位，接线裁决不变） |

（旧行不动，收敛指针由 root 在窗口开启时批量落——本登记零旧行改写。）
