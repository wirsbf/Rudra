# 辅助脚本工具库 (Tools & Scripts)

此处归档所有用于项目测试辅助、Ghidra API 挂钩导出、一致性检测对拍的各种外部脚本（如 Python、Shell 脚本等）。不要将它们零散地扔在 Rust 项目根目录下。

目前主要脚本有：
- `ffi_test.py`: 涉及通过 C++ FFI 联调的一些绑定与驱动测试段。
- `ghidra_export.py`: 挂载在 Ghidra 原生环境中执行，用于将其内部的 P-code 数据导出为我们可以对比的形式。
- `pcode_compare_test.py`: 自动比较我们的 P-code 生成串与 Ghidra 原生串的微小差异脚本。

## 可复现快速构建

`rudra_build.py` 是 Cargo 的受控入口。它默认使用 `--locked --offline`、
固定 locale/timezone、记录工具链和输入指纹，并使用全部可用 CPU。若系统安装了
`sccache`，脚本同时缓存 Rust 与 C/C++；只有 `ccache` 时仅缓存 C/C++；两者都没有时
安全回退到直接编译。`cc` build dependency 的 `parallel` feature 会让 22 个 SLEIGH
翻译单元遵守 Cargo jobserver 并行构建。

```bash
# 日常快速语义检查（默认 fast-release）
python3 tools/rudra_build.py check --all-targets --report /tmp/rudra-build.json

# 快速可运行产物
python3 tools/rudra_build.py build --all-targets

# 最终发布构建仍使用原来的 fat-LTO release profile
python3 tools/rudra_build.py build --profile release

# 查看将执行的受控命令和环境，不启动编译
python3 tools/rudra_build.py check --dry-run
```

`fast-release` 只用于反馈速度；它不替代最终 `release` 门禁，也不改变锁定 oracle
或行为证据的判定标准。

## Changed-function fixture 选择

`select_fixtures.py` 使用生成式 `FUNCTION_LEDGER.json` 的 Rust 函数 span 和稳定 ID，
把 git diff 映射到 `tests/oracle/fixture_registry.json`。删除、顶层改动或没有已登记
fixture 的 `src/*.rs` 改动会 fail-closed：选择全部 fixture，并在 `--strict` 下返回 2，
不会用“没选中测试”冒充无影响。缺少 `impact` 的迁移前 legacy 条目只按 global/tier
参与选择（其 schema 违规仍由 `oracle_registry.py lint` fail-closed 跟踪，直至
ORACLE-METADATA-MIGRATE-0001 完成）。

```bash
# 当前工作树，机器可读结果
python3 tools/select_fixtures.py --pretty

# 提交前只看暂存区；未覆盖源码改动直接失败
python3 tools/select_fixtures.py --staged --strict --pretty

# 显式函数或路径诊断
python3 tools/select_fixtures.py --function RG-F-9f9b178c52fe97265fbe --pretty
python3 tools/select_fixtures.py --path src/sleigh_ffi.rs --pretty
```

## 四级门禁

`rudra_gate.py` 把相同事实源组合成四个延迟层级，并为每条命令记录输入 hash、
工具输出 hash、耗时、timeout 和 exit 状态：

| 层级 | 目标 | 主要内容 |
|---|---|---|
| `edit` | 秒级反馈 | 门禁健康、changed annotation/ref、fast library check |
| `commit` | 原子提交 | 全静态门禁、生成账本、fast all-targets、受影响 fixture |
| `wave` | 集成 wave | commit + 全测试 + 全 fixture + curl/httpd/语法/诊断 golden |
| `nightly` | 冷闭包 | wave + fresh-target canonical release 全目标构建 |

```bash
python3 tools/rudra_gate.py edit --report /tmp/rudra-edit-gate.json
python3 tools/rudra_gate.py commit --staged --report /tmp/rudra-commit-gate.json
python3 tools/rudra_gate.py wave --report /tmp/rudra-wave-gate.json
python3 tools/rudra_gate.py nightly --report /tmp/rudra-nightly-gate.json

# 只查看命令和 fixture 选择，不执行
python3 tools/rudra_gate.py commit --staged --dry-run
```

`commit` 以上层级遇到 fixture coverage gap 会在运行前返回 2。`wave`/`nightly`
固定运行 registry 中的全部 fixture；旧 11.3.2 golden 只保留 diagnostic 身份。fixture
默认通过内容寻址缓存运行；`--no-cache` 强制直跑，`--refresh-fixtures` 重新执行并验证
相同 provenance 不会产生不同结果。

## Oracle 内容寻址缓存

`oracle_cache.py` 保存昂贵 oracle runner 的 stdout/stderr、阶段 manifest 或其他产物。
键不是“测试名”，而是锁定 oracle commit、architecture、compiler spec、analysis
options、输入、工具、comparand、命令和显式环境的规范化 provenance hash。每次命中仍会
重算这些输入并逐文件校验缓存内容；损坏或 provenance 漂移会 fail-closed。

capture 的子进程环境与 provenance 环境完全一致（2026-08-15，
`ORACLE-CACHE-HARDEN-0002`）：`Popen(env=...)` 只包含已声明变量
（`DEFAULT_ENV_KEYS` + 执行必需的 `EXEC_ENV_KEYS` + `--env`），未声明环境变量对命令
不可见；argv0 按子进程 PATH 解析，PATH 值或 PATH 目录内容变化会更换 key。命令执行后
重读环境与 provenance，漂移即拒绝入库；restore 恢复后逐 artifact 交叉校验
hash/size/结构并重新校验缓存源，任何缺失、多余或篡改均 fail-closed。

```bash
# 查看键
python3 tools/oracle_cache.py key \
  --metadata tests/oracle/decompress_1204.metadata.json \
  --input fixture=tests/oracle/decompress_1204.cc \
  --tool runner=tools/run_decompress_oracle.sh \
  --comparand rust=src/compression.rs

# 缓存并重放成功 runner；失败结果不会进入缓存
python3 tools/oracle_cache.py capture \
  --metadata tests/oracle/decompress_1204.metadata.json \
  --input fixture=tests/oracle/decompress_1204.cc \
  --tool runner=tools/run_decompress_oracle.sh \
  --comparand rust=src/compression.rs \
  -- tools/run_decompress_oracle.sh
```

默认缓存位于 `.rudra-cache/oracle/`，不进入 Git。`store`/`verify`/`restore` 可用于
阶段快照；restore 目标必须不存在，恢复文件为只读，避免把缓存对象当工作副本修改。

## Pipeline stage 首差异

`stage_diff.py` 将提升、SSA、结构化、打印等阶段的**原始** artifact 依序写入 manifest，
随后定位两侧第一个 provenance、stage ID、顺序、schema、state、内容 hash 或缺失差异。
工具不重排 JSON、不消除别名、不规范化 CFG，因此不会为了让 diff 变小而丢掉决定性语义。

```bash
python3 tools/stage_diff.py snapshot \
  --metadata tests/oracle/sleigh_decode_1204.metadata.json \
  --producer rudra --stage lift=/tmp/rudra-lift.json --stage ssa=/tmp/rudra-ssa.json \
  --output /tmp/rudra-stages.json

python3 tools/stage_diff.py compare /tmp/ghidra-stages.json /tmp/rudra-stages.json --pretty
```

`compare` 返回 0 表示所有阶段原始 hash 相同，1 表示找到差异，2 表示 manifest/provenance
无效。stage manifest 也可作为 `oracle_cache.py store` 的只读 artifact 保存。

## 失败输入最小化

`reduce_fixture.py` 对仍能复现 oracle mismatch 的输入做 deterministic `ddmin`，支持
顶层 JSON list、JSON Pointer 指向的对象字段 list，以及 hex byte stream。predicate 用 argv
直接启动，必须含独立的 `{input}` 占位符；不经过 shell。默认 exit 1=interesting、exit
0=boring，其他 exit/timeout/重复运行不一致均 fail-closed。

```bash
python3 tools/reduce_fixture.py \
  --input /tmp/failing.json --output /tmp/min.json --trace /tmp/min.trace.json \
  --format json-field --field /functions/0/ops \
  -- python3 tools/my_mismatch_predicate.py '{input}'
```

候选按内容 hash 在单次 reduction 内 memoize；最终会重新验证 predicate，并逐个尝试删除
剩余 unit 证明 1-minimal。输出 trace 保留原始/最小输入指纹、完整 argv/可执行文件 hash、
受控构建环境、所有 predicate 结果、超时与重试参数；额外必需环境变量用 `--env NAME`
显式加入。这样最小 case 可连同完整证据升格为正式 oracle fixture。

### Schema 2 合同（2026-08-15，`DIFF-REDUCE-HARDEN-0002`）

seed 先对**原始文件 bytes** fresh 执行（绕过 memo），并检测 render normalization drift
（原始与 re-rendered seed 双指纹入 trace；若 drift 改变 `predicate_signature` 则
fail-closed，渲染层不得掩盖真实差异）。predicate 每次执行四分型：
`INTERESTING(predicate_signature)` / `BORING` / `INVALID`（`--invalid-exit`，默认 3，
只跳过当前 candidate；interesting 但签名≠seed 也记 `INVALID(signature_mismatch)`，
bug A 不会缩到 bug B）/ `HARNESS_ERROR`（fail-closed）。签名取自 stdout JSON（整体或
末行）的 `predicate_signature` 键，规范为 sorted-compact JSON 字符串，跨进程可比。
谓词不输出签名时为兼容模式（`signature_enforced=false`），bug 漂移防护依赖谓词履约
输出稳定签名。最终验证绕过 memo 按 `--retries` 次对最小 case fresh 重跑并要求
签名==seed，防缓存假阳性。执行记录 fsync 追加到 `<trace>.eval.jsonl`（成功后删除），
中断后 `--resume <log|trace.json>` 在谓词身份（argv/exit/timeout/retries/可执行文件
sha256/环境/输入指纹）逐字段匹配后热启动 memo 续跑；schema 1 旧 trace fail-closed 拒绝。

## Oracle fixture registry 治理（2026-08-23，`ORACLE-REGISTRY-HARDEN-0002`）

`oracle_registry.py`（零依赖）提供 registry 目标契约与迁移工具链：

- `tests/oracle/schema/fixture-v1.schema.json`：registry 条目目标契约——`schema`
  const、40-hex `oracle_commit`、fixture 必填 `impact.{rust,ghidra}_function_ids`
  （`RG-F-/GH12-F-` 20-hex pattern，显式拒绝 ordinal/placeholder）、`evidence_status`
  限定 B2 状态机、全路径 repo-relative。
- `doctor`：反向发现磁盘全部 metadata/runner/comparand 并与 registry 交叉核对；
  orphan、重复 ID、runner/metadata 多 owner 或多链接、缺 provenance、状态冲突、
  stale/rekey-gap/unmappable function ID 全部 fail-closed（rc 0/1/2），输出
  repo-relative、排序、无时间戳。metadata 状态只接受
  B2 四态或迁移期 `PARTIAL_MATCH`，可后接 ASCII/全角冒号或成对、非空的括号说明
  （括号前可有空白）；冒号后的说明也必须非空，整个字符串必须完整匹配；
  任意空白 prose、大小写漂移及复合 token 都产生 `METADATA_STATUS_INVALID`，不会伪装成
  “缺字段”。旧式顶层共享 pin 继续合法，但只白名单
  `expected_stdout_sha256`、`expected_statement_stdout_sha256` 与
  `expected_observation_sha256`；`raw_diff`、tool、runner、golden、input 或自造相似
  key 都不算输出 pin。使用 side-qualified pin 时，则白名单路径内
  Ghidra/Rudra 两侧都必须存在且为精确 64-hex，任一侧缺失仍是 `SINGLE_SIDE_MATCH`。
- `schema`：内置 draft-07 子集校验器（不依赖 jsonschema）。
- `lint [--strict]`：doctor + schema 合并检查（前向兼容 ENFORCE-0001）。
- `migration-status [--strict] [--json]`：只读汇总 doctor、schema、registry/metadata
  pre-B2 状态及 function-ID plan（包括未被 fixture 引用的 rekey family）的全部迁移
  blocker；文本和 JSON 都按稳定键排序且不含主机时间。rc=0 表示 blocker 为零，rc=1
  表示仍有 blocker，rc=2 表示 schema/ledger/migration 等工具输入损坏；坏 JSON/$ref
  不得泄漏 traceback。它不会重写 registry、metadata 或 migration table。
- `plan [--check-determinism]`：生成确定性迁移计划——replacements 按
  (file:line:column) 断言式替换，manual_reselect/unmappable 禁止文本替换须按账本
  重选；计划头部带 registry/ledger/migration 及可选 continuity 文件 sha256 指纹，
  应用前须重生成；
  collateral_pins 列出 runner 编辑后须同 commit 重钉的 `comparand.runner_sha256`。

### Function-ID 历史重键（`FUNCTION-ID-MIGRATE-REKEY-0001`）

`generate_function_ledger.py --migrate` 只保留为一次性的 scheme-1→scheme-2 原点生成器；
不得用它覆盖已有迁移来源。后续账本演进使用独立命令：

```bash
python3 tools/generate_function_ledger.py --reconcile-migration
python3 tools/generate_function_ledger.py --reconcile-migration --check
python3 tools/generate_function_ledger.py --reconcile-continuity
python3 tools/generate_function_ledger.py --reconcile-continuity --check
```

该命令锁定 source `235b91bb552261fb3f94b7974926ef6db9b21515`
（src tree `7a9746660c9c569edf1ea922618bcad2ac9860ae`）与 target
`8d129628c84eb87f4094b5012833b8970ff21ae9`
（src tree `004b20c8ed6da74cf6457a4386570bae4801bc78`），逐个重放 332 个
first-parent commit。自动 transition 必须是同文件、完整 module/owner/name 唯一 1→1，
并至少具有同 patch hunk、相同非空 annotation 或相同 masked body 之一；其余仅允许使用
带 legacy/base/final/commit/blob 精确 pin 的 6 个同名人工例外与 8 个跨名 successor。
任一 1→2、2→1、碰撞、脏 src、tree/blob/ledger 漂移、非祖先关系或坏 schema 均 rc=2，
不写半成品且不泄漏 traceback。

schema-2 `FUNCTION_ID_MIGRATION.json` 保留 24,323 个 live origin、146 条 live rekey
lineage、149 个 base/intermediate alias 与 47 个 tombstone，三条两跳链不会被压平丢失
中间 token。tombstone 只产生 `TOMBSTONED_FUNCTION_ID`，永远不会自动映射到同名或现存
wrapper。当前 corpus 的迁移计划应为 `auto=9`、`manual=0`、`tombstoned=0`、
`rekey_gap_family=0`；剩余 21 处（14 个唯一值）GH placeholder 继续是 unmappable，不能猜。

后续 raw scheme-2 变化写入独立、append-only 的
`FUNCTION_ID_CONTINUITY.json`，绝不覆盖上述历史 migration。当前 checkpoint 固定为
`80ffb7d138dd6825990a4986ed77f0ae7d2355ee`（src tree
`4d47cf92b618eac87975dfa707bd6a20c13fc76d`，REGISTRY-CHECKPOINT-ADVANCE 第九窗：
分支线锚 80ffb7d1（^1=b382a54f，master 侧 e486fb18）折叠 2026-09 整月开发窗
（salvage、SubfloatFlow、unionresolve 系列、POSTFIX-RETIRE W1/W2、
RuleStringStore、varmap NameRecommend、RETREC、multigoto 家族、jumptable
matchModel 家族、value-set solver、FS/GS+flag lifts、drill 模块、PLT thunk、
MERGEBATCH 各车道与 SCOPEBREAK；该窗取代未合并的 w-registry10 推进
（7c955a78 折叠 af678926），其内容为本窗所包含）。与第六/七/八窗相同拓扑：
分支 tip 已被 master 包含，锚合并树 == master tip，HEAD:src 不变量直接钉在锚的
src 树上），从 baseline target 连续重放 437 个 first-parent commit。checkpoint 推进是幂等重跑流程：advance 五常量(commit/tree/src/parent/count)→重生成 ledger→零漂移 probe 枚举窗口移除/新增→逐条 git 证据定性(reviewed transition/tombstone/ephemeral/automatic)→以 probe 全量重算 EXPECTED_* allowlist→`--reconcile-continuity`→重生成→`--check`。本窗（10581→11007 条，+611/−185）: 119 reviewed transitions（117 同 4-key re-key + 2 个历史 token 回退闭环——debugproto void_signature_dwarf_prototype 回退 26eee4ad 改名、printc emit_flow_basic 回退 rustfmt 尾分隔符）、66 tombstones（STRNCPY x10/EXPEL-CORPUS x5/typeop fd-aware x5/switch default join x5/PendingBrace x5/POSTFIX-RETIRE W2 四刀）、492 introduced（BlockMultiGoto x27、drill 模块 x24、varmap NameRecommend x15 等 131 个 origin commit）、11 个 introduced 死亡、零未证删除。自动 continuity 仅接受同 path/module/owner/name 的唯一 1→1，且签名
差异严格限于参数 pattern 起始的 binding `mut` 或 rustfmt 尾分隔符，同时必须独立复算同 patch hunk 与相同非空
annotation；`&mut`、`&'a mut`、`*mut` 和 `&mut pattern` 不规范化，也不改变 raw ID 公式。
当前文件记录 588 条 lineage、1483 个 `introduced_live` 与 127 个 tombstone（reviewed 规则 363+127，逐条带 origin 钉定）。loader 先解析 baseline alias，再组合 continuity terminal；任一
chain 断裂、1→2/2→1、跨层 token 复用、terminal collision/缺失、event commit/blob、
first-parent、projection hash/count、dirty/src tree 漂移均 rc=2。continuity tombstone 只作
诊断，永不进入自动 replacement。schema 2 允许 reviewed tombstone 覆盖 post-baseline
introduced 谱系（行内 `origin` 块携带完整 introduced_live provenance，oracle_registry 对
origin 做 commit/blob/记录字段/token 唯一性全量校验）；schema 1 行为不变。若某个
`introduced_live` 在同一 replay 区间后续又被删除且无 reviewed 规则，生成器会 rc=2，不能
静默丢掉 origin。Rust 侧 raw ID 碰撞（同 module+owner+signature，如两个 #[test] 域内的
同名 helper）由 `enclosing_scope_header` 内容消解器分离（最近包裹 item 的原始头部，
position-independent；不能分离仍 rc=2），与 Ghidra 侧 preprocessor guard 消解器同构。

`--cross-check`（FMAPRECON §4.4.5 采纳）用 REFSDEF 行形解析器对 114 个 `.cc` 做 ctags
枚举旁证：逐文件唯一名合计 5549（解析器）/5530（ctags 剥 `ghidra::` 后），残差
122/103 为已分类的算子拼写/嵌套构造/类体内联自由键等名粒度差异——锁定 oracle 上为
常量，任一漂移（含 ctags 行为漂移）rc=1，须先重新裁决再重生成。解析器在 `.hh` 系统性
高估（doxygen 尾注释击穿 `;` 守卫），只作 `.cc` 旁证，不作分母枚举器。

metadata 的未闭合证据必须结构化放在 `coverage.<case>.status`、`observation_scope`、
`known_dependencies`、`residuals`、`known_residuals`、`uncovered_boundaries` 或
`residual_union[].status`；只有非 `MATCH` 状态或这些 residual 容器中的明确未覆盖记录
才阻止顶层 `MATCH`。这些容器会递归检查 group/list；父级 `MATCH` 不会屏蔽子级
`UNTESTED`，显式但未知的 `status` 会保守记为 `INVALID_STATUS`。推荐门禁顺序：

```bash
python3 -m py_compile tools/oracle_registry.py
python3 tools/generate_function_ledger.py --self-test
python3 tools/oracle_registry.py self-test
python3 tools/oracle_registry.py plan --check-determinism
python3 tools/oracle_registry.py migration-status --strict
python3 tools/oracle_registry.py lint --strict
```

迁移执行见 `ORACLE-METADATA-MIGRATE-0001`；不要在文档写死会随 corpus 变化的 issue 数。

## 12.0.4 golden 重生（2026-08-15，`ORACLE-0002`）

- `build_ghidra_1204_headless.sh` — 从锁定 oracle commit e40ed130 源码构建可运行
  Ghidra 12.0.4 headless distribution。自动获取便携 JDK21/Gradle 到 /tmp（无需
  root），处理 flatRepo 依赖与代理；障碍规避：unset LD_PRELOAD（proxychains 劫持
  loopback 会杀死 Gradle daemon）、需非沙箱执行。约 40 分钟可重建。
- `regen_ghidra_golden.py` — golden 重生与自检。`--regen` 用真 headless 产
  canonical golden（tests/golden/ghidra_{curl,httpd}_1204.c + provenance）并跑
  direct-runner 交叉验证；`--direct-runner` 单独重生补充 golden；`--check` 校验
  输入 SHA/oracle/arch/cspec/逐函数行数与 hash。

## 确定性双跑门禁（2026-08-16，`DETERMINISM-GATE-CI-0006`）

`check_determinism.py` 把 run-to-run 输出漂移（RUN-NONDETERM-0001 一类 bug）变成响亮失败：

```bash
python3 tools/check_determinism.py                    # 默认：all+compare 各 2 跑
python3 tools/check_determinism.py --mode all --runs 3
python3 tools/check_determinism.py --mode compare --compare-fn main
python3 tools/check_determinism.py --self-test        # sed 注入假漂移自检
```

- **All 模式**：`curl_decompile`（无参全量）stdout sha256 全部相等 + 退出码 0。
- **compare 模式**：`--rudra-timeout-isolation-compare-function <fn>`（默认 main）
  不得报 `isolated output changed`，退出码 0，stdout sha256 相等。
- **失败报告**：两 run 的 sha256/字节数/输出文件路径 + 首个差异行（行号与两侧
  内容）；输出文件保留在临时目录供 forensics，成功才清理。退出码 0/1/2
  （2=build 失败）。
- **`--runs N`（默认 2）/ `--timeout SEC`（默认 900）**：逐跑超时与重复次数。
- **二进制快照隔离**：先 `cargo build --release --example curl_decompile` 一次
  （`--no-build` 跳过），再把产物 copy 到临时目录执行整组运行——多 agent 工作区
  里并发 cargo build 会在两次运行间替换共享二进制（实测 30679B↔50966B 互换），
  快照后漂移只可能来自进程内部（HashMap 种子等）。
- **自测**：真实跑一次，`sed` 把输出中间一行替换为漂移标记，断言门禁抓到
  （sha 不等 + first_diff 行号 = 注入行）。

## audit_syntax 函数提取修复（2026-08-16，`AUDIT-SYNTAX-SKIPLINE-0001`）

`audit_syntax.py` 的 depth 计数原从签名行起算，吞不掉 Ghidra skip_line 布局
（签名行、空行、独立 `{` 行）的函数体——锁定 golden 自身 116/116 FAIL，
curl 输出同样 0/112。修复后：

- **skip_line depth**：签名后跳过空行/少量外提局部声明行，到独立 `{` 行才起算
  depth；找不到 `{` 则签名行单独成 body，gcc 以 `expected '{'` 响亮失败。
- **字面量安全括号计数**：`cVar3 != '{'` 字符字面量不再破坏函数边界（原 glob_set
  被吞进 glob_word）。golden 提取覆盖 116→124。
- **签名词表**：补 Ghidra 基础返回类型（undefinedN/ulong/uint/ushort/byte/
  time_t/FILE/CURLcode 等）与双词函数名（`processEntry _start`）。
- **桩环境**：STUB_HEADERS 增 Ghidra 基础 typedef（byte/ushort/uint/ulong/
  undefinedN/code 等 + 不透明 FILE/stat/EVP_PKEY_CTX）、stdarg.h、PTR_/DAT_
  约定全局 extern；与被审文件自带 inline typedef/extern 同名时逐函数去重，
  Rudra 自产声明保持自身拼写。
- **验证**：`tests/golden/ghidra_curl_1204.c` 0/116 → **104/124 OK**（20 个残余
  FAIL 均为 golden 固有的非 C 构造：`::` 域限定/`processEntry _start` 双词名/
  `stack0x…` 槽名/`._0_4_` 位选择器，及需要 DWARF 布局的域结构体成员访问
  URLGlob/Configurable/FILE/DAT_ 算术）；`result/curl_cur.c` 0/112 → 53/116 OK，
  残余失败为当前 WIP 输出的真实发现（`xunknown8` 类型拼写、`{` 前外提声明等）。

## Pipeline stage 投影首分歧二分（2026-08-23，`PIPE-STAGE-BISECT-0001`）

`stage_bisect.py` 消费**逐 Action/Rule 应用的修改投影**（Ghidra 侧/Rudra 侧各一份，
由 `tools/stage_bisect_projection.cc` 骨架描述的 fixture harness 产出），定位两侧
第一个分歧边界，并把缺陷归因到**某 Action/Rule 的某一轮应用**（阶段路径 + restart
轮次 + repeatapply pass + 计数器状态），比 `stage_diff.py` 的整阶段 artifact hash
再细一级。RUDRA-GLUE：oracle 无对应物，工具只读投影，不改任何管线语义。

投影格式（每行一项，`--format` 可打印）：

```text
META side=ghidra commit=e40ed130... func=FUN_00401000 arch=x86:LE:64:default
@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr
1 universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr \
  0040102c: (PTRADD,20) uni4 = uni3 4|0040102c: (PTRSUB,20) uni4 = uni3 4
@END universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr \
  changes=1 tests=6 apply=1
@CONVERGED universal:fullloop:mainloop:stackstall:oppool1
@RESTART 1
```

- 记录行 = `<seq> <action_path> <before>|<after>`：`<seq>` 是原生
  `opactdbg_count`（funcdata.cc:1010-1052），同一应用改 k 个 op 就有 k 行同 seq；
  before/after 为 `PcodeOp::printDebug`（op.cc:376）原文，`|` 转义为 `\|`。
- 边界行 = `@BEGIN/@END/@CONVERGED/@RESTART`；轮次状态由工具按"上次 @RESTART
  以来每路径的 @BEGIN 计数"推导（@RESTART 重置），满足
  `PIPELINE_STAGES_1204.md` §4 的登记要求。

```bash
# 定位首分歧（human 可读，含上下文与归因建议）
python3 tools/stage_bisect.py /tmp/ghidra.proj /tmp/rudra.proj

# 机读报告
python3 tools/stage_bisect.py /tmp/ghidra.proj /tmp/rudra.proj --json

# triage 辅助：屏蔽 unique 空间 id（仅用于缩小范围，不能当对齐证据）
python3 tools/stage_bisect.py /tmp/ghidra.proj /tmp/rudra.proj --relax-unique

# 打印 Ghidra 侧投影收集 harness 骨架（含 -DOPACTION_DEBUG 构建/链接命令模板）
python3 tools/stage_bisect.py --emit-harness

# 自测（合成投影 + 已知分歧点）
python3 tools/stage_bisect.py --selftest
```

判定与归因：`AFTER_DIVERGENCE`（同 before 异 after）→ 缺陷在该 Action/Rule 该轮
apply 内；`BEFORE_DIVERGENCE` → 缺陷更早，回退到报告的 last good boundary 再收窄；
`PATH/BOUNDARY/SEQ/STREAM_KIND/LENGTH_DIVERGENCE` 分别指向遍历顺序、计数会计、
序号、事件对齐与提前终止。退出码沿用 `stage_diff.py`：0 一致 / 1 有分歧 / 2 格式
或用法错误。

## v2 drill 双侧文件四层对拍（2026-09-22，`PIPE-STAGE-BISECT-0001` 下钻）

`drill_diff.py` 消费**v2 drill 文件**（stage-bisect 的下钻层：每个 `@BEGIN <seq>
<path>` 应用括号包裹一次 Action/Rule 应用的原生 before/after printDebug 记录流，
`DEBUG <n>: <name>` 头 + `<seqnum>: <before>` / 三空格前缀 `<seqnum>: <after>` 严格
成对，`**` 为 dead op 标记，文件尾 `@DONE` 统计行）。RUDRA-GLUE：oracle 无对应物，
纯消费端只读工具，不改任何管线语义；原生观测机制同 `stage_bisect.py` 头注
（funcdata.cc:1010-1052 / op.cc:374-384 / address.cc:32-37）。

四层输出（自动化 Lane AL 的人工归因流程）：

1. **路径层**：按 action path 聚合应用块，报告 shared / oracle-only / rudra-only
   路径清单与每路径应用计数差（按 |delta| 排序）。
2. **首记录分歧**：全局记录行流（剥 DEBUG 头，文件序）的公共前缀长度 + 首个不同
   记录的两侧原文、行号与所属应用块；一侧为另一侧前缀时报 LENGTH 分歧。
3. **记录分类**：共享路径按出现序配对（k 对 k）、等 op 数块内逐 op 比较，差异按
   首匹配分类：`dead_marker`（单侧 dead）→ `seqnum_drift`（mask `<pc>:<uniq>` 的
   uniq 计数后相等，计数为十六进制）→ `const_width`（mask `#v[:size]` 宽度后缀后
   相等）→ `opcode_name`（标识符 token 多重集不同）→ `other`；并附全文件
   `#v[:w]` 常量宽度形态普查（informational，宽度信号多落在 op 数不等的未配对块，
   逐块配对层看不到）。未配对块出现数与未配对 op 记录数单独计数。
4. **@DONE 统计**：逐 key 对照（值差 / 单侧缺失）。

META 行仅作 provenance 提示（oracle_commit/arch/cspec 等），不参与退出码判定。

```bash
# 人工可读报告（--top N 控制计数差/普查显示条数）
python3 tools/drill_diff.py next_url.oracle.drill next_url.rudra.drill

# 机读报告
python3 tools/drill_diff.py next_url.oracle.drill next_url.rudra.drill --json

# 驱动脚本（退出码同 stage_bisect 惯例：0 一致 / 1 有差异 / 2 用法或格式错误）
bash tools/run_drill_bisect.sh <oracle.drill> <rudra.drill>

# 自测（8 个合成场景：一致/路径层/首分歧/前缀长度/五类分类/@DONE/格式错误/退出码）
python3 tools/drill_diff.py --selftest
```

真实语料验证（next_url，oracle 1293 块/1019 记录 vs rudra 1550/1122）：路径层
shared=103 / oracle-only=2（`oppool2:loadvarnode`、`oppool1:subvar_subpiece`）/
rudra-only=13（top `mainloop:unreachable` x24），计数差 top = earlyremoval
368→399、ptrarith 4→28、propagatecopy 278→299、termorder 5→21、boolnegate
17→30；首分歧 = 公共前缀 2 行后 `universal:extrapopsetup`（应用 4）oracle
`0x505d:2ce` vs rudra `0x50ce:2ce` —— 与 Lane AL 的 ATTRIBUTION_V2.md / M2 采样
报告逐项一致。

## result/ 产物刷新约定（2026-08-23）

`result/curl_cur.c` 是 `cargo run --release --example curl_decompile` 的 stdout 存档（工具链的正式结构化对比输入）。
**每次 E2E 门禁后必须回流**：`cp /tmp/<run>.log result/curl_cur.c`，再跑 compare_ghidra/audit_syntax 确认。本 wave 曾出现 06:35 存档滞后到 19:09 的事故（跑批只写 /tmp）——root 已修正。

## 生产 types 图环棘轮（2026-09-26，HHMIRROR A2.5）

`cycle_ratchet.py` 复刻 HHMIRROR 压测的 v3 生产 types 图方法（字段持有 + 被持有 trait 签名
依赖、`#[cfg(test)]` 生产切割、crate::/super::/self:: 导入解析、子目录折叠模块名归一、
lib.rs 再导出归位）,Tarjan SCC 后执法三断言: (a) SCC 成员 ⊆ 冻结 24 模块集、
(b) SCC 内环边证据（`form|item|anchor` 锚级）全部在 E1-E16 白名单内、(c) 56 solo 基线
模块不入环。改善方向（破环）打 `[INFO]` 放行,倒退方向 FAIL。冻结基线 = HHMIRROR 实测树
master `9ac04ade`（24 SCC / 86 边对 / 186 证据键）。**白名单只进不漏**: 新环边必须先按
HHMIRROR §2 方法逐边定性并登记 `docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md` 账本,
再 `--emit-freeze --accept-new` 重冻结;禁止直接改 `FROZEN_*` 常量塞边。

```bash
python3 tools/cycle_ratchet.py                  # 棘轮扫描（退出码 0/1/2）
tools/verify_cycle_ratchet.sh                   # CI 门禁 wrapper（Phase A/A2 启用强制）
python3 tools/cycle_ratchet.py --emit-freeze    # 维护: 打印当前树冻结字面量
```

