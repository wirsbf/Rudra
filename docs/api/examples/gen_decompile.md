# `examples/gen_decompile.rs` — hermetic 单函数/全量反编译门禁驱动

Source: `examples/gen_decompile.rs`（GENSMOKE 谱系 gen 面；本档首次登记于车道
CODEPTR / `GEN-CODEPTR-SYMBOLIZE-0001`，2026-09-27）。

## 定位

镜面 gen 面的**正典驱动**：BFD 函数发现（静态 `.symtab` FUNC → `.dynsym` FUNC →
PLT JUMP_SLOT 桩，按地址 `or_insert_with` 首胜去重）+ PT_LOAD 内存镜像 + bare
Architecture + 全默认 action 管线 + `PrintC::doc_function`。两种运行形态：

- `--one <index>`：单进程单函数（大栈线程内）；
- all-mode（默认）：每函数一个隔离子进程，`RUGRA_GEN_TIMEOUT_SECS` 逐函数
  超时帽（默认 60s），`RUGRA_GEN_MIRROR=1` 对齐 golden direct-runner 契约。

对照 oracle = `tools/regen_ghidra_golden.py` 的 "one"/全量模式（BfdArchitecture
init → followFlow(code:0, code:highest) → universal action → PrintC docFunction），
golden = `tests/golden/ghidra_{sq,sqlite}_1204.direct-runner.c`。

## 符号通道（GEN-CODEPTR-SYMBOLIZE-0001 / S2CODESTAR-DOWNCHAIN-0001）

驱动持有**三条**函数符号通道，对齐 golden harness 的层次结构：

1. **名字代理**（既有）：`fd.add_symbol(vaddr, name)` → `fd.symbol_table`
   （`Funcdata::addSymbol`，funcdata.cc:34 的驱动侧形态）。call-site 命名、
   PTRSUB 符号化等按地址直查该表。
2. **analysis-DB 通道**（2026-09-28 补，S2CODESTAR-DOWNCHAIN-0001 根因一）：
   `build_architecture` 之后、flow/action 之前，构造 `Database::new(false)` 并
   对全局 scope 逐 GenFunction `add_function(Address::new(vaddr), name, 1)`，
   克隆 Architecture `set_symboltab` 后作为**分析侧** `fd.arch`。这是 oracle
   golden harness 的 `registerFunctionSymbol`（regen_ghidra_golden.py:219-231 →
   `scope->addFunction`；生产同面 = `BfdArchitecture::init` readLoaderSymbols）
   的 1:1 对应：`ActionConstantPtr::isPointer` 的容器查询（coreaction.cc:1151
   `queryContainer`，Rugra 侧 `Funcdata::query_container_parent_scope`）自此能
   命中函数地址常量，`Funcdata::spacebaseConstant`（funcdata.cc:360-461）把
   LEA 派生常量换形 `PTRSUB(spacebase-0, symaddr)` 并将输出定型为
   ptr-to-符号类型——函数符号类型 = `TypeCode`（database.cc
   FunctionSymbol::buildType），即 typeprop 的 **code\* 铸造种子**。
   此前该查询通道恒 None，镜面 arm 的 code* 种子恒零。
3. **print-DB 通道**（2026-09-27 补）：action 管线之后、`PrintC::new` 之前，
   构造同内容 `Database`，克隆 Architecture `set_symboltab` 后换入 `fd.arch`。
   `doc_function` 起点快照 `fd.arch.symboltab`（printc.rs，对应
   `glb->symboltab`），使 `PrintC::push_ptr_code_constant`
   （printc.cc:1730-1742）的 `queryFunction(Address(code,val))` 命中后经
   名字代理印函数显示名——先例 = curl 驱动 CURL-CODEREF-SYMBOLIZE-0001
   print-DB（curl_decompile.rs:6894-6924）。

**契约要点**：

- analysis-DB 先于 flow/action 安装（oracle 的符号自 Architecture init 起即在）；
  analysis 相位的 symboltab 消费者由此可命中：`ActionConstantPtr::isPointer`、
  spacebase 容器查询、CALLIND 常量目标 deindirect 等。
- print swap 仍是 print-only 语义（内容与 analysis-DB 同构）；DB 只含
  FunctionSymbol（无数据符号/只读区间），其它 symboltab 消费者在代码地址外
  不命中，与 golden 同 DB 内容同命中语义。
- 去重契约：`discover_functions` 地址唯一（static → dynamic → PLT 首胜），
  对齐 golden `registerFunctionSymbol`（regen_ghidra_golden.py:219-231）的
  `queryFunction` 先注册胜语义；ELF 裸符号名无 `::`，全局 scope + 全名即
  `findCreateScopeFromSymbolName` 的退化形态。
- 残差注记：CODEPTR-TYPE 形态②（`code *pcStack` vs `int8 iStack`）、
  CODEPTR-DECL 形态③（`code *unaff_R12` vs `xunknown1 *`）与 7 星指针戳链
  （`uint4 *******`）的深层根因 = varmap↔downChain 反馈环 runaway
  （SQLCENSUS-CODESTAR-DOWNCHAIN-0001 根因二，事件级已钉死、src 修复待续，
  见 /dev/shm/rugra-reports/LANE_S2CODESTAR_2026-09-28.md）。

## 门禁用法

```bash
# 单函数（stderr 出 --list 索引）
target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch --one 391

# 镜面全量（cwd=worktree 根，sleigh_specs CWD 相对）
RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
  target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch \
  > /dev/shm/.../sq_mirror.c 2> /dev/shm/.../sq_mirror.err

python3 tools/compare_ghidra.py <mirror.c> tests/golden/ghidra_sq_1204.direct-runner.c \
  --base 0 --summary-only
python3 /dev/shm/rugra-tests/mirrortriage/mirror_family_census.py <mirror.c> <golden.c> \
  --clusters 25 --samples <face>_census.json
```

关联：`docs/api/examples/parallel_decompile.md`（同 face 的线程形态驱动）；
MIRRORTRIAGE 终报 §3.1（/dev/shm/rugra-reports/LANE_MIRRORTRIAGE_2026-09-27.md）。
