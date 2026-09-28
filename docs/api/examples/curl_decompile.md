# `examples/curl_decompile.rs` — curl 正典反编译门禁驱动

Source: `examples/curl_decompile.rs`（CURLWIRE/PARAMID 谱系 curl 面；本档首次登记于车道
INITPROTOFID / `CURLCANON-INITPROTO-FID-0001`，2026-09-28）。

## 定位

curl 正典（canon）面驱动：`examples/curl` 二进制 → 124 函数锁定语料 →
隔离子进程逐函数反编译 → stdout C 语料，对照 golden
`tests/golden/ghidra_curl_1204.c`（oracle `e40ed130`，Ghidra 12.0.4
analyzeHeadless 正典产物）。差分门禁 =
`tools/compare_ghidra.py <out> tests/golden/ghidra_curl_1204.c --summary-only`。

驱动携带的正典数据通道（canon-only，镜面组件恒拒——五投影 bank 纯净性；
`RUGRA_SEEDS=0` 为全局裸脸逃生门）包括：

- PLT/libc ABI 签名表 + DWARF callee 签名（`link_call_specs`，queryCall 边界）；
- FIELDRETYPE 字段改型台账（`field_retype_curl_1204.json`，DFLIP 默认开）；
- CMTSEED 注释种子（`curl_cmt_1204.json`）；
- V3SIG callee 锁定原型清单（`callee_siglock_curl_1204.json`，opt-in）；
- 自托管 Parameter ID 迭代（PARAMID，默认开，`RUGRA_PARAMID=0` 逃生）。

## analysis-DB 入口签名台账（CURLCANON-INITPROTO-FID-0001）

**2026-09-28 补（车道 INITPROTOFID）**：正典 golden 的分析栈（analyzeHeadless
的 Function ID 分析器）把 crt 桩 `_init`@0x102000 与 `__libc_csu_init`@0x105400
误配到携带 `EVP_PKEY_CTX *ctx` 参数的库签名条目（FID 桩误配模式；三源消零
复核：EVP_PKEY_CTX 在二进制/DWARF/驱动通道 0 出现）。提交后的 DB 签名经
`FuncProto::setPieces`（fspec.cc:3843-3852）锁 name+arity+types，golden 头部
逐字打印：

- `int _init(EVP_PKEY_CTX *ctx)`（:3；参数名 `ctx` = FID 库名 → NAME_LOCKED）
- `void __libc_csu_init(EVP_PKEY_CTX *param_1,undefined8 param_2,undefined8 param_3)`
  （:2653；参数名 = buildDefaultName，不锁）

下游全部由既有管线产出（非台账数据）：`int` 返回 → `int iVar1; iVar1 = 0;
… return iVar1;`；csu 调用点 `_init(param_1)` 转发（ActionDefaultParams
`fc->copy(otherfunc->getFuncProto())`，coreaction.cc:2322-2330）；8 字节锁定参的
32 位子流 `(ulong)param_1 & 0xffffffff` 与随行折行。

### 通道形态

清单 `tests/golden/manifests/fidsig_curl_1204.json`（oracle_commit +
golden_sha256 + adjudication + witnesses 溯源）。装配方
`install_fidsig_own_proto` / `install_fidsig_callsite_protos`，类型解析
`resolve_fidsig_type`（共享 TypeFactory 名树 intern——findByName
（grammar.cc:2989）/get_base_named→findAdd（type.cc:3412）；FID 铸名
`EVP_PKEY_CTX` 以 8B unknown 命名基 intern，语料内仅指针层可观测）。

两个安装半（镜像既有两条 Program-DB 边界传输）：

1. **own-proto 半**：目标函数自身命中台账地址 → `fd.funcp = proto`
   （DWARF own-proto overlay 位置——在 DWARF/PLT overlay **之后**，那些整体
   替换 fd.funcp；`!dwarf_applied` 守卫保持优先级显式）。
2. **call-site 半**：目标的 CALL 被调地址命中台账 → callspec 装锁
   （V3SIG install 位置——`link_call_specs` 之后、V3SIG/paramid 之**前**，
   oracle DB 真值赢 `has_model()` gap-fill 竞速；恢复通道的 skip 守卫保持其位）。

### 门极性（DFLIP，booldrill 先例形）

- 默认开（canon 面默认装台账）；
- 镜面组件（RUGRA_MIRROR / RUGRA_FLOW_MIRROR / RUGRA_BARE_LOAD /
  RUGRA_ORACLE_FIXTURE_DATA，含 bundle 传递）恒拒；
- `RUGRA_SEEDS=0` 全局裸脸；
- `RUGRA_FIDSIG=0` 通道自 opt-out（= 基线脸 `8dafa799…` 字节恒等）；
- `RUGRA_FIDSIG_MANIFEST=<path>` 覆盖清单路径；缺失/损坏 = 响亮 no-op。

### 验收锚（2026-09-28，基 4df1e154）

canon curl 42→27/0/0（`_init` 8 + `__libc_csu_init` 7 全收敛，两函数
byte-identical；其余 122 函数逐函数零漂移）；SUBFLOW-CSU-MASK-0001 的掩码行
与 LINEWRAP 折行作为签名数据下游一并收敛（改判：数据根，非独立机制根）。
