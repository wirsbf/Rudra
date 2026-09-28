# `examples/curl_decompile.rs` — curl canon/mirror 双面反编译驱动

Source: `examples/curl_decompile.rs`（本档首次登记于车道 BOOLDRILL /
`CANON-BOOLCHAR-FIELDTYPE-0001`，2026-09-28；此前该驱动的车道证据散见
TODO_BOARD 各 DONE 行——ENVDAT / CURLWIRE / DISPLAYREBASE / R3MERGE 等）。

## 定位

curl 语料的**门禁驱动**：canon 面（默认）以 analyzeHeadless 契约装配
传输层后跑全默认 action 管线 + `PrintC`，对照 golden
`tests/golden/ghidra_curl_1204.c`（锁定 oracle e40ed130，Ghidra 12.0.4）；
镜面面（`RUGRA_MIRROR` 族）复现 direct-runner oracle 契约（BfdArchitecture
裸装载 + `followFlow`）。

## ENTRYCONV 通道（canon 默认开，`CURLCANON-ENTRYCONV-0001`）

### 现象与根因

canon curl `_start` 5 行残差（签名对 2 + `undefined8 unaff_retaddr;` 声明 1 +
`__libc_start_main` 实参位 2）：golden 印 `void processEntry
_start(undefined8 param_1,undefined8 param_2)`，Rugra 印 3 参形 +
`unaff_retaddr`。**根因=传送缺口，非机制缺陷**——cspec 数据层
（`sleigh_specs/x86-64-gcc.cspec:258-283` `processEntry` 原型：input#1=RDX、
input#2=stack[0] 槽、伪 retaddr=RBP、extrapop=0、unaffected RSP）、fspec 消费层
（`FuncProto::possibleInputParam` 委托模型 pentry 表 → ActionInputPrototype
试验注册 → resolveModel/deriveInputMap）与 printc 渲染层
（`printc.rs:17518-17527` `option_convention`+`print_in_decl` 前缀）全数在位，
唯缺「入口函数绑定该命名模型」的传送。

### 机制链（Java 侧亲读，12.0.4 build 树）

```
ElfProgramBuilder.java:64-67   PROCESS_ENTRY_CALLING_CONVENTION_NAME = "processEntry"
ElfProgramBuilder.java:664-673 processEntryPoints: OSABI∈{LINUX(3),NONE(0)}
                                → entryFunc.setCallingConvention("processEntry")
FunctionPrototype.java:129-136 grabFromFunction: modelname=getCallingConventionName,
                                modellock=(name≠UNKNOWN)→true
FunctionPrototype.java:326-328 encodePrototype: <prototype model="processEntry"
                                modellock="true">（反编译器侧 XML 形）
fspec.cc:4690-4705             FuncProto::decode: mod=glb->getModel("processEntry")
                                → setModel(mod)（extrapop 从模型）+ modellock
```

**modellock 承重**：`ActionPrototypeTypes`（coreaction.cc:4617-4619）对未锁
模型重绑 evalfp——无锁即中途抹掉约定（Rugra `coreaction.rs:12038` 同构守卫）。

### 通道形态

- **驱动装配**: `decompile_request` 内 DWARF/PLT 原型覆盖**之后**（两者整替
  `fd.funcp`；约定=Function DB 独立字段，与签名同记录双读——组合语义同
  `grabFromFunction` 双字段同读），条件
  `!mirror_bare_load_enabled() ∧ vaddr0==e_entry ∧ OSABI∈{NONE,LINUX} ∧
  arch.proto_models 含 processEntry` →
  `fd.funcp.set_model(Some(processEntry)) + fd.funcp.set_model_lock(true)`，
  `[ENTRYCONV]` stderr 记账行。
- **门极性**: canon 面默认装；`mirror_bare_load`（=RUGRA_MIRROR ∨
  RUGRA_BARE_LOAD）恒拒——BfdArchitecture+readLoaderSymbols 裸环境无 Java
  ElfProgramBuilder，direct-runner golden 亲证 `_start` 保持 3 参+unaff_retaddr
  裸形（镜面 `_start` diff=3 预存基线残差零漂移）。
- **触发面**: 全语料恰 1 站（e_entry 唯一匹配 `_start`；记账行恰 1 条亲证）。

### 验收（2026-09-28，wt/entryconv 基=76dfa697）

fixture-first 四观察点首跑全中、`_start` 输出与 golden 逐字节恒等：
(a) 2 参形 (b) stack[0]→param_2 折叠（`pop %rsi` 读=声明输入非默认模型
retaddr 槽） (c) unaff_retaddr 消失（伪 retaddr=RBP 被 `xor %ebp,%ebp` 杀死；
RDX 读=param_1 非 param_3） (d) `processEntry ` 前缀。canon curl 42→37
（−5 精确，全语料 A/B diff 恰 `_start` 5 行外科手术式）；canon httpd 26
零漂移（httpd 语料显式跳过 `_start`——零连带如实记）；镜面五面钉值恒等；
bank 391/391；cargo test 1965P（examples-only 零新测）。详证=
`/dev/shm/rugra-reports/LANE_ENTRYCONV_2026-09-28.md`。
