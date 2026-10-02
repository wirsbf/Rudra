# stringmanage.rs — String management API

Faithful port of Ghidra's `stringmanage.hh` / `stringmanage.cc` (477 lines)
plus the `GhidraStringManager` contract from `string_ghidra.{hh,cc}`.

**Status:** L2.5（manager 核心）. Complete UTF8/UTF16/UTF32 decoding +
Architecture-owned StringManager with positive/negative caching, the native
`StringManagerUnicode` reader (2048-byte search clamp) and the declared
GhidraStringManager/Java-contract reader (unbounded detection, 2048-char
return truncation). Locked bilaterally by
`tests/oracle/stringmanager_core_1204.*` (STRINGMANAGER-CORE-JAVACONTRACT-0001,
oracle 12.0.4 `e40ed13014`). L3 gap: consumer wiring (ruleaction/printc/
funcdata/driver — TYPEOP-LOCALTYPE-DISPATCH-0001 D3) and XML space-name
restore in encode/decode.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.{hh,cc}`,
`string_ghidra.{hh,cc}`, `sleigh_arch.cc:247-251`, `ghidra_arch.cc:365-369`.

## Declared detection contract (JAVA CONTRACT)

Ghidra has two concrete managers, both `maximumChars=2048`:

- `StringManagerUnicode`（standalone/SLEIGH，sleigh_arch.cc:250）自读 loadimage，
  终止符搜索在 `maximumChars` 字节处封顶（stringmanage.cc:452-457）——NUL 超过
  字节 2048 的字符串一律负结果。
- `GhidraStringManager`（GUI/service，ghidra_arch.cc:368）把检测交给 Java 侧
  （`ELEM_COMMAND_GETSTRINGDATA`，ghidra_arch.cc:780-810）：**检测不设 2048 界**
  （字符集合法 + NUL 终止），`maximumChars=2048` 只截断返回的字节并设置 `isTrunc`。

正典 golden（`tests/golden/ghidra_curl_1204.c` hugehelp：NUL 在 3354–10329 字节
处的字符串以 2048 字符 `/* TRUNCATED STRING LITERAL */` 字面量出现）证明 oracle 走
`GhidraStringManager` 契约。Rudra 生产 manager（`new_ghidra_contract`，
`Architecture::build_string_manager` 安装）按此契约实现并显式声明；native
2048 界行为由 `new_unicode` 保留并由同一双侧 fixture 锁定。

## 2026-09-26：StringDataClient 环境查询通道（STRLIT-ENVDAT-0001；CR-ENVDAT 修订）

`GhidraStringManager::getStringData`（string_ghidra.cc:33-48）**从不自读 image**：
缓存未命中时把查询整体转发给环境（`glb->getStringData` ->
`ArchitectureGhidra::getStringData`，ghidra_arch.cc:780-822 的
`ELEM_COMMAND_GETSTRINGDATA` 管道协议）。C++ 半边的这一控制流是钉死的；
**环境半边的真实 Java 语义**（CR-ENVDAT F1，reviewer 亲拉
Ghidra_12.0.4_build `DecompileCallback.getStringData` 核实）：

1. `getDataContaining(addr)`——按**包含** Data 解析，非精确起始；
2. string Data 的 interior 字节经 `getByteOffcut(diff)` 返回 **offcut 后缀**
   （从 offcut 到终止符的游程），非空答；
3. 无包含 string Data 时走 `MemoryBufferImpl` **原始内存读回退**（非零读取），
   检测受 maxChars 界（`length > maxChars → null`）；
4. 返回 byteData **含尾部 NUL**（DecompileProcess `sz = res.length+1`；
   ghidra_arch.cc:801-810 全量入 buffer）——字节级 B2 fixture 须计入
   （CR-ENVDAT F3，STRINGMANAGE-CLIENT-NUL-CONV-0001）。

canon headless 的 `&DAT_<addr>` 符号形**不是** string-manager 语义的产物：
保住 &DAT 的是 `RulePtrsubCharConstant` 的 **charPrint 类型门**
（ruleaction.cc:7369 `!basetype->isCharPrint() → return 0`）——DAT 标签的
undefined1\* PTRSUB 在 isString 查询（:7375）**之前**被拦截，string manager
在这些地址从未被查询（CR-ENVDAT F2）。真正承重的是 **DB 通道的 undefined1
条目**（驱动侧 DAT 标签层）；string-manager 的正答集只在折叠路径
（字符串起始引用经 charPrint 门后折叠为字面量）与 print 侧
`pushPtrCharConstant`（printc.cc:1698）消费。

Rudra 侧新增（src/stringmanage.rs）：

- `trait StringDataClient: Send + Sync` — 环境半边（Java 进程的替身）：
  `get_string_data(addr, charsize, max_bytes) -> Option<(Vec<u8>, bool)>`。
  契约见 trait 文档（真实桥语义=接缝契约；全形客户端=offcut 后缀+maxChars
  界 raw 回退+尾部 NUL）。
- `StringBackend::GhidraJavaContract { loader, client }` — `client: Some` 时
  `get_string_data` **只**查询 client（零 image 读取，镜像 string_ghidra.cc:45
  的转发控制流）；`None` 保持既有声明的 raw-read 形态（无环境层的面：
  httpd 驱动、测试、bare/mirror 面）。注意（CR-ENVDAT F4，
  STRINGMANAGE-JAVAFALLBACK-MAXCHARS-0001）：None 臂"检测无界"的声明与
  真实 Java 回退（maxChars 界）不符——预存声明，登记待再推导，行为冻结。
- `set_string_data_client(&mut self, client)` — 驱动注入点（C++ 对应物是
  sout/sin 管道本身，ghidra_arch.cc:783-795）。

**驱动现挂载的是可观察查询点正答集的语料见证投影**（canon golden 逐地址
fold/&DAT 判据），窄于全形：仅在见证的 string-Data 起点答 `Some`、其余 `None`，
字节向量不含尾部 NUL（打印不可观测）。全形 offcut+回退客户端
（STRINGMANAGE-CLIENT-OFFCUT-0001）落地后可消纳驱动的 interior 硬表
（CANON_INTERIOR_STRING_DATA）。

消费面不变：rule 侧 `RulePtrsubCharConstant`（ruleaction.cc:7375）与 print 侧
`PrintC::printCharacterConstant`（printc.cc:1537/1541）共享同一 Architecture
单例，正/负缓存一次成型。单测
`test_client_channel_exact_start_semantics` 锁定投影的可观察契约：client
挂载后 loader 零读取、投影外地址负结果（含 loader 持有效串字节的 interior
字节）。


## Structs

### `StringData`
String data stored by StringManager (stringmanage.hh:43).
- Fields: `is_truncated: bool`, `byte_data: Vec<u8>`.

### `StringManager`
Storage for decoding and storing strings (stringmanage.hh:40). Cache keyed by
the **complete `Address` (space+offset)**（stringmanage.hh:48），正/负结果同样缓存：
query 先在 map 占坑（stringmanage.cc:437），opaque/DataUnavailError/无终止符/编码
非法全部留下空条目 —— 同地址二次询问零 image 读取。
- `new(max)` — base manager（无 reader：仅缓存查询，Ghidra 抽象基类的等价物）。
- `new_unicode(loader, max)` — 1:1 native `StringManagerUnicode` reader
  （stringmanage.cc:414；sleigh_arch.cc:250 安装形态；2048 字节搜索界）。
- `new_ghidra_contract(loader, max)` — 生产 manager，声明的 GhidraStringManager/
  Java 契约（string_ghidra.cc:20；ghidra_arch.cc:368 安装形态）。
- `clear()`, `get_maximum_chars()`, `num_strings()`, `has_entry(addr)`,
  `insert_string_data(addr, data)`, `set_string_data_client(client)`
  （GhidraJavaContract 后端的环境查询目标注入，见 2026-09-26 节）。
- `is_string(addr)` — legacy 单参桥（stringmanage.cc:166），charType 投影为 1 字节
  非 opaque 字符；带 reader 时执行真实 image 读取（含负缓存）。
- `is_string_typed(addr, charsize, opaque)` — typed 形态。
- `get_string_data(addr, charsize, opaque, &mut is_trunc) -> Vec<u8>` — 虚
  `getStringData` 契约（stringmanage.hh:61-69）：缓存命中直返；未命中先占坑再读。
- `register_internal_string_data(addr, buf, charsize) -> u64` — 内部字符串注册
  （stringmanage.cc:185-199），键为常量空间 hash 地址。
- `calc_internal_hash(addr, buf) -> u64`（stringmanage.cc:95-105，CRC32 init
  `0x7b7c66a9` ^ offset<<32）。
- `encode(encoder)`（stringmanage.cc:203）/ `decode(decoder)`（stringmanage.cc:231）。

## Free functions (UTF helpers)
- `write_utf8(out, codepoint)` — encode codepoint as UTF8 (stringmanage.cc:124).
- `read_utf16(buf, bigend) -> i32` — read UTF16 element (stringmanage.cc:297).
- `get_codepoint(buf, charsize, bigend) -> (i32, i32)` — extract next codepoint
  + bytes consumed (stringmanage.cc:347). 非法前缀（0xAD 等，无 c0/e0/f0 前缀）
  返回 -1 —— hugehelp 0x7180/0x99a8/0xc1d8 负缓存判定基础（stringmanage.cc:390-391）。
- `check_characters(buf, charsize, bigend) -> i32` — count chars or -1
  (stringmanage.cc:324).
- `has_char_terminator(buf, charsize) -> bool` — check for null terminator
  (stringmanage.cc:277).
- `write_unicode(out, buf, charsize, bigend, max) -> bool` — translate to UTF8,
  count 在 max 处截断（stringmanage.cc:36）。
- `assign_string_data(data, buf, charsize, num_chars, bigend, max)` — populate
  StringData（stringmanage.cc:66）：`charsize==1 && numChars<max` 原样整块拷贝
  （含终止符所在 32 字节块），否则翻译/截断 + 显式补 NUL，
  `isTruncated = (numChars >= max)`。

## Architecture wiring（见 docs/api/arch.md）

`Architecture::build_string_manager`（architecture.hh:308 / architecture.cc:1401
语义）在 `init` 中安装 `new_ghidra_contract(loader, 2048)` 单例；loader 先于其安装
（Ghidra init 顺序）。

## L3 gaps
- 消费侧接线：ruleaction.cc:7375 守卫 / printc.cc:1537 打印 / funcdata 内部串 /
  driver string_table 退役（TYPEOP-LOCALTYPE-DISPATCH-0001 D3 及其 print 子任务）。
- XML encode/decode 的 space-name 恢复（当前 encode 记录 offset+tag id，decode
  恢复为 spaceless 形态；Ghidra 用 `<addr space=...>`）。
<!-- annotation-pass: 2026-08-24 -->


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
