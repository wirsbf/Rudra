# `examples/httpd_decompile.rs` — httpd canon/mirror 双面反编译驱动

Source: `examples/httpd_decompile.rs`（本档首次登记于车道 STRDATENV /
`CANON-STRDAT-HTTPD-ENVTABLE-0001`，2026-09-28；此前该驱动的车道证据散见
TODO_BOARD 各 DONE 行——DISPLAYREBASE / ACTION-SYMDB-DATASYM / DFLIP 等）。

## 定位

httpd 语料的**门禁驱动**：canon 面（默认）以 analyzeHeadless 契约装配
传输层后跑全默认 action 管线 + `PrintC`，对照 golden
`tests/golden/ghidra_httpd_1204.c`（锁定 oracle e40ed130，Ghidra 12.0.4）；
镜面面（`RUGRA_MIRROR=1`）复现 direct-runner oracle 契约（BfdArchitecture
裸装载 + `followFlow`），对照 `ghidra_httpd_1204.direct-runner.c`。

## ACTION-SYMDB builder（canon-only 传输层，mirror 永不进入）

`build_action_data_symbol_db` 是 canon 面对 oracle analyzeHeadless 前端层的
数据装配镜像，按臂安装：

| 臂 | 内容 | 通道 |
|---|---|---|
| (0)/(0b) | 全局 scope PT_LOAD 属地范围 + R-only 段表 | mapGlobals/isReadOnly |
| (1) | 函数符号（canon print DB 入口集） | queryFunction |
| (2) | dynsym STT_OBJECT 数据符号 | queryContainer |
| (3) | GOT `PTR_<name>` 槽 | relocation 标签层 |
| (4) | .rodata ASCII 扫描 char[] typelock 符号 | ActionConstantPtr 字符串臂 |
| (4b) | canon 1B DAT 标签见证（本车道新增） | isPointer exact-hit 臂 |
| (5) | harvest 引用缺符号处的默认 `DAT_<addr>` | 前端默认标签层 |
| (5b) | canon offcut `UNK_` 代码标签（DISPLAYREBASE） | spacebaseConstant |
| (6) | R-only PT_LOAD 属性范围 | pushPtrCharConstant 门 |

## canon 环境事实见证表（CANON-STRDAT-HTTPD-ENVTABLE-0001）

curl ENVDAT 车道（STRLIT-ENVDAT-0001）钉死的结论在 httpd 同构成立：
analyzeHeadless 的 string-Data/DAT-标签层是**逐地址环境事实**，不可从字节
推导（长度/字符集/引用性规则均被 curl 语料证伪）。驱动因此以锁定传输
捕获（`/dev/shm/rugra-tests/headlessdist/xml/httpd/*.xml`，canon golden 的
协议亲捕）为 ground truth 持四张见证表：

| 常量 | 值 | 语义 |
|---|---|---|
| `CANON_UNK_CODE_LABELS_HTTPD` | `[(0x12df1b,"UNK_0012df1b")]` | canon offcut UNK 代码标签（DISPLAYREBASE，arm 5b） |
| `CANON_ABSENT_STRING_STARTS_HTTPD` | `[0x17b82f, 0x17a41d]` | canon 无 string-Data 的扫描 run 起点——arm (4) 跳过（ACTION 侧专属；print 侧 `fd.add_string` 全扫描保持，curl containment 同形） |
| `CANON_DAT_LABELS_HTTPD` | `[(0x17b831,"DAT_0017b831"), (0x17a41d,"DAT_0017a41d")]` | canon 引用目标 1B DAT 标签（arm 4b，未后缀 `undefined` + TYPELOCK/NAMELOCK/READONLY） |
| `CANON_HARVEST_REF_EXCLUSIONS_HTTPD` | `[0x131f4ab]` | harvest 收割的 mov-立即数假阳性（Module Magic Number 整数，非数据地址；canon 零 mapsym）——arm (5) 跳过 |

三位点机制链（oracle 亲读）：`ActionConstantPtr::isPointer` exact-hit
`queryContainer`（coreaction.cc:1151-1163）→ `Funcdata::spacebaseConstant`
（funcdata.cc:362-462）→ `PrintC::opPtrsub` TYPE_SPACEBASE 臂
（printc.cc:1057-1094）印 `&DAT_0017b831` / `&DAT_0017a41d`；反向站删除
假阳性 DAT 后常量回落裸整数字面量 `0x131f4ab`。

**1B 点位载荷**：canon DAT mapsym 的 typeref 是未后缀 1 字节 `undefined`
（save_state typegrp 槽名）；等尺寸（1B）unknown 点位经 castStandard 的
pointer-to-unknown 规则（cast.cc:374-376）抑制 `(char *)&DAT` 前置 cast，
而 undefined8 点位会因尺寸不等触发 cast.cc:337 插入（CURLWIRE-SIGLOCK-
WIRING-0001 教训）。

## 已知残留

- arm (5) 对窗内 `lea 0x7b82f`（0x49f70，非 census 窗口函数）收割装
  `DAT_0017b82f`（undefined8@8B，canon 无此标签）——当前 34 函数面零可观测
  （census 零差）；该引用函数若进入未来窗口需补见证。

## 验证口径

```bash
CARGO_TARGET_DIR=<t> cargo build --release --example httpd_decompile
<t>/release/examples/httpd_decompile > httpd_cur.c          # canon 面
python3 tools/compare_ghidra.py httpd_cur.c tests/golden/ghidra_httpd_1204.c --summary-only
RUGRA_MIRROR=1 <t>/release/examples/httpd_decompile        # 镜面面（第四门禁）
tools/verify_mirror_gate.sh --corpus httpd --bin-dir <t>/release/examples
```

---


> canon（headless 传输面）驱动的 httpd 反编译入口。写域=examples 驱动层
> （canon DB 传输/见证表），行为由 canon A/B + 镜面门覆盖。

## 2026-09-28：CANON-ADDRFORM-GLOBALARRAY-0001 — 指针表 STT_OBJECT 的 8B ptr 首槽定型（Lane MAINMIXED）

**现象**：canon httpd main for 头 `for(ppuVar15 = ap_prelinked_modules; ...)` 缺 `&`
（golden `= &ap_prelinked_modules;`）——嵌于 for 头折行复合 hunk 的可分离子差。

**根因（canon DB 传输 XML 亲证，0x12b820.xml mapsym id 0xa23）**：
`ap_prelinked_modules` 在锁定 oracle 的分析 DB 中是 **ptr→undefined、map 仅首槽
8 字节**（typelock/namelock），后续槽在别的窗口另有独立 `PTR_*` 8B 符号；同型
证据 `ap_preloaded_modules`(0x19d020)/`ap_prelinked_module_symbols`(0x19d100)
均为 8B ptr。而驱动 `object_datatype` 的 W6 臂（V3SIG-UND224-TYPEORDER-0001）
把"全槽指针证据"的表定型为 `undefined*[size/8]` **数组**——printc.rs SPACEBASE
臂（printc.cc:1064）对 TYPE_ARRAY 符号 **丢弃 `&`**（cc:1071-1073 才印
`&name`），故 Rugra 直印裸符号。W6 见证文件 o_w6_proto_arrayptr.c 第 205 行亲证
oracle 对**数组形**种子印的是裸 `ppxVar15 = ap_prelinked_modules`（无 `&`）——
前代票面把 `&` 归给 W6 是误读。

**修复**：`object_datatype` 返回 `(Arc<Datatype>, usize)` 二元组；全指针槽表改注册
`ptr→undefined` 且 **map_size=8（仅首槽）**；`covered` 仍按整段 extent 推进（防
harvest/rodata 在尾槽建影子标签）。其余形态（W5 undefined8[]/getBase undefined[]/
≤10 标量）不变。

**验收**：canon httpd 34→30（main 13→9，本根 −4：`&` 2 行 + 复合 hunk 折点连带
2 行——`&` 增一字使 Oppen 溢出提前、断点从合成 0 宽 token 落回逗号后，与 golden
折点重合）；canon curl 42 零漂移；for 头与 golden 逐字节恒等（除 declfam 待并的
死槽计数位移）；镜面五面 PASS；bank 391/391。

## 文档状态

- 2026-09-28 初建（Lane MAINMIXED，CANON-ADDRFORM-GLOBALARRAY-0001 收口）。

- 2026-09-28 STRDATENV 档与 MAINMIXED 档 add/add 并集（MB37 合并解）。
