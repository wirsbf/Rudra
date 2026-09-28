# `examples/curl_decompile.rs` — curl canon/mirror 双面反编译驱动

Source: `examples/curl_decompile.rs`（本档首次登记于车道 BOOLDRILL /
`CANON-BOOLCHAR-FIELDTYPE-0001`，2026-09-28；STRDATCURL /
`CANON-STRDAT-CURL-DATSLOT-0001` 同日增补 DAT slot 见证表节；此前该驱动的
车道证据散见 TODO_BOARD 各 DONE 行——ENVDAT / CURLWIRE / DISPLAYREBASE /
R3MERGE 等）。

## 定位

curl 语料的**门禁驱动**：canon 面（默认）以 analyzeHeadless 契约装配
传输层后跑全默认 action 管线 + `PrintC`，对照 golden
`tests/golden/ghidra_curl_1204.c`（锁定 oracle e40ed130，Ghidra 12.0.4）；
镜面面（`RUGRA_MIRROR` 族）复现 direct-runner oracle 契约（BfdArchitecture
裸装载 + `followFlow`）。

## FIELDRETYPE 通道（canon 默认开，`CANON-BOOLCHAR-FIELDTYPE-0001`）

### 现象与裁决

canon golden main 的 `::config.remotefile ==/!= false`（4 站）与
getparameter 的 `::config.remotefile = (bool)(::config.remotefile ^ 1)`（1
站）共 10 行，Rugra 基线印 `'\0'` 字符字面量与无 cast 形。前波（R4BOOL /
CURLFAM）双证伪判决在 4df1e154 重钻恒等：**Java headless DWARF importer
提交层字段改型，非渲染/传播缺陷**——

- 库侧机械 1:1（oracle 亲读）：`PrintC::pushConstant`（printc.cc:1744-1816）
  metatype 分发——TYPE_BOOL→`pushBoolConstant`（:1488-1495）印
  `true`/`false`，TYPE_INT/UINT+isCharPrint→`pushCharConstant` 印 `'\0'`；
  `(bool)` cast 来自 castStandard（cast.cc:300-392，req=TYPE_BOOL 落 :387
  default→cast）。常量的 facing 型随字段型走——字段 char 则 `'\0'` 即正确
  库行为。
- DWARF 输入真值：`remotefile` DW_AT_type=\<0x17f\> 直接 signed char
  （readelf 亲证，decl_line 299）——锁定 C++ 库对 char 字段必印 char 形。
- golden 的 bool 形源头=analyzeHeadless 的
  `DWARFDataTypeImporter.makeDataTypeForTypedef`→`makeNamedBaseType` 把
  CU1 的 char DIE \<0x17f\> 名键 remap 成内建 bool（"DWARF data type
  remappings: /char -> /bool"），per-field 提交是 importer 文件序状态机
  函数，**无 (DWARF×usage) 决策函数可复现**（同 DIE 异果/零布尔用法
  bool[N] 双机器证伪，详见
  `tests/golden/manifests/field_retype_curl_1204.json` adjudication 与
  HEADLESS_BRIDGE_V1_DESIGN §21.1）。

⇒ 票面改判**数据传输域**（displayrebase/strdatenv 先例形态）：canon DB
真值=改型后字段，驱动以台账装数据。

### 通道形态（DWARFSEED canon-committed 先例）

- **manifest**: `tests/golden/manifests/field_retype_curl_1204.json`——
  oracle_commit + binary/golden sha256 溯源 + adjudication 裁决全文 +
  entries[(struct,field)→retype target]（现役一条
  `Configurable.remotefile`→bool，5 行 golden witness 逐条列出）。
- **驱动装种**: `install_field_retype_channel()` 于 main() 顶、任何
  DWARF pass 之前——解析语料 DWARF 一次，台账字段换核心 bool，
  `destroy_type`+`get_typedef` 重占共享工厂名槽；`intern_named`
  (variant,size,metatype) 去重让后续所有解析共享同一身份（= Java type
  manager remap 后的单身份状态，cast.cc:304 指针同一性比较无 cast）。
  刻意不用 per-site 树改写（第二身份会分裂 cast 引擎指针同一性检查）。
- **门极性（SYMDB DFLIP 形状，BOOLDRILL 2026-09-28 翻转）**:
  canon 面**默认装**；`RUGRA_FIELDRETYPE=0` 恢复 DWARF 字面（char）脸；
  mirror 组件恒拒（五投影纯净）；`RUGRA_SEEDS=0` 全局裸脸逃生；
  `RUGRA_FIELDRETYPE_MANIFEST=<path>` 覆盖；manifest 缺失/损坏=响亮
  no-op。

### 效果（基=4df1e154 A/B 亲测）

canon curl **42→32/0/0**（−10 精确=票面全额：main 9→1[BOOLCHAR 8 消，
残 1=`char *V` 声明=MIRATTR-F-DECL 域]+getparameter 2→0 除名；其余
122 函数零漂移，7 残差函数计数恒等；5 witness 行逐字节==golden
:695/:712/:738/:1021/:1871）。

## DAT slot 见证表（canon-only，`CANON-STRDAT-CURL-DATSLOT-0001`）

### 现象（canon curl 残差 myprogress 3 行）

golden `fVar9 = DAT_00107178 * fVar10;`（ghidra_curl_1204.c:1163）vs
Rugra `fVar9 = _DAT_00107178 * fVar10;` + 函数头
`/* WARNING: Globals starting with '_' overlap smaller symbols at the
same address */`。同站双票登记：`CURLCANON-DATSLOT-SIZE-0001`（尺寸）
≡`CANON-GLOBALSYM-UNDERSCORE-0001`（`_` 前缀+WARNING）——同一 3 行。

### 双侧钉死（事件级，零猜测）

- **二进制真值**：0x107178（base-0 0x7178）= 4 字节 float 100.0
  （`00 00 c8 42`），myprogress `movss`（0x10359f）4 字节读。
- **canon DB 真值**（headlessdist 传输捕获 xml/curl/0x1034d0.xml，该窗口
  唯一数据 mapsym）：`DAT_00107178`，typeref **undefined4**、entry
  **size 4**、typelock/namelock/readonly、merge=false——oracle 的
  reference-following data creation 按**访问宽度**定 Data 尺寸（对照：同窗
  `lea` 站 DAT_001061d9=1 字节 undefined）。
- **Rugra 基线 DB**（probe 亲证 `query_container(0x107178,1)→
  DAT_00107178+3`）：通用非 string 臂 8 字节宽被 next-string-start 裁到
  **3**（裁刀=浮点末字节 0x42='B' 构成的 1 字符 run @0x10717b——canon
  strings analyzer 从不收录），symbol type=undefined1。
- **双症状机制链**（oracle 亲读）：①mapGlobals 伸展测试
  （funcdata_varnode.cc:1711）4 字节 float persist 组 > 3 字节 entry →
  `inconsistentuse`→warningHeader（:1717-1718）；②symbol type（1）<
  vn 尺寸（4）→`HighVariable::setSymbol` 不入完美匹配臂
  （variable.cc:265-267 要求 type size==vn size）→symboloff=0→
  `pushSymbolDetail`（printlanguage.cc:255-260）落 `pushMismatchSymbol`
  （printc.cc:2072-2075）印 `_`+displayName。

### 通道形态

- **见证表**: `CANON_DAT_SLOT_WIDTHS_CURL=[(0x7178,4)]`（base-0 键，
  +img_base 查询；全量溯源注释随常量）——装 canon 传输的精确
  typeref/entry 尺寸/flags（undefined4@4+TYPELOCK/NAMELOCK，READONLY 沿
  .rodata 通用臂），**跳过**指针槽宽度与 next-string-start 裁剪。
- **canon-only 三重门**（=字符串 registry 的 containment）：mirror
  bundle/flow/bare 任何组件在则查表返回 None——镜面 face 不装（bundle
  走 bare-load 分支整个不进此循环），flow gate 保 hybrid face 字节恒等。
- **泛化路径**（注释在案）：引用读宽扫描（iced 内存访问定靶）可从二进制
  推导宽度——语料现役唯一 sized-read 站，第二站出现前按台账装。

### 效果（基=e973d71e A/B 亲测）

canon curl **27→24/0/0**（−3=票面全额：myprogress 3→0 从残差清单除名，
`--func myprogress` **[Skeleton] identical**；base/fix 全文 diff 恰 3 行=
WARNING 注释+尾随空行+`_DAT_`→`DAT_` 行，其余 123 函数字节恒等；DAT
token 集 13==13 双侧全等、`_` 前缀族清零、overlap-WARNING 0==0）。
同族扫描：canon curl 唯一 `_DAT_` 站=本站；`&PTR_DAT_` 形双侧恒等。

## 验证口径

```bash
CARGO_TARGET_DIR=<t> cargo build --release --example curl_decompile
<t>/release/examples/curl_decompile > curl_cur.c             # canon 面（默认装 retype）
python3 tools/compare_ghidra.py curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
RUGRA_FIELDRETYPE=0 <t>/release/examples/curl_decompile     # DWARF 字面脸逃生
tools/verify_mirror_gate.sh --corpus curl --bin-dir <t>/release/examples
```
