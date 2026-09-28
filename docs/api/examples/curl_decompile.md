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

## 验证口径

```bash
CARGO_TARGET_DIR=<t> cargo build --release --example curl_decompile
<t>/release/examples/curl_decompile > curl_cur.c             # canon 面（默认装 retype）
python3 tools/compare_ghidra.py curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
RUGRA_FIELDRETYPE=0 <t>/release/examples/curl_decompile     # DWARF 字面脸逃生
tools/verify_mirror_gate.sh --corpus curl --bin-dir <t>/release/examples
```
