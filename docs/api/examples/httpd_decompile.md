# `examples/httpd_decompile.rs` API Reference

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
