# Rudra vs Ghidra: 差距分析与路线图

> **时效声明（2026-09-26）**：正文第 1-4 节为第 8 阶段历史快照，多数"差距/下一步"已被
> 后续波次消化（如 uVar 碎片化、while/if 检测、DCE 等）；当前缺口以文末
> 「2026-09-26 波次缺口增量」节 + `docs/TODO_BOARD.md` 为准。

本文档概述了 Rudra（截至第 8 阶段）与 Ghidra 之间的技术差距，重点关注 C/C++ 反编译质量。虽然 Rudra 已经实现了一个功能性的反编译流水线，但要达到 Ghidra 的行业标准输出，还需要通过几个高级功能来弥补差距。

## 1. 变量恢复与符号化 (Variable Recovery & Symbolization)

| 特性 | Ghidra | Rudra | 差距 / 下一步 |
| :--- | :--- | :--- | :--- |
| **变量合并** | 使用“高级变量 (High Variables)”在整个函数生命周期内合并 SSA 节点，智能处理寄存器复用。 | 实现了 `HighVariableMap`，但代码生成仍依赖于启发式命名 (`RegisterNamer`) 和基础栈分析。 | **关键**：将 `HighVariable` 分析完全集成到 `codegen` 中。将所有 SSA 版本映射到单个逻辑变量，以消除 `uVarX` 碎片化。 |
| **栈帧分析** | 复杂的栈帧重构，处理动态栈指针 (`alloca`) 和复杂的函数序言 (prologues)。 | 基于偏移量的基础栈变量检测 (`local_X`)。输出中已隐藏栈指针调整 (`RSP`)。 | 实现虚拟栈指针跟踪，以处理非标准栈帧。 |
| **寄存器命名** | 上下文感知的命名。 | 改进的命名 (`uVar1`, `param_1`) 已取代大多数原始寄存器名 (`rax`)。 | 实现用户定义的命名覆盖和基于类型的匈牙利命名法（如指针用 `pcVar1`）。 |

## 2. 类型系统与推断 (Type System & Inference)

| 特性 | Ghidra | Rudra | 差距 / 下一步 |
| :--- | :--- | :--- | :--- |
| **类型传播引擎** | 基于约束的系统，在 P-code 图中向前和向后传播类型。 | **已实现**：`TypeSolver` 现在具备完整的全程序类型传播能力，基于统一的 `DataType` 系统处理所有 P-code 操作和 SSA Phi 节点。 | **完成**：持续优化特定架构的类型推断规则。 |
| **类型库** | 包含 C/C++ 标准库（`libc`, `windows.h` 等）的海量数据库，用于自动函数签名解析。 | **部分**：PLT 解析可识别外部函数（如 `printf`）。类型仅从使用上下文中推断。 | **重大**：集成类型库格式，以对已解析的 PLT 函数强制执行标准签名。 |
| **结构体/联合体恢复** | 根据指针偏移量和访问模式自动重构结构体。 | **已实现**：迭代式结构体恢复算法。自动监控指针算术运算，从 `ptr + offset` 模式中逆向出结构体布局并生成 `StructDef`。 | **完成**：下一步支持嵌套结构体和联合体。 |
| **指针算术** | 解析复杂的指针算术 (`ptr[i].field`)。 | **已实现**：代码生成器现在能够识别指向结构体的指针，并输出 `ptr->field_offset` 语法，替代原始的 `*(type*)(ptr + off)`。 | **完成**：增强对数组索引 `ptr[i]` 的支持。 |
| **字符串字面量** | 自动将字符串指针解析为字面量。 | **已实现**：通过启发式扫描从 `.rodata` 自动恢复 C 字符串。 | 支持非 ASCII 字符串 (UTF-16/32) 和复杂数据引用（跳转表）。 |

## 3. 控制流结构化 (Control Flow Structuring)

| 特性 | Ghidra | Rudra | 差距 / 下一步 |
| :--- | :--- | :--- | :--- |
| **结构恢复** | 高级的“块结构化”算法处理不可约循环、复杂的 `switch` 语句和 `goto` 消除。 | 对自然循环 (`while`) 和 `if/else` 块的基本检测。对于复杂流回退到 `goto`。 | 实现完整的“基于区域 (Region-based)”的结构分析，以清晰地恢复 `for`, `do-while` 和 `switch-case` 结构。 |
| **布尔逻辑** | 将嵌套分支折叠为逻辑运算符 (`&&`, `||`)。 | 生成嵌套的 `if` 语句。 | 在 AST 构建器中实现条件折叠逻辑。 |

## 4. 优化与惯用语识别 (Optimization & Idiom Recognition)

| 特性 | Ghidra | Rudra | 差距 / 下一步 |
| :--- | :--- | :--- | :--- |
| **编译器惯用语** | 识别除法转乘法、内联 `memcpy`/`memset` 和安全编码模式 (canaries)。 | 基础常量折叠。栈 canary 显示为原始逻辑。 | 添加模式匹配过程，以识别编译器惯用语并将其替换为高级等价形式。 |
| **死代码消除** | 激进的、数据流驱动的 DCE。 | **已实现**：增强型 DCE 利用 SSA 版本信息，不仅移除临时变量，还能安全移除未使用的寄存器定义（如死循环计数器）。 | 继续增强对副作用（如内存写入、标志位）的精细分析。 |

## 总结路线图

为了缩小与 Ghidra 的差距，Rudra 需要从一个**带有基础分析的 P-code 提升器**进化为一个**语义重构引擎**。

**近期优先事项：**
1.  **高级控制流结构化**：实现基于区域（Region-based）的结构化算法，以完美恢复 `switch`、`for` 和 `do-while`。
2.  **库签名匹配**：构建标准库函数签名数据库（libc, winapi），为类型系统提供更强的锚点。
3.  **C++ 特性支持**：探索 C++ 虚函数表恢复和类继承关系的分析。

---

## 5. 2026-09-26 波次缺口增量（基=master `efc28f4a`；在飞车道另计）

> 记账口径：本节只列 W-2026-09-26 波次内**状态翻转**的缺口（新闭/新开）；
> 存量未动缺口见 `docs/TODO_BOARD.md` 全账。状态标注"已并"=master efc28f4a 含交付 commit，
> "在飞"=车道分支交付待 root 合并。

### 5.1 本波次已闭缺口

| 缺口 | 票 | 状态 | 闭法一句话 |
|---|---|---|---|
| configtest if/else 取向翻转（~166 行） | HTTPDMAIN-F5-IFELSE-RETEST-0001 | **已并**（58af028a+2ed48430） | ActionPreferComplement BFS 对 Goto/MultiGoto 包裹子树下降；httpd main 232→78 |
| libc 参数名推荐缺失（`__s1` 名族） | HTTPDMAIN-F7-NAMERECOMMEND-0001 | **已并**（09bc75fb+b2220069+f3d4f32d） | NameRecommend 三存储+恢复链+IMPORTFLIP 台账默认装；httpd 590→439 |
| 双重强转打印（switch 头双层同型 cast） | HTTPDMAIN-F3-DOUBLECAST-0001 | **在飞**（wt/printcs de36abd3） | legacy LOAD 臂 CAST 包装省略+printlanguage.cc:277 嵌套规则 |
| 数组指针 cast 非法 C 形 `(t [N]*)` | MIRATTR-F-ARRCAST-0001 | **在飞**（wt/printcs 3f9a10e2） | pushType 链 run 语义重写→`(t (*) [N])`；httpd 镜 265→253 |
| WhileDo 入口标号缺发（悬空 goto） | MSTRUCT-WHILEDO-LABEL-PRINTC-0001 | **在飞**（wt/printcs 6ec4e705） | 四循环构造入口补 emit_any_label_statement；curl 镜 110→101 |
| CALLOTHER 语句打印（裸 `;`） | STRNCPY-PRINT-CALLOTHER-0001 | **在飞·printc 半**（wt/printcs e8b6ec5e） | dispatch_op_rpn 补 CPUI_CALLOTHER 臂+四 display 臂+读回链；ap_ht_time 恢复 `builtin_strncpy(...)` 语句。**剩余=输出 token 三级链，拆出 COREACTION-CALLOTHER-OUTTOKEN-0001**（见 5.2） |
| ruleaction union 消费退化形（14 站点） | UNIONRESOLVE-PKG-D-0001 | **已并**（961b332f+a308dbc8） | fd-aware 孪生+slot 键对照 op->getSlot |
| with_field 指针臂非工厂形 | UNIONRESOLVE-PKG-G-0001 | **已并**（e94c3640+efc28f4a） | TypeFactory intern（findAdd 规范化） |
| printc union 消费退化形（29 站点） | UNIONRESOLVE-PKG-C-0001 | **在飞**（wt/printcs 83213b78，语料中性） | find_resolve_snap 快照通道 |
| `// Ghidra:` 引用行漂移（工具无定义起始行验证） | TOOLS-REFS-DEFSTART-0001 | **已并**（9aa565ec+ba3f2dc8） | 门禁升级+288 处全修 |
| noreturn 台账缺失→F1 级联（~272 行） | HTTPDMAIN-F1-NORETURN-0001 | **已并**（4455636b+f80763ea，背景） | KNOWN_NO_RETURN 21 名单+canon 传输 |
| goto 边槽位镜像残留→switch 退化 | MSTRUCT-SWITCHGOTO-SELECTGOTO-0001 | **已并**（1414f6e3，背景） | resync_goto_edge_mirrors |
| 循环承载值驻留（my_get_line F-RESIDE） | MIRATTR-F-RESIDE-0001 | **已并**（1f7fe30a，背景） | intersection 第二判定臂（testUntiedCallIntersection） |
| stale descend 泄漏→NULLLOCALTYPE/FORCEDINTERSECT panic | GEN4-SQ-NULLLOCALTYPE-0001 / GEN4-SQ-MERGE-FORCEDINTERSECT-0001 | **在飞**（wt/sqnullt 948974df；SQMERGE 独立确认收敛同根因） | set_opcode_and_inputs 委托 op_set_all_input；sq panic 4→2 |

### 5.2 本波次新开缺口

| 缺口 | 票 | 级 | 域 | 要点 |
|---|---|---|---|---|
| CALLOTHER 输出 token 三级链缺失 | COREACTION-CALLOTHER-OUTTOKEN-0001 | P2 | coreaction.rs+userop.rs | TypeOpCallother::getOutputLocal（typeop.cc:866-872）→InternalStringOp 特化（userop.cc:361-364）→默认 TYPE_UNKNOWN 非 Int；修后 STRNCPY 票逐字节验收即达（PRINTCS 车道登记，在 wt/printcs 分支） |
| checkAddressOfCast 整体未移植 | PRINTC-CHECKADDRESSOFCAST-0001 | P2 | printc.rs | cc:379/381/403 `&` 数组衰减形（PKG-C 伴生） |
| gen 驱动符号 DB 通道缺失 | GENDRIVER-SYMTAB-DB-0001 | P2 | examples/gen_decompile.rs | BFD 函数符号不喂 Architecture symboltab→ActionConstantPtr queryContainer 恒 miss→vsh `main` 印裸地址（CODENAME 票判定移交） |
| 字节车道重构形态差 | GEN4-SQ-BYTELANE-STRUCT-0001 | P2 | 待判域（疑 subflow/heritage 交互） | header.1 读改写链 oracle 逐字节 MULTIEQUAL 重构 vs Rudra 寄存器粒度；不 panic、defects=0，SQMERGE 车道登记（在 wt/sqmerge 分支） |
| 病态慢族（首个性能级分歧） | GEN5-SQLITE-PATHOSLOW-BITVEC-0001 | **P1** | 待探针定位（疑 heritage/merge 活跃性或 blockaction fixpoint） | sqlite3BitvecSet/Clear/TestNotNull：oracle 毫秒级 vs Rudra 600s 墙杀；GEN5 车道登记（在 wt/gen5 分支） |

> 同波次证据扩容（不开新票）：PRETTYFLUSH panic 族半径 ×13.5（sq 2 站点→sqlite 27 站点，
> MIRROR3-PRETTYFLUSH-FAILCLOSED-0001 建议升 P1/P2 头名）；sqlite 面既有结构族（CAST/SWITCH/
> UNAFF/STACKSLOT ~1.2 万行级）与链表 for 形 31:0 缺席归并 MSTRUCT-FORSPLIT 等原票。