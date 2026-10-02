# Ghidra 对齐蓝图：SSA Phi 节点强置规则 (Phi Node Placement)

**[状态]**: 🟢 理论补全  
**[目标模块]**: 结构化控制流下的数据并发交汇处理机制  
**[关联 Ghidra 源码位置]**: `Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc: Heritage::buildPhiNodes`  
**[关联 Rudra 源码位置]**: `src/heritage.rs`  

---

## 1. 目标描述 (Description)

在将非 SSA 形态转化为完全静态单赋值网络时，不仅需要利用支配边界 (Dominance Frontier) 建立 `MULTIEQUAL` (Phi) 节点，还需要针对“永远死循环无法退出”、“虚假分支”以及**别名指针**带来的不确定性调整构建策略。
Rudra 的目标是在 `src/heritage.rs` 完全复刻 Ghidra 的启发式重排过滤法则与空间敏感的递进式 SSA 构建过程 (Phased SSA Construction)，避免生成臃肿且错误的 Phi 节点。

## 2. Ghidra 的核心实现逻辑与数据结构约束 (Ghidra Implementation)

### 2.1 空间敏感的递进延迟构建 (Space-Sensitive Heritage Delays)
Ghidra 采用多轮重叠的 SSA 构建策略。不同类型的存储空间 (Address Space) 在进入 SSA 的轮次上有严格的先后顺序和延迟 (Delay) 控制：
*   **寄存器空间 (Register Space)**: 通常延迟最低（delay = 0），在第一时间被 SSA 化，因为它们极少受到别名覆盖（Aliasing）的影响。
*   **栈空间 (Stack Space)**: 通常会有一定的延迟（例如 delay = 1 或 2）。这是因为局部变量经常可能遭受栈溢出或多级指针引用的影响，如果在指针分析清晰之前强行 SSA 化，会导致巨大的内存交变流（Memory Aliasing Artifacts）问题。
*   `LocationMap` (对应 `heritage.rs: LocationMap`): 按地址精准管理当前变量是否达到可以被 SSA 化的 pass 阈值。

### 2.2 死代码与不可达节点规避 (Dead Code Avoidance)
*   如果一个流保护块 (FlowBlock) 被标记为 `DEAD`（例如永远不会执行的垃圾指令），则在支配边界扫描和 Phi 节点推导时必须直接忽略，防止虚假的合并路径污染正常的数据流。

### 2.3 迭代式支配边界与工作队列 (Iterative Dominance Frontier)
Ghidra 的 Phi 放置算法并非常规的静态一次性生成，而是通过工作队列 (`PriorityQueue`) 动态推演的：
1.  **定义收集**: 收集地址域所有的显式定义 (Write)。
2.  **迭代放置**: 将定义块放入 `PriorityQueue`（按深度）。如果某个块的定义触及支配边界，且边界块未曾产生过此地址的 Phi，则在该边界块内插入一个 `MULTIEQUAL` (Phi)。
3.  **增量扩散**: 插入的新 Phi 本身也是一次“定义”，将其再次入队继续触发边界扩散。
4.  **按需定长**: Phi 的尺寸必须根据该地址历史生命周期中观测到的最大交汇尺寸进行对齐。

### 2.4 重命名与链接 (Renaming Phase)
*   **重命名栈 (Renaming Stacks)**: 针对每个内存地址维护一个重命名栈。按照支配树做深度优先遍历 (DFS)。
*   遇到定义，新 Varnode 入栈。
*   遇到使用，选取栈顶 Varnode 进行 Use-Def 挂载。
*   为所有后继块 (Successors) 的开头处的 Phi 节点分配对应的来源输入。
*   退出当前块及其子树时，弹出本次定义，回退状态。

## 3. Rudra 的工程演进与对齐方案 (Rudra Approach)

Rudra 的 `src/heritage.rs` 已经具备了基本的支配前沿 (DF) 和重命名扫描实现。下一步必须完善如下严格的对齐逻辑：

- [ ] **多轮次管控 (Pass Tracking)**: 强化 `HeritageInfo`，禁止在 pass 计数未达到栈变量的 delay 阈值时对其执行 `place_multiequals`。
- [ ] **地址大小交叉检测 (Size Overlap Detection)**: Ghidra 在生成时会对同一位置但不同大小 (例如 AL 与 EAX) 的局部写入进行分量拆解或拼接合并。目前 `heritage.rs` 单纯回退到 `4` 字节 fallback 是不合格的。须引入基于 `LocationMap` 的精细范围检查。
- [ ] **死区拦截 (Dead Block Pruning)**: 在 `visit_rename` 收集定义点以及在 `place_multiequals` 入列工作清单 (Worklist) 之前，增加 `block.is_dead()` 的直接截断。
