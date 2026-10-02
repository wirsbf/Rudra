# 方法论（学术/模型）沉淀模板 (Methodology)

在这里存放对 RustVSR / Rudra 中具备较高理论性、有学术突破向或打破逆向工程常理的方法、抽象模型的探讨文档。

## 命名指引
`method_YYYY-MM-DD_<high-level-topic>.md` 

---

## 报告结构标准

### 1. 论点与创新 (Claim)
我们在某个方向提出了什么不一样的核心论点？(例如无类型安全环境下的极速变量合并算法等。)

### 2. 问题剖析与现状 (Problem Domain)
描述传统 Ghidra 等静态反编译器在处理这方面的问题时遇到了怎样的瓶颈，或由于 C++ 旧包袱造成的性能墙。

### 3. 解题模型与数据流向 (Algorithm & Mathematical Logic)
用高度抽象的层级阐述我们的算法流图、逻辑图或者方程式。不在这里写一堆底层的代码细节。

### 4. 映射到系统 (System Implementation Link)
详细的落地编码应该另开文件，记录在 `docs/method/impl/` 下，此处仅给出链接或指明是哪个 Rust 的 `src/...` 模块。
    
