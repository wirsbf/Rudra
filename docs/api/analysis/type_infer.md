## analysis/type_infer.rs

ActionTypePropagate：多轮迭代类型传播 + 结构体指针检测 + LOAD 输出推断。

### 执行顺序
1. Phase 1-4: 结构体指针检测
2. Phase 5: LOAD 输出推断（单 pass）
3. Phase 6: 迭代类型传播（7轮到收敛）

### 迭代传播规则
COPY/LOAD(force_override)/INT_ZEXT/INT_SEXT/INT_ADD/INT_SUB。

### void 指针推断（2026-06-28）
当指针的 ptr_to size==0（void/unknown struct），从 LOAD 输出 size 推断元素类型（4→int, 8→long）。

### 已知限制
piVar92=*(int*)(piVar89+0x128) 仍显示 int* —— 变量名在声明阶段生成，使用不同的类型查找路径。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-23（VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 编译适配）
type_infer.rs 两处 high 类型直写 `high_arc.write().unwrap().v_type = X` 改为 `.v_type.set(X)`（:296 new_type、:380 elem_type）。`HighVariable::v_type` 缓存迁入 `TypeCell` 锁域（Ghidra variable.hh:141 `mutable` 的对应物，详见 docs/api/variable.md）。`.set()` 保持原直写缓存语义（不置脏），行为不变。
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
