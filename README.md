# Rudra 🦀

**Ghidra 12.0.4 反编译核心的纯 Rust 1:1 移植** —— 将 NSA Ghidra 反编译器（`decompile/cpp`，114 个 C++ 源文件）的核心算法管线忠实移植到 Rust，并以「锁定同版本 Ghidra、同输入同输出」的自动化差分门禁作为唯一正确性标准。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Oracle](https://img.shields.io/badge/oracle-Ghidra%2012.0.4-e94f37.svg)](docs/VERIFICATION_GUIDE.md)
[![Pure Rust SLEIGH](https://img.shields.io/badge/SLEIGH-pure%20Rust%20(kuna--sleigh)-brightgreen.svg)](crates/README.md)

---

## 为什么做 Rudra

Ghidra 的反编译器是一套成熟完备的 C++ 工程实现——涵盖 SSA/Heritage 构造、值域分析、控制流结构化、类型与变量恢复、规则重写等完整管线。但原生 C++ 实现不易直接嵌入 Rust 工具链、缺乏内存安全保证，且难以在函数级做可重复的行为验证。

Rudra 的目标是 **算法层 1:1 忠实对齐，工程层纯 Rust 现代化**：

- **源码级可追溯**：核心实现逐函数标注对应的 Ghidra 源位置（`// Ghidra: <file>:<line>`），可通过提交钩子与校验脚本自动核验。
- **差分门禁驱动**：不靠“看起来像”，而是以锁定版本 Ghidra 12.0.4（commit `e40ed130`）为 oracle，在单元测试、双侧差分 fixture、投影银行与多语料端到端门禁上验证行为等价。
- **开箱即用**：已彻底退役 C++ SLEIGH FFI 运行时，默认采用纯 Rust SLEIGH 引擎（[`crates/kuna-sleigh`](crates/README.md)），普通构建与运行不再依赖本地编译 Ghidra。

适合用于：**反编译与程序分析研究、嵌入式静态分析/安全审计基座、PL/编译课程参考，以及大型 C++ 核心向 Rust 渐进式迁移的工程实践。**

---

## 核心特性

- **纯 Rust SLEIGH 提升链**：内置 `kuna-base` / `kuna-num` / `kuna-sleigh` / `kuna-slacomp` 工作区 crate，直接消费 Ghidra `.sla` 处理器规格与 `.cspec` 调用约定，目前支持 x86-64（架构层已为多架构预留接口）。
- **完整 Action / Rule 反编译管线**：按原注册序重建 Ghidra `universalAction` 嵌套管线树（`universal` → `fullloop` → `mainloop` → `stackstall`）与规则池。
- **全套核心反编译算法**：覆盖 ELF 加载、P-code IR、SSA/Heritage、值域分析（`CircleRange`）、控制流结构化（`TraceDAG` / `collapse` 族）、参数与类型恢复（`varmap` / `ScopeLocal`）、变量合并（`merge` 族）与 C 伪代码输出（`PrintC`）。
- **多层自动化差分验证**：涵盖单元测试、391 项投影银行（Projection Bank）、双侧 oracle 差分 fixture 与五大真实二进制端到端镜面门禁，任何漂移 fail-closed。
- **严格确定性输出**：无时间或哈希遍历序依赖，同一输入多次运行及全量语料输出均保持逐字节一致。

---

## 效果演示

反编译真实 `curl` 二进制中的 `GetStr` 函数，输出与 Ghidra 12.0.4 逐字节一致：

```c
// $ cargo run --release --example curl_decompile | sed -n '/GetStr/,/^}/p'
void GetStr(char **string,char *value)
{
  char *pcVar1;

  if (*string != (char *)0x0) {
    free(*string);
    *string = (char *)0x0;
  }
  if (value != (char *)0x0) {
    pcVar1 = strdup(value);
    *string = pcVar1;
  }
  return;
}
```

---

## 快速开始

### 1. 构建与运行（纯 Rust，无需 Ghidra 源码）

```bash
git clone https://github.com/wirsbf/Rudra.git
cd Rudra
cargo build --release
```

运行内置反编译示例与测试：

```bash
# 反编译 curl 语料（124 个函数）
cargo run --release --example curl_decompile > curl_out.c

# 反编译 httpd 语料（34 个函数）
cargo run --release --example httpd_decompile > httpd_out.c

# 使用通用入口反编译任意 ELF 二进制
cargo run --release --example gen_decompile -- <path/to/binary>

# 运行库单元测试
cargo test --lib

# 与 Ghidra 12.0.4 golden 对比
python3 tools/compare_ghidra.py curl_out.c tests/golden/ghidra_curl_1204.c --summary-only
```

### 2. 运行双侧 Oracle 差分验证（可选）

仅在需要从头运行双侧 C++ Oracle 差分 fixture 时，才需要以侧车方式准备锁定版本的 Ghidra 源码树（详见 [docs/VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md)）：

```bash
git clone https://github.com/NationalSecurityAgency/ghidra ghidra-src
git -C ghidra-src checkout e40ed13014025f82488b1f8f7bca566894ac376b
ln -s "$(pwd)/ghidra-src" ghidra

# 运行单个双侧差分 fixture 示例
bash tools/run_transform_multiequal_insert_oracle.sh
```

---

## 工作原理

```text
 ELF            SLEIGH .sla / .cspec             锁定 Ghidra 12.0.4 (可选侧车)
  │                      │                                   │
  ▼                      ▼                                   ▼
binary/ ──► kuna-sleigh ──► P-code IR ──► Action 管线 ──► C 伪代码
(goblin)    (纯 Rust 提升)  (Varnode /    (Heritage/SSA,       ▲
                            PcodeOp)      控制流结构化,         │
                                          规则池, 类型恢复)     │
                                                │              │
                                                └── 差分门禁 ──┘
                                              (fixture + golden)
```

`src/` 中的核心模块与 Ghidra C++ 源文件基本一一对应（如 `src/varmap.rs` ↔ `varmap.cc`、`src/blockaction.rs` ↔ `blockaction.cc`、`src/ruleaction.rs` ↔ `ruleaction.cc`），完整映射见 [RUDRA_GHIDRA_MAPPING.md](RUDRA_GHIDRA_MAPPING.md)。

---

## 仓库结构

```text
src/                     # 反编译器核心模块（与 Ghidra decompile/cpp 1:1 对应）
crates/                  # 纯 Rust SLEIGH 工作区（kuna-base / kuna-num / kuna-sleigh / kuna-slacomp）
sleigh_specs/            # x86-64 .sla / .pspec / .cspec 处理器规格文件
examples/                # 端到端示例（curl_decompile / httpd_decompile / gen_decompile / parallel_decompile 等）
tests/                   # 单元测试、golden 语料与双侧 oracle 差分 fixture
benches/                 # 性能基准测试
tools/                   # 差分比对、语法审计、门禁校验与 oracle 运行脚本
docs/                    # API 文档、任务看板（TODO_BOARD.md）与对齐审计报告
```

---

## 与相关项目的区别

| 维度 | Rudra | Ghidra（`decompile/cpp`） | angr / RetDec |
|---|---|---|---|
| 实现语言 | 纯 Rust | C++ | Python / C++ |
| SLEIGH 解码 | 内置纯 Rust（`kuna-sleigh`） | 原生 C++ | 自研 IR / LLVM IR |
| 与 Ghidra 语义关系 | 逐函数对拍验证的 1:1 移植 | 本体 | 独立算法，语义不同源 |
| 正确性验证 | 锁定 Oracle 多层差分门禁 | 自身即 Oracle | 各自测试集 |
| 使用形态 | 可嵌入 Rust 库 + CLI 示例 | 桌面逆向套件 | 分析框架 / 工具链 |

---

## 项目状态

**活跃开发中**（截至 2026-10-03，`master` @ MB101），当前在锁定 Ghidra 12.0.4 Oracle 下的实测门禁状态：

| 验证维度 | 当前结果 |
|---|---|
| Canon 双语素端到端对齐 | `curl` **124/124**、`httpd` **34/34** 全部 `skeleton=0 / defects=0 / numbering=0` |
| 镜面五面全量门禁 | `curl` (0/74) · `httpd` (0/29) · `vsh` (0/71) · `sq` (0/810) · `sqlite` (0/1385) — **0/0/0/0/0 全 PASS** |
| 投影银行（Projection Bank） | **391 / 391 MATCH** |
| 单元测试（`cargo test --lib`） | **2,062 passed / 0 failed**（5 ignored，含 `PcodeOpTree` 4000 轮不变式 fuzz） |

当前聚焦于**保持行为零位移前提下的性能优化**（如 `ActionMarkImplied` 遍历收敛、`PcodeOpTree` 树序后继链接等）。暂不包含 Ghidra GUI 功能，多架构支持仍在规划中。

详细进度与文档索引：
- 质量与指标快照：[CURRENT_STATUS.md](CURRENT_STATUS.md)
- 模块级对齐路线图：[ALIGNMENT_ROADMAP.md](ALIGNMENT_ROADMAP.md) & [ALIGNMENT_PROGRESS.md](ALIGNMENT_PROGRESS.md)
- 差距分析与模块映射：[GAP_ANALYSIS.md](GAP_ANALYSIS.md) & [RUDRA_GHIDRA_MAPPING.md](RUDRA_GHIDRA_MAPPING.md)
- 活动任务看板：[docs/TODO_BOARD.md](docs/TODO_BOARD.md)

---

## 参与开发

本项目通过严格的自动化门禁守护对齐纪律：修改任何核心算法前需先阅读对应 Ghidra 源码，提交钩子会校验 `// Ghidra:` 源位置注释与对齐证据块，关键模块改动需经过独立交叉复核。完整开发规范请阅读 [AGENTS.md](AGENTS.md)。

## License

本项目采用 [Apache License 2.0](LICENSE) 开源。关于 Ghidra 衍生溯源及第三方 crate 归属声明详见 [NOTICE](NOTICE)。
