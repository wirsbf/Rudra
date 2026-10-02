# Rudra 🦀

**Ghidra 反编译器的 Rust 移植** —— 把 NSA Ghidra 的反编译核心(`decompile/cpp`,纯 C++)忠实搬到 Rust,并以"锁定同版本 Ghidra、同输入同输出"的差分测试作为唯一正确性标准。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Ghidra](https://img.shields.io/badge/oracle-Ghidra%2012.0.4-e94f37.svg)](docs/VERIFICATION_GUIDE.md)

---

## 为什么做这个

Ghidra 的反编译器是一份教科书级的 C++ 代码库——SSA 构造、值域分析、控制流结构化、类型恢复,四十万行沉淀。但它不易嵌入、不易实验、没有内存安全保证,而且行为难以验证。

Rudra 的目标:**算法层 1:1 移植,工程层现代化**。每一处实现都标注它对应的 Ghidra 源码位置(`// Ghidra: varmap.cc:1263 buildDynamicName`),并用自动化差分门禁证明"Ghidra 在同样输入下产出同样的东西"。移植就是理解——当你能把 jumptable 恢复或 conditional-execution 消除逐行复刻并被 oracle 验证时,才算真的读懂了它。

适合:反编译研究、PL 课程参考、嵌入式静态分析基座、以及对"老牌 C++ 项目如何安全演进"感兴趣的人。

## 特性

- **真实 SLEIGH 提升链**:直接消费 Ghidra 编译的 `.sla` 处理器规格与 `.cspec` 调用约定,指令语义与 Ghidra 同源,目前支持 x86-64
- **完整的 Action/Rule 反编译管线**:Ghidra `universalAction` 的嵌套树(universal → fullloop → mainloop → stackstall)与三个规则池(150 条 Rule)按原注册序重建
- **算法全家桶**:SSA/Heritage、值域分析(CircleRange)、控制流结构化(TraceDAG/collapse 族)、参数与类型恢复(varmap/ScopeLocal)、变量合并(merge 族)、C 伪代码生成(PrintC 协议)
- **三位一体差分验证**:锁定 oracle 指纹 → 119 个双侧逐字节 fixture → 全语料端到端 golden 门禁;任何漂移 fail-closed,状态如实登记(UNTESTED 不冒充 MATCH)
- **确定性输出**:同输入同输出,无时间/哈希序依赖

## 演示

反编译一个真实的 curl 函数,输出与 Ghidra 逐字节一致:

```c
// $ cargo run --release --example curl_decompile   |  sed -n '/GetStr/,/^}/p'
void GetStr(char **string,char *value)
{
  char *pcVar1;
  if (*string != (char *)0x0) {
    free(*string);
  }
  if ((value != (char *)0x0) && (*value != '\0')) {
    pcVar1 = strdup(value);
    *string = pcVar1;
    return;
  }
  *string = (char *)0x0;
  return;
}
```

## 快速开始

构建需要锁定版本的 Ghidra 源码树（SLEIGH 引擎经 FFI 编译 + 对齐锚点校验）：

```bash
git clone https://github.com/wirsbf/Rudra.git
cd Rudra
# 侧车方式放置锁定 oracle(build.rs 会校验 commit):
git clone https://github.com/NationalSecurityAgency/ghidra ghidra-src
git -C ghidra-src checkout e40ed13014025f82488b1f8f7bca566894ac376b
ln -s "$(pwd)/ghidra-src" ghidra

cargo build --release

# 反编译整个 curl 二进制(124 个函数)
cargo run --release --example curl_decompile > result.c

# 反编译 httpd
cargo run --release --example httpd_decompile

# 单元测试 + 单函数门禁
cargo test --lib
python3 tools/compare_ghidra.py result.c tests/golden/ghidra_curl_1204.c --summary-only
```

运行双侧差分 fixture(需要本机可编译锁定 Ghidra,见 [docs/VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md)):

```bash
bash tools/run_transform_multiequal_insert_oracle.sh
```

## 工作原理

```
 ELF            SLEIGH .sla/.cspec             锁定 Ghidra 12.0.4 (ghidra/)
  │                    │                              │
  ▼                    ▼                              ▼
binary/ ──► disasm/ ──► P-code IR ──► Action 管线 ──► C 伪代码
 (goblin)   (x86_lift)  (Varnode/     (Heritage/SSA,      ▲
                          PcodeOp)     结构化,规则池,      │
                                       类型/变量恢复)      │
                                            │              │
                                            └── 差分门禁 ──┘
                                                (fixture + golden)
```

核心模块与 Ghidra 源文件一一对应(`src/varmap.rs` ↔ `varmap.cc`、`src/blockaction.rs` ↔ `blockaction.cc`……),模块状态与逐函数账本见 [ALIGNMENT_ROADMAP.md](ALIGNMENT_ROADMAP.md)。

## 与相关项目的区别

| | Rudra | Ghidra(反编译核心) | angr / RetDec |
|---|---|---|---|
| 语言 | Rust | C++ | Python/C++ |
| 与 Ghidra 语义关系 | 逐函数对拍验证的移植 | 本体 | 自研算法,语义不同源 |
| 验证方式 | 锁定 oracle 双侧差分 | 自身即 oracle | 各自测试集 |
| 形态 | 可嵌入库 + CLI 示例 | 桌面套件 | 框架/工具链 |

## 项目状态

**Alpha,活跃开发中。** 以函数级差分为准的当前硬数字(锁定 Ghidra 12.0.4 oracle,双双 defects=0/numbering=0):

| 指标 | 数值 |
|---|---|
| curl 语料骨架残差 | **1438 行(wave 起点 3718,−61.3%)** |
| httpd 语料骨架残差 | **1447 行(wave 起点 3576,−59.5%)** |
| 管线全程投影 MATCH 函数 | **5 个**(next_url/match_url/parseconfig/myprogress/getparameter,每阶段 IR 逐字节==oracle) |
| 文本逐字节零差函数 | curl 59/124(httpd 6/32) |
| 双侧投影 fixture 银行 | 5 函数 pin 入库 + `tools/verify_projection_bank.sh` 门禁 runner |

当前不支持 Ghidra GUI 功能与多架构(架构层已为多处理器留位);全局完成度未宣称(函数账本见 alignment_audit)。

- 模块级进度:[ALIGNMENT_ROADMAP.md](ALIGNMENT_ROADMAP.md)
- 活动任务看板:[docs/TODO_BOARD.md](docs/TODO_BOARD.md)
- 质量快照:[CURRENT_STATUS.md](CURRENT_STATUS.md)

## 参与开发

本项目用严格的门禁守护对齐纪律:改任何函数前必须先读对应 Ghidra 源码、提交钩子校验源位置注释与对齐证据块、核心算法改动需独立交叉复核。规则全文见 [AGENTS.md](AGENTS.md)。

## License

Apache-2.0
