# Edit-Before-Read Alignment Hook（铁律 1.2 / 机制 E）

> **目的**: 强制执行 AGENTS.md 铁律 1.2 / 机制 E —— "修改一个函数的代码前, 必须重新先看
> 对应的 Ghidra 函数代码"。防止 agent "声称对齐但实际没读对应行" 的自欺
> (2026-07-02 `181538f` 事故的根因模式)。

## 机制概览

四层强制, 互为冗余:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1 (运行时, 主): PreToolUse hook on Edit|Write|MultiEdit  │
│   .zcode/align_gate.py                                          │
│   编辑 src/*.rs 前拦截: 该 fn 的 // Ghidra: file:line 引用必须   │
│   有"本 session 读过"的回执, 否则 deny (exit 2).                │
│   函数范围由 tools/rust_fn_scanner.py 与 commit checker 共用。   │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2 (自动回执): PostToolUse hook on Read                    │
│   .zcode/record_receipt.py                                      │
│   agent 每读一个 Ghidra cpp 源文件, 自动写入回执到               │
│   .alignment_receipts.json (key=ghidra相对文件名, val=ts+ranges) │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3 (commit 兜底): versioned Git hooks                     │
│   .githooks/pre-commit → health/doc-sync/annotations/          │
│   strict refs(def-start)/corpus-markers                        │
│   .githooks/commit-msg → Alignment Evidence 4/4                │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4 (最终信任边界): CI                                     │
│   sparse checkout 锁定 e40ed130 oracle 后重复全部静态门禁        │
└─────────────────────────────────────────────────────────────────┘
```

## 配置位置 (逆向 ZCode 二进制确认)

ZCode CLI 的项目级 hook 配置在 **`<project>/.zcode/config.json`** (不是
`settings.json`!)。schema (来自 `app.asar` `out/host/index.js`):

```jsonc
{
  "hooks": {
    "enabled": true,                    // 顶层总开关, 必须为 true
    "events": {
      "PreToolUse": [                   // 支持的事件: SessionStart,
        {                               //   UserPromptSubmit, PreToolUse,
          "matcher": "Edit|Write|MultiEdit",  //  PermissionRequest,
          "hooks": [                    //   PostToolUse, PostToolUseFailure,
            {                           //   Stop
              "type": "process",        // ← 注意: "process", 非 "command"
              "command": "python3",
              "args": ["${ZCODE_PROJECT_DIR}/.zcode/align_gate.py"]
            }
          ]
        }
      ]
    }
  }
}
```

**关键差异 (与 Claude Code 原版)**:
- 文件名是 `config.json` (zcode source) 或 `settings.json` (legacy/claude source)
- ZCode 格式 hook 条目用 `type: "process"`, Claude 格式用 `type: "command"`
- 事件放在 `hooks.events.<EventName>` (zcode) 或 `hooks.<EventName>` (legacy)
- `command` 只能是 executable，脚本和参数必须分别放入 `args[]`
- `${ZCODE_PROJECT_DIR}` 由 ZCode 展开，禁止硬编码 Windows 或个人目录
- 当前 ZCode 二进制只用 `startup` 与 `resume` 作为 SessionStart source；项目配置的
  matcher 必须是 `startup|resume`，不能填写并不存在的 `clear`/`compact` source

## Hook 输入/输出契约 (逆向 zcode.cjs 确认)

### stdin payload (PreToolUse on Edit)
```json
{
  "hook_event_name": "PreToolUse",
  "session_id": "sess_...",
  "tool_name": "Edit",
  "tool_input": { "file_path": "...", "old_string": "...", "new_string": "..." },
  "tool_use_id": "...",
  "cwd": "...",
  "timestamp": "..."
}
```

### 阻断编辑 (deny) —— 两种等价方式
1. **stdout JSON** (结构化, 推荐):
   ```json
   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
     "permissionDecision":"deny",
     "permissionDecisionReason":"...原因..."}}
   ```
2. **exit code 2 + stderr 文本** (兜底, `Gcn()` in zcode.cjs 会把 stderr
   文本当作 deny 原因): 最可靠, 即使 JSON 路径不被 honoring 也能阻断。

`align_gate.py` 两种都发 (belt-and-suspenders)。

## 回执新鲜度语义

- **edit-cycle 级**: receipt 必须晚于 session start，也必须不早于该函数上次
  gate 成功的时间戳；再次编辑同一函数前要重新读对应 oracle。这样既阻止
  跨 session 复用旧记忆，也阻止一次 read 被无限复用。
- `.alignment_session_start` 文件由 SessionStart hook (`align_gate.py --session-start`)
  打时间戳。回执 ts 必须 >= 该时间戳才算 fresh。
- 若 PostToolUse hook 未生效 (旧 session), agent 可手动
  `python3 .zcode/record_receipt.py coreaction.cc 4886 4960` 补回执
  (形态: `<ghidra_file> [<line_start> [<line_end>]]; 本机无 `python` 别名, 用 `python3`)。

## 跨根编辑语义（GATE-WORKTREE-ROOTMISMATCH-0001）

hook 根（由脚本自身位置推导的 ROOT）与被编辑文件所在仓不一致时（典型形态：协调者
会话的项目目录=主仓，派生的子 Agent 在 worktree 中编辑 `src/*.rs`，主仓 hook 收到
worktree 文件路径），gate **不再静默放行**，按以下顺序处理：

1. 用被编辑文件所在目录解析 `git rev-parse --show-toplevel`（清洗
   `GIT_DIR`/`GIT_WORK_TREE` 等劫持变量，清洗清单与
   `tools/check_gate_health.py` 的 GATE-WORKTREE-GITDIR-0001 一致）；
2. 若文件相对该 toplevel 是 `src/*.rs`，则以该 toplevel 作为 gate root：
   回执文件、session 起始戳、ghidra 路径全部改锚定到该 toplevel（worktree 的
   `ghidra` 是 symlink，`resolve()` 归一化后与 worktree 本地 hook 行为一致），
   照常按该仓自己的回执判定 allow/deny —— 跨根时门禁**正确工作**，而非一律拒绝；
3. 仍无法解析出任何 repo root 且路径形态可疑（含 `/src/` 组件且以 `.rs` 结尾）
   → **fail-closed**：deny 并输出
   “hook 根与文件根不一致且无法解析 toplevel”，提示改在文件所属仓的会话中编辑；
4. 跨根的非 src 文件（如别的仓的 docs）照旧不 gate；`ZCODE_ALIGN_GATE=0` 逃生阀
   与既有日志行为不变；文件就在 hook ROOT 下的主流程行为不变。

`.zcode/align_gate.log` 中的 `CROSS-ROOT rebase ...`（成功重锚定）与
`DENY cross-root-unresolved ...`（fail-closed）条目即该分支的运行痕迹。
`--self-test` 内含跨根用例（`TemporaryDirectory` + 临时 git 仓模拟 worktree 布局，
不触碰真实 worktree），CI 的 `--self-test` 步骤随之覆盖；
`tools/check_gate_health.py` 对 rebase/fail-closed 分支做静态断言。

## 哪些 fn 会被 gate

`align_gate.py` 对**受编辑影响的 src/*.rs fn**, 找其 Ghidra 对应位置:
1. fn 上方注释块的规范 `// Ghidra: <file>:<line> <fn>` 标注; 或
2. fn body 内首个 `// ... <file>.<cc|hh>:<digits> ...` 内联引用
   (覆盖本代码库的 `(coreaction.cc:4886)` 风格, 302 处)。

无任何 Ghidra 引用的 fn → 不 gate (由 `check_ghidra_annotations.py`
在 commit 时强制要求加注释)。`// RUDRA-GLUE:` 标注的 fn → 豁免。

## pre-commit 的 refs 门禁语义（TOOLS-REFS-DEFSTART-0001，2026-09-26 REFSDEF lane 更新）

版本化 `.githooks/pre-commit` 的 refs 检查行固定运行：

```bash
python3 "$REPO_ROOT/tools/check_ghidra_refs.py" --all --strict || exit $?
```

REFSDEF 车道（commits `9aa565ec`+`ba3f2dc8`）之后，该检查是**两段语义**：

1. **存在性（所有引用形态）**：任何注释里的 `<file>.cc|hh|h :<digits>` 引用，文件
   必须在锁定 oracle cpp 树内且行号不越界（旧语义，保持不变）；
2. **定义起始行验证（def-start，新语义）**：头注解
   `// Ghidra: <file>.cc:<line> <fn>` 中 `<fn>` 若在锁定 oracle 的 `<file>` 定义表
   内可解析，cited line 必须是 `<fn>` 的**函数定义起始行**——漂移引用（指向调用点、
   函数体中部、旧 oracle 行号）不再能通过"行号恰好在文件内"的旧检查。

**豁免（脚本计数、不阻塞）**：`.hh`/`.h` 引用保持存在性检查（声明/内联文档惯例）；
`<fn>` 在被引文件解析不出（类名级代表行、.hh 内联访问器、跨文件调用点引用）→ 计入
`unresolved` 桶，不算 drift。解析器形态（强制分隔符 + 裸 ctor/析构/operator/模板
分支 + 调用行/doc 行/关键字返回类型排除）详见 `tools/check_ghidra_refs.py` 头部
docstring；未来任何 citation 批量工具必须沿用该形态。

**摸底命令**（不阻塞，两种结论下都附普查块）：

```bash
python3 tools/check_ghidra_refs.py --all --strict --defstart-report
```

输出五项计数：existence problems / def-start checked / ok / DRIFT /
unresolved(exempt)，DRIFT 非零时附 per-file 明细。健康树长相示例（2026-09-26 亲测，
基 `d0e27c14`）：checked 3782 / DRIFT 0 / unresolved 823。注意该工具**没有
`--help`**——不认识的参数被忽略后直接执行检查（只有 `.rs` 结尾参数被当作文件），
查参数请读脚本头。

pre-commit 其余检查行（同一 hook 内，顺序执行）：`check_gate_health.py` →
`check_doc_sync.py --staged` → `check_ghidra_annotations.py --all` → 上面的 refs
行 → `check_corpus_markers.py --all`（AUDIT-CORPUS-MARKERS-GATE-0001，库生产代码
零语料标记防复发门禁）。任一非零即拒绝提交。

## 安装与验证

```bash
git config core.hooksPath .githooks
python3 tools/check_gate_health.py
python3 tools/rust_fn_scanner.py
python3 tools/check_ghidra_annotations.py --self-test
python3 .zcode/align_gate.py --self-test
python3 tools/check_ghidra_annotations.py --all
python3 tools/check_ghidra_refs.py --all --strict
python3 tools/check_ghidra_refs.py --all --strict --defstart-report   # 摸底普查（不阻塞）
python3 tools/check_alignment_evidence.py --self-test
```

所有命令必须 exit 0 才能宣称门禁健康。CI 会从 NSA 仓库 sparse checkout
精确 commit `e40ed13014025f82488b1f8f7bca566894ac376b`，再重复这些检查；本地
hook 不是最终信任边界。

## 紧急逃生

`ZCODE_ALIGN_GATE=0` 环境变量仅用于已登记的门禁自身修复，必须在 TODO 和
提交证据中记录理由。禁止把 `git commit --no-verify` 当作正常工作流。

## ⚠ 重要: 配置仅在新 session 加载

ZCode 在 **session 创建时** 加载 `.zcode/config.json` (一次)。若在 session
中途添加/修改 hook 配置, **当前 session 不会生效**, 必须重启 session。
现行二进制会以 `startup` 或 `resume` source 触发 SessionStart，并重新写入
session 起始时间戳；它没有 `clear`/`compact` source。

验证 hook 已加载: 重启后做一次 src/*.rs 编辑, 若被 deny (且你没读对应
Ghidra), 即生效; 也可查 `.zcode/align_gate.log` 是否有新条目。

## 文件清单

| 文件 | 作用 |
|---|---|
| `.zcode/config.json` | hook 配置 (PreToolUse + PostToolUse + SessionStart) |
| `.zcode/align_gate.py` | PreToolUse gate + SessionStart 打戳 |
| `.zcode/record_receipt.py` | PostToolUse 自动回执 + 手动补回执 |
| `tools/rust_fn_scanner.py` | checker 与 edit hook 共用的 Rust 函数范围扫描器 |
| `.alignment_receipts.json` | 回执存储 (gitignore, 不入库) |
| `.alignment_session_start` | session 起始时间戳 |
| `tools/check_gate_health.py` | 锁定 oracle、hook mode/path、ZCode schema 自检 |
| `tools/check_ghidra_refs.py` | commit/CI 时全库 strict 引用校验（存在性 + REFSDEF 定义起始行验证；`--defstart-report` 摸底） |
| `tools/check_alignment_evidence.py` | commit-msg Evidence 4/4 严格校验 |
| `.githooks/pre-commit` | health/doc-sync/annotation/strict-ref(def-start)/corpus-marker 门禁 |
| `.githooks/commit-msg` | Alignment Evidence 门禁 |
| `.github/workflows/alignment-gates.yml` | 版本化 CI 最终信任边界 |
