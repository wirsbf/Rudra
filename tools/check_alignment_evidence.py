#!/usr/bin/env python3
"""
check_alignment_evidence.py — AGENTS.md 机制 A 的 commit-msg 门禁脚本。

扫描 commit message，若命中 align/port/对齐/faithful 关键词，
强制要求 message 体包含一个 `## Alignment Evidence` 块，
否则拒绝提交（机制 A：对齐证据块）。

判定逻辑:
  1. message 首行或正文含触发词 (align/port/对齐/faithful, 大小写不敏感)
     且改动声称是对齐 Ghidra → 触发检查
  2. 触发后, 必须找到 `## Alignment Evidence` 标题
  3. 该块必须逐项填写四类决定性语义，并包含四项全部勾选的固定核对行。
     模糊关键词、3/4 项、TODO/N/A/"未核对"均拒绝。

退出码:
  0 — 通过 (或未触发检查)
  1 — 拒绝 (命中触发词但缺证据块)

本地安装：`.githooks/commit-msg` 已版本化；运行
`git config core.hooksPath .githooks` 启用。hook 使用仓库根目录和
`python3`，不依赖个人路径。

用法 (独立调用, 不需安装为 hook):
  python tools/check_alignment_evidence.py <commit_msg_file>
  python tools/check_alignment_evidence.py --inline "align: port X"
"""
import re
import sys
from pathlib import Path

# 触发词: message 含这些词之一即视为"声称对齐 Ghidra"
TRIGGER_RE = re.compile(
    r'\b(align|aligned|aligns|alignment|port|ported|porting|faithful)\b',
    re.IGNORECASE,
)
TRIGGER_CN = re.compile(r'(对齐|移植)')

REQUIRED_SECTIONS = [
    ('引用/输出参数', re.compile(r'^\s*-\s*引用/输出参数\s*:\s*(\S.*)$', re.MULTILINE)),
    ('循环边界/遍历顺序', re.compile(r'^\s*-\s*循环边界/遍历顺序\s*:\s*(\S.*)$', re.MULTILINE)),
    ('计数器/累加器', re.compile(r'^\s*-\s*计数器/累加器\s*:\s*(\S.*)$', re.MULTILINE)),
    ('排序/比较键', re.compile(r'^\s*-\s*排序/比较键\s*:\s*(\S.*)$', re.MULTILINE)),
]
INVALID_EVIDENCE = re.compile(r'(^|\W)(TODO|TBD|N/?A|UNKNOWN)($|\W)|未核对|待核对|占位', re.I)
GHIDRA_LINE = re.compile(r'^Ghidra:\s+\S+\.(?:cc|hh):\d+\s+\S.*$', re.MULTILINE)
# AGENTS.md 机制 A 模板是 `Rugra: <file>:<line> <对应函数>`，未限定 src/；
# 仓库内 Ghidra 语义的 Rust 代码还包括 examples/ 驱动（如 curl_decompile.rs
# 的 oracle 语义 port），因此接受 src/ 与 examples/ 两种路径形态。
RUDRA_LINE = re.compile(r'^Rugra:\s+(?:src|examples)/\S+\.rs:\d+\s+\S.*$', re.MULTILINE)
CHECKLIST_ITEMS = ('引用参数', '遍历顺序', '计数器', '排序键')


def message_triggers_alignment(msg: str) -> bool:
    """message 是否声称对齐 Ghidra (触发机制 A)。"""
    return bool(TRIGGER_RE.search(msg) or TRIGGER_CN.search(msg))


def extract_evidence_block(msg: str) -> str:
    """提取 `## Alignment Evidence` 块正文; 不存在则返回 ''."""
    # 匹配 ## Alignment Evidence 到下一个 ## 标题或消息末尾
    m = re.search(
        r'^##\s*Alignment Evidence\s*$(.*?)(?=^##\s|\Z)',
        msg, re.MULTILINE | re.DOTALL,
    )
    return m.group(1) if m else ''


def validate_evidence_block(block: str) -> tuple[bool, str]:
    """严格验证 Evidence 块的结构和四项显式核对。"""
    if not GHIDRA_LINE.search(block):
        return False, '缺少 `Ghidra: <file>:<line> <完整签名>` 行。'
    if not RUDRA_LINE.search(block):
        return False, '缺少 `Rugra: src/<file>.rs:<line> <对应函数>` 或 `Rugra: examples/<file>.rs:<line> <对应函数>` 行。'

    for label, pattern in REQUIRED_SECTIONS:
        match = pattern.search(block)
        if not match:
            return False, f'缺少 `- {label}: ...` 决定性语义。'
        detail = match.group(1).strip()
        if len(detail) < 4 or INVALID_EVIDENCE.search(detail):
            return False, f'`{label}` 内容为空、占位或明确未核对。'

    checklist = next(
        (line for line in block.splitlines() if line.strip().startswith('四类决定性语义核对:')),
        '',
    )
    if not checklist:
        return False, '缺少 `四类决定性语义核对:` 固定核对行。'
    missing = [
        label for label in CHECKLIST_ITEMS
        if re.search(rf'\[x\]\s*{re.escape(label)}\b', checklist, re.I) is None
    ]
    if missing:
        return False, f'四类核对未全部勾选: {", ".join(missing)}。'
    return True, '四类决定性语义 4/4 显式填写并勾选。'


def check_message(msg: str) -> tuple[bool, str]:
    """
    返回 (ok, reason)。
    ok=True 表示通过门禁; ok=False 给出拒绝理由。
    """
    if not message_triggers_alignment(msg):
        return True, '(未触发对齐检查: message 无 align/port/对齐 关键词)'

    block = extract_evidence_block(msg)
    if not block:
        return (
            False,
            '机制 A 违反: commit message 声称对齐 Ghidra (含 '
            'align/port/对齐/faithful), 但缺少 `## Alignment Evidence` 块。\n'
            '请在 message 体补上证据块, 逐字摘录 Ghidra 关键行签名, '
            '并核对四类决定性语义:\n'
            '  1. 引用/输出参数 (&/*, 是否跨调用共享)\n'
            '  2. 循环边界与遍历顺序 (容器, 排序键, 边界)\n'
            '  3. 计数器/累加器 (初值, 增量时机, per-X 还是全局)\n'
            '  4. 排序/比较键 (compare 字段, tie-break)\n'
            '格式见 AGENTS.md 机制 A。',
        )

    valid, detail = validate_evidence_block(block)
    if not valid:
        return False, f'机制 A 违反: `## Alignment Evidence` 不完整。\n{detail}'
    return True, f'(机制 A 通过: {detail})'


def self_test() -> int:
    valid = '''align: port Foo\n\n## Alignment Evidence\nGhidra: foo.cc:10 void Foo::bar(int4 &out)\n  关键决定性语义（四类，逐条核对）:\n  - 引用/输出参数: out 由引用写回并跨调用共享。\n  - 循环边界/遍历顺序: 顺序遍历 vector 的 begin() 到 end()。\n  - 计数器/累加器: count 初值 0，在成功写出后递增。\n  - 排序/比较键: 不排序，保留 vector 插入顺序。\nRugra: src/foo.rs:20 fn bar\n  - 使用 &mut 输出并保持相同更新时机。\n四类决定性语义核对: [x]引用参数 [x]遍历顺序 [x]计数器 [x]排序键\n'''
    three_of_four = valid.replace(' [x]排序键', '')
    negative = valid.replace('out 由引用写回并跨调用共享。', '未核对')
    examples_path = valid.replace('Rugra: src/foo.rs:20 fn bar', 'Rugra: examples/curl_decompile.rs:948 fn check_characters_utf8')
    cases = [
        ('ordinary commit', True),
        ('align: port Foo', False),
        (valid, True),
        (three_of_four, False),
        (negative, False),
        (examples_path, True),
    ]
    failed = []
    for index, (message, expected) in enumerate(cases, 1):
        actual, reason = check_message(message)
        if actual != expected:
            failed.append(f'case {index}: expected {expected}, got {actual}: {reason}')
    if failed:
        print('\n'.join(failed), file=sys.stderr)
        return 1
    print('check_alignment_evidence: self-test OK (6 cases, strict 4/4)')
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == '--self-test':
        return self_test()
    if len(argv) >= 2 and argv[1] == '--inline':
        if len(argv) < 3:
            print('用法: --inline "<commit message>"', file=sys.stderr)
            return 2
        msg = argv[2]
    elif len(argv) >= 2:
        # commit-msg hook 调用: argv[1] = 临时消息文件路径
        msg = Path(argv[1]).read_text(encoding='utf-8', errors='replace')
    else:
        print('用法: check_alignment_evidence.py <commit_msg_file>', file=sys.stderr)
        print('      check_alignment_evidence.py --inline "<message>"', file=sys.stderr)
        return 2

    ok, reason = check_message(msg)
    if ok:
        # 静默通过 (或给提示到 stderr, 不污染 commit)
        print(f'[机制A] {reason}', file=sys.stderr)
        return 0
    else:
        print(f'[机制A 拒绝提交]\n{reason}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
