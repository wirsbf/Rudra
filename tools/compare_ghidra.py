#!/usr/bin/env python3
"""
compare_ghidra.py — Rugra vs Ghidra 反编译输出的多维度结构化对比。

替代旧的 if/while 计数对比（计数相同 ≠ 结构对齐，且检测不到真实缺陷）。
本工具做两类对比:

  1. 归一化结构骨架 diff (normalize_skeleton)
     把变量名/字面量归一化为占位符后, 比较控制流骨架。屏蔽命名差异, 露出:
       - 空 else {} 块 (Rugra CFG 不完整的典型症状)
       - 丢失的函数调用 (如 strdup/fwrite 在 Rugra 输出里缺失)
       - 寄存器泄漏 (RAX_1738/EAX_1743 等, Ghidra 不会泄漏)
       - 真实结构差异 (循环拆分、goto vs return)

  2. 变量名编号连续性检查 (check_numbering_continuity)
     不比较 Rugra iVar1 == Ghidra iVar1 (两套坐标系不重叠: Rugra=StackX_N,
     Ghidra=类型化连续编号), 只验证 "单一共享计数器" 这一不变量: Ghidra
     buildVariableName 用单一共享 int4 base, 所有前缀共用, 故函数内所有声明
     变量的编号集合应近似稠密且 max(num) ≈ 声明总数。直接检测 181538f 类 bug
     (per-prefix 各自从 1 计数 → 大量小数字重复, max(num) << 声明总数)。
     只统计声明行 (`  <type> <name>;`), 不统计表达式中的使用。

为什么不用计数: 计数是极度有损投影。for↔while 等价变换时计数不同但结构对齐;
Rugra 空 else{} + 调用丢失时计数可能凑巧相同但结构完全不对齐。

用法:
    python tools/compare_ghidra.py result/curl_cur.c result/ghidra_curl_ref.c
    python tools/compare_ghidra.py <rugra.c> <ghidra.c> [--base 0xOFFSET] \\
        [--func NAME] [--mode skeleton|numbering|all]
"""
import argparse
import difflib
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 解析: 从反编译输出提取函数 (两边格式相同: /* ---- 0xADDR: NAME (SIZE bytes) ---- */)
# ---------------------------------------------------------------------------

HEADER_RE = re.compile(
    r'/\* ---- 0x([0-9a-f]+): (\S+) \((\d+) bytes\) ---- \*/'
)
# GCC 优化后缀, Rugra 保留而 Ghidra 剥离
GCC_SUFFIX_RE = re.compile(r'\.(?:constprop|part|isra|llvm)\.[0-9]+')


def parse_functions(text):
    """提取函数: [(addr, name, size, body)]。跳过非函数头行(日志噪音)。"""
    funcs = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = HEADER_RE.match(lines[i])
        if m:
            addr = int(m.group(1), 16)
            name = m.group(2)
            size = int(m.group(3))
            body_lines = []
            j = i + 1
            while j < len(lines) and not HEADER_RE.match(lines[j]):
                body_lines.append(lines[j])
                j += 1
            funcs.append((addr, name, size, '\n'.join(body_lines)))
            i = j
        else:
            i += 1
    return funcs


def strip_gcc_suffix(name):
    """剥除 GCC 优化后缀 (.constprop.0/.part.0/.isra.0) 以便跨边匹配。"""
    return GCC_SUFFIX_RE.sub('', name)


def match_functions(rugra_funcs, ghidra_funcs, base_offset=0x100000):
    """
    匹配 Rugra 和 Ghidra 函数。优先用归一化地址, 备选函数名 (先精确名, 再 strip 后缀)。
    返回 [(addr, rugra_name, rugra_body, ghidra_name, ghidra_body)]。

    同名函数配对语义 (MCENSUS3-COMPARE-MISPAIR-CURL-0001):
      1. 地址探测链 (最强信号, 四探针代数不变, 见下);
      2. 完整函数名精确配对: 双侧携带同名后缀对 (如 SetHTTPrequest.part.0 +
         SetHTTPrequest) 时, 各自配到 oracle 同名对应物; 候选取 golden 文件序
         (即 oracle 输出序) 中首个未消费者;
      3. strip 后缀兜底配对 (跨边改名场景), 同样取首个未消费者。
    不变量: 每个 golden 函数至多被消费一次 (one-consumption)。旧版 by_name 是
    last-wins 字典, 双胞胎名 (strip 后同 key) 会双配到后出现的那个 golden,
    另一个 golden (如 golden SetHTTPrequest.part.0, 与 rugra 同名函数恒等)
    从未被比较, 同时给先到的 rugra 函数制造幻影 diff 行 (curl 镜面 6 行伪差)。
    """
    by_addr = {}
    by_exact = {}
    by_name = {}
    for addr, name, size, body in ghidra_funcs:
        norm_addr = addr - base_offset
        by_addr[norm_addr] = (name, body)
        by_exact.setdefault(name, []).append((norm_addr, name, body))
        by_name.setdefault(strip_gcc_suffix(name), []).append((norm_addr, name, body))

    matched = []
    used_keys = set()  # 已消费 golden 的 norm_addr 键 (one-consumption)

    def take_addr(probe_key):
        """地址探针: 命中未消费的 golden 则消费并返回, 否则 None。"""
        if probe_key in used_keys:
            return None
        g = by_addr.get(probe_key)
        if g is not None:
            used_keys.add(probe_key)
        return g

    for addr, name, size, body in rugra_funcs:
        # Probe algebra (base = base_offset, keys stored as golden_addr - base):
        #   G1 golden image-based / R2 rugra base-0  -> probe 1 (addr == key)
        #   G1 golden image-based / R1 rugra image  -> probe 2 (addr-base == key)
        #   G2 golden base-0     / R2 rugra base-0  -> probe 2 (both negative keys)
        #   G2 golden base-0     / R1 rugra image  -> probe 4 (addr-2*base == key),
        #     the direct-runner mirror convention pair (golden headers base-0,
        #     Rugra mirror headers image-based). NB: with --base 0 (the official
        #     mirror-gate invocation) all four probes collapse to probe 1, so
        #     the G2/R1 pair resolves via the name path below — which is why
        #     the name path must carry the same one-consumption + exact-name
        #     semantics as the address path (probe 4 alone cannot fix it).
        # Probe 4 is a provable no-op for the other three combos (its key is
        # either negative where G1 keys are >= 0, or off by one base), so
        # existing pairings cannot drift.
        ghidra = (take_addr(addr) or take_addr(addr - base_offset)
                  or take_addr(addr + base_offset)
                  or take_addr(addr - 2 * base_offset))
        if ghidra is None:
            # 精确完整名 → strip 后缀, 依次取 golden 文件序首个未消费者。
            for candidates in (by_exact.get(name, ()),
                               by_name.get(strip_gcc_suffix(name), ())):
                for norm, gname, gbody in candidates:
                    if norm not in used_keys:
                        used_keys.add(norm)
                        ghidra = (gname, gbody)
                        break
                if ghidra is not None:
                    break
        if ghidra:
            matched.append((addr, name, body, ghidra[0], ghidra[1]))
    return matched


# ---------------------------------------------------------------------------
# 规范化: 剥离格式噪音, 归一化为结构骨架
# ---------------------------------------------------------------------------

# Rugra 独有噪音
RUGRA_TYPEDEF_RE = re.compile(r'^\s*typedef\b.*;$', re.MULTILINE)
RUGRA_EXTERN_RE = re.compile(r'^\s*extern\b.*;$', re.MULTILINE)
RUGRA_BANNER_RE = re.compile(r'^===.*===\s*$', re.MULTILINE)
# 裸寄存器泄漏 (Ghidra 永不泄漏, 出现即缺陷)
REGISTER_LEAK_RE = re.compile(
    r'\b(?:RAX|R BX|RCX|RDX|RSI|RDI|RBP|RSP|R8|R9|R10|R11|R12|R13|R14|R15|'
    r'EAX|EBX|ECX|EDX|ESI|EDI|EBP|ESP)_\d+\b'
)
# 空块 (else {} 或 { })
EMPTY_BLOCK_RE = re.compile(r'\belse\s*\{\s*\}')
# StackX_N 裸栈偏移变量
STACKX_RE = re.compile(r'\bStackX_[0-9a-fA-F]+\b')
# Ghidra 独有噪音
GHIDRA_PTR_RE = re.compile(r'PTR_[A-Za-z0-9_]+')
GHIDRA_DAT_RE = re.compile(r'\bDAT_[0-9a-f]+\b')
GHIDRA_CODE_CAST_RE = re.compile(r'\(\s*code\s*\*\s*\)')
GHIDRA_LAB_RE = re.compile(r'\bLAB_[0-9a-f]+\b')

# 变量名归一化 (iVar1/lVar2/bVar3/config/param_1/StackX_0 → V)
VAR_RE = re.compile(
    r'\b(?:[a-z]Var\d+|param_\d+|StackX_[0-9a-fA-F]+|'
    r'[a-zA-Z_]\w*Var\w*|[a-z]{3,}Var\d+)\b'
)
# 字面量归一化
INT_LIT_RE = re.compile(r'\b\d+\b')
HEX_LIT_RE = re.compile(r'0x[0-9a-fA-F]+')
STR_LIT_RE = re.compile(r'"[^"]*"')


def strip_noise(body, side):
    """剥离格式噪音, 返回干净函数体。side='rugra'|'ghidra'。"""
    s = body
    s = RUGRA_TYPEDEF_RE.sub('', s)
    s = RUGRA_EXTERN_RE.sub('', s)
    s = RUGRA_BANNER_RE.sub('', s)
    if side == 'ghidra':
        s = GHIDRA_PTR_RE.sub('PTR', s)
        s = GHIDRA_DAT_RE.sub('DAT', s)
        s = GHIDRA_CODE_CAST_RE.sub('', s)
        s = GHIDRA_LAB_RE.sub('LAB', s)
    # 清理多余空行
    s = re.sub(r'\n\s*\n+', '\n', s)
    return s.strip()


def normalize_skeleton(body):
    """
    归一化为控制流骨架: 变量名→V, 字面量→LIT, 保留结构关键词和函数调用名。
    输出每行一个骨架 token, 供行级 diff。
    屏蔽命名差异, 露出空else/调用缺失/结构差异。
    """
    s = strip_noise(body, 'rugra')
    # 顺序: 先字符串(避免 hex 被部分匹配), 再 hex, 再十进制
    s = STR_LIT_RE.sub('"LIT"', s)
    s = HEX_LIT_RE.sub('LIT', s)
    # 函数调用名保留: 形如 name( 中的 name 不归一化
    # 先保护调用名, 归一化变量, 再恢复
    call_names = []

    def stash_call(m):
        call_names.append(m.group(1))
        return f'\x00CALL{len(call_names)-1}\x01('

    s = re.sub(r'\b([a-zA-Z_]\w*)\s*\(', stash_call, s)
    # 变量名 → V
    s = VAR_RE.sub('V', s)
    # StackX 也归一化 (上面 VAR_RE 已部分覆盖, 兜底)
    s = STACKX_RE.sub('V', s)
    # 剩余十进制字面量 → LIT
    s = INT_LIT_RE.sub('LIT', s)
    # 恢复调用名
    for i, cn in enumerate(call_names):
        s = s.replace(f'\x00CALL{i}\x01', cn)
    # 规范化空白
    s = re.sub(r'[ \t]+', ' ', s)
    s = re.sub(r'\s*\n\s*', '\n', s)
    return [line.strip() for line in s.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# 编号连续性检查 (181538f 直接检测器)
# ---------------------------------------------------------------------------

# 匹配 [a-z]Var 后跟数字 (iVar1/lVar2/bVar3/pcVar7...)。Ghidra 风格。
# 仅用于历史/外部引用; 编号检查现在只统计声明, 见 VARDECL_LINE_RE。
VARDECL_RE = re.compile(r'\b([a-z]+Var)(\d+)\b')

# 声明行: <缩进> <C 类型> <指针/空格>* <Var 名> (; | =)。
# 必须锚定到行首 + 要求 Var 名前有一个真正的 C 类型关键字, 这样:
#   - 表达式中的 *使用* (如 `return pcVar1;`, `if (bVar5)`, `sVar8 = ...`)
#     不会被误判为声明;
#   - `return pcVar1;` 里的 `return` 不是类型关键字 → 不匹配;
#   - 赋值 `sVar8 = ...;` 行首直接是名字(无类型) → 不匹配。
# 这是旧 checker 的核心 bug 修复: 旧版用 VARDECL_RE 扫整个函数体, 把
# 每一次 *使用* 当 *声明* 计数, 导致 Ghidra 的正确黄金输出也报 995 个问题。
_TYPE_TOKENS = (r'(?:unsigned\s+|signed\s+|const\s+)*'
                r'(?:char|short|int|long|float|double|bool|void|byte|'
                r'size_t|wchar_t|FILE|time_t|undefined\d*|_struct|'
                r'struct\s+\w+|enum\s+\w+)')
VARDECL_LINE_RE = re.compile(
    r'^[ \t]+' + _TYPE_TOKENS + r'(?:\s|\*)*\b([a-z]+Var)(\d+)\b\s*(?:;|=)',
    re.MULTILINE,
)


def check_numbering_continuity(body):
    """
    检查变量名编号连续性。返回 issues 列表。

    只统计**声明**(`  <type> <name>;` 行), 不统计表达式中的使用。旧版扫整个
    函数体把使用当声明, 导致单变量被引用 N 次就报 N 个 "duplicate" — 对
    Ghidra 正确输出也误报 995 个问题。

    检测的不变量 (181538f 类 per-prefix 计数 bug 的真实特征):
      - 重复声明: 同一全名 (prefix+num) 在一个函数里被声明两次 (Rugra/Ghidra
        正常都不该出现, 单变量只声明一次)。
      - 共享计数器: Ghidra buildVariableName 用单一共享 `int4 base`
        (database.cc:2850 assignDefaultNames), 所有前缀共用一个从 1 单调递增的
        计数器 → 函数内所有声明变量 (跨前缀) 的编号集合应近似稠密, 且
        max(num) ≈ 声明变量总数。181538f 错误是 per-prefix 各自从 1 计数 →
        大量小数字重复出现, max(num) << 声明总数。判据:
        声明数 >= 5 且 max(num) < 声明数 * 0.6 时报告 per_prefix_counter。

    不再检查 "per-prefix 文本序单调/无大跳号": 该启发式被声明字母序输出
    (Rugra BTreeMap) 干扰, 对正确编号也误报 (如 bVar27,bVar30,bVar4 在字母序
    下非单调, 但底层共享计数器完全正确)。共享计数器不变量更直接抓 181538f。

    返回 [{'prefix':..., 'type':..., 'detail':...}, ...]
    """
    issues = []
    # 收集声明 (按出现顺序), 同时跟踪重复
    decls = []  # [(prefix, num)] in declaration order
    seen = set()
    duplicate_reported = set()
    for m in VARDECL_LINE_RE.finditer(body):
        prefix, num = m.group(1), int(m.group(2))
        decls.append((prefix, num))
        key = (prefix, num)
        if key in seen and key not in duplicate_reported:
            issues.append({
                'prefix': prefix,
                'type': 'duplicate',
                'detail': f'{prefix}{num} declared twice',
            })
            duplicate_reported.add(key)
        seen.add(key)

    # 共享计数器不变量 (181538f 检测器)
    if decls:
        total = len(decls)
        max_num = max(n for _, n in decls)
        # 共享计数器: max_num 应接近 total (允许少量参数/跳号导致偏小)。
        # per-prefix 计数器: max_num 远小于 total。阈值 0.6 经验值, 区分明显
        # (正确共享: max/total ≈ 0.9-1.0; 181538f: max/total ≈ 0.3-0.4)。
        if total >= 5 and max_num < total * 0.6:
            issues.append({
                'prefix': '*',
                'type': 'per_prefix_counter',
                'detail': f'shared-counter invariant violated: '
                          f'{total} declared locals but max number is only '
                          f'{max_num} (Ghidra single shared base would give '
                          f'max~={total}); suggests per-prefix restart bug',
            })
    return issues


# ---------------------------------------------------------------------------
# 结构缺陷检测 (Rugra 特有)
# ---------------------------------------------------------------------------

def detect_defects(body):
    """检测 Rugra 特有的结构缺陷。返回缺陷描述列表。"""
    defects = []
    # 空 else {} 块
    for m in EMPTY_BLOCK_RE.finditer(body):
        line = body[:m.start()].count('\n') + 1
        defects.append(f'empty else block (line {line})')
    # 寄存器泄漏
    reg_hits = set(REGISTER_LEAK_RE.findall(body))
    # 规范化寄存器名 (R BX → RBX)
    reg_hits = {r.replace(' ', '') for r in reg_hits}
    if reg_hits:
        defects.append(f'register leak: {sorted(reg_hits)[:5]}')
    return defects


# ---------------------------------------------------------------------------
# 主对比逻辑
# ---------------------------------------------------------------------------

def diff_function(rugra_body, ghidra_body, mode='all'):
    """
    对比单个函数, 返回结构化结果 dict。
    mode: 'skeleton' | 'numbering' | 'all'
    """
    result = {'skeleton_diff': [], 'numbering': {}, 'defects': []}

    if mode in ('skeleton', 'all'):
        r_sk = normalize_skeleton(rugra_body)
        g_sk = normalize_skeleton(ghidra_body)
        diff = list(difflib.unified_diff(
            g_sk, r_sk, fromfile='ghidra', tofile='rugra', lineterm='', n=1,
        ))
        result['skeleton_diff'] = diff

    if mode in ('numbering', 'all'):
        result['numbering']['rugra'] = check_numbering_continuity(rugra_body)
        result['numbering']['ghidra'] = check_numbering_continuity(ghidra_body)

    if mode in ('skeleton', 'all'):
        result['defects'] = detect_defects(rugra_body)

    return result


def format_result(addr, rname, gname, res, verbose=False):
    """格式化单函数对比结果为可读字符串。"""
    lines = [f'=== {rname}', ]

    # 结构骨架 diff
    diff = res.get('skeleton_diff', [])
    if diff:
        n_diff = sum(1 for l in diff if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))
        lines.append(f'[Skeleton] {n_diff} lines differ')
        if verbose:
            lines.extend(f'  {l}' for l in diff[:30])
            if len(diff) > 30:
                lines.append(f'  ... ({len(diff)-30} more)')
    else:
        lines.append('[Skeleton] identical')

    # 结构缺陷
    defects = res.get('defects', [])
    if defects:
        lines.append(f'[Defects] {len(defects)}')
        for d in defects:
            lines.append(f'  → {d}')

    # 编号连续性
    numbering = res.get('numbering', {})
    for side in ('rugra', 'ghidra'):
        issues = numbering.get(side, [])
        if issues:
            lines.append(f'[Numbering:{side}] {len(issues)} issues')
            for iss in issues[:5]:
                lines.append(f'  → {iss["type"]}: {iss["detail"]}')
        else:
            lines.append(f'[Numbering:{side}] OK (monotonic)')

    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(
        description='Rugra vs Ghidra 多维度结构化对比 (替代 if/while 计数)')
    ap.add_argument('rugra_c', help='Rugra 反编译输出 .c')
    ap.add_argument('ghidra_c', help='Ghidra 反编译输出 .c')
    ap.add_argument('--base', default='0x100000', help='地址基址偏移 (hex)')
    ap.add_argument('--func', default=None, help='只对比指定函数名')
    ap.add_argument('--mode', default='all',
                    choices=['skeleton', 'numbering', 'all'],
                    help='对比维度')
    ap.add_argument('-v', '--verbose', action='store_true', help='显示完整 diff')
    ap.add_argument('--summary-only', action='store_true',
                    help='只输出汇总统计')
    args = ap.parse_args()

    base = int(args.base, 16)
    rugra_text = Path(args.rugra_c).read_text(encoding='utf-8', errors='replace')
    ghidra_text = Path(args.ghidra_c).read_text(encoding='utf-8', errors='replace')

    rugra_funcs = parse_functions(rugra_text)
    ghidra_funcs = parse_functions(ghidra_text)
    matched = match_functions(rugra_funcs, ghidra_funcs, base)

    print(f'Rugra functions: {len(rugra_funcs)}')
    print(f'Ghidra functions: {len(ghidra_funcs)}')
    print(f'Matched: {len(matched)}\n')

    if args.func:
        matched = [t for t in matched if t[1] == args.func or t[3] == args.func]
        if not matched:
            print(f'No match for function: {args.func}', file=sys.stderr)
            sys.exit(1)

    total_skeleton_diff = 0
    total_defects = 0
    total_numbering = 0
    funcs_with_defects = 0

    for addr, rname, rbody, gname, gbody in matched:
        res = diff_function(rbody, gbody, args.mode)
        n_diff = sum(1 for l in res.get('skeleton_diff', [])
                     if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))
        n_def = len(res.get('defects', []))
        n_num = len(res.get('numbering', {}).get('rugra', []))
        total_skeleton_diff += n_diff
        total_defects += n_def
        total_numbering += n_num
        if n_def > 0:
            funcs_with_defects += 1

        if args.summary_only:
            status = '✗' if (n_def > 0 or n_diff > 0) else '✓'
            print(f'  {status} {rname:<30} diff={n_diff:<4} '
                  f'defects={n_def} numbering={n_num}')
        else:
            print(format_result(addr, rname, gname, res, args.verbose))
            print()

    print(f'\n{"="*60}')
    print(f'Total skeleton diff lines: {total_skeleton_diff}')
    print(f'Total Rugra defects: {total_defects} '
          f'(in {funcs_with_defects}/{len(matched)} functions)')
    print(f'Total Rugra numbering issues: {total_numbering}')
    print(f'\nNOTE: skeleton diff > 0 不一定是对齐缺陷 (for↔while 等价变换).')
    print(f'      判定口径 (MSTRUCT 2026-09-25): 对 canon/headless golden (桥接层富化),')
    print(f'      for↔while 拆分等形态差可为 HEAD 伪差; 对 direct-runner mirror golden')
    print(f'      (tests/golden/*_1204.direct-runner.c, 同输入 oracle 真值), 形态差')
    print(f'      = 真实输出差 (库侧修复, 不做工具归一化 — 见 MSTRUCT-FORMDIFF-BOUNDARY-0001).')
    print(f'      defects > 0 是真实质量缺陷 (空else/寄存器泄漏/调用丢失).')
    print(f'      numbering issues > 0 是 181538f 类编号 bug (per-prefix 计数器 / 重复声明).')


if __name__ == '__main__':
    main()
