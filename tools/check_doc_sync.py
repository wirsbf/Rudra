#!/usr/bin/env python3
"""
check_doc_sync.py — 检查 src/ 下被修改的 .rs 文件是否有对应的 docs/api/ 文档更新。

用法:
    python tools/check_doc_sync.py          # 检查 git diff (未提交的改动)
    python tools/check_doc_sync.py --staged # 检查 git diff --staged (已暂存的改动)
    python tools/check_doc_sync.py --all    # 检查所有 src/*.rs 是否都有 docs/api/*.md

退出码:
    0 = 全部同步
    1 = 存在未同步的文档
"""

import subprocess
import sys
import os
from pathlib import Path

# 项目子目录根——rudra 源代码所在位置
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DOC_DIR = PROJECT_ROOT / "docs" / "api"


def detect_git_prefix() -> str:
    """
    检测当前项目目录相对于 git 仓库根的前缀。
    例如 git root 是 D:/ghidra，项目在 D:/ghidra/rudra，则返回 "rudra/"。
    """
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    git_root = Path(result.stdout.strip())
    try:
        rel = PROJECT_ROOT.relative_to(git_root)
        prefix = str(rel).replace("\\", "/")
        return (prefix + "/") if prefix and prefix != "." else ""
    except ValueError:
        return ""


GIT_PREFIX = detect_git_prefix()  # e.g. "rudra/"


def rs_to_doc_path(rs_rel: str) -> Path:
    """将 src/foo/bar.rs 映射到 docs/api/foo/bar.md (相对于项目根)"""
    return DOC_DIR / Path(rs_rel).relative_to("src").with_suffix(".md")


def strip_prefix(path: str) -> str:
    """从 git diff 输出的路径中去掉 git 项目前缀，得到相对于项目根的路径"""
    if GIT_PREFIX and path.startswith(GIT_PREFIX):
        return path[len(GIT_PREFIX):]
    return path


def get_modified_files(staged: bool = False) -> list[str]:
    """从 git diff 获取被修改的文件列表（已去掉 git 前缀）"""
    cmd = ["git", "diff", "--name-only"]
    if staged:
        cmd.append("--staged")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    raw = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    return [strip_prefix(f) for f in raw]


def get_all_rs_files() -> list[str]:
    """获取 src/ 下所有 .rs 文件（相对于项目根）"""
    rs_files = []
    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith(".rs"):
                full = Path(root) / f
                rs_files.append(str(full.relative_to(PROJECT_ROOT)).replace("\\", "/"))
    return rs_files


def check_sync(rs_files: list[str], modified_docs: set[str] | None = None) -> list[tuple[str, str, str]]:
    """
    检查每个 .rs 文件是否有对应的 .md 文档。
    返回 [(rs_path, doc_path, reason), ...]
    """
    missing = []
    for rs in rs_files:
        # 2026-09-26 SLEIGHP3: staged DELETIONS of src files must not demand a
        # doc update — a src file being removed (with its doc removed in the
        # same wave) is a consistent state, not a sync gap. Skip src paths that
        # no longer exist in the working tree.
        if not (PROJECT_ROOT / rs).exists():
            continue
        doc = rs_to_doc_path(rs)
        doc_rel = str(doc.relative_to(PROJECT_ROOT)).replace("\\", "/")

        if not doc.exists():
            missing.append((rs, doc_rel, "文档不存在"))
        elif modified_docs is not None:
            if doc_rel not in modified_docs:
                missing.append((rs, doc_rel, "源码已修改但文档未同步更新"))
    return missing


def main():
    mode = "--diff"
    if len(sys.argv) > 1:
        mode = sys.argv[1]

    if mode == "--all":
        rs_files = get_all_rs_files()
        problems = check_sync(rs_files)
    elif mode == "--staged":
        all_files = get_modified_files(staged=True)
        rs_files = [f for f in all_files if f.startswith("src/") and f.endswith(".rs")]
        if not rs_files:
            print("✅ 暂存区无 .rs 文件改动")
            return 0
        modified_docs = {f for f in all_files if f.startswith("docs/api/") and f.endswith(".md")}
        problems = check_sync(rs_files, modified_docs)
    else:
        all_files = get_modified_files(staged=False)
        rs_files = [f for f in all_files if f.startswith("src/") and f.endswith(".rs")]
        if not rs_files:
            print("✅ 工作区无 .rs 文件改动")
            return 0
        modified_docs = {f for f in all_files if f.startswith("docs/api/") and f.endswith(".md")}
        problems = check_sync(rs_files, modified_docs)

    if not problems:
        print(f"✅ 所有 {len(rs_files)} 个 .rs 文件的 docs/api/ 文档均已同步")
        return 0

    print(f"\n❌ 发现 {len(problems)} 个文档同步缺失:\n")
    for rs, doc, reason in problems:
        print(f"  {rs}")
        print(f"    → {doc}")
        print(f"    原因: {reason}\n")

    print("请在提交前同步更新对应的 docs/api/ 文档。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
