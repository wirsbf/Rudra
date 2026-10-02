#!/usr/bin/env python3
# RUDRA-GLUE: no oracle counterpart. This tool is a pure consumer of v2
# drill files (stage-bisect "down-zoom" artifacts) produced by fixture
# harnesses around the locked oracle (Ghidra 12.0.4, commit
# e40ed13014025f82488b1f8f7bca566894ac376b) and around the Rudra driver
# layer. It changes no pipeline semantics, produces no IR, and injects no
# state; per docs/alignment_docs/PIPELINE_STAGES_1204.md section 5 such
# tooling must live outside the perform() tree. The observation format it
# consumes is the native one wrapped by the drill generators:
#
#   - funcdata.cc:1010-1052  Funcdata::debugModCheck/debugModPrint
#     (#ifdef OPACTION_DEBUG): after every Action::apply (action.cc:317-321)
#     or Rule::applyOp (action.cc:839-845) each modified PcodeOp is printed
#     as a before/after printDebug pair under a "DEBUG <n>: <name>" header.
#   - op.cc:374-384          PcodeOp::printDebug: "<seqnum>: <printRaw>",
#     where a dead/unattached op prints "<seqnum>: **".
#   - address.cc:32-37       SeqNum printing: "<pc.printRaw()>:<uniq>".
#   - varnode.cc:705-756     Varnode raw text: space shortcut, ":size"
#     suffix only when size != translate default, "#value" constants.
#
# The drill generator (examples side, both Ghidra and Rudra) wraps the
# native per-application stream in @BEGIN/@END application brackets and a
# @DONE statistics trailer (see /dev/shm notes in DRILL_DESIGN.md; META
# records oracle commit / arch / cspec / build flags for provenance).

"""Compare two v2 drill files across four observation layers.

A drill file is a line-oriented record of one decompilation run:

  META side=... oracle_commit=... func=... arch=... cspec=... \\
        format=... producer=...            (exactly one, first line)
  @BEGIN <seq> <path> [empty=1]           one application of an
                                          Action/Rule starts; <seq> is the
                                          1-based perform bracket counter,
                                          <path> the ':'-separated action
                                          tree path (action.cc:265-282)
  DEBUG <n>: <name>                       opactdbg_count header for the
                                          modified-op stream (only present
                                          in non-empty applications; <n>
                                          starts at 0, funcdata.hh:584-602)
  <seqnum>: <before-printDebug>           cached before state of one
     <3 spaces><seqnum>: <after>          modified PcodeOp (strictly
                                          interleaved before/after pairs;
                                          dead ops print "**" as the body)
  @END <seq> <path>                       application finished
  @DONE key=value ...                     exactly one, final statistics
                                          line (applications=, records=,
                                          opactdbg_final=, ...)

Blank lines inside a block are ignored (the native debug stream ends each
application with a newline, so oracle files carry a trailing blank line
before @END).

Comparison layers:

  1. Path layer      -- application blocks aggregated by action path:
                        shared / oracle-only / rudra-only path sets and
                        per-path application-count deltas (the "which
                        actions fire and how often" view).
  2. First record divergence -- global record-line stream (DEBUG headers
                        and brackets stripped, file order): common prefix
                        length plus the first differing before/after line
                        with its owning application on each side.
  3. Record classification -- within shared paths, k-th occurrence paired
                        with k-th occurrence and op-by-op comparison when
                        both blocks hold the same op count; differing line
                        pairs are classified (first match wins):
                          dead_marker   one side dead ("**"), other live
                          seqnum_drift  equal after masking <pc>:<uniq>
                                        uniq counters (pc kept)
                          const_width   equal after masking "#v[:size]"
                                        constant width suffixes
                          opcode_name   masked forms still differ and the
                                        identifier-token multisets differ
                                        (operator spelling changed)
                          other         residual (values/structure)
  4. @DONE stats     -- key-by-key statistics comparison.

META lines are compared informationally only (provenance note); they do
not gate the exit code.

Exit codes: 0 drills observationally identical across all four layers,
1 differences reported, 2 usage or format error. Selftest: 0 pass, 1 fail.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "drill_diff"

KIND_MATCH = "match"
KIND_DIVERGENCE = "record_divergence"
KIND_LENGTH = "length_divergence"

PATH_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
BEGIN_RE = re.compile(r"^@BEGIN (\d+) (\S+)(?:\s+(.*))?$")
END_RE = re.compile(r"^@END (\d+) (\S+)$")
DEBUG_RE = re.compile(r"^DEBUG (\d+): (.+)$")
DONE_RE = re.compile(r"^@DONE(?:\s+(.*))?$")
SEQNUM_RE = re.compile(r"^\S+: .*$")

AFTER_PREFIX = "   "  # three spaces: funcdata.cc:1046-1053 after-state prefix

# Classification normalizers (documented order: dead -> seqnum -> width).
# SeqNum uniq counters (address.cc:32-37), pc kept.  Uniq/time values are
# printed via ostream hex formatting in the drill corpus (:2ce, :5ad), so the
# counter part is a hex run.  The lookbehind keeps '#'-prefixed constants
# out: '#0x0:4' is a varnode size suffix, not a uniq.
UNIQ_RE = re.compile(r"(?<!#)(0x[0-9a-fA-F]+):[0-9a-fA-F]+")
CONST_RE = re.compile(r"#(0x[0-9a-fA-F]+)(:\d+)?")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
DEC_RE = re.compile(r"\d+")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class FormatError(RuntimeError):
    """A drill file violates the v2 drill format."""


@dataclass
class OpRecord:
    """One modified PcodeOp: before/after printDebug pair."""

    before: str
    after: str
    before_line: int
    after_line: int


@dataclass
class Block:
    """One @BEGIN/@END application bracket."""

    seq: int
    path: str
    begin_line: int
    end_line: int = 0
    debug_seq: int = -1
    debug_name: str = ""
    records: list[OpRecord] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.records


@dataclass
class Drill:
    """One parsed drill file."""

    name: str
    meta: dict[str, str]
    meta_line: int
    blocks: list[Block]
    done: dict[str, str]
    done_line: int

    def record_blocks(self) -> list[Block]:
        return [b for b in self.blocks if b.records]

    def path_counts(self) -> Counter:
        return Counter(b.path for b in self.blocks)

    def blocks_by_path(self) -> dict[str, list[Block]]:
        by_path: dict[str, list[Block]] = {}
        for block in self.blocks:  # file order preserved
            by_path.setdefault(block.path, []).append(block)
        return by_path

    def record_stream(self):
        """Global (text, line_no, seq, path, phase) stream, file order."""
        for block in self.blocks:
            for record in block.records:
                yield (record.before, record.before_line, block.seq,
                       block.path, "before")
                yield (record.after, record.after_line, block.seq,
                       block.path, "after")


def parse_meta(line: str, line_no: int) -> dict[str, str]:
    kv: dict[str, str] = {}
    tokens = line.split()[1:]
    if not tokens:
        raise FormatError(f"line {line_no}: META requires key=value tokens")
    for token in tokens:
        if "=" not in token:
            raise FormatError(
                f"line {line_no}: malformed META token {token!r}")
        key, value = token.split("=", 1)
        kv[key] = value
    return kv


def parse_kv(tokens: str | None, line_no: int, what: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for token in (tokens or "").split():
        if "=" not in token:
            raise FormatError(
                f"line {line_no}: malformed {what} token {token!r}")
        key, value = token.split("=", 1)
        kv[key] = value
    return kv


def load_drill(path: str) -> Drill:
    """Parse one drill file; raises FormatError on any grammar violation."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from exc

    meta: dict[str, str] = {}
    meta_line = 0
    blocks: list[Block] = []
    open_block: Block | None = None
    pending_before: OpRecord | None = None
    done: dict[str, str] = {}
    done_line = 0

    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if done_line:
            if line.strip():
                raise FormatError(
                    f"line {index}: content after @DONE trailer")
            continue
        if not line.strip():
            continue  # native stream trailing newlines / separators

        if line.startswith("META "):
            if meta_line or blocks or open_block:
                raise FormatError(
                    f"line {index}: META must be the first line")
            if not line.startswith("META side="):
                raise FormatError(
                    f"line {index}: META must start with side=")
            meta = parse_meta(line, index)
            meta_line = index
        elif line.startswith("@BEGIN"):
            if open_block is not None:
                raise FormatError(
                    f"line {index}: @BEGIN inside open block "
                    f"@BEGIN {open_block.seq} {open_block.path}")
            match = BEGIN_RE.match(line)
            if not match:
                raise FormatError(f"line {index}: malformed @BEGIN: {line}")
            seq = int(match.group(1))
            path = match.group(2)
            if not PATH_RE.match(path):
                raise FormatError(
                    f"line {index}: invalid path {path!r}")
            extras = parse_kv(match.group(3), index, "@BEGIN")
            if set(extras) - {"empty"} or \
                    extras.get("empty") not in (None, "1"):
                raise FormatError(
                    f"line {index}: only 'empty=1' allowed on @BEGIN")
            open_block = Block(seq=seq, path=path, begin_line=index)
        elif line.startswith("@END"):
            if open_block is None:
                raise FormatError(f"line {index}: @END without @BEGIN")
            match = END_RE.match(line)
            if not match:
                raise FormatError(f"line {index}: malformed @END: {line}")
            if int(match.group(1)) != open_block.seq or \
                    match.group(2) != open_block.path:
                raise FormatError(
                    f"line {index}: @END {match.group(1)} {match.group(2)} "
                    f"does not close @BEGIN {open_block.seq} {open_block.path}")
            if pending_before is not None:
                raise FormatError(
                    f"line {index}: before record without after state")
            open_block.end_line = index
            blocks.append(open_block)
            open_block = None
        elif line.startswith("DEBUG "):
            if open_block is None:
                raise FormatError(
                    f"line {index}: DEBUG record outside application block")
            match = DEBUG_RE.match(line)
            if not match:
                raise FormatError(f"line {index}: malformed DEBUG: {line}")
            if open_block.debug_seq >= 0:
                raise FormatError(
                    f"line {index}: second DEBUG header in block "
                    f"@BEGIN {open_block.seq}")
            open_block.debug_seq = int(match.group(1))
            open_block.debug_name = match.group(2)
        elif line.startswith(AFTER_PREFIX):
            body = line[len(AFTER_PREFIX):]
            if open_block is None:
                raise FormatError(
                    f"line {index}: after record outside application block")
            if pending_before is None:
                raise FormatError(
                    f"line {index}: after record without before state")
            if not SEQNUM_RE.match(body):
                raise FormatError(
                    f"line {index}: malformed after record: {line}")
            pending_before.after = body
            pending_before.after_line = index
            open_block.records.append(pending_before)
            pending_before = None
        elif line.startswith("@DONE"):
            if open_block is not None:
                raise FormatError(
                    f"line {index}: @DONE inside open block "
                    f"@BEGIN {open_block.seq} {open_block.path}")
            done = parse_kv(DONE_RE.match(line).group(1), index, "@DONE")
            done_line = index
        else:
            if open_block is None:
                raise FormatError(
                    f"line {index}: record outside application block: {line}")
            if pending_before is not None:
                raise FormatError(
                    f"line {index}: consecutive before records")
            if not SEQNUM_RE.match(line):
                raise FormatError(
                    f"line {index}: malformed record: {line}")
            pending_before = OpRecord(
                before=line, after="", before_line=index, after_line=0)

    if open_block is not None:
        raise FormatError(
            f"EOF: unclosed block @BEGIN {open_block.seq} {open_block.path}")
    if pending_before is not None:
        raise FormatError("EOF: before record without after state")
    if not done_line:
        raise FormatError("EOF: missing @DONE trailer")
    if not meta_line:
        raise FormatError("missing META header line")
    for position, block in enumerate(blocks, start=1):
        if block.seq != position:
            raise FormatError(
                f"@BEGIN sequence not 1-based monotonic at position "
                f"{position}: got {block.seq}")
        if block.empty and block.debug_seq >= 0:
            raise FormatError(
                f"@BEGIN {block.seq} {block.path}: DEBUG header but no "
                f"before/after records")
        if not block.empty and block.debug_seq < 0:
            raise FormatError(
                f"@BEGIN {block.seq} {block.path}: records without DEBUG "
                f"header")

    return Drill(name=path, meta=meta, meta_line=meta_line, blocks=blocks,
                 done=done, done_line=done_line)


# ---------------------------------------------------------------------------
# Classification normalizers
# ---------------------------------------------------------------------------

def is_dead(text: str) -> bool:
    """op.cc:376-384: a dead/unattached op prints '**' as the whole body."""
    return text.endswith(": **") and not text.endswith(": ***")


def mask_uniq(text: str) -> str:
    """Mask <pc>:<uniq> uniq counters (address.cc:32-37), keeping pc."""
    return UNIQ_RE.sub(r"\1:U", text)


def mask_const_width(text: str) -> str:
    """Mask constant '#v[:size]' width suffixes, including their absence."""
    return CONST_RE.sub(r"#\1:W", text)


def skeleton(text: str) -> str:
    """Mask all numeric literals (addresses, uniqs, values, widths)."""
    return DEC_RE.sub("N", HEX_RE.sub("H", text))


def ident_tokens(text: str) -> Counter:
    """Identifier tokens with hex literals masked out (so 'x8' inside
    '#0x8' is never a token; only genuine operator/varnode names are)."""
    return Counter(IDENT_RE.findall(HEX_RE.sub("H", text)))


def classify_pair(oracle_text: str, rudra_text: str) -> str:
    """First-match classification of one differing record-line pair."""
    if is_dead(oracle_text) != is_dead(rudra_text):
        return "dead_marker"
    if mask_uniq(oracle_text) == mask_uniq(rudra_text):
        return "seqnum_drift"
    if mask_const_width(oracle_text) == mask_const_width(rudra_text):
        return "const_width"
    if ident_tokens(oracle_text) != ident_tokens(rudra_text):
        return "opcode_name"
    return "other"


# ---------------------------------------------------------------------------
# Layer comparisons
# ---------------------------------------------------------------------------

def compare_meta(left: Drill, right: Drill) -> dict:
    differing = sorted(
        key for key in set(left.meta) & set(right.meta)
        if left.meta[key] != right.meta[key])
    left_only = sorted(set(left.meta) - set(right.meta))
    right_only = sorted(set(right.meta) - set(left.meta))
    return {
        "left_side": left.meta.get("side", "?"),
        "right_side": right.meta.get("side", "?"),
        "differing_keys": differing,
        "left_only_keys": left_only,
        "right_only_keys": right_only,
    }


def compare_paths(left: Drill, right: Drill) -> dict:
    """Layer 1: application blocks aggregated by action path."""
    left_counts = left.path_counts()
    right_counts = right.path_counts()
    shared = set(left_counts) & set(right_counts)
    count_deltas = sorted(
        ({"path": path,
          "oracle": left_counts[path],
          "rugra": right_counts[path],
          "delta": right_counts[path] - left_counts[path]}
         for path in shared if left_counts[path] != right_counts[path]),
        key=lambda item: (-abs(item["delta"]), item["path"]))
    return {
        "oracle_blocks": len(left.blocks),
        "rudra_blocks": len(right.blocks),
        "oracle_record_blocks": len(left.record_blocks()),
        "rudra_record_blocks": len(right.record_blocks()),
        "shared_paths": len(shared),
        "oracle_only": {path: left_counts[path]
                        for path in sorted(set(left_counts) - shared)},
        "rudra_only": {path: right_counts[path]
                       for path in sorted(set(right_counts) - shared)},
        "count_deltas": count_deltas,
        "shared_equal_counts": sum(1 for path in shared
                                   if left_counts[path] == right_counts[path]),
    }


def compare_first_divergence(left: Drill, right: Drill) -> dict | None:
    """Layer 2: first differing line of the global record stream."""
    left_stream = list(left.record_stream())
    right_stream = list(right.record_stream())
    common = 0
    for left_item, right_item in zip(left_stream, right_stream):
        if left_item[0] != right_item[0]:
            break
        common += 1
    if common == len(left_stream) == len(right_stream):
        return None
    report: dict = {
        "common_prefix_lines": common,
        "common_op_pairs": common // 2,
        "left_total_lines": len(left_stream),
        "right_total_lines": len(right_stream),
    }
    if common == len(left_stream) or common == len(right_stream):
        report["kind"] = KIND_LENGTH
        longer, side = (right_stream, "rugra") if common == len(left_stream) \
            else (left_stream, "oracle")
        text, line_no, seq, path, phase = longer[common]
        report["first_extra"] = {
            "side": side, "line_no": line_no, "seq": seq, "path": path,
            "phase": phase, "text": text,
        }
        return report
    report["kind"] = KIND_DIVERGENCE
    for stream, side in ((left_stream, "oracle"), (right_stream, "rugra")):
        text, line_no, seq, path, phase = stream[common]
        report[side] = {"line_no": line_no, "seq": seq, "path": path,
                        "phase": phase, "text": text}
    report["phase"] = left_stream[common][4]
    return report


def compare_classification(left: Drill, right: Drill, max_examples: int = 3,
                           truncate: int = 96) -> dict:
    """Layer 3: record content classification inside paired occurrences."""
    stats = {
        "compared_line_pairs": 0,
        "differing_line_pairs": 0,
        "dead_marker": 0,
        "seqnum_drift": 0,
        "const_width": 0,
        "opcode_name": 0,
        "other": 0,
        "unpaired_block_occurrences": 0,
        "unpaired_op_records": 0,
        "unequal_op_count_blocks": 0,
        "examples": {key: [] for key in
                     ("dead_marker", "seqnum_drift", "const_width",
                      "opcode_name", "other")},
    }
    for path in sorted(set(left.path_counts()) & set(right.path_counts())):
        left_blocks = left.blocks_by_path()[path]
        right_blocks = right.blocks_by_path()[path]
        paired = min(len(left_blocks), len(right_blocks))
        stats["unpaired_block_occurrences"] += \
            abs(len(left_blocks) - len(right_blocks))
        for occurrence in range(paired):
            left_block = left_blocks[occurrence]
            right_block = right_blocks[occurrence]
            if len(left_block.records) != len(right_block.records):
                stats["unequal_op_count_blocks"] += 1
                stats["unpaired_op_records"] += abs(
                    len(left_block.records) - len(right_block.records))
                continue
            for left_record, right_record in zip(left_block.records,
                                                 right_block.records):
                for phase, left_text, right_text in (
                        ("before", left_record.before, right_record.before),
                        ("after", left_record.after, right_record.after)):
                    stats["compared_line_pairs"] += 1
                    if left_text == right_text:
                        continue
                    stats["differing_line_pairs"] += 1
                    category = classify_pair(left_text, right_text)
                    stats[category] += 1
                    examples = stats["examples"][category]
                    if len(examples) < max_examples:
                        examples.append({
                            "path": path,
                            "occurrence": occurrence + 1,
                            "seq": left_block.seq,
                            "phase": phase,
                            "oracle_text": left_text[:truncate],
                            "rudra_text": right_text[:truncate],
                        })
    return stats


def const_census(drill: Drill) -> tuple[Counter, int, int]:
    """Whole-file '#value[:width]' census over all record lines.

    Complements the paired-block classification: SUBPIECE constant-width
    signals typically live in blocks whose op counts differ (counted as
    unpaired there), so the width signal is also quantified file-wide.
    """
    counts: Counter = Counter()
    explicit = 0
    bare = 0
    for block in drill.blocks:
        for record in block.records:
            for text in (record.before, record.after):
                for value, width in CONST_RE.findall(text):
                    form = f"#{value}:{width[1:]}" if width else f"#{value}"
                    counts[form] += 1
                    if width:
                        explicit += 1
                    else:
                        bare += 1
    return counts, explicit, bare


def compare_const_census(left: Drill, right: Drill) -> dict:
    """Informational whole-file constant width-form comparison."""
    left_counts, left_explicit, left_bare = const_census(left)
    right_counts, right_explicit, right_bare = const_census(right)
    forms = sorted(
        ({"form": form,
          "oracle": left_counts.get(form, 0),
          "rugra": right_counts.get(form, 0),
          "delta": right_counts.get(form, 0) - left_counts.get(form, 0)}
         for form in set(left_counts) | set(right_counts)
         if left_counts.get(form, 0) != right_counts.get(form, 0)),
        key=lambda item: (-abs(item["delta"]), item["form"]))
    return {
        "oracle_explicit_width": left_explicit,
        "oracle_bare": left_bare,
        "rudra_explicit_width": right_explicit,
        "rugra_bare": right_bare,
        "differing_forms": forms,
    }


def compare_done(left: Drill, right: Drill) -> dict:
    """Layer 4: @DONE statistics comparison."""
    differing = sorted(
        key for key in set(left.done) & set(right.done)
        if left.done[key] != right.done[key])
    return {
        "oracle_kv": dict(left.done),
        "rudra_kv": dict(right.done),
        "differing": differing,
        "oracle_only_keys": sorted(set(left.done) - set(right.done)),
        "rudra_only_keys": sorted(set(right.done) - set(left.done)),
    }


def build_report(left: Drill, right: Drill, max_examples: int = 3) -> dict:
    path_layer = compare_paths(left, right)
    first_divergence = compare_first_divergence(left, right)
    classification = compare_classification(left, right,
                                            max_examples=max_examples)
    classification["const_census"] = compare_const_census(left, right)
    done_layer = compare_done(left, right)

    path_differs = bool(path_layer["oracle_only"] or
                        path_layer["rudra_only"] or
                        path_layer["count_deltas"])
    done_differs = bool(done_layer["differing"] or
                        done_layer["oracle_only_keys"] or
                        done_layer["rudra_only_keys"])
    classification_differs = bool(classification["differing_line_pairs"] or
                                  classification["unpaired_block_occurrences"]
                                  or classification["unpaired_op_records"])

    if first_divergence is None:
        kind = KIND_MATCH
    elif first_divergence["kind"] == KIND_LENGTH:
        kind = KIND_LENGTH
    else:
        kind = KIND_DIVERGENCE

    return {
        "kind": kind,
        "left": left.name,
        "right": right.name,
        "differences": bool(path_differs or first_divergence is not None or
                            classification_differs or done_differs),
        "meta": compare_meta(left, right),
        "path_layer": path_layer,
        "first_divergence": first_divergence,
        "classification": classification,
        "done": done_layer,
    }


# ---------------------------------------------------------------------------
# Human report
# ---------------------------------------------------------------------------

def clip(text: str, width: int = 96) -> str:
    return text if len(text) <= width else text[:width - 3] + "..."


def human_report(report: dict, top: int = 10) -> str:
    lines: list[str] = []
    meta = report["meta"]
    lines.append(
        f"drill_diff: {report['left']} ({meta['left_side']}) vs "
        f"{report['right']} ({meta['right_side']})")

    lines.append("== [1] path layer (application blocks by action path) ==")
    path_layer = report["path_layer"]
    lines.append(
        f"blocks: oracle={path_layer['oracle_blocks']} "
        f"({path_layer['oracle_record_blocks']} with records), rudra="
        f"{path_layer['rudra_blocks']} "
        f"({path_layer['rudra_record_blocks']} with records)")
    lines.append(
        f"shared paths={path_layer['shared_paths']} "
        f"({path_layer['shared_equal_counts']} with equal counts), "
        f"oracle-only={len(path_layer['oracle_only'])}, "
        f"rudra-only={len(path_layer['rudra_only'])}")
    for path, count in path_layer["oracle_only"].items():
        lines.append(f"  oracle-only: {path} x{count}")
    for path, count in path_layer["rudra_only"].items():
        lines.append(f"  rudra-only:  {path} x{count}")
    deltas = path_layer["count_deltas"]
    lines.append(f"shared paths with count delta: {len(deltas)} "
                 f"(top {min(top, len(deltas))} by |delta|)")
    for item in deltas[:top]:
        lines.append(
            f"  {item['path']}: {item['oracle']} -> {item['rudra']} "
            f"({item['delta']:+d})")

    lines.append("== [2] first record divergence (global stream order) ==")
    divergence = report["first_divergence"]
    if divergence is None:
        lines.append("  record streams identical")
    elif divergence["kind"] == KIND_LENGTH:
        extra = divergence["first_extra"]
        lines.append(
            f"  common prefix={divergence['common_prefix_lines']} lines "
            f"({divergence['common_op_pairs']} complete op pairs); "
            f"{extra['side']} stream continues with "
            f"@BEGIN {extra['seq']} {extra['path']} {extra['phase']}:")
        lines.append(f"    {extra['side']} line {extra['line_no']}: "
                     f"{clip(extra['text'])}")
    else:
        lines.append(
            f"  common prefix={divergence['common_prefix_lines']} lines "
            f"({divergence['common_op_pairs']} complete op pairs); "
            f"first difference in {divergence['phase']} state:")
        for side in ("oracle", "rugra"):
            item = divergence[side]
            lines.append(
                f"    {side} line {item['line_no']} "
                f"[@BEGIN {item['seq']} {item['path']}]: "
                f"{clip(item['text'])}")

    lines.append("== [3] record classification (paired shared-path "
                 "occurrences, equal op counts) ==")
    stats = report["classification"]
    lines.append(
        f"compared line pairs={stats['compared_line_pairs']}, "
        f"differing={stats['differing_line_pairs']} "
        f"(dead_marker={stats['dead_marker']}, "
        f"seqnum_drift={stats['seqnum_drift']}, "
        f"const_width={stats['const_width']}, "
        f"opcode_name={stats['opcode_name']}, other={stats['other']})")
    lines.append(
        f"unpaired block occurrences={stats['unpaired_block_occurrences']}, "
        f"unequal op count blocks={stats['unequal_op_count_blocks']} "
        f"(unpaired op records={stats['unpaired_op_records']})")
    census = stats["const_census"]
    lines.append(
        f"  const width-form census (whole file, informational): oracle "
        f"explicit={census['oracle_explicit_width']} bare="
        f"{census['oracle_bare']}, rudra explicit="
        f"{census['rudra_explicit_width']} bare={census['rudra_bare']}; "
        f"differing forms={len(census['differing_forms'])} "
        f"(top {min(top, len(census['differing_forms']))} by |delta|)")
    for form in census["differing_forms"][:top]:
        lines.append(
            f"    {form['form']}: oracle={form['oracle']} "
            f"rudra={form['rudra']} ({form['delta']:+d})")
    for category in ("dead_marker", "seqnum_drift", "const_width",
                     "opcode_name", "other"):
        for example in stats["examples"][category]:
            lines.append(
                f"  {category} [{example['path']} #{example['occurrence']} "
                f"seq={example['seq']} {example['phase']}]")
            lines.append(f"    oracle: {clip(example['oracle_text'])}")
            lines.append(f"    rudra:  {clip(example['rudra_text'])}")

    lines.append("== [4] @DONE statistics ==")
    done = report["done"]
    if not (done["differing"] or done["oracle_only_keys"]
            or done["rudra_only_keys"]):
        lines.append("  identical: " + " ".join(
            f"{key}={value}" for key, value in sorted(done["oracle_kv"].items())))
    else:
        keys = sorted(set(done["oracle_kv"]) | set(done["rudra_kv"]))
        for key in keys:
            oracle_value = done["oracle_kv"].get(key, "<missing>")
            rudra_value = done["rudra_kv"].get(key, "<missing>")
            marker = "  =" if oracle_value == rudra_value else "  !"
            lines.append(f" {marker} {key}: oracle={oracle_value} "
                         f"rudra={rudra_value}")

    meta = report["meta"]
    if meta["differing_keys"] or meta["left_only_keys"] or \
            meta["right_only_keys"]:
        lines.append(
            f"note: META provenance differs (keys: "
            f"{', '.join(meta['differing_keys'] + meta['left_only_keys'] + meta['right_only_keys'])}); "
            f"informational only")

    lines.append(f"verdict: {'IDENTICAL' if not report['differences'] else 'DIFFERENT'}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

def make_drill(side: str, blocks: list[tuple, ...], done: dict[str, str],
               extra_meta: str = "") -> str:
    """Render a synthetic drill file.

    ``blocks`` entries are (seq, path, records, empty) where records is a
    list of (before, after) op pairs; empty blocks pass ``records=None``.
    """
    lines = [
        f"META side={side} oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b "
        f"func=selftest arch=x86:LE:64:default cspec=gcc "
        f"format=raw-native-printdebug {extra_meta}".rstrip()
    ]
    for seq, path, records, empty in blocks:
        if empty or not records:
            lines.append(f"@BEGIN {seq} {path} empty=1")
            lines.append(f"@END {seq} {path}")
            continue
        debug_seq = seq - 2  # arbitrary but deterministic opactdbg_count
        name = path.rsplit(":", 1)[-1]
        lines.append(f"@BEGIN {seq} {path}")
        lines.append(f"DEBUG {max(debug_seq, 0)}: {name}")
        for before, after in records:
            lines.append(before)
            lines.append(AFTER_PREFIX + after)
        lines.append(f"@END {seq} {path}")
    lines.append("@DONE " + " ".join(
        f"{key}={value}" for key, value in sorted(done.items())))
    return "\n".join(lines) + "\n"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def scenario_identical():
    blocks = [
        (1, "universal:start", None, True),
        (2, "universal:constbase",
         [("0x1000:2cd: **", "0x1000:2cd: DF(0x1000:2cd) = #0x0:1")], False),
        (3, "universal:defaultparams", None, True),
    ]
    text = make_drill("oracle", blocks,
                      {"applications": "3", "records": "1",
                       "opactdbg_final": "1"})
    left = load_drill_from(text, "a.drill")
    right = load_drill_from(text, "b.drill")
    report = build_report(left, right)
    check(report["kind"] == KIND_MATCH, "identical drills must match")
    check(not report["differences"], "identical drills report no differences")
    check(report["path_layer"]["shared_paths"] == 3, "3 shared paths")
    check(report["first_divergence"] is None, "no divergence")
    check(report["classification"]["differing_line_pairs"] == 0,
          "no classification diffs")


def load_drill_from(text: str, name: str) -> Drill:
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".drill", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return load_drill(path)
    finally:
        Path(path).unlink()


def scenario_path_layer():
    """oracle-only path, rudra-only path, shared count delta (next_url form)."""
    oracle_blocks = [
        (1, "universal:start", None, True),
        (2, "universal:constbase",
         [("0x1000:1: **", "0x1000:1: DF(0x1000:1) = #0x0:1")], False),
        (3, "oppool2:loadvarnode",
         [("0x2000:4: V(0x2000:4) = *(ram,u0x1000(0x2000:3))",
           "0x2000:4: V(0x2000:4) = #0x5:8")], False),
        (4, "oppool1:earlyremoval",
         [("0x3000:7: **", "0x3000:7: RAX(0x3000:7) = #0x1:8")], False),
        (5, "oppool1:earlyremoval",
         [("0x3100:8: **", "0x3100:8: RBX(0x3100:8) = #0x2:8")], False),
    ]
    rudra_blocks = [
        (1, "universal:start", None, True),
        (2, "universal:constbase",
         [("0x1000:1: **", "0x1000:1: DF(0x1000:1) = #0x0:1")], False),
        (3, "mainloop:unreachable", None, True),  # rudra-only
        (4, "oppool1:earlyremoval",
         [("0x3000:7: **", "0x3000:7: RAX(0x3000:7) = #0x1:8")], False),
    ]
    left = load_drill_from(
        make_drill("oracle", oracle_blocks, {"applications": "5"}), "o.drill")
    right = load_drill_from(
        make_drill("rugra", rudra_blocks, {"applications": "4"}), "r.drill")
    report = build_report(left, right)
    layer = report["path_layer"]
    check(layer["shared_paths"] == 3,
          f"expected 3 shared paths, got {layer['shared_paths']}")
    check(list(layer["oracle_only"]) == ["oppool2:loadvarnode"],
          "oracle-only set mismatch")
    check(list(layer["rudra_only"]) == ["mainloop:unreachable"],
          "rudra-only set mismatch")
    check(len(layer["count_deltas"]) == 1 and
          layer["count_deltas"][0]["path"] == "oppool1:earlyremoval" and
          layer["count_deltas"][0]["oracle"] == 2 and
          layer["count_deltas"][0]["rugra"] == 1,
          "earlyremoval count delta 2->1 expected")
    check(report["differences"], "path differences must flag report")


def scenario_first_divergence():
    """next_url form: identical constbase prefix, extrapopsetup first-touched
    op differs."""
    def block(seq, path, first_pc):
        return (seq, path, [
            (f"0x{first_pc}:2ce: **",
             f"0x{first_pc}:2ce: RSP(0x{first_pc}:2ce) = RSP(free) + #0x8"),
            ("0x5065:2cf: **",
             "0x5065:2cf: RSP(0x5065:2cf) = RSP(free) + #0x8"),
        ], False)

    oracle_blocks = [
        (1, "universal:start", None, True),
        (2, "universal:constbase",
         [("0x4ff4:2cd: **",
           "0x4ff4:2cd: DF(0x4ff4:2cd) = #0x0:1")], False),
        (3, "universal:defaultparams", None, True),
        block(4, "universal:extrapopsetup", "505d"),
    ]
    rudra_blocks = [
        (1, "universal:start", None, True),
        (2, "universal:constbase",
         [("0x4ff4:2cd: **",
           "0x4ff4:2cd: DF(0x4ff4:2cd) = #0x0:1")], False),
        (3, "universal:defaultparams", None, True),
        block(4, "universal:extrapopsetup", "50ce"),
    ]
    left = load_drill_from(
        make_drill("oracle", oracle_blocks, {"records": "3"}), "o.drill")
    right = load_drill_from(
        make_drill("rugra", rudra_blocks, {"records": "3"}), "r.drill")
    report = build_report(left, right)
    divergence = report["first_divergence"]
    check(divergence is not None, "divergence expected")
    check(divergence["common_prefix_lines"] == 2,
          f"common prefix must be 2 lines, got "
          f"{divergence['common_prefix_lines']}")
    check(divergence["common_op_pairs"] == 1, "one complete op pair")
    check(divergence["phase"] == "before", "diverges on a before line")
    check(divergence["oracle"]["path"] == "universal:extrapopsetup" and
          divergence["rugra"]["path"] == "universal:extrapopsetup",
          "divergence block path")
    check(divergence["oracle"]["text"] == "0x505d:2ce: **",
          "oracle first differing text")
    check(divergence["rugra"]["text"] == "0x50ce:2ce: **",
          "rudra first differing text")


def scenario_prefix_length():
    """One record stream is a strict prefix of the other."""
    oracle_blocks = [
        (1, "oppool1:earlyremoval", [
            ("0x4ff4:5ad: RAX(0x4ff4:5ad) = RBX(0x4ff0:5ac)",
             "0x4ff4:5ad: RAX(0x4ff4:5ad) = #0x0:4"),
        ], False),
        (2, "oppool1:earlyremoval", [
            ("0x5000:5ae: **", "0x5000:5ae: RBX(0x5000:5ae) = #0x1:4"),
        ], False),
    ]
    rudra_blocks = [oracle_blocks[0]]
    left = load_drill_from(
        make_drill("oracle", oracle_blocks, {"records": "2"}), "o.drill")
    right = load_drill_from(
        make_drill("rugra", rudra_blocks, {"records": "1"}), "r.drill")
    report = build_report(left, right)
    divergence = report["first_divergence"]
    check(divergence is not None and divergence["kind"] == KIND_LENGTH,
          "length divergence expected")
    check(divergence["first_extra"]["side"] == "oracle",
          "oracle stream continues beyond rudra")
    check(divergence["common_prefix_lines"] == 2, "2 common lines")


def scenario_classification():
    """One paired block with one oracle/rudra pair per classification
    category; before and after phases each contribute one count."""
    live = "0x10:5: RAX(0x10:5) = #0x8:8"
    pairs = [
        # dead_marker: oracle op dead ("**") in both phases, rudra live
        ("0x10:5: **", "0x10:5: **", live, live),
        # seqnum_drift: same pcs, different uniq counters everywhere
        ("0x20:5ad: RAX(0x20:5ad) = SUB84(0x20:5ad,RBX(0x30:2),#0x0:4)",
         "0x20:5ad: RAX(0x20:5ad) = SUB84(0x20:5ad,RBX(0x30:2),#0x1:4)",
         "0x20:4d6: RAX(0x20:4d6) = SUB84(0x20:4d6,RBX(0x30:2),#0x0:4)",
         "0x20:4d6: RAX(0x20:4d6) = SUB84(0x20:4d6,RBX(0x30:2),#0x1:4)"),
        # const_width: identical text except '#0x0' vs '#0x0:4'
        ("0x40:9: RAX(0x40:9) = SUB84(0x40:9,RBX(0x30:2),#0x0)",
         "0x40:9: RAX(0x40:9) = SUB84(0x40:9,RBX(0x30:2),#0x1)",
         "0x40:9: RAX(0x40:9) = SUB84(0x40:9,RBX(0x30:2),#0x0:4)",
         "0x40:9: RAX(0x40:9) = SUB84(0x40:9,RBX(0x30:2),#0x1:4)"),
        # opcode_name: same seqnum, call vs callind operator spelling
        ("0x50:12: RAX(0x50:12) = call ffunc_2530(RDI(0x60:3))",
         "0x50:12: RAX(0x50:12) = call ffunc_2530(RDI(0x60:3))",
         "0x50:12: RAX(0x50:12) = callind r0x00016fa0",
         "0x50:12: RAX(0x50:12) = callind r0x00016fa0"),
        # other: same identifiers, different constant value
        ("0x70:15: RAX(0x70:15) = RBX(0x30:2) + #0x8",
         "0x70:15: RAX(0x70:15) = RBX(0x30:2) + #0x8",
         "0x70:15: RAX(0x70:15) = RBX(0x30:2) + #0x10",
         "0x70:15: RAX(0x70:15) = RBX(0x30:2) + #0x10"),
    ]
    left = load_drill_from(make_drill(
        "oracle",
        [(1, "oppool2:test", [(o_b, o_a) for o_b, o_a, _, _ in pairs], False)],
        {"records": "5"}), "o.drill")
    right = load_drill_from(make_drill(
        "rugra",
        [(1, "oppool2:test", [(r_b, r_a) for _, _, r_b, r_a in pairs], False)],
        {"records": "5"}), "r.drill")
    report = build_report(left, right)
    stats = report["classification"]
    for category in ("dead_marker", "seqnum_drift", "const_width",
                     "opcode_name", "other"):
        check(stats[category] == 2,
              f"{category}: expected 2 (before+after), got {stats[category]}")
    check(stats["differing_line_pairs"] == 10, "10 differing line pairs")
    check(stats["unpaired_op_records"] == 0, "no unpaired ops")
    census = stats["const_census"]
    census_map = {form["form"]: form for form in census["differing_forms"]}
    check(census_map["#0x0"]["oracle"] == 1 and census_map["#0x0"]["rugra"] == 0,
          "census: oracle #0x0 bare form x1 (before line only)")
    check(census_map["#0x0:4"]["oracle"] == 1
          and census_map["#0x0:4"]["rugra"] == 2,
          "census: #0x0:4 forms (seqnum-pair before both sides, plus rudra "
          "width-pair before)")
    check(census["oracle_bare"] > 0 and census["rudra_explicit_width"] > 0,
          "census aggregate counters populated")


def scenario_done_stats():
    oracle_blocks = [(1, "universal:start", None, True)]
    left = load_drill_from(make_drill(
        "oracle", oracle_blocks,
        {"applications": "3", "records": "1", "opactdbg_final": "1",
         "perform_calls": "311", "final_return": "1269", "nodes": "232"}),
        "o.drill")
    right = load_drill_from(make_drill(
        "rugra", oracle_blocks,
        {"applications": "5", "records": "1", "opactdbg_final": "1",
         "perform_calls": "480", "nodes": "78"}),
        "r.drill")
    report = build_report(left, right)
    done = report["done"]
    check(done["differing"] == ["applications", "nodes", "perform_calls"],
          "differing done keys")
    check(done["oracle_only_keys"] == ["final_return"],
          "final_return missing on rudra side")
    check(report["differences"], "done stats differences flag report")


def scenario_format_error():
    text = ("META side=oracle func=x\n"
            "0x10:5: **\n"
            "   0x10:5: DF(0x10:5) = #0x0:1\n"
            "@DONE applications=0\n")
    try:
        load_drill_from(text, "bad.drill")
    except FormatError:
        return
    raise AssertionError("record outside @BEGIN must raise FormatError")


def scenario_exit_codes():
    """main() exit contract: 0 identical, 1 differences, 2 format error."""
    import io
    import tempfile
    from contextlib import redirect_stdout

    blocks = [(1, "universal:constbase",
               [("0x10:1: **", "0x10:1: DF(0x10:1) = #0x0:1")], False)]
    same = make_drill("oracle", blocks, {"applications": "1"})
    other = make_drill("rugra", [(1, "universal:constbase",
                                  [("0x20:1: **",
                                    "0x20:1: DF(0x20:1) = #0x0:1")], False)],
                       {"applications": "1"})
    bad = "META side=oracle\nnope\n@DONE applications=0\n"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "a.drill").write_text(same)
        (tmp_path / "b.drill").write_text(other)
        (tmp_path / "bad.drill").write_text(bad)
        with redirect_stdout(io.StringIO()):
            check(main([str(tmp_path / "a.drill"),
                        str(tmp_path / "a.drill")]) == 0,
                  "identical -> exit 0")
            check(main([str(tmp_path / "a.drill"),
                        str(tmp_path / "b.drill")]) == 1,
                  "differences -> exit 1")
            check(main([str(tmp_path / "a.drill"),
                        str(tmp_path / "bad.drill")]) == 2,
                  "format error -> exit 2")
        try:
            main([])
        except SystemExit as exc:  # argparse usage error path
            check(exc.code == 2, f"usage error -> exit 2, got {exc.code}")
        else:
            raise AssertionError("missing operands must exit via argparse")


SELFTEST_SCENARIOS = (
    ("identical_match", scenario_identical),
    ("path_layer_counts", scenario_path_layer),
    ("first_divergence", scenario_first_divergence),
    ("prefix_length", scenario_prefix_length),
    ("classification", scenario_classification),
    ("done_stats", scenario_done_stats),
    ("format_error", scenario_format_error),
    ("exit_codes", scenario_exit_codes),
)


def run_selftest() -> int:
    passed = 0
    failures = []
    for name, func in SELFTEST_SCENARIOS:
        try:
            func()
            passed += 1
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001 - report every failure
            failures.append((name, exc))
            print(f"FAIL {name}: {exc}")
    total = len(SELFTEST_SCENARIOS)
    print(f"drill_diff selftest: {passed}/{total} scenarios passed")
    if failures:
        for name, exc in failures:
            print(f"  failed: {name}: {exc}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="drill_diff.py",
        description=(
            "Compare two v2 drill files across four observation layers: "
            "path-level application alignment, first record divergence, "
            "record content classification, and @DONE statistics. Pure "
            "consumer of drill files; changes no pipeline semantics "
            "(RUDRA-GLUE)."
        ),
    )
    parser.add_argument(
        "left", nargs="?", help="left drill file (typically oracle side)")
    parser.add_argument(
        "right", nargs="?", help="right drill file (typically rudra side)")
    parser.add_argument(
        "--json", action="store_true",
        help="emit a machine-readable JSON report")
    parser.add_argument(
        "--top", type=int, default=10, metavar="N",
        help="show top N shared-path count deltas (default 10)")
    parser.add_argument(
        "--max-examples", type=int, default=3, metavar="N",
        help="classification examples per category (default 3)")
    parser.add_argument(
        "--selftest", action="store_true",
        help="run built-in synthetic selftest (exit 0 on pass)")
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest()
    if not args.left or not args.right:
        parser.error("two drill files are required (left right)")

    try:
        left = load_drill(args.left)
        right = load_drill(args.right)
    except FormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(left, right, max_examples=max(0, args.max_examples))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(human_report(report, top=max(0, args.top)))

    return 0 if not report["differences"] else 1


if __name__ == "__main__":
    sys.exit(main())
