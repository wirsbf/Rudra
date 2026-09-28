#!/usr/bin/env python3
"""cycle_ratchet.py — 生产 types 图环棘轮（HHMIRROR A2.5 落地版）。

来源与方法: docs/alignment_docs/LANE_HHMIRROR_2026-09-26.md §1/§5/§7.4
（原工具 /dev/shm/hhmirror_tmp/type_deps3.py v3 FINAL 方法的复刻 + 棘轮断言层）。

口径（与 HHMIRROR v3 逐项一致,勿改——改口径=换基线,必须重新冻结）:
  1. 生产/测试切割: 每文件在首个行首 `#[cfg(test)]` 处截断（v1 假阳性修复: 测试内
     struct OwnershipGraph { fd: Funcdata } 曾误计为生产边）。
  2. 导入解析: `use crate::/super::/self::` 裸名解析（v2 re.M 修复后 PcodeOp.output→
     Varnode 等边才可见）; 模块名归一到 crate 路径首段（v3: type_system::datatype →
     type_system,与 crate::type_system:: 引用口径一致,消灭幻影节点）。
  3. lib.rs 再导出归位: `use crate::X;` 根级裸名经 lib.rs `pub use` 表解析回真实模块
     （如 crate::AddressSpace → space）。HHMIRROR 原工具此处留幻影节点,本工具归位
     （冻结基线以本口径为准,2026-09-26 实测与 HHMIRROR 24-SCC 恒等）。
  4. sink 图 = struct/enum/union 字段依赖 + 被持有 trait（dyn X 字段持有）的签名依赖
     （无人持有的 trait/分析器 struct/类型别名/impl 块一律浮动,不算边——即 A2 的
     "types 下沉 + impl 浮顶" 语义投影）。
  5. Tarjan SCC,只看多模块 SCC（size>1）。自环（mod→mod）是模块内类型互指,不构成
     跨模块分层事件;冻结 SCC 成员的自环边照常入白名单,solo 模块自环只记 INFO。

断言（任一 FAIL 即退出码 1）:
  (a) 每个多模块 SCC 的成员集 ⊆ FROZEN_SCC（24 模块冻结集;新成员入环=FAIL,列出
      新成员及其入环边）。
  (b) SCC 内每条边（含自环）的每条证据（哪个 struct 字段/哪个被持有 trait 签名）必须
      在 FROZEN_EDGES 白名单内（键=from|to|form|item|anchor,行号不进键——行号会漂移,
      边形态才是身份）。白名单外证据=FAIL。E1-E16 逐边分类账本见
      docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md。
  (c) FROZEN_SOLO（solo 基线,v3 折叠粒度 56 模块）中任何模块落入多模块 SCC = FAIL。
      （口径 reconciliation: HHMIRROR 报告的 "74/98" 是 v2 每文件粒度;权威 24-SCC 来自
      v3 折叠粒度,同粒度 solo 基线 = 56/80。两数并存只是粒度差,不是矛盾。）
  改善方向（SCC 变小/白名单边消失/模块出环）不 FAIL,打 [INFO] 提示重新冻结。

维护规程（白名单只进不漏）: 任何新增环边必须先按 HHMIRROR §2 方法逐边定性
（亲核 Rust 字段/trait 签名 + Ghidra .hh 前置声明/include 对应行,给出 a/b/c 分类与
处置方案）,登记入 docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md 账本后,方可
`--emit-freeze --accept-new` 重新冻结。禁止直接改 FROZEN_* 常量塞进新边。

用法:
  python3 tools/cycle_ratchet.py                 # 对本仓库 src/ 跑棘轮
  python3 tools/cycle_ratchet.py --src <dir>     # 对指定树（变异测试用）
  python3 tools/cycle_ratchet.py --json out.json # 机器可读报告
  python3 tools/cycle_ratchet.py --emit-freeze   # 打印当前树冻结基线字面量（维护用）
退出码: 0=PASS 1=FAIL（棘轮违规） 2=用法/内部错误
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ============================================================================
# 冻结基线（HHMIRROR 2026-09-26 @ master 9ac04ade 实测;改动需走维护规程）
# ============================================================================
# fmt: off
FROZEN_SCC = [
    "action",
    "arch",
    "block",
    "cover",
    "cpool",
    "database",
    "drillobserve",
    "fspec",
    "funcdata",
    "heritage",
    "jumptable",
    "merge",
    "op",
    "options",
    "pcodeinject",
    "pcodeparse",
    "prefersplit",
    "transform",
    "type_system",
    "unionresolve",
    "userop",
    "variable",
    "varmap",
    "varnode",
]
FROZEN_SOLO = [
    "address",
    "align",
    "analysis",
    "bin",
    "binary",
    "blockaction",
    "callgraph",
    "capability",
    "comment",
    "compression",
    "condexe",
    "constseq",
    "context",
    "coreaction",
    "crc32",
    "debugproto",
    "disasm",
    "double_precis",
    "drillfmt",
    "dynamic",
    "emulate",
    "error",
    "expression",
    "ffi",
    "float_emulate",
    "flow",
    "frontend",
    "grammar",
    "graph",
    "lib",
    "loadimage",
    "marshal",
    "memstate",
    "modelrules",
    "opbehavior",
    "opcodes",
    "override_rs",
    "paramid",
    "pcoderaw",
    "prettyprint",
    "printc",
    "printlanguage",
    "rangemap",
    "rangeutil",
    "ruleaction",
    "sailr",
    "signature",
    "sleigh_ffi",
    "space",
    "stringmanage",
    "subflow",
    "tracedag",
    "translate",
    "typeop",
    "types",
    "unify",
    "utils",
]  # v3 折叠粒度 solo 基线（2026-09-26 冻结;HHMIRROR "74/98" 为 v2 每文件粒度,见口径 reconciliation）
# intra-SCC 边证据白名单: "from->to" -> "form|item|anchor" 键集合（行号不进键）
FROZEN_EDGES = {
    "action->action": [
        'dyn-hold|struct ActionDatabase|Action',
        'dyn-hold|struct ActionGroup|Action',
        'dyn-hold|struct ActionPool|Rule',
    ],
    "action->drillobserve": [
        'held-trait-sig|via dyn Action sig|Action',
    ],
    "action->funcdata": [
        'held-trait-sig|via dyn Action sig|Action',
        'held-trait-sig|via dyn Rule sig|Rule',
    ],
    "action->op": [
        'field|struct ActionPool|op_state',
        'held-trait-sig|via dyn Rule sig|Rule',
    ],
    "arch->action": [
        'field|struct Architecture|allacts',
    ],
    "arch->arch": [
        'dyn-hold|struct CapabilityRegistry|ArchitectureCapability',
    ],
    "arch->cpool": [
        'field|struct Architecture|cpool',
    ],
    "arch->database": [
        'field|struct Architecture|symboltab',
    ],
    "arch->fspec": [
        'field|struct Architecture|default_return_addr',
        'field|struct Architecture|defaultfp',
        'field|struct Architecture|evalfp_called',
        'field|struct Architecture|evalfp_current',
        'field|struct TrackedRegister|loc',
    ],
    "arch->options": [
        'field|struct Architecture|options_db',
    ],
    "arch->pcodeinject": [
        'field|struct Architecture|pcodeinjectlib',
    ],
    "arch->prefersplit": [
        'field|struct Architecture|split_records',
    ],
    "arch->transform": [
        'field|struct Architecture|lane_records',
    ],
    "arch->type_system": [
        'field|struct Architecture|types',
    ],
    "arch->userop": [
        'field|struct Architecture|userops',
    ],
    "block->block": [
        'dyn-hold|struct BlockBasic|FlowBlock',
        'dyn-hold|struct BlockCondition|FlowBlock',
        'dyn-hold|struct BlockCopy|FlowBlock',
        'dyn-hold|struct BlockDoWhile|FlowBlock',
        'dyn-hold|struct BlockEdge|FlowBlock',
        'dyn-hold|struct BlockGoto|FlowBlock',
        'dyn-hold|struct BlockGraph|FlowBlock',
        'dyn-hold|struct BlockIf|FlowBlock',
        'dyn-hold|struct BlockInfLoop|FlowBlock',
        'dyn-hold|struct BlockList|FlowBlock',
        'dyn-hold|struct BlockMultiGoto|FlowBlock',
        'dyn-hold|struct BlockRef|FlowBlock',
        'dyn-hold|struct BlockSwitch|FlowBlock',
        'dyn-hold|struct BlockWhileDo|FlowBlock',
        'dyn-hold|struct CaseOrder|FlowBlock',
    ],
    "block->jumptable": [
        'field|struct BlockSwitch|jump',
    ],
    "block->op": [
        'field|struct BlockBasic|ops',
        'field|struct BlockWhileDo|initialize_op',
        'field|struct BlockWhileDo|iterate_op',
        'field|struct BlockWhileDo|loop_def',
        'held-trait-sig|via dyn FlowBlock sig|FlowBlock',
    ],
    "block->varnode": [
        'field|struct BlockSwitch|index_varnode',
    ],
    "cover->cover": [
        'dyn-hold|struct PcodeOpSet|PcodeOpSetImpl',
    ],
    "cover->op": [
        'held-trait-sig|via dyn PcodeOpSetImpl sig|PcodeOpSetImpl',
    ],
    "cover->varnode": [
        'held-trait-sig|via dyn PcodeOpSetImpl sig|PcodeOpSetImpl',
    ],
    "cpool->type_system": [
        'field|struct CPoolRecord|data_type',
    ],
    "database->type_system": [
        'field|struct QueryContainerHit|symbol_type',
        'field|struct QueryContainerHit|type_metatype',
        'field|struct Symbol|dtype',
    ],
    "drillobserve->arch": [
        'field|struct Recorder|arch',
    ],
    "drillobserve->op": [
        'field|struct Recorder|modify_list',
    ],
    "fspec->op": [
        'field|struct FuncCallSpecs|op',
    ],
    "fspec->type_system": [
        'field|struct FuncCallSpecs|proto_model',
        'field|struct FuncProto|return_type',
        'field|struct ParameterPieces|ty',
        'field|struct ProtoParameter|data_type',
        'field|struct PrototypePieces|in_types',
        'field|struct PrototypePieces|out_type',
    ],
    "funcdata->arch": [
        'field|struct Funcdata|arch',
    ],
    "funcdata->block": [
        'field|struct Funcdata|bblocks',
        'field|struct Funcdata|sblocks',
    ],
    "funcdata->database": [
        'field|struct Funcdata|symbol_entry_cache',
    ],
    "funcdata->fspec": [
        'field|struct Funcdata|active_output',
        'field|struct Funcdata|callspecs',
        'field|struct Funcdata|funcp',
    ],
    "funcdata->heritage": [
        'field|struct Funcdata|heritage',
    ],
    "funcdata->jumptable": [
        'field|struct Funcdata|jump_tables',
    ],
    "funcdata->merge": [
        'field|struct Funcdata|merge_state',
    ],
    "funcdata->op": [
        'field|struct Funcdata|modify_list',
        'field|struct Funcdata|obank',
    ],
    "funcdata->transform": [
        'field|struct Funcdata|std',
    ],
    "funcdata->type_system": [
        'field|struct Funcdata|global_struct_ptrs',
    ],
    "funcdata->unionresolve": [
        'field|struct Funcdata|crate',
    ],
    "funcdata->varmap": [
        'field|struct Funcdata|scope',
    ],
    "funcdata->varnode": [
        'field|struct Funcdata|vbank',
    ],
    "heritage->op": [
        'field|struct Heritage|load_copy_ops',
        'field|struct LoadGuard|op',
    ],
    "heritage->varnode": [
        'field|struct StackWalkNode|vn',
    ],
    "jumptable->funcdata": [
        'field|struct EmulateFunction|fd',
        'held-trait-sig|via dyn JumpModel sig|JumpModel',
    ],
    "jumptable->jumptable": [
        'dyn-hold|struct JumpBasic|JumpValues',
        'dyn-hold|struct JumpTable|JumpModel',
    ],
    "jumptable->op": [
        'field|struct EmulateFunction|current_op',
        'field|struct EmulateFunction|last_op',
        'field|struct GuardRecord|cbranch',
        'field|struct GuardRecord|read_op',
        'field|struct JumpAssisted|assist_op',
        'field|struct JumpAssisted|calc_op',
        'field|struct JumpAssisted|indop',
        'field|struct JumpParentFacts|indirect',
        'field|struct JumpTable|indirect',
        'field|struct JumpValuesRangeDefault|extraop',
        'field|struct JumpValuesRange|startop',
        'field|struct PcodeOpNode|op',
        'field|struct RootedOp|op',
        'held-trait-sig|via dyn JumpModel sig|JumpModel',
        'held-trait-sig|via dyn JumpValues sig|JumpValues',
    ],
    "jumptable->varnode": [
        'field|struct GuardRecord|base_vn',
        'field|struct GuardRecord|vn',
        'field|struct JumpAssisted|switchvn',
        'field|struct JumpBasic2|extra_vn',
        'field|struct JumpBasic|normalvn',
        'field|struct JumpBasic|switchvn',
        'field|struct JumpValuesRangeDefault|extravn',
        'field|struct JumpValuesRange|normqvn',
        'field|struct PathMeld|common_vn',
        'held-trait-sig|via dyn JumpModel sig|JumpModel',
        'held-trait-sig|via dyn JumpValues sig|JumpValues',
    ],
    "merge->op": [
        'field|struct MergePersistentState|copy_trims',
        'field|struct MergePersistentState|proto_partial',
        'field|struct MergeTypeIntersectCache|stack_affecting_ops',
        'field|struct Merge|copy_trims',
    ],
    "merge->type_system": [
        'field|enum LocalTypeKey|Base',
        'field|enum LocalTypeKey|BaseNoChar',
    ],
    "merge->varnode": [
        'field|struct AddrTiedLocRange|members',
        'field|struct BlockVarnode|vn',
    ],
    "op->block": [
        'dyn-hold|struct PcodeOp|FlowBlock',
        'field|struct PcodeOp|parent',
    ],
    "op->op": [
        'held-trait-sig|via dyn FlowBlock sig|FlowBlock',
    ],
    "op->varnode": [
        'field|struct PcodeOp|inrefs',
        'field|struct PcodeOp|output',
    ],
    "options->arch": [
        'held-trait-sig|via dyn ArchOption sig|ArchOption',
    ],
    "options->options": [
        'dyn-hold|struct OptionDatabase|ArchOption',
    ],
    "pcodeinject->pcodeparse": [
        'dyn-hold|struct PcodeInjectLibrary|SleighSymbolLookup',
        'field|struct InjectPayload|tpl',
        'field|struct PcodeInjectLibrary|sleigh',
    ],
    "pcodeparse->pcodeparse": [
        'dyn-hold|struct PcodeSnippet|SleighSymbolLookup',
    ],
    "pcodeparse->varnode": [
        'field|enum SleightSymbolKind|Varnode',
        'field|struct PcodeData|invar',
        'field|struct PcodeData|outvar',
    ],
    "prefersplit->funcdata": [
        'field|struct PreferSplitManager|data',
    ],
    "prefersplit->op": [
        'field|struct PreferSplitManager|tempsplits',
    ],
    "prefersplit->varnode": [
        'field|struct SplitInstance|hi',
        'field|struct SplitInstance|lo',
        'field|struct SplitInstance|vn',
    ],
    "transform->funcdata": [
        'field|struct TransformManager|fd',
    ],
    "transform->op": [
        'field|struct TransformOp|op',
        'field|struct TransformOp|replacement',
    ],
    "transform->varnode": [
        'field|struct TransformManager|preserve_address_override',
        'field|struct TransformVar|replacement',
        'field|struct TransformVar|vn',
    ],
    "type_system->database": [
        'field|enum LiveSpacebaseMap|Global',
        'field|enum SpacebaseMap|Global',
        'field|struct TypeFactory|symboltab',
        'field|struct TypeSpacebase|scope',
    ],
    "type_system->fspec": [
        'field|struct TypeCode|proto',
    ],
    "type_system->varmap": [
        'field|enum LiveSpacebaseMap|Local',
        'field|enum SpacebaseMap|Local',
        'field|struct TypeFactory|live_local_scopes',
        'field|struct TypeSpacebase|fd',
    ],
    "unionresolve->funcdata": [
        'field|struct ScoreUnionFields|fd',
    ],
    "unionresolve->op": [
        'field|struct Trial|op',
    ],
    "unionresolve->type_system": [
        'field|struct ResolvedUnion|base_type',
        'field|struct ResolvedUnion|resolve',
        'field|struct ScoreUnionFields|fields',
        'field|struct ScoreUnionFields|typegrp',
        'field|struct Trial|fit_type',
    ],
    "unionresolve->varnode": [
        'field|struct Trial|vn',
    ],
    "userop->fspec": [
        'field|struct SegmentOp|constresolve',
    ],
    "userop->type_system": [
        'field|enum UserOpType|Datatype',
        'field|struct UserPcodeOp|local_input_types',
        'field|struct UserPcodeOp|local_output_type',
    ],
    "variable->cover": [
        'field|struct HighVariable|cover',
        'field|struct VariablePiece|cover',
    ],
    "variable->database": [
        'field|struct HighVariable|symbol',
    ],
    "variable->type_system": [
        'field|struct TypeCell|pub struct TypeCell(pub RwLock<Arc<Datatype>>)',
    ],
    "variable->varnode": [
        'field|struct HighVariable|instances',
        'field|struct HighVariable|name_representative',
    ],
    "varmap->arch": [
        'field|struct ScopeLocal|arch_lookup',
    ],
    "varmap->database": [
        'field|struct ScopeLocal|std',
    ],
    "varmap->type_system": [
        'field|struct LocalSymbol|dtype',
        'field|struct MapState|default_type',
        'field|struct RangeHint|dtype',
        'field|struct TypeRecommend|dtype',
    ],
    "varmap->varnode": [
        'field|struct AddBase|base',
        'field|struct AddBase|index',
    ],
    "varnode->cover": [
        'field|struct Varnode|cover',
    ],
    "varnode->database": [
        'field|struct Varnode|mapentry',
    ],
    "varnode->fspec": [
        'field|struct Varnode|call_spec',
    ],
    "varnode->op": [
        'field|struct Varnode|def',
        'field|struct Varnode|descend',
    ],
    "varnode->type_system": [
        'field|struct VarnodeBank|type_factory',
        'field|struct Varnode|v_type',
    ],
    "varnode->variable": [
        'field|struct Varnode|high',
    ],
}
# fmt: on

# SCC 内边分类账本（HHMIRROR E1-E16 家族归属;报告/维护用,不参与机器判定——
# 机器判定只看 FROZEN_EDGES 键成员资格）。
# 形态类: a=可解(下沉/浮动) b=伪影 c=真互持/锁死 glue=RUGRA-GLUE 偏离
PAIR_TAGS: dict[str, tuple[str, str, str]] = {
    # --- E7 (c) op↔varnode↔variable↔block 互持字段组（.hh 前置声明隐形边） ---
    "op->varnode":       ("E7",    "c", "PcodeOp.output/inrefs ↔ Varnode.def/descend 互持"),
    "varnode->op":       ("E7",    "c", "Varnode.def/descend: Weak<PcodeOp>"),
    "varnode->variable": ("E7",    "c", "Varnode.high ↔ HighVariable.instances"),
    "variable->varnode": ("E7",    "c", "HighVariable.instances/name_representative"),
    "op->block":         ("E7",    "c", "PcodeOp.parent: Weak<dyn FlowBlock>"),
    "block->op":         ("E7",    "c", "BlockBasic.ops + BlockWhileDo ops 字段 + FlowBlock 签名族"),
    "op->op":            ("E7",    "c", "FlowBlock 签名拉入（get_ops/first_op 族）"),
    "block->block":      ("E7",    "c", "16 个 Block* struct 持 dyn FlowBlock（族内互持）"),
    # --- E9 家族 (a) funcdata↔卫星 + 枢纽持有面 ---
    "funcdata->arch":        ("E9", "a", "Funcdata.arch（funcdata.hh:22-27 include 面同构）"),
    "funcdata->block":       ("E9", "a", "Funcdata.bblocks/sblocks"),
    "funcdata->database":    ("E9", "a", "Funcdata.symbol_entry_cache"),
    "funcdata->fspec":       ("E9", "a", "Funcdata.funcp/callspecs/active_output"),
    "funcdata->heritage":    ("E9", "a", "Funcdata.heritage（旗舰案例: 卫星 types 干净可沉）"),
    "funcdata->merge":       ("E9", "a", "Funcdata.merge_state"),
    "funcdata->transform":   ("E9", "a", "Funcdata 内联字段（LanedRegister 容器）"),
    "funcdata->type_system": ("E9", "a", "Funcdata.global_struct_ptrs"),
    "funcdata->unionresolve": ("E9", "a", "Funcdata.union_map（ResolvedUnion/ResolveEdge 干净可沉）"),
    "funcdata->varmap":      ("E9", "a", "Funcdata.scope"),
    "funcdata->varnode":     ("E9", "a", "Funcdata.vbank"),
    "funcdata->op":          ("E9", "a", "Funcdata.modify_list/obank"),
    "heritage->block":       ("E9", "a", "卫星内部: InsertAnchor/WorkItem 持 dyn FlowBlock"),
    "heritage->op":          ("E9", "a", "卫星内部: LoadGuard.op/Heritage.load_copy_ops"),
    "heritage->varnode":     ("E9", "a", "卫星内部: StackWalkNode.vn"),
    "merge->op":             ("E9", "a", "卫星内部: Merge*/MergePersistentState 字段"),
    "merge->varnode":        ("E9", "a", "卫星内部: AddrTiedLocRange/BlockVarnode"),
    "merge->type_system":    ("E9", "a", "卫星内部: LocalTypeKey(TypeMetatype)"),
    "unionresolve->op":      ("E9", "a", "卫星内部: Trial.op"),
    "unionresolve->varnode": ("E9", "a", "卫星内部: Trial.vn"),
    "unionresolve->type_system": ("E9", "a", "卫星内部: ResolvedUnion/Trial/ScoreUnionFields Datatype 字段"),
    # --- E9-ARCH (a) Architecture 枢纽持有面（architecture.hh:21-35 同构） ---
    "arch->action":     ("E9-ARCH", "a", "Architecture.allacts（E13 持有链的持有侧）"),
    "arch->arch":       ("E9-ARCH", "a", "CapabilityRegistry 持 dyn ArchitectureCapability（族内）"),
    "arch->cpool":      ("E9-ARCH", "a", "Architecture.cpool"),
    "arch->database":   ("E9-ARCH", "a", "Architecture.symboltab"),
    "arch->fspec":      ("E9-ARCH", "a", "Architecture.defaultfp/evalfp*/TrackedRegister.loc"),
    "arch->pcodeinject": ("E9-ARCH", "a", "Architecture.pcodeinjectlib"),
    "arch->prefersplit": ("E9-ARCH", "a", "Architecture.split_records"),
    "arch->transform":  ("E9-ARCH", "a", "Architecture.lane_records"),
    "arch->userop":     ("E9-ARCH", "a", "Architecture.userops"),
    # --- 下层 oracle 本体字段边（.hh include 序合法下行,字段物化） ---
    "block->jumptable": ("SCC-BASE", "a", "BlockSwitch.jump（block.hh:462-473 同构）"),
    "block->varnode":   ("SCC-BASE", "a", "BlockSwitch.index_varnode"),
    "cpool->type_system": ("SCC-BASE", "a", "CPoolRecord.data_type"),
    "database->type_system": ("SCC-BASE", "a", "Symbol.dtype/QueryContainerHit（database.hh 同构）"),
    "fspec->op":        ("SCC-BASE", "a", "FuncCallSpecs.op: Weak<PcodeOp>"),
    "pcodeparse->varnode": ("SCC-BASE", "a", "VarnodeData 字段（SleightSymbolKind/PcodeData）"),
    "prefersplit->funcdata": ("SCC-BASE", "a", "PreferSplitManager.data: *mut Funcdata（oracle 指针字段）"),
    "prefersplit->op":  ("SCC-BASE", "a", "PreferSplitManager.tempsplits"),
    "prefersplit->varnode": ("SCC-BASE", "a", "SplitInstance.vn/hi/lo"),
    "transform->funcdata": ("SCC-BASE", "a", "TransformManager.fd: *mut Funcdata（oracle 指针字段）"),
    "transform->op":    ("SCC-BASE", "a", "TransformOp.op/replacement"),
    "transform->varnode": ("SCC-BASE", "a", "TransformVar.vn/replacement"),
    "type_system->database": ("SCC-BASE", "a", "TypeSpacebase.scope/TypeFactory.symboltab（type.hh:725/database.hh 同构）"),
    "userop->fspec":    ("SCC-BASE", "a", "SegmentOp.constresolve: VarnodeData"),
    "userop->type_system": ("SCC-BASE", "a", "UserPcodeOp local types/enum 判别值"),
    "variable->cover":  ("SCC-BASE", "a", "HighVariable/VariablePiece.cover"),
    "variable->database": ("SCC-BASE", "a", "HighVariable.symbol"),
    "variable->type_system": ("SCC-BASE", "a", "TypeCell(pub RwLock<Arc<Datatype>>)"),
    "varmap->type_system": ("SCC-BASE", "a", "RangeHint/MapState/LocalSymbol/TypeRecommend dtype"),
    "varmap->varnode":  ("SCC-BASE", "a", "AddBase.base/index"),
    "varnode->cover":   ("SCC-BASE", "a", "Varnode.cover（varnode.hh:143-150 同构）"),
    "varnode->database": ("SCC-BASE", "a", "Varnode.mapentry"),
    "varnode->type_system": ("SCC-BASE", "a", "Varnode.v_type/VarnodeBank.type_factory"),
    # --- 被持有 trait 签名族（E13/E14/E15 同款机制,E 表未逐条列出的家族） ---
    "cover->cover":     ("TRAIT-SIG", "c", "PcodeOpSet 持 dyn PcodeOpSetImpl（族内）"),
    "cover->op":        ("TRAIT-SIG", "c", "PcodeOpSetImpl 签名 op: &PcodeOp"),
    "cover->varnode":   ("TRAIT-SIG", "c", "PcodeOpSetImpl 签名 vn: &Varnode"),
    "pcodeinject->pcodeparse": ("TRAIT-SIG", "c", "持 dyn SleighSymbolLookup + InjectPayload.tpl: ConstructTpl"),
    "pcodeparse->pcodeparse": ("TRAIT-SIG", "c", "PcodeSnippet 持 dyn SleighSymbolLookup（族内）"),
    # --- E12 (a+GLUE) drill 双件 + Action 默认体 GLUE 阻断 ---
    "action->drillobserve": ("E12", "glue", "Action trait 默认方法体调 drillobserve::activate（HHMIRROR: 需移出默认体）"),
    "drillobserve->arch": ("E12", "a", "Recorder.arch（drill 双件浮顶后消解）"),
    "drillobserve->op":  ("E12", "a", "Recorder.modify_list"),
    # --- E13 (c) Action/Rule trait 签名→funcdata ---
    "action->funcdata": ("E13", "c", "Action/Rule 签名 fd: &mut Funcdata（action.hh:102/120 fwd-decl 承载）"),
    "action->op":       ("E13", "c", "Rule 签名 op 参数 + ActionPool.op_state"),
    "action->action":   ("E13", "c", "ActionGroup/ActionPool/ActionDatabase 持 dyn Action/Rule（族内）"),
    # --- E14 (c) ArchOption trait 签名→arch ---
    "options->arch":    ("E14", "c", "ArchOption::apply 签名 arch: &mut Architecture（options.hh:27 fwd-decl）"),
    "options->options": ("E14", "c", "OptionDatabase 持 dyn ArchOption（族内）"),
    "arch->options":    ("E14", "c", "Architecture.options_db（E14 持有侧）"),
    # --- E15 (c) JumpModel trait 签名→funcdata ---
    "jumptable->funcdata": ("E15", "c", "JumpModel 7 签名族 recover_model(fd)（jumptable.hh:249-260）+ EmulateFunction.fd"),
    "jumptable->jumptable": ("E15", "c", "JumpTable 持 dyn JumpModel/JumpBasic 持 dyn JumpValues（族内）"),
    "jumptable->op":    ("E15", "c", "JumpModel 签名 indop + Jump* 字段族"),
    "jumptable->varnode": ("E15", "c", "JumpModel/JumpValues 签名 + Jump* 字段族"),
    "funcdata->jumptable": ("E15", "c", "Funcdata.jump_tables（E15 持有侧）"),
    # --- E16 (c) type_system 反转环 ×2 ---
    "type_system->varmap": ("E16-1", "c", "TypeSpacebase.fd: ScopeLocal + TypeFactory.live_local_scopes（type.hh:725 同构）"),
    "varmap->arch":     ("E16-1", "c", "ScopeLocal.arch_lookup: Architecture"),
    "varmap->database": ("E9", "a", "ScopeLocal.live_symbols: ScopeInternal 符号表活句柄 memo（varmap.hh:22 include database.hh + :212 继承同构;E9 funcdata→database symbol_entry_cache 同族;MB31 定性入账）"),
    "arch->type_system": ("E16-1", "c", "Architecture.types: TypeFactory（3-环闭包边）"),
    "type_system->fspec": ("E16-2", "c", "TypeCode.proto: FuncProto（type.hh:696）"),
    "fspec->type_system": ("E16-2", "c", "FuncCallSpecs.proto_model: ProtoModel（2-环闭包边;另有 Datatype 字段族）"),
    # --- RUGRA-GLUE 偏离（HHMIRROR §2 尾注/§3） ---
    "varnode->fspec":   ("GLUE", "glue", "Varnode.call_spec: Weak<FuncCallSpecs>（Ghidra 编码在 IPTR_FSPEC 整数,varnode L7 < fspec L12 倒置）"),
    "unionresolve->funcdata": ("GLUE", "glue", "ScoreUnionFields.fd: &Funcdata（Ghidra 从 op->getParent()->getFuncdata() 派生,Rust 穿参）"),
}

# ============================================================================
# 分析器（HHMIRROR type_deps3 v3 方法）
# ============================================================================
ITEM_START = re.compile(
    r"^\s*(?:pub(?:\([a-z]+\))?\s+)?(struct|enum|trait|union)\s+([A-Z][A-Za-z0-9_]*)")
TYPE_ALIAS = re.compile(
    r"^\s*(?:pub(?:\([a-z]+\))?\s+)?type\s+([A-Z][A-Za-z0-9_]*)\s*=")
CREF = re.compile(r"\bcrate::([a-z_][a-z_0-9]*)")
IDENT = re.compile(r"\b[A-Z][A-Za-z0-9_]*\b")
USE_LINE = re.compile(r"^\s*(?:pub\s+)?use\s+(.+?);", re.M)  # re.M 必须保留(v2 教训)
CFG_TEST = re.compile(r"^#\[cfg\(test\)\]", re.M)
REEXPORT = re.compile(r"^\s*pub\s+use\s+([a-z_][a-z_0-9]*)::\{?([^;]+)\}?\s*;", re.M)
FIELD_ANCHOR = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?([a-z_][a-z0-9_]*)\s*:")
VARIANT_ANCHOR = re.compile(r"^\s*(?:pub\s+)?([A-Z][A-Za-z0-9_]*)\s*[=(]")


def neutralize_comments(text: str) -> str:
    """把注释内容替换为等长空白（保留行号与换行结构）。

    使 USE_LINE/ITEM_START/CREF 匹配与证据行号均基于真实文件行。块注释整块填充,
    行注释填充 `//` 起的后段。已知局限: 字符串字面量内的 `//`/`/*` 会被误填充——
    生产类型定义字段不含字符串字面量,影响面为零（同 HHMIRROR 原工具口径）。
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def production_text(text: str) -> str:
    m = CFG_TEST.search(text)
    return text[: m.start()] if m else text


def module_of(path: Path, src: Path) -> str:
    rel = path.relative_to(src)
    if rel.name == "lib.rs":
        return "lib"
    if rel.name == "mod.rs":
        return str(rel.parent).split("/")[0]
    # 折叠子目录到首段: crate 引用走 crate::type_system:: 门面（v3 模块名归一）
    if rel.parent != Path("."):
        return str(rel.parent).split("/")[0]
    return rel.stem


def parse_reexports(lib_text: str) -> dict:
    out = {}
    for m in REEXPORT.finditer(lib_text):
        mod, names = m.group(1), m.group(2)
        for nm in names.replace("{", "").replace("}", "").split(","):
            nm = nm.strip().split(" as ")[0].strip()
            if re.fullmatch(r"[A-Z][A-Za-z0-9_]*", nm):
                out[nm] = mod
    return out


def parse_imports(text: str, reexports: dict) -> dict:
    """use 子句裸名 → 模块。根级再导出经 reexports 归位。"""
    name2mod = {}
    for m in USE_LINE.finditer(text):
        clause = m.group(1)
        if not clause.startswith(("crate::", "super::", "self::")):
            continue
        head, _, rest = clause.partition("{")
        hm = re.match(r"(?:crate|super|self)::([a-z_][a-z_0-9]*)", head.rstrip(": ").strip())
        if "{" in clause:
            mod = hm.group(1) if hm else None
            for nm in rest.split("}", 1)[0].split(","):
                nm = nm.strip().split(" as ")[0].strip()
                if not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", nm):
                    continue
                if mod:
                    name2mod[nm] = mod
                elif nm in reexports:  # use crate::{A, B} 根级再导出
                    name2mod[nm] = reexports[nm]
        else:
            parts = clause.split("::")
            up = next((i for i, p in enumerate(parts) if re.fullmatch(r"[A-Z][A-Za-z0-9_]*", p)), None)
            if up is not None and up >= 1:
                target = parts[up]
                if up == 1 and target in reexports:
                    name2mod[target] = reexports[target]
                else:
                    name2mod[target] = parts[1]
    return name2mod


def _brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def extract_items(padded: str):
    """提取 depth-0 的 struct/enum/trait/union/type 项。

    相比 HHMIRROR 原工具增加 depth-0 过滤: 函数体/trait 默认方法体内的局部 struct
    不计入（防局部类型幻影边;2026-09-26 实测对冻结树结果恒等）。
    返回 (kind, name, body_lines, start_line_1based) 列表。
    """
    lines = padded.split("\n")
    items, i, n = [], 0, len(lines)
    depth = 0
    while i < n:
        line = lines[i]
        if depth == 0:
            m = ITEM_START.match(line)
            ta = TYPE_ALIAS.match(line)
            if m:
                kind, name = m.group(1), m.group(2)
                depth2, started, j, body = 0, False, i, []
                while j < n:
                    ln = lines[j]
                    body.append(ln)
                    depth2 += _brace_delta(ln)
                    if "{" in ln:
                        started = True
                    if started and depth2 == 0:
                        break
                    if not started and ";" in ln:
                        break
                    j += 1
                items.append((kind, name, body, i + 1))
                i = j + 1
                continue
            if ta:
                items.append(("type", ta.group(1), [line], i + 1))
                i += 1
                continue
        depth = max(0, depth + _brace_delta(line))
        i += 1
    return items


def line_refs(ln: str, imports: dict) -> set:
    refs = set()
    for cm in CREF.finditer(ln):
        refs.add(cm.group(1))
    for im in IDENT.finditer(ln):
        if im.group(0) in imports:
            refs.add(imports[im.group(0)])
    return refs


def anchor_of(form: str, item: str, text: str) -> str:
    """证据锚: 字段名/变体名/trait 名;否则归一化文本（跨行字段的续行等）。"""
    if form == "dyn-hold":
        m = re.search(r"dyn\s+([A-Z][A-Za-z0-9_]*)", text)
        return m.group(1) if m else text.strip()
    if form == "held-trait-sig":
        m = re.match(r"via dyn ([A-Z][A-Za-z0-9_]*) sig", item)
        return m.group(1) if m else item
    m = FIELD_ANCHOR.match(text)
    if m:
        return m.group(1)
    m = VARIANT_ANCHOR.match(text)
    if m:
        return m.group(1)
    norm = re.sub(r"\s+", " ", text.strip().rstrip(",;"))
    return norm[-60:] if len(norm) > 60 else norm


def analyze(src: Path) -> dict:
    """构建生产 types 图。返回 mods/edges/evidence/items 统计。"""
    lib_path = src / "lib.rs"
    reexports = {}
    if lib_path.exists():
        reexports = parse_reexports(production_text(neutralize_comments(lib_path.read_text(errors="replace"))))

    mods = set()
    items_by_mod = {}
    for path in sorted(src.rglob("*.rs")):
        mod = module_of(path, src)
        mods.add(mod)
        padded = neutralize_comments(production_text(path.read_text(errors="replace")))
        imports = parse_imports(padded, reexports)
        for kind, name, body, start in extract_items(padded):
            items_by_mod.setdefault(mod, []).append(dict(
                kind=kind, name=name, body=body, line=start,
                imports=imports, mod=mod, path=str(path)))

    trait_mod = {}
    for mod, lst in items_by_mod.items():
        for it in lst:
            if it["kind"] == "trait":
                trait_mod[it["name"]] = mod

    def evidence_key(ev):
        return f'{ev["form"]}|{ev["item"]}|{ev["anchor"]}'

    edges: dict = {}          # from -> set(to)
    evidence: dict = {}       # (from,to) -> {key: [ev,...]}
    held_trait_holders: dict = {}  # trait -> set(mod) （报告用）

    def add_edge(fm, tm, ev):
        edges.setdefault(fm, set()).add(tm)
        evidence.setdefault((fm, tm), {}).setdefault(evidence_key(ev), []).append(ev)

    for mod, lst in items_by_mod.items():
        for it in lst:
            if it["kind"] not in ("struct", "enum", "union"):
                continue
            # ① 字段依赖（逐行）;目标过滤: 只对真实文件模块建边（幻影目标不入图）
            for off, ln in enumerate(it["body"]):
                for d in line_refs(ln, it["imports"]):
                    if d not in mods:
                        continue
                    add_edge(mod, d, dict(form="field",
                                          item=f'{it["kind"]} {it["name"]}',
                                          anchor=anchor_of("field", "", ln),
                                          line=it["line"] + off,
                                          text=ln.strip(),
                                          path=it["path"]))
            # ② dyn 持有 trait: 边 + 签名依赖拉入持有者
            seen_traits = set()
            for off, ln in enumerate(it["body"]):
                for m2 in re.finditer(r"\bdyn\s+([A-Z][A-Za-z0-9_]*)", ln):
                    t = m2.group(1)
                    if t not in trait_mod:
                        continue
                    tmod = trait_mod[t]
                    add_edge(mod, tmod, dict(form="dyn-hold",
                                             item=f'{it["kind"]} {it["name"]}',
                                             anchor=t,
                                             line=it["line"] + off,
                                             text=f"holds dyn {t}",
                                             path=it["path"]))
                    held_trait_holders.setdefault(t, set()).add(mod)
                    if t in seen_traits:
                        continue
                    seen_traits.add(t)
                    tit = next((x for x in items_by_mod.get(tmod, []) if x["kind"] == "trait" and x["name"] == t), None)
                    if tit is None:
                        continue
                    item_label = f"via dyn {t} sig"
                    for toff, tln in enumerate(tit["body"]):
                        for d in line_refs(tln, tit["imports"]):
                            if d not in mods:
                                continue
                            add_edge(mod, d, dict(form="held-trait-sig",
                                                  item=item_label,
                                                  anchor=anchor_of("held-trait-sig", item_label, ""),
                                                  line=tit["line"] + toff,
                                                  text=tln.strip(),
                                                  path=tit["path"]))
    return dict(mods=mods, edges=edges, evidence=evidence,
                held_trait_holders=held_trait_holders, items=items_by_mod)


def tarjan_scc(mods, edges):
    sys.setrecursionlimit(100000)
    counter = [0]
    stack, on = [], set()
    num, low = {}, {}
    sccs = []

    def strongconnect(v):
        num[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in sorted(edges.get(v, ())):
            if w not in num:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], num[w])
        if low[v] == num[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(sorted(comp))

    for v in sorted(mods):
        if v not in num:
            strongconnect(v)
    return sccs


# ============================================================================
# 棘轮断言
# ============================================================================
def run_ratchet(src: Path) -> dict:
    g = analyze(src)
    sccs = tarjan_scc(g["mods"], g["edges"])
    scc_multi = [c for c in sccs if len(c) > 1]
    in_multi = set()
    for c in scc_multi:
        in_multi.update(c)

    frozen_scc = set(FROZEN_SCC)
    frozen_solo = set(FROZEN_SOLO)
    frozen_edges = {k: set(v) for k, v in FROZEN_EDGES.items()}

    report = {
        "src": str(src),
        "total_modules": len(g["mods"]),
        "scc_multi": scc_multi,
        "violations": [],
        "info": [],
        "assertions": {},
    }

    # --- 断言 (a): 多模块 SCC 成员 ⊆ FROZEN_SCC ---
    new_members = sorted(in_multi - frozen_scc)
    rep_a = {"name": "(a) core-SCC membership ratchet (<= %d frozen)" % len(FROZEN_SCC),
             "ok": not new_members, "new_members": new_members}
    if new_members:
        for nm in new_members:
            host_sccs = [c for c in scc_multi if nm in c]
            # 该新成员的入环边（指向 SCC 内成员的边）
            inbound = []
            for c in host_sccs:
                for other in c:
                    if other == nm:
                        continue
                    for (fm, tm), evs in g["evidence"].items():
                        if fm == other and tm == nm and fm in c:
                            inbound.append((fm, tm, list(evs.values())[0][0]))
                        if fm == nm and tm == other and tm in c:
                            inbound.append((fm, tm, list(evs.values())[0][0]))
            rep_a["detail"] = "new SCC members: %s; witness edges: %s" % (
                new_members, sorted({(a, b) for a, b, _ in inbound}))
            for fm, tm, ev in inbound:
                report["violations"].append(dict(
                    assertion="(a)", kind="new-scc-member",
                    edge=f"{fm}->{tm}", member=nm,
                    loc=f'{ev["path"]}:{ev["line"]}',
                    form=ev["form"], item=ev["item"], anchor=ev["anchor"],
                    text=ev["text"][:110]))
    report["assertions"]["a"] = rep_a

    # --- 断言 (b): SCC 内边证据全部在白名单 ---
    rep_b = {"name": "(b) intra-SCC edge whitelist (HHMIRROR E1-E16 ledger)",
             "ok": True, "unknown": []}
    observed_pairs = set()
    for (fm, tm), evs in sorted(g["evidence"].items()):
        if fm in in_multi and tm in in_multi:
            observed_pairs.add(f"{fm}->{tm}")
            allowed = frozen_edges.get(f"{fm}->{tm}", set())
            for key, evlist in sorted(evs.items()):
                if key in allowed:
                    continue
                ev = evlist[0]
                tag = PAIR_TAGS.get(f"{fm}->{tm}")
                rep_b["ok"] = False
                rep_b["unknown"].append(f"{fm}->{tm}:{key}")
                report["violations"].append(dict(
                    assertion="(b)", kind="unwhitelisted-edge-evidence",
                    edge=f"{fm}->{tm}",
                    loc=f'{ev["path"]}:{ev["line"]}',
                    form=ev["form"], item=ev["item"], anchor=ev["anchor"],
                    text=ev["text"][:110],
                    hint=("pair-tagged %s but evidence not in frozen inventory"
                          % (tag[0] if tag else "UNTAGGED-PAIR"))))
    frozen_pairs = set(frozen_edges.keys())
    vanished = sorted(frozen_pairs - observed_pairs)
    rep_b["vanished_pairs"] = vanished
    if vanished:
        report["info"].append(
            "[INFO] improvement: %d frozen intra-SCC edge pair(s) no longer present: %s "
            "(cycles were broken; re-freeze with --emit-freeze after review)" %
            (len(vanished), ", ".join(vanished)))
    report["assertions"]["b"] = rep_b

    # --- 断言 (c): solo 基线模块不入环 ---
    fallen = sorted(frozen_solo & in_multi)
    rep_c = {"name": "(c) solo-baseline ratchet (%d frozen solo modules)" % len(FROZEN_SOLO),
             "ok": not fallen, "fallen": fallen}
    for m in fallen:
        witness = []
        for (fm, tm), evs in g["evidence"].items():
            if tm == m and fm in in_multi and fm != m:
                witness.append((fm, tm, list(evs.values())[0][0]))
        for fm, tm, ev in witness:
            report["violations"].append(dict(
                assertion="(c)", kind="solo-fell-into-scc",
                edge=f"{fm}->{tm}", member=m,
                loc=f'{ev["path"]}:{ev["line"]}',
                form=ev["form"], item=ev["item"], anchor=ev["anchor"],
                text=ev["text"][:110]))
    report["assertions"]["c"] = rep_c

    # --- 附加观察（不 FAIL） ---
    scc_now = sorted(in_multi & frozen_scc)
    if len(scc_now) < len(frozen_scc):
        freed = sorted(frozen_scc - in_multi)
        report["info"].append(
            "[INFO] improvement: %d frozen SCC module(s) left the multi-module SCC: %s" %
            (len(freed), ", ".join(freed)))
    solo_selfloops = sorted(
        m for m in (g["mods"] - in_multi) if m in g["edges"].get(m, set()))
    if solo_selfloops:
        report["info"].append(
            "[INFO] solo modules with intra-module self-edges (not a layering event): %s" %
            ", ".join(solo_selfloops))
    new_mods = sorted(g["mods"] - frozen_scc - frozen_solo - {"lib"})
    if new_mods:
        report["info"].append(
            "[INFO] new module(s) since freeze (fine unless they join the SCC): %s" %
            ", ".join(new_mods))
    report["ok"] = not report["violations"]
    return report


def emit_freeze(src: Path, accept_new: bool) -> int:
    g = analyze(src)
    sccs = tarjan_scc(g["mods"], g["edges"])
    scc_multi = [c for c in sccs if len(c) > 1]
    in_multi = set()
    for c in scc_multi:
        in_multi.update(c)
    frozen_scc = set(FROZEN_SCC)
    new_members = sorted(in_multi - frozen_scc)
    if new_members and not accept_new:
        print("REFUSED: tree has SCC members outside the frozen baseline: %s" % new_members,
              file=sys.stderr)
        print("Adjudicate them per the HHMIRROR edge-by-edge method first (see module docstring),\n"
              "register in docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md, then pass --accept-new.",
              file=sys.stderr)
        return 1
    solo = sorted(g["mods"] - in_multi)
    print("# ---- freeze snapshot (paste into cycle_ratchet.py) ----")
    print("FROZEN_SCC = [")
    for m in sorted(in_multi):
        print('    "%s",' % m)
    print("]")
    print("FROZEN_SOLO = [")
    for m in solo:
        print('    "%s",' % m)
    print("]")
    lines_out = ["FROZEN_EDGES = {"]
    for (fm, tm) in sorted(g["evidence"]):
        if fm not in in_multi or tm not in in_multi:
            continue
        keys = sorted(g["evidence"][(fm, tm)].keys())
        lines_out.append('    "%s->%s": [' % (fm, tm))
        for k in keys:
            lines_out.append('        %r,' % k)
        lines_out.append("    ],")
    lines_out.append("}")
    print("\n".join(lines_out))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="production types-graph cycle ratchet (HHMIRROR A2.5)")
    ap.add_argument("--src", default=None, help="src/ directory (default: repo of this script)")
    ap.add_argument("--json", default=None, help="write machine-readable report to this path")
    ap.add_argument("--emit-freeze", action="store_true",
                    help="print frozen-baseline literal for the current tree (maintenance)")
    ap.add_argument("--accept-new", action="store_true",
                    help="with --emit-freeze: allow new SCC members after adjudication")
    ap.add_argument("--quiet", action="store_true", help="only print the verdict line")
    args = ap.parse_args()

    src = Path(args.src) if args.src else (Path(__file__).resolve().parent.parent / "src")
    if not src.is_dir():
        print("error: src dir not found: %s" % src, file=sys.stderr)
        return 2

    if args.emit_freeze:
        return emit_freeze(src, args.accept_new)

    rep = run_ratchet(src)

    if not args.quiet:
        print("=== cycle ratchet: production types graph (HHMIRROR v3 method) ===")
        print("src: %s   modules: %d" % (rep["src"], rep["total_modules"]))
        print("multi-module SCC(s):")
        for c in rep["scc_multi"]:
            print("  [%d] %s" % (len(c), " ".join(c)))
        for a in rep["assertions"].values():
            status = "PASS" if a["ok"] else "FAIL"
            extra = ""
            if not a["ok"]:
                extra = " -> %s" % ({k: v for k, v in a.items() if k not in ("name", "ok")})
            print("%s  %s%s" % (status, a["name"], extra))
        if rep["violations"]:
            print("\n--- violations (%d) ---" % len(rep["violations"]))
            for v in rep["violations"]:
                print("  [%s] %s  %s  %s:%s" % (v["assertion"], v["kind"], v["edge"], v["loc"], ""))
                print("        form=%s item=%s anchor=%s" % (v["form"], v["item"], v["anchor"]))
                print("        %s" % v.get("text", ""))
                if v.get("member"):
                    print("        member dragged into SCC: %s" % v["member"])
                if v.get("hint"):
                    print("        %s" % v["hint"])
        for line in rep["info"]:
            print(line)
    print("CYCLE-RATCHET: %s%s" % ("PASS" if rep["ok"] else "FAIL",
                                   "" if rep["ok"] else " (%d violations)" % len(rep["violations"])))
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
