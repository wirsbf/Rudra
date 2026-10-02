#!/usr/bin/env python3
"""harvest_local_manifest.py — C1 TYPE-SEED-LOCAL manifest harvester.

Harvests the committed-local seed manifest from a canonical analyzeHeadless
golden (HEADLESS_BRIDGE_V1_DESIGN.md 5.1): per function, the declaration
block between the opening '{' and the first non-declaration line yields
(type, name, array dims) for every `local_[0-9a-f]+` declarator.  Stack
offset = -int(name[6:], 16) (the offset is embedded in the name by Ghidra's
stack buildDefaultName).

C2 DWARF mode (`--dwarf BINARY GOLDEN.c ...`) harvests the DWARF
semantic-name seed channel instead: variable names come from .debug_info
and their stack offsets from inline DW_OP_fbreg locations (see
DWARF_HARVEST_RULE below for the domain rules, each pinned by locked-oracle
pre-validation).

Output manifest records oracle commit + golden sha256 (B2 provenance).

Usage (C1 golden-decl mode):
  harvest_local_manifest.py GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--typed-only]
Usage (C2 DWARF-name mode):
  harvest_local_manifest.py --dwarf BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--dwarf-raw-types]
Usage (C4 DWARF-struct mode):
  harvest_local_manifest.py --struct BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json
Usage (V3 callee-siglock mode):
  harvest_local_manifest.py --callee GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--targets main,ap_fini]
                                               [--dwarf-types BINARY]
Usage (CMT warning-comment mode):
  harvest_local_manifest.py --cmt BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json
Usage (V4 typedef-def mode):
  harvest_local_manifest.py --typedef BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json
"""
import hashlib
import json
import re
import sys

FUNC_HEADER = re.compile(r"^/\* ---- 0x([0-9a-f]+): (.+) \(\d+ bytes\) ---- \*/$")
DECL = re.compile(
    r"^\s*(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*?)"
    r"(?P<stars>\s*\*+\s*|\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r";\s*$"
)
LOCAL_NAME = re.compile(r"^local_[0-9a-f]+$")
# Parenthesized declarators (function pointers / array-of pointers to
# arrays): `undefined1 (*pauVar6) [16];` — must not end the decl block.
DECL_PAREN = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_ ]*?\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r"\s*;\s*$"
)
# B29 VARARGS-SAVE-ANCHOR GUARD (LANE B29CONDEXE 2026-09-26, oracle-verified
# on the locked e40ed130 tree): a body line of the form
#   ap[0].reg_save_area = local_b8;
# marks local_b8 as the va_list register-save-area anchor. Committing that
# declarator as a typelocked ARRAY seed blocks the local-alias chain at the
# anchor (ScopeLocal::markUnaliased, varmap.cc:1383: TYPE_ARRAY locks turn
# aliason off for every later entry when alias_block_level > 1, default 2 =
# architecture.cc:1430), the downstream varargs save slots lose their alias
# protection, their call shadows become collapsible, and the whole
# in_AL/in_XMM*/in_R* register-save family is removed by RuleEarlyRemoval
# (stage stackstall:oppool1) — reproduced identically in the locked oracle
# with the same seed set. The golden's `undefined1 local_b8 [8];` decl form
# is the varmap's own guard-derived array (the unseeded canon-body oracle
# prints the <t>Stack_<off> [8] family with the decayed reg_save_area
# reference), so dropping the anchor seed costs only the bridge-invented
# local_ name, never the array form.
SAVE_ANCHOR = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*\[\d+\]\.reg_save_area\s*=\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)


# Bases the C1 v1 seed channel can install with faithful size/metatype
# (scalar/pointer/array domain). Struct-typed committed locals (sigaction,
# sigset_t, ...) are C4 composite-channel domain and are skipped here so the
# manifest never carries a type the channel would mistype.
KNOWN_BASES = {
    "void", "char", "byte",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "short", "ushort", "int", "uint", "long", "ulong", "size_t", "time_t",
    "__pid_t", "float", "double", "bool",
}


def base_of(type_expr):
    # strip ALL stars (multi-pointer spellings normalize as `char * *` —
    # rstrip("*") leaves the inner star and the servable-base gate then
    # misrejects `char **` evidence; CURLPREP double-pointer casts)
    return " ".join(type_expr.split("[")[0].replace("*", " ").split())


def parse_type_expr(type_text, stars, arr):
    base = " ".join(type_text.split())
    if not base:
        return None
    nstars = stars.count("*")
    ptr = " " + "*" * nstars if nstars else ""
    dims = "".join("[%d]" % int(d) for d in re.findall(r"\[(\d+)\]", arr or ""))
    return base + ptr + dims


def split_functions(text):
    """Yield (addr, name, [lines]) per golden function block."""
    cur_addr = None
    cur_name = None
    cur_lines = []
    for line in text.split("\n"):
        m = FUNC_HEADER.match(line)
        if m:
            if cur_addr is not None:
                yield cur_addr, cur_name, cur_lines
            cur_addr, cur_name, cur_lines = "0x" + m.group(1), m.group(2), []
        elif cur_addr is not None:
            cur_lines.append(line)
    if cur_addr is not None:
        yield cur_addr, cur_name, cur_lines


def harvest_function(lines):
    # B29: collect the va_list reg_save_area anchors referenced in the body
    # BEFORE consuming the decl block (harvest_function sees the whole
    # function text; the anchor assignment lives past the first statement).
    save_anchors = set()
    for line in lines:
        m = SAVE_ANCHOR.match(line)
        if m is not None:
            save_anchors.add(m.group("name"))

    locals_ = []
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            if stripped == "{":
                started = True
            continue
        if not stripped:
            continue
        dm = DECL.match(line)
        if dm is None:
            dm = DECL_PAREN.match(line)
            if dm is not None:
                continue  # parenthesized declarator: never a local_ seed (v1 domain)
        if dm is None:
            break  # first statement ends the declaration block
        if not LOCAL_NAME.match(dm.group("name")):
            continue
        type_expr = parse_type_expr(dm.group("type"), dm.group("stars"), dm.group("arr"))
        if type_expr is None:
            continue
        if base_of(type_expr) not in KNOWN_BASES:
            continue  # C4 composite domain: outside the v1 seed channel
        name = dm.group("name")
        if name in save_anchors and dm.group("arr"):
            # B29 VARARGS-SAVE-ANCHOR GUARD: never commit the va_list
            # reg_save_area anchor as a typelocked array — the array lock
            # blocks the local-alias chain (varmap.cc:1383) and kills the
            # whole varargs register-save family (see SAVE_ANCHOR comment).
            continue
        # TYPESEEDARB (HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001) lock-model
        # classification, pinned by the locked-oracle stage_seed_diag
        # experiment (e40ed130, 2026-09-27): a golden-decl ARRAY declarator
        # is the decompiler's own RECOVERED aggregate (canon `long local_70
        # [6]` = createEntry varmap.cc:622-627, unlocked; neither oracle
        # face locks it). Seeding it typelocked fires markUnaliased's
        # alias_block branch (varmap.cc:1376-1385, TYPE_ARRAY at
        # alias_block_level=2) — the same-seed locked oracle reproduced the
        # dead canary web on httpd main, the namelock-only payload keeps it
        # alive. Array entries therefore ride the NAME-ONLY transport
        # (typelock=false -> collectNameRecs downgrade varmap.cc:357-381 ->
        # reattach unlocked). Scalars keep the C1 locked bridge: they
        # cannot fire alias_block and pin the analyzer-assisted typing
        # layer the hermetic library cannot recover (C1 HEAD residual,
        # HEADLESS_BRIDGE_V1_DESIGN.md §9.1). DWARF/STRUCT channels stay
        # typelocked — those locks are analyzer-REAL (curl debug info).
        typelock = not bool(dm.group("arr"))
        locals_.append(
            {"offset": -int(name[6:], 16), "name": name, "type": type_expr,
             "typelock": typelock}
        )
    return locals_


def harvest(path):
    text = open(path, "r", encoding="utf-8").read()
    functions = {}
    for addr, name, lines in split_functions(text):
        locs = harvest_function(lines)
        if locs:
            functions[addr] = {"name": name, "locals": locs}
    return functions


# ---------------------------------------------------------------------------
# C2 DWARF semantic-name mode (HEADLESS_BRIDGE_V1 C2 lane; W1B residual
# attribution: the curl -45 balance's bulk is the DWARF-named domain).
#
# Domain rules, each pinned by locked-oracle (e40ed130) pre-validation via
# stage_seed_diag <localdb> seeding (oracle-level reproduction of the canon
# named decl layer) plus canon-golden observation:
#   - Only DW_FORM_exprloc single-op DW_OP_fbreg(N) locations are seeded.
#     Ghidra's DWARF importer drops sec_offset location lists — canon never
#     names main's i/res/url (all loc-list vars) while it does name every
#     exprloc var; seeding loc-list vars would over-seed vs canon.
#   - DW_OP_addr (static storage) vars are skipped: global-symbol channel.
#   - Variables only. Formal parameters are the C3 prototype domain
#     (match_url's by-value stack param `glob` prints in canon's signature).
#   - offset = fbreg(N) + 8: frame_base is DW_OP_call_frame_cfa here, CFA =
#     RSP_entry + 8, and the Ghidra stack-space offset 0 is the RSP_entry
#     slot. Calibrated on main: urlnum fbreg(-0x22c) -> cmpl 0x34(%rsp)
#     (prologue 6 pushes + sub 0x228) -> Ghidra -0x224; errorbuffer
#     fbreg(-0x150) -> lea 0x110(%rsp).
#   - Canon-committed typing: the [256]/[4096] char arrays print `bool` in
#     canon (usedarg-family boolean usage; stage_seed_diag confirms
#     bool-seeds reproduce the canon decl layer and char-seeds do not), so
#     the default maps those arrays to bool; --dwarf-raw-types keeps the
#     raw DWARF spelling for attribution experiments.
#   - Slot ownership: the first DWARF claim on a stack slot decides its
#     fate (canon main: progressbar's slot -504 never prints passarg); a
#     slot first claimed by an unservable (C4) var is a residual and later
#     servable same-slot vars drop with it.
#   - KNOWN_BASES-only (TYPEFIX rule): an unknown base spelling is a dead
#     entry under parse_c_type's no-fallback bail, so the harvest drops it.
# ---------------------------------------------------------------------------

DWARF_HARVEST_RULE = (
    "DWARF .debug_info walk (pyelftools): DW_TAG_variable under "
    "subprogram/lexical_block/inlined_subroutine with abstract-origin "
    "chasing; location must be DW_FORM_exprloc single-op DW_OP_fbreg(N) "
    "(sec_offset loc-lists are dropped by Ghidra's importer — canon never "
    "names them; DW_OP_addr statics are the global channel; formal "
    "parameters are C3); offset = fbreg(N)+8 (frame_base=call_frame_cfa, "
    "Ghidra stack offset 0 = RSP_entry slot; calibrated urlnum "
    "fbreg(-0x22c) -> -0x224); canon key = DW_AT_low_pc + 0x100000; "
    "types: KNOWN_BASES bases only (parse_c_type no-fallback), array "
    "count = upper_bound+1, char[256]/char[4096] remap to bool (canon-"
    "committed typing, stage_seed_diag-validated; --dwarf-raw-types keeps "
    "raw), first-DIE slot claim wins and unservable first claims shadow "
    "the slot (progressbar/passarg). Canon-decl adjacency adoption: a "
    "canon-committed synthesized stack slot (uStack_/iStack_/... form, "
    "offset embedded in the name) whose extent borders a DWARF-seeded "
    "slot is adopted with source='canon-decl' — the seed's typelock "
    "would otherwise absorb the uncommitted neighbor into the array "
    "(oracle-verified: file2string buffer-only seeding yields 'bool "
    "abStack_150[8]' in the locked oracle too, while canon commits "
    "undefined8 uStack_150 and keeps the partition; both-seeded oracle "
    "reproduces canon's separate slots)"
)

# C4 STRUCT-SEED domain rule (HEADLESS-BRIDGE-V1 C3NEXT, the §11.4 residual
# set: urls/outs/heads/progressbar+passarg/fileinfo/glob x2/ap/statbuf/
# aliases). Names/offsets from .debug_info exactly like the C2 DWARF-name
# channel, but the type spelling names a DWARF composite (structure/union/
# enum) or a typedef over a composite/array, which parse_c_type resolves
# through the shared TypeFactory name tree (glb->types->findByName mirror,
# grammar.cc:2989; the factory is populated by the driver's unconditional
# parse_type_names DWARF import). Locked-oracle pre-validation
# (stage_seed_diag, /dev/shm/rugra-tests/c3next): the struct seed set
# reproduces canon's committed declaration layer (URLGlob *urls; OutStruct
# outs/heads; ProgressData progressbar; stat fileinfo; stat statbuf;
# LongShort aliases [50]; Configurable *local_5b8; HttpPost *local_5a8;
# va_list ap) and the field-form family (outs.stream/outs.filename/
# heads.stream/fileinfo.st_size/progressbar.total/ap[0].gp_offset,
# by-value ap passing). va_list must seed as the ARRAY form (typedef over
# __va_list_tag[1]): the struct-collapsed variant prints ap.field and
# passes &ap, the array form prints ap[0].field and passes ap — canon is
# the array form (oracle-verified). Canon-decl adoption: local_[0-9a-f]+
# declarators whose base names a DWARF composite (getparameter
# Configurable *local_5b8 / HttpPost *local_5a8) adopt name+offset from
# the golden decl layer, base must exist in the DWARF named-type set
# (TYPEFIX-equivalent: an unknown base is a dead entry under the factory
# name lookup). KNOWN_BASES spellings stay in the C1/C2 manifests
# (disjoint by construction); first-DIE slot claim keeps the
# progressbar-over-passarg shadowing.
STRUCT_HARVEST_RULE = (
    "DWARF walk as DWARF_HARVEST_RULE but the type domain is DWARF-named "
    "composites/typedefs (base must exist in the .debug_info named-type "
    "set with a size; arrays as Base[N], pointers as Base *); local_[hex] "
    "canon-decl adoption for struct-pointer bases; KNOWN_BASES domain "
    "excluded (C1/C2 manifests); slot ownership first-DIE-claim; oracle "
    "prevalidation stage_seed_diag witness in "
    "/dev/shm/rugra-tests/c3next (seed_*.xml + oracle_*_seeded.c)"
)

# canon synthesized stack-name forms with the offset embedded in the name
# (uStack_150 / iStack_160 / pcStack_218 / ...); in_stack_ (positive
# full-width hex) and local_ (W1B C1 domain) are deliberately not matched.
STACK_NAME = re.compile(r"^[A-Za-z]*[Ss]tack_([0-9a-f]{1,6})$")


# ---------------------------------------------------------------------------
# V3 callee-siglock mode (HEADLESS-BRIDGE-V3-SIGLOCK-0003; the SHAPEFIX
# verdict's transport: canon's `long *` subscript family in httpd main /
# ap_fini / ap_vhost comes from the analyzeHeadless Decompiler Parameter ID
# analyzer committing locked prototypes to CALLED functions — oracle-flip
# evidence /dev/shm/rugra-reports/LANE_SHAPEFIX_2026-09-25.md, harness
# /dev/shm/rugra-tests/shapefix/stage_shape_diag.cc). The golden's own
# callee headers are NOT the harvest source: Parameter ID's final committed
# self-signature can disagree with the call-site state main was decompiled
# against (canon prints ap_setup_prelinked_modules's own header as
# `char * f(undefined8 *)` while main's call site shows `(long*)->long`);
# the call-site printed forms are the observable truth (task rule:
# "以 canon 印出的调用点实参形态为准反推").
#
# Evidence rules, each observable in the canon text:
#   - arity: the number of printed top-level arguments at each call site;
#     any disagreement across sites = varargs/derived callee -> dropped.
#   - param type evidence per slot, conflict-sensitive:
#       bare local x          -> x's declared type (arrays decay to elem*)
#       x[k]                  -> element type of x's array/pointer decl
#       x + k / x + -k        -> x's declared type
#       *x                    -> pointee of x's declared type
#       &x                    -> pointer to x's declared type
#       "literal"             -> char * (string constant)
#       (T *)expr / (int)x    -> T * / int (ActionSetCasts casts a call
#                                 argument exactly to the callsite param's
#                                 local type, so the cast target IS the
#                                 canon callsite param type)
#       numeric / other exprs -> no evidence (never a conflict)
#     two disagreeing spellings kill the slot (canon passed long* AND
#     undefined8* vars to apr_pool_create_ex's param1 with no cast ->
#     that slot was not type-locked in canon).
#   - input lock only when EVERY slot has agreeing KNOWN_BASES evidence
#     (TYPEFIX rule: an unknown base spelling is a dead slot); otherwise
#     the callee keeps active arity recovery and only the return locks.
#   - return type evidence: every CONSUMING site assigns without a cast
#     and the consumer declared types agree; any cast on the call result
#     (canon `plVar6 = (long *)apr_palloc(...)`) or all-unused -> no
#     output lock (unused != void).
#   - no parameter names: canon's caller vars keep plVar/puVar spellings,
#     so unlike the SHAPEFIX harness XML (namelock="true" renamed main's
#     var to `mod`) the manifests never carry namelock.
# ---------------------------------------------------------------------------

CALLEE_SIGLOCK_RULE = (
    "canon call-site form harvest over the target functions: per callee, "
    "arity = printed argument count (conflict = varargs drop), param slot "
    "types from bare-local/element/addr-of/deref/literal/cast-target "
    "evidence with conflict-sensitivity, input lock only on full "
    "KNOWN_BASES evidence, return lock only on cast-free agreeing "
    "consumers, no param names; call-site forms are authoritative over "
    "the callee's own golden header (Parameter ID iteration drift)"
)

# A statement-level call match: optional `lvalue = `, optional pointer cast
# on the call result, callee identifier, then the balanced argument list.
CALLEE_CALL = re.compile(
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?"
    r"(?P<cast>\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)\s*)?"
    r"(?P<callee>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
# Simple value casts on arguments: (int)x, (long)x, (char *)x, (char **)x ...
# `\**` (zero or more stars) is the union of the pre-CURLPREP `\*?` (scalar
# `(long)x` casts are slot evidence — memcmp's size_t slot) and CURLPREP's
# `\*+` (multi-star `(char **)0x0` keeps its star count); `\*+` alone dropped
# the zero-star form, and the all-or-nothing input lock then cost memcmp its
# whole lock (HARVEST-SCALARCAST-0001).
CALLEE_ARG_CAST = re.compile(r"^\(\s*(?P<t>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<ptr>\**)\s*\)\s*")
IDENT_EXPR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NUMERIC = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")


def _norm_type(spelling):
    """Collapse whitespace around '*' into Ghidra's `T *` spelling."""
    stars = spelling.count("*")
    base = " ".join(spelling.replace("*", " ").split())
    dims = "".join("[%d]" % int(d) for d in re.findall(r"\[(\d+)\]", base))
    base = base.split("[")[0].strip()
    return base + (" *" * stars) + dims


def _elem_type(spelling):
    """Element type of an array/pointer decl (strip one [N] / one *)."""
    spelling = _norm_type(spelling)
    if "[" in spelling:
        return spelling.split("[")[0].strip()
    if spelling.endswith(" *"):
        return spelling[:-2].strip()
    return spelling


def _ptr_type(spelling):
    # append one star INSIDE the normalization: `_norm_type(sp) + " *"`
    # would emit `char * *` for a pointer input, whose base_of() misparse
    # (`char *`) then fails the servable-base gate (CURLPREP: &::global
    # member evidence feeds pointer-typed spellings here)
    return _norm_type(spelling + "*")


def _pointee_type(spelling):
    spelling = _norm_type(spelling)
    if not spelling.endswith(" *"):
        return None
    return spelling[:-2].strip()


def _in_string(body, pos):
    """Is column `pos` inside a double-quoted string literal?"""
    return body.count('"', 0, pos) % 2 == 1


def _parse_signature_params(sig_line):
    """`f(type1 n1, type2 n2)` -> {n1: type1, ...} (name = last ident)."""
    open_paren = sig_line.find("(")
    close_paren = sig_line.rfind(")")
    if open_paren < 0 or close_paren < open_paren:
        return {}
    inner = sig_line[open_paren + 1 : close_paren]
    params = {}
    depth = 0
    cur = ""
    parts = []
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    for part in parts:
        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
        if not ids:
            continue
        name = ids[-1]
        type_text = part[: part.rfind(name)].strip()
        if type_text.endswith("*"):
            type_text = _norm_type(type_text)
        if type_text:
            params[name] = _norm_type(type_text)
    return params


# Curl-corpus extension (CURLPREP lane): the V3 evidence domain grows two
# corpus-conditioned surfaces when --dwarf-types BINARY is given. Default
# (httpd form): _SERVABLE_BASES == KNOWN_BASES, empty global table — the
# original behavior, byte-for-byte.
_SERVABLE_BASES = set(KNOWN_BASES)
# canon-global spelling table: "::config" / "&::config.useragent" arg forms
# -> DWARF-derived type spellings (globals + struct member chains).
_DWARF_GLOBALS = {}
# the corpus's DWARF-named composite/typedef set (CURLPREP --dwarf-types
# extension; stays empty in the default httpd form).
_dwarf_named_types = set()


def _arg_evidence(arg, decls):
    """(spelling|None) — the canon call-site param type this arg exhibits."""
    arg = arg.strip()
    if arg.startswith('"'):
        return "char *"
    if NUMERIC.match(arg):
        return None
    cast = CALLEE_ARG_CAST.match(arg)
    if cast is not None:
        base = cast.group("t")
        if base not in _SERVABLE_BASES:
            return None
        if cast.group("ptr"):
            # preserve the FULL star count: `(char **)x` is char**, not
            # _ptr_type(base)'s single star
            return _norm_type(base + " " + cast.group("ptr"))
        return base
    # ::global / ::global.field / &-prefixed forms (curl canon: GetStr's
    # `&::config.useragent`, fopen's `::config.outfile`): spelling from the
    # DWARF global/member table; the empty table (httpd default) never hits.
    m = re.match(r"^&(::[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$", arg)
    if m is not None:
        spelled = _DWARF_GLOBALS.get(m.group(1))
        return _ptr_type(spelled) if spelled else None
    m = re.match(r"^(::[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$", arg)
    if m is not None:
        spelled = _DWARF_GLOBALS.get(m.group(1))
        if spelled is None:
            return None
        spelling = _norm_type(spelled)
        if "[" in spelling:
            return _elem_type(spelling) + " *"
        return spelling
    # ident[k] element access
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\d+\s*\]$", arg)
    if m is not None and m.group(1) in decls:
        return _elem_type(decls[m.group(1)])
    # ident + k / ident + -k pointer arithmetic keeps the pointer type
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*-?(?:0x[0-9a-fA-F]+|\d+)$", arg)
    if m is not None and m.group(1) in decls:
        return _norm_type(decls[m.group(1)])
    # bare ident: arrays decay to element pointers
    if IDENT_EXPR.match(arg) is not None:
        if arg in decls:
            spelling = _norm_type(decls[arg])
            if "[" in spelling:
                return _elem_type(spelling) + " *"
            return spelling
        return None
    # &ident
    m = re.match(r"^&\s*([A-Za-z_][A-Za-z0-9_]*)$", arg)
    if m is not None and m.group(1) in decls:
        return _ptr_type(decls[m.group(1)])
    # *ident
    m = re.match(r"^\*\s*([A-Za-z_][A-Za-z0-9_]*)$", arg)
    if m is not None and m.group(1) in decls:
        return _pointee_type(decls[m.group(1)])
    return None


def _type_spell_dwarf(unit, tattr, named, depth=0):
    """DW_AT_type -> spelling in the extended servable domain: KNOWN_BASES
    bases, pointers, arrays, and DWARF-named composites/typedefs (the
    corpus's parse_type_names tree — FILE/Configurable/... resolve there,
    which is exactly the surface the curl driver's parse_c_type uses)."""
    if depth > 12 or tattr is None:
        return None
    tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
    if tdir is None:
        return None
    if tdir.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        return name if name in KNOWN_BASES else None
    if tdir.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _type_spell_dwarf(unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1)
    if tdir.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        return name if name in named else None
    if tdir.tag == "DW_TAG_pointer_type":
        inner = _type_spell_dwarf(unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1)
        return (inner + " *") if inner else None
    if tdir.tag == "DW_TAG_array_type":
        count = None
        for child in tdir.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                ub = _die_attr(child, "DW_AT_upper_bound")
                if ub is not None and isinstance(ub.value, int):
                    count = ub.value + 1
        inner = _type_spell_dwarf(unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1)
        if inner is None or count is None:
            return None
        return "%s[%d]" % (inner, count)
    if tdir.tag in (
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
    ):
        name = _attr_str(_die_attr(tdir, "DW_AT_name"))
        return name if name and name in named else None
    return None


def load_dwarf_evidence_domain(binary):
    """Populate the curl extension surfaces: _SERVABLE_BASES grows the
    corpus's DWARF-named composites/typedefs-with-size, and _DWARF_GLOBALS
    maps '::name' / '::name.member[.member...]' spellings (file-scope
    variables with static storage + struct member chains) to servable type
    spellings. Called only behind --dwarf-types; the default domain stays
    the httpd form."""
    from elftools.elf.elffile import ELFFile

    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        if not any(s.name == ".debug_info" for s in elf.iter_sections()):
            sys.stderr.write(
                "WARNING: %s carries no .debug_info: --dwarf-types is "
                "corpus-inapplicable\n" % binary
            )
            return
        dw = elf.get_dwarf_info()
        # named set: sized composites + typedefs over them (the factory
        # name-lookup surface, shared shape with the C4 channel)
        _dwarf_named_types.update(_named_composite_set(dw))
        members_by_type = {}
        globals_ = {}
        for unit in dw.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag in (
                    "DW_TAG_structure_type",
                    "DW_TAG_union_type",
                ):
                    tname = _attr_str(_die_attr(die, "DW_AT_name"))
                    if not tname:
                        continue
                    for child in die.iter_children():
                        if child.tag != "DW_TAG_member":
                            continue
                        mname = _attr_str(_die_attr(child, "DW_AT_name"))
                        if not mname:
                            continue
                        spell = _type_spell_dwarf(
                            unit, _die_attr(child, "DW_AT_type"), _dwarf_named_types
                        )
                        if spell:
                            members_by_type.setdefault(tname, {})[mname] = spell
                elif die.tag == "DW_TAG_variable":
                    vname = _attr_str(_die_attr(die, "DW_AT_name"))
                    loc = _die_attr(die, "DW_AT_location")
                    # file-scope statics only (DW_OP_addr form): the
                    # canon '::global' spelling domain
                    if not vname or loc is None:
                        continue
                    if loc.form != "DW_FORM_exprloc":
                        continue
                    blob = bytes(loc.value)
                    if len(blob) < 2 or blob[0] != 0x03:  # DW_OP_addr
                        continue
                    spell = _type_spell_dwarf(
                        unit, _die_attr(die, "DW_AT_type"), _dwarf_named_types
                    )
                    if spell:
                        globals_[vname] = spell
        _SERVABLE_BASES.update(_dwarf_named_types)
        for gname, gspell in sorted(globals_.items()):
            _DWARF_GLOBALS["::" + gname] = gspell
            base = gspell.split("[")[0].rstrip("*").strip()
            # member chains one level deep (the canon arg forms observed:
            # &::config.useragent / ::config.outfile); deeper chains would
            # need union member resolution, left unharvested (no evidence)
            for member, mspell in sorted(members_by_type.get(base, {}).items()):
                _DWARF_GLOBALS["::%s.%s" % (gname, member)] = mspell


def harvest_callee(path, target_names):
    """V3 callee-siglock table: per callee (canon-address keyed) the
    call-site-derived prototype evidence. Returns (callees, drops,
    function_addresses)."""
    text = open(path, "r", encoding="utf-8").read()
    # function name -> canon address (first occurrence: thunks precede the
    # EXTERNAL-space pseudo entries in the address-ordered golden).
    function_addresses = {}
    for addr, name, _lines in split_functions(text):
        function_addresses.setdefault(name, addr)
    callees = {}
    drops = []
    for addr, name, lines in split_functions(text):
        if name not in target_names:
            continue
        # declared local types: decl block + the signature's own formals
        decls = {}
        started = False
        for line in lines:
            stripped = line.strip()
            if not started:
                if stripped == "{":
                    started = True
                continue
            if not stripped:
                continue
            dm = DECL.match(line)
            if dm is None:
                break
            decls[dm.group("name")] = parse_type_expr(
                dm.group("type"), dm.group("stars"), dm.group("arr")
            )
        body = "\n".join(lines)
        # The signature line (before the body's opening brace) also matches
        # the call pattern (`void f(long param_1, ...)`); harvest calls only
        # from the statement region, and read the formals from the sig.
        sig_params = _parse_signature_params(body.split("{", 1)[0])
        decls.update(sig_params)
        body = body[body.find("{") + 1 :]
        for m in CALLEE_CALL.finditer(body):
            callee = m.group("callee")
            if callee in ("if", "while", "for", "switch", "sizeof", "return"):
                continue
            if _in_string(body, m.start()):
                continue
            # balanced argument extraction. The argument list's opening
            # paren is the LAST paren before the match end (the callee
            # group's trailing `\s*\(`), NOT the first paren from the match
            # start: a cast-result site `x = (FILE *)fopen(a,b)` has the
            # result cast's paren between the lhs and the callee, and
            # finding from m.start() would extract `(FILE *)` as a bogus
            # 1-argument list (curl's fopen: 8 sites, 5 casted -> spurious
            # arity conflict drop; same latent defect for any httpd
            # cast-result site).
            start = body.rfind("(", 0, m.end())
            depth = 0
            end = start
            for i in range(start, len(body)):
                if body[i] == "(":
                    depth += 1
                elif body[i] == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            argstr = body[start + 1 : end]
            args = []
            depth = 0
            cur = ""
            for ch in argstr:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if ch == "," and depth == 0:
                    args.append(cur.strip())
                    cur = ""
                else:
                    cur += ch
            if cur.strip():
                args.append(cur.strip())
            lhs = (m.group("lhs") or "").strip().rstrip("=").strip()
            cast = (m.group("cast") or "").strip()
            entry = callees.setdefault(
                callee,
                {
                    "name": callee,
                    "addr": function_addresses.get(callee),
                    "sites": 0,
                    "arity": None,
                    "slot_evidence": {},
                    "slot_conflict": set(),
                    "return_evidence": {},
                    "return_cast": False,
                },
            )
            entry["sites"] += 1
            if entry["arity"] is None:
                entry["arity"] = len(args)
            elif entry["arity"] != len(args):
                entry["arity"] = -1  # varargs / derived conflict marker
            for slot, arg in enumerate(args):
                ev = _arg_evidence(arg, decls)
                if ev is None:
                    continue
                if base_of(ev) not in _SERVABLE_BASES:
                    entry["slot_conflict"].add(slot)
                    continue
                prior = entry["slot_evidence"].get(slot)
                if prior is None:
                    entry["slot_evidence"][slot] = _norm_type(ev)
                elif prior != _norm_type(ev):
                    entry["slot_conflict"].add(slot)
            if cast:
                entry["return_cast"] = True
            elif lhs and lhs in decls:
                rt = _norm_type(decls[lhs])
                if base_of(rt) in _SERVABLE_BASES:
                    prior = entry["return_evidence"].get(rt)
                    entry["return_evidence"][rt] = prior + 1 if prior else 1
    # finalize
    out = {}
    for callee, entry in sorted(callees.items()):
        if entry["addr"] is None:
            drops.append({"callee": callee, "reason": "no golden header address"})
            continue
        if entry["arity"] < 0:
            drops.append(
                {
                    "callee": callee,
                    "reason": "arity conflict across sites (varargs/derived)",
                }
            )
            continue
        arity = entry["arity"]
        params = []
        full = arity > 0
        for slot in range(arity):
            if slot in entry["slot_conflict"] or slot not in entry["slot_evidence"]:
                params.append({"type": None, "locked": False})
                full = False
            else:
                params.append({"type": entry["slot_evidence"][slot], "locked": True})
        ret = None
        if not entry["return_cast"] and entry["return_evidence"]:
            if len(entry["return_evidence"]) == 1:
                ret = next(iter(entry["return_evidence"]))
        out[entry["addr"]] = {
            "name": callee,
            "sites": entry["sites"],
            "arity": arity,
            "input_lock": full,
            "params": params,
            "return": ret,
        }
    return out, drops, function_addresses

BASE_SIZES = {
    "void": 0, "char": 1, "byte": 1,
    "undefined": 1, "undefined1": 1, "undefined2": 2, "undefined4": 4,
    "undefined8": 8, "short": 2, "ushort": 2, "int": 4, "uint": 4,
    "long": 8, "ulong": 8, "size_t": 8, "time_t": 8, "__pid_t": 4,
    "float": 4, "double": 8, "bool": 1,
}


def _spelling_size(spelling):
    """Byte size of a servable seed spelling (pointer=8, arrays multiply)."""
    dims = [int(d) for d in re.findall(r"\[(\d+)\]", spelling)]
    base = spelling.split("[")[0]
    if base.endswith("*"):
        size = 8
    else:
        size = BASE_SIZES.get(base.strip())
        if size is None:
            return None
    for dim in dims:
        size *= dim
    return size


def _canon_neighbor_seeds(golden_text, dwarf_functions):
    """Adopt canon-committed synthesized slots bordering a DWARF seed.

    The canon decl layer is the committed-symbol truth (W1B harvest
    source); a slot the analyzer committed (and canon prints separately)
    must also be committed on our side, or the DWARF seed's typelock
    absorbs the uncommitted neighbor (file2string uStack_150, oracle-
    verified). Only immediately-bordering KNOWN_BASES-typed slots are
    adopted — the minimal evidence-backed set."""
    adopted = {}
    for addr, name, lines in split_functions(golden_text):
        if addr not in dwarf_functions:
            continue
        seeds = dwarf_functions[addr]["locals"]
        seed_extents = []
        for seed in seeds:
            size = _spelling_size(seed["type"])
            if size:
                seed_extents.append((seed["offset"], seed["offset"] + size))
        neighbors = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            dm = DECL.match(line)
            if dm is None:
                continue
            nm = STACK_NAME.match(dm.group("name"))
            if nm is None:
                continue
            type_expr = parse_type_expr(
                dm.group("type"), dm.group("stars"), dm.group("arr")
            )
            if type_expr is None or base_of(type_expr) not in KNOWN_BASES:
                continue
            nsize = _spelling_size(type_expr)
            if not nsize:
                continue
            noff = -int(nm.group(1), 16)
            nrange = (noff, noff + nsize)
            borders = any(
                nrange[1] == s[0] or s[1] == nrange[0] for s in seed_extents
            )
            if not borders:
                continue
            if any(s["offset"] == noff for s in seeds):
                continue  # already DWARF-seeded
            neighbors.append(
                {
                    "offset": noff,
                    "name": dm.group("name"),
                    "type": type_expr,
                    "typelock": True,
                    "source": "canon-decl",
                    "adopt_reason": "borders DWARF seed (partition guard)",
                }
            )
        if neighbors:
            adopted.setdefault(addr, []).extend(neighbors)
    return adopted


def _sleb128(blob, i):
    val = 0
    shift = 0
    while True:
        b = blob[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                val -= 1 << shift
            return val, i


def _decode_fbreg(blob):
    """Single-op DW_OP_fbreg(N) -> N; any other expression -> None."""
    if len(blob) >= 2 and blob[0] == 0x91:
        try:
            n, i = _sleb128(blob, 1)
        except IndexError:
            return None
        if i == len(blob):
            return n
    return None


def _ref_abs(unit, attr):
    """DIE reference value -> section-absolute offset (ref1/2/4/8/udata are
    CU-relative; DW_FORM_ref_addr already absolute)."""
    if attr.form == "DW_FORM_ref_addr":
        return attr.value
    return unit.cu_offset + attr.value


def _die_attr(die, name):
    return die.attributes.get(name)


def _attr_str(attr):
    return attr.value.decode() if attr and isinstance(attr.value, bytes) else None


def _origin_chain(unit, die):
    """[die, origin...] — the concrete DIE first, then abstract-origin /
    specification targets (location/name/type lookups walk the chain)."""
    chain = [die]
    cur = die
    for _ in range(16):
        ref = _die_attr(cur, "DW_AT_abstract_origin") or _die_attr(
            cur, "DW_AT_specification"
        )
        if ref is None:
            break
        nxt = unit.get_DIE_from_refaddr(_ref_abs(unit, ref))
        if nxt is None:
            break
        chain.append(nxt)
        cur = nxt
    return chain


def _chain_attr(chain, name):
    for die in chain:
        attr = _die_attr(die, name)
        if attr is not None:
            return attr
    return None


def _type_spell(unit, tattr, bool_arrays, depth=0):
    """DW_AT_type attr -> (spelling|None, reason) in the seed channel's
    servable domain (KNOWN_BASES + pointer/array composition)."""
    if depth > 12 or tattr is None:
        return None, "no-type"
    tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
    if tdir is None:
        return None, "unresolved-type"
    if tdir.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in ("int", "char"):
            return name, None
        return None, "base-" + name
    if tdir.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _type_spell(
            unit, _die_attr(tdir, "DW_AT_type"), bool_arrays, depth + 1
        )
    if tdir.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in KNOWN_BASES:
            return name, None
        return None, "typedef-" + name
    if tdir.tag == "DW_TAG_pointer_type":
        inner = _die_attr(tdir, "DW_AT_type")
        spell, why = _type_spell(unit, inner, bool_arrays, depth + 1)
        if spell is None:
            return None, why or "ptr-inner"
        return spell + " *", None
    if tdir.tag == "DW_TAG_array_type":
        count = None
        for child in tdir.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                cnt = _die_attr(child, "DW_AT_count")
                if cnt is not None:
                    count = cnt.value
                else:
                    ub = _die_attr(child, "DW_AT_upper_bound")
                    if ub is not None and isinstance(ub.value, int):
                        count = ub.value + 1  # lower bound defaults to 0
        inner_spell, why = _type_spell(
            unit, _die_attr(tdir, "DW_AT_type"), bool_arrays, depth + 1
        )
        if inner_spell is None:
            return None, why or "array-inner"
        if count is None:
            return None, "array-unknown-count"
        if bool_arrays and inner_spell == "char" and count in (256, 4096):
            # canon-committed boolean typing (stage_seed_diag-validated)
            return "bool[%d]" % count, None
        return "%s[%d]" % (inner_spell, count), None
    if tdir.tag in (
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
    ):
        return None, "composite"
    return None, tdir.tag


def _scope_range(die):
    lo = _die_attr(die, "DW_AT_low_pc")
    if lo is None:
        return None
    hi = _die_attr(die, "DW_AT_high_pc")
    hi_v = hi.value if hi is not None else 0
    if hi is not None and hi.form.startswith("DW_FORM_data"):
        hi_v = lo.value + hi.value  # offset form
    return [lo.value, hi_v]


def _named_composite_set(dw):
    """DWARF names resolvable by the Rust factory name lookup (the
    parse_type_names mirror): typedefs over composite/enum/array-with-size
    and named structure/union/enumeration DIEs with byte_size."""
    named = set()
    for unit in dw.iter_CUs():
        for die in unit.iter_DIEs():
            if die.tag in (
                "DW_TAG_structure_type",
                "DW_TAG_union_type",
                "DW_TAG_enumeration_type",
            ):
                name = _attr_str(_die_attr(die, "DW_AT_name"))
                size = _die_attr(die, "DW_AT_byte_size")
                if name and size is not None and size.value > 0:
                    named.add(name)
            elif die.tag == "DW_TAG_typedef":
                name = _attr_str(_die_attr(die, "DW_AT_name"))
                if not name:
                    continue
                tattr = _die_attr(die, "DW_AT_type")
                if tattr is None:
                    continue
                tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
                # chase through typedef/qualifier layers to a sized carrier
                for _ in range(16):
                    if tdir is None:
                        break
                    if tdir.tag in (
                        "DW_TAG_typedef",
                        "DW_TAG_const_type",
                        "DW_TAG_volatile_type",
                    ):
                        nxt = _die_attr(tdir, "DW_AT_type")
                        tdir = (
                            unit.get_DIE_from_refaddr(_ref_abs(unit, nxt))
                            if nxt is not None
                            else None
                        )
                        continue
                    break
                if tdir is None:
                    continue
                if tdir.tag in (
                    "DW_TAG_structure_type",
                    "DW_TAG_union_type",
                    "DW_TAG_enumeration_type",
                ):
                    size = _die_attr(tdir, "DW_AT_byte_size")
                    if size is not None and size.value > 0:
                        named.add(name)
                elif tdir.tag == "DW_TAG_array_type":
                    named.add(name)  # va_list-class: array typedef
    return named


def _type_spell_struct(unit, tattr, named, depth=0):
    """DW_AT_type attr -> (spelling|None, reason) in the C4 struct domain:
    bases must be DWARF-named composites/typedefs (factory name lookup);
    KNOWN_BASES spellings are the C1/C2 channel's domain, dropped here."""
    if depth > 12 or tattr is None:
        return None, "no-type"
    tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
    if tdir is None:
        return None, "unresolved-type"
    if tdir.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _type_spell_struct(
            unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1
        )
    if tdir.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in named:
            return name, None
        return None, "typedef-unservable-" + name
    if tdir.tag == "DW_TAG_pointer_type":
        inner = _die_attr(tdir, "DW_AT_type")
        spell, why = _type_spell_struct(unit, inner, named, depth + 1)
        if spell is None:
            return None, why or "ptr-inner"
        return spell + " *", None
    if tdir.tag == "DW_TAG_array_type":
        count = None
        for child in tdir.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                cnt = _die_attr(child, "DW_AT_count")
                if cnt is not None:
                    count = cnt.value
                else:
                    ub = _die_attr(child, "DW_AT_upper_bound")
                    if ub is not None and isinstance(ub.value, int):
                        count = ub.value + 1
        inner_spell, why = _type_spell_struct(
            unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1
        )
        if inner_spell is None:
            return None, why or "array-inner"
        if count is None:
            return None, "array-unknown-count"
        return "%s[%d]" % (inner_spell, count), None
    if tdir.tag in (
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
    ):
        name = _attr_str(_die_attr(tdir, "DW_AT_name"))
        if name and name in named:
            return name, None
        return None, "composite-unnamed"
    if tdir.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        return None, "c1c2-domain-" + name
    return None, tdir.tag


def _warn_if_no_dwarf(binary, elf):
    """Loud zero-yield verdict for DWARF-less corpora (HSEED lane: the
    httpd corpus is stripped — no .debug_* sections — so the C2/C4 channels
    are corpus-inapplicable, not merely empty). stdout stays parseable;
    the manifest bytes are unchanged (curl determinism preserved)."""
    if not any(s.name == ".debug_info" for s in elf.iter_sections()):
        sys.stderr.write(
            "WARNING: %s carries no .debug_info section (stripped corpus): "
            "the DWARF seed channel is corpus-inapplicable; harvest yield "
            "is provably 0 (C2/C4 need a DWARF-bearing binary)\n" % binary
        )


def harvest_struct(binary, golden_path):
    """C4 struct-seed table: DWARF-named composite locals + canon-decl
    struct-pointer local_[hex] adoption. Returns (functions, drops)."""
    from elftools.elf.elffile import ELFFile

    inventory = []
    dwarf_functions = set()
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        named = _named_composite_set(dw)
        for unit in dw.iter_CUs():
            for top in unit.iter_DIEs():
                if top.tag != "DW_TAG_subprogram":
                    continue
                low = _die_attr(top, "DW_AT_low_pc")
                if low is None:
                    continue
                fn_name = None
                for die in _origin_chain(unit, top):
                    fn_name = _attr_str(_die_attr(die, "DW_AT_name"))
                    if fn_name:
                        break
                dwarf_functions.add((low.value, fn_name))
                stack = [(top, None)]
                while stack:
                    node, scope = stack.pop()
                    for child in node.iter_children():
                        if child.tag == "DW_TAG_subprogram":
                            if _die_attr(child, "DW_AT_low_pc") is not None:
                                stack.append((child, None))
                        elif child.tag in (
                            "DW_TAG_lexical_block",
                            "DW_TAG_inlined_subroutine",
                        ):
                            stack.append((child, child))
                        elif child.tag == "DW_TAG_variable":
                            inventory.append((low.value, fn_name, unit, child))
        functions = {}
        drops = []
        entries = []
        for low_pc, fn_name, unit, die in inventory:
            chain = _origin_chain(unit, die)
            name = None
            for cdie in chain:
                name = _attr_str(_die_attr(cdie, "DW_AT_name"))
                if name:
                    break
            loc = _chain_attr(chain, "DW_AT_location")
            if loc is None:
                continue
            if loc.form not in (
                "DW_FORM_exprloc",
                "DW_FORM_block",
                "DW_FORM_block1",
                "DW_FORM_block2",
                "DW_FORM_block4",
            ):
                continue
            fbreg = _decode_fbreg(bytes(loc.value))
            if fbreg is None:
                continue
            tattr = _chain_attr(chain, "DW_AT_type")
            spell, why = _type_spell_struct(unit, tattr, named)
            entries.append(
                {
                    "fn": fn_name or "<anon>",
                    "name": name,
                    "canon": "0x%x" % (low_pc + 0x100000),
                    "offset": fbreg + 8,
                    "type": spell,
                    "drop": why,
                }
            )
        # first DWARF claim per (function, slot) owns the slot (the
        # progressbar/passarg shadowing rule carries over verbatim)
        slot_owner = {}
        for e in entries:
            key = (e["canon"], e["offset"])
            if key not in slot_owner:
                slot_owner[key] = e
        seen = set()
        for e in entries:
            label = "%s/%s@%d" % (e["fn"], e["name"], e["offset"])
            if label in seen:
                drops.append((e["fn"], e["name"], "duplicate"))
                continue
            seen.add(label)
            if e["type"] is None:
                drops.append((e["fn"], e["name"], e["drop"] or "unservable"))
                continue
            owner = slot_owner[(e["canon"], e["offset"])]
            if owner is not e:
                drops.append(
                    (
                        e["fn"],
                        e["name"],
                        "slot-owned-by-%s(%s)"
                        % (owner["name"], owner["drop"] or owner["type"]),
                    )
                )
                continue
            fn = functions.setdefault(
                e["canon"], {"name": e["fn"], "locals": []}
            )
            fn["locals"].append(
                {
                    "offset": e["offset"],
                    "name": e["name"],
                    "type": e["type"],
                    "typelock": True,
                    "source": "dwarf-struct",
                }
            )
        # canon-decl adoption: local_[hex] declarators whose base names a
        # DWARF composite (getparameter Configurable *local_5b8 /
        # HttpPost *local_5a8); the function must itself be a DWARF
        # subprogram (the committed type's provenance).
        by_lowpc = {low: nm for low, nm in dwarf_functions}
        golden_text = open(golden_path, "r", encoding="utf-8").read()
        for addr, fn_name, lines in split_functions(golden_text):
            low = int(addr, 16) - 0x100000 if int(addr, 16) >= 0x100000 else None
            if low is None or low not in by_lowpc:
                continue
            for line in lines:
                dm = re.match(
                    r"^\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*(\*+)\s*"
                    r"(local_[0-9a-f]+)\s*((?:\[\d+\])*)\s*;",
                    line,
                )
                if dm is None:
                    continue
                base = dm.group(1).strip()
                if base not in named:
                    continue
                type_expr = parse_type_expr(dm.group(1), dm.group(2), dm.group(4))
                if type_expr is None:
                    continue
                name = dm.group(3)
                fn = functions.setdefault(addr, {"name": fn_name, "locals": []})
                if any(l["offset"] == -int(name[6:], 16) for l in fn["locals"]):
                    continue
                fn["locals"].append(
                    {
                        "offset": -int(name[6:], 16),
                        "name": name,
                        "type": type_expr,
                        "typelock": True,
                        "source": "canon-decl",
                        "adopt_reason": "struct-pointer base in DWARF named-type set",
                    }
                )
        for fn in functions.values():
            fn["locals"].sort(key=lambda local: local["offset"])
    return functions, drops


def harvest_dwarf(binary, golden_path=None, canon_types=True):
    """Walk the binary's .debug_info and build the DWARF-name seed table
    keyed by canon golden addresses (low_pc + 0x100000). Returns
    (functions, drops) where drops is the accounting list for the manifest."""
    from elftools.elf.elffile import ELFFile

    inventory = []
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        for unit in dw.iter_CUs():
            for top in unit.iter_DIEs():
                if top.tag != "DW_TAG_subprogram":
                    continue
                low = _die_attr(top, "DW_AT_low_pc")
                if low is None:
                    continue
                fn_name = None
                for die in _origin_chain(unit, top):
                    fn_name = _attr_str(_die_attr(die, "DW_AT_name"))
                    if fn_name:
                        break
                stack = [(top, None)]
                while stack:
                    node, scope = stack.pop()
                    for child in node.iter_children():
                        if child.tag == "DW_TAG_subprogram":
                            if _die_attr(child, "DW_AT_low_pc") is not None:
                                stack.append((child, None))
                        elif child.tag in (
                            "DW_TAG_lexical_block",
                            "DW_TAG_inlined_subroutine",
                        ):
                            stack.append((child, child))
                        elif child.tag == "DW_TAG_variable":
                            inventory.append((low.value, fn_name, unit, child, scope))
                            stack.append((child, scope))
        # first DWARF claim per (function, slot) owns the slot
        slot_owner = {}
        entries = []
        for low_pc, fn_name, unit, die, scope in inventory:
            chain = _origin_chain(unit, die)
            name = None
            for cdie in chain:
                name = _attr_str(_die_attr(cdie, "DW_AT_name"))
                if name:
                    break
            loc = _chain_attr(chain, "DW_AT_location")
            if loc is None:
                continue
            if loc.form not in (
                "DW_FORM_exprloc",
                "DW_FORM_block",
                "DW_FORM_block1",
                "DW_FORM_block2",
                "DW_FORM_block4",
            ):
                continue  # sec_offset loc-list: Ghidra's importer drops it
            fbreg = _decode_fbreg(bytes(loc.value))
            if fbreg is None:
                continue  # DW_OP_addr static / piece / multi-op: other channels
            tattr = _chain_attr(chain, "DW_AT_type")
            spell, why = _type_spell(unit, tattr, canon_types)
            entries.append(
                {
                    "fn": fn_name or "<anon>",
                    "name": name,
                    "canon": "0x%x" % (low_pc + 0x100000),
                    "offset": fbreg + 8,
                    "type": spell,
                    "drop": why,
                    "inline": scope is not None
                    and scope.tag == "DW_TAG_inlined_subroutine",
                    "scope": _scope_range(scope) if scope is not None else None,
                }
            )
        slot_owner = {}
        for e in entries:
            key = (e["canon"], e["offset"])
            if key not in slot_owner:
                slot_owner[key] = e
        functions = {}
        drops = []
        seen = set()
        for e in entries:
            label = "%s/%s@%d" % (e["fn"], e["name"], e["offset"])
            if label in seen:
                drops.append((e["fn"], e["name"], "duplicate"))
                continue
            seen.add(label)
            if e["type"] is None:
                reason = e["drop"] or "unservable"
                drops.append((e["fn"], e["name"], reason))
                continue
            owner = slot_owner[(e["canon"], e["offset"])]
            if owner is not e:
                drops.append(
                    (
                        e["fn"],
                        e["name"],
                        "slot-owned-by-%s(%s)" % (owner["name"], owner["drop"] or owner["type"]),
                    )
                )
                continue
            fn = functions.setdefault(
                e["canon"], {"name": e["fn"], "locals": []}
            )
            fn["locals"].append(
                {
                    "offset": e["offset"],
                    "name": e["name"],
                    "type": e["type"],
                    "typelock": True,
                    "lex_scope": e["scope"] is not None,
                    "inline_origin": e["inline"],
                    "scope_range": e["scope"],
                }
            )
        for fn in functions.values():
            fn["locals"].sort(key=lambda local: local["offset"])
    if golden_path is not None:
        adopted = _canon_neighbor_seeds(
            open(golden_path, "r", encoding="utf-8").read(), functions
        )
        for addr, neighbors in adopted.items():
            functions[addr]["locals"].extend(neighbors)
            functions[addr]["locals"].sort(key=lambda local: local["offset"])
    return functions, drops


# ---------------------------------------------------------------------------
# CMT warning-comment mode (CMTSEED lane; CMTFILL hand-over promotion). The
# canon golden's `/* Unresolved local var: ... */` blocks are the analyzeHead
# less Java front-end's unresolved-variable warnings stored through the
# program comment database (type=warning; printlanguage.cc:582 instr_comment
# _type user2|warning prints them mid-body). The decompiler reads them back
# through CommentSorter::findPosition (comment.cc:270: the first op at-or-
# after the anchor whose basic block contains the anchor address, else the
# spaceless exact-match backup at comment.cc:298-306 which hangs the comment
# on an op only when op.addr == comm.addr) and PrintC's emitLineComment
# renders the block (20-col `/* ` first line, 23-col commentfill
# continuations — the emitter's ` */` closer is never part of the record
# text). The channel harvests:
#   - text: verbatim from the canon golden (presence gate: only records
#     canon itself prints; never re-spelled from DWARF types);
#   - anchors: .debug_info scope structure (function-domain group ->
#     concrete subprogram low_pc; lexical-domain group -> scope low_pc or
#     the scope's DW_AT_ranges FIRST interval begin; group members are
#     variables whose location is DW_FORM_sec_offset or absent — exprloc
#     vars resolve to named locals and never join a record);
#   - matching: per function, exact var-name-sequence equality against the
#     DWARF groups in canon order, one group consumed per record;
#   - calibration (curl table below): the backup path's exact-match
#     requirement means an anchor in a dead-coded entry prologue or a
#     mid-instruction lexical-block start has no live op and the record is
#     excised; each calibration re-anchors to the first live op of the
#     statement canon anchors the block before (RUDRA_DUMP_FUNC dumps;
#     e40ed130 stage_cmt_diag oracle re-verified: 17 records / 45 lines
#     byte-exact vs canon).
# ---------------------------------------------------------------------------

CMT_HARVEST_RULE = (
    "canon golden text gate (`/* Unresolved local var: ... */` blocks, "
    "20-col `/* ` first line / 23-col commentfill continuations, emitter "
    "closer stripped — record text is verbatim canon output, never "
    "re-spelled from DWARF); anchors from .debug_info: function-domain "
    "group -> concrete subprogram low_pc, lexical-domain group -> scope "
    "low_pc | DW_AT_ranges FIRST interval begin, members = variables with "
    "DW_FORM_sec_offset or absent location (exprloc vars become named "
    "locals); per-function matching by exact var-name sequence in canon "
    "order, one group per record; calibration table per corpus (e40ed130 "
    "stage_cmt_diag oracle-verified): CommentSorter::findPosition backup "
    "path (comment.cc:298-306) requires op.addr == comm.addr, so "
    "dead-coded-prologue / mid-instruction anchors re-anchor to the first "
    "live op of the canon-anchored statement; records keyed by canon "
    "golden addresses (ELF vaddr + 0x100000)"
)

# Curl corpus calibrations: raw DWARF anchor -> (live-op anchor, reason).
# Each target is the first live op of the statement canon anchors the
# block before; CMTFILL lane oracle evidence (stage_cmt_diag @ e40ed130,
# /dev/shm/rugra-reports/LANE_CMTFILL_2026-09-25.md).
CMT_CALIBRATIONS_CURL = {
    0x3720: (0x3729, "my_get_token INT_EQUAL if((line==0)&&..): entry prologue dead-coded"),
    0x3840: (0x3850, "my_get_line PTRSUB buf-alias (5 live ops; oracle placement identical to the entry anchor)"),
    0x3C80: (0x3C91, "parseconfig INT_ADD canary read: entry prologue dead-coded"),
    0x3F00: (0x3F52, "getparameter first op after the alias-ptr init statements (for-init COPY@0x3f02 sorts below them in the op tree)"),
    0x4283: (0x428D, "getparameter CALL strchr(...,0x3a): lexical-block start lands mid-instruction"),
    0x44AF: (0x44BB, "getparameter COPY ';auto' (strstr arg): lexical-block start lands mid-instruction"),
    0x5220: (0x522E, "match_url LOAD *filename (movzbl (%rdi)): entry prologue dead-coded"),
}

# canon emitter forms: 20-col `/* ` first line, 23-col commentfill
# continuation (CMTFILL PRINTC-COMMENTFILL-ARM: 20 indent + 3 fill).
CMT_FIRST_LINE = re.compile(r"^ {20}/\* (Unresolved local var: .*)$")
CMT_CONT_LINE = re.compile(r"^ {23}(Unresolved local var: .*)$")
# golden function header line (column 0 starts the signature)
CMT_FUNC_HEAD = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:[ \*]+[A-Za-z_][A-Za-z0-9_]*)*)\("
)
# record text -> the variable's DWARF name (text spelling is canon's)
CMT_VAR_NAME = re.compile(r"Unresolved local var: .*?([A-Za-z_][A-Za-z0-9_]*)@\[")


def parse_cmt_blocks(path):
    """canon golden -> [(func_name, [record line, ...])] in file order.

    The text gate: blocks are exactly the emitter's rendered form; the
    ` */` closer belongs to the emitter and is stripped from the record."""
    blocks = []
    cur_func = None
    pending = None

    def close():
        nonlocal pending
        if pending is not None:
            blocks.append((cur_func, pending))
            pending = None

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line and not line[0].isspace():
                m = CMT_FUNC_HEAD.match(line)
                if m:
                    cur_func = m.group(1).split()[-1].lstrip("*")
                close()
                continue
            fm = CMT_FIRST_LINE.match(line)
            if fm:
                close()
                rec0 = fm.group(1)
                if rec0.endswith(" */"):
                    rec0 = rec0[: -len(" */")]
                    pending = [rec0]
                    close()
                else:
                    pending = [rec0]
                continue
            if pending is not None:
                cm = CMT_CONT_LINE.match(line)
                if cm:
                    rec = cm.group(1)
                    if rec.endswith(" */"):
                        pending.append(rec[: -len(" */")])
                        close()
                    else:
                        pending.append(rec)
                else:
                    close()
    close()
    return blocks


def collect_cmt_anchor_groups(binary):
    """DWARF walk -> {func_name: [(anchor, [var names])]} in DIE order.

    Function-domain variables anchor at the concrete subprogram low_pc;
    lexical-domain variables at the scope's low_pc or, failing that, the
    scope's DW_AT_ranges FIRST interval begin. Members are variables with
    DW_FORM_sec_offset or absent locations only."""
    from elftools.elf.elffile import ELFFile

    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        rlists = dw.range_lists()
        groups = {}

        def var_entry(unit, die):
            chain = _origin_chain(unit, die)
            nm = None
            for cdie in chain:
                nm = _attr_str(_die_attr(cdie, "DW_AT_name"))
                if nm:
                    break
            if nm is None:
                return None
            loc = _chain_attr(chain, "DW_AT_location")
            if loc is not None and loc.form != "DW_FORM_sec_offset":
                return None  # exprloc -> named local, never a record member
            return nm

        def anchor_of(die):
            low = _die_attr(die, "DW_AT_low_pc")
            if low is not None:
                return low.value
            rng = _die_attr(die, "DW_AT_ranges")
            if rng is not None:
                try:
                    for e in rlists.get_range_list_at_offset(rng.value, die.cu):
                        if hasattr(e, "begin_offset"):
                            return e.begin_offset
                except Exception:
                    return None
            return None

        def add(fn, anchor, nm):
            for anc, names in groups[fn]:
                if anc == anchor:
                    names.append(nm)
                    return
            groups[fn].append((anchor, [nm]))

        def walk(unit, fn, anchor, node):
            for child in node.iter_children():
                if child.tag == "DW_TAG_subprogram":
                    if _die_attr(child, "DW_AT_low_pc") is not None:
                        walk(unit, fn, anchor, child)
                elif child.tag in (
                    "DW_TAG_lexical_block",
                    "DW_TAG_inlined_subroutine",
                ):
                    sub = anchor_of(child)
                    walk(unit, fn, sub if sub is not None else anchor, child)
                elif child.tag == "DW_TAG_variable":
                    ent = var_entry(unit, child)
                    if ent is not None:
                        add(fn, anchor, ent)

        for unit in dw.iter_CUs():
            for top in unit.iter_DIEs():
                if top.tag != "DW_TAG_subprogram":
                    continue
                low = _die_attr(top, "DW_AT_low_pc")
                if low is None:
                    continue
                fn = None
                for die in _origin_chain(unit, top):
                    fn = _attr_str(_die_attr(die, "DW_AT_name"))
                    if fn:
                        break
                if fn is None:
                    continue
                groups.setdefault(fn, [])
                walk(unit, fn, low.value, top)
    return groups


# ---------------------------------------------------------------------------
# V4 typedef-def mode (HEADLESS-BRIDGE-V4-COMPOSITE-0005; the TYPEDEFIMM
# channel's production trigger surface, LANE_TYPEDEFIMM_2026-09-27.md
# hand-over item 2: "生产 typedef 触发面（DWARFSEED/TYPESEED manifest →
# <typedef> decode → 剥离环活跃）归 HEADLESS-BRIDGE-V4-COMPOSITE-0005 域").
#
# The oracle's production typedef source is the <def> element stream
# (TypeFactory::decodeTypedef, type.cc:4263-4313: read name/id/format,
# decode the immediate target inline, delegate to getTypedef
# type.cc:3818-3840 — the clone that carries typedefImm type.hh:196,
# consumed by the four stripping loops cast.cc:325-328 / printc.cc:390-393
# / coreaction.cc:2476-2479 / typeop.cc:2337-2340). The analyzeHeadless
# DWARF analyzer is what populates that stream for the canon corpora, so
# the manifest harvests the DWARF typedef graph restricted to the golden
# declaration layer's referenced names (signature lines + decl-block
# declarators), chain-closed over typedef-of-typedef targets.
#
# Servability split (staged channel, each rule pinned to the driver's
# public install surface — no src/ dependency on this lane):
#   - BASE targets install through the factory's canonical core spellings
#     (the DWARFDataTypeManager initBaseDataTypes alias table, mirrored
#     in Rugra's standard_base_alias debugproto.rs:1776 — "long unsigned
#     int"->"ulong" etc.). Core-spelling identity is what makes the
#     master-side name-table twin of isOpIdentical (coreaction.rs:6602,
#     the one live strip loop pre-MB22) strip size_t-family clones onto
#     the same interned node parse_c_type("ulong") returns.
#   - TYPEDEF-ref targets resolve from earlier manifest entries
#     (dependency-ordered emission; time_t -> __time_t -> long).
#   - COMPOSITE/ENUM/ARRAY targets (FILE/_IO_FILE, va_list over
#     __va_list_tag[1], CURLcode over an anon enum) need the DWARF name
#     index at install time — but building parse_type_names interns the
#     typedef names as channel-less aliases first (resolve_type's typedef
#     branch -> alias_type -> intern_named), and TypeFactory::get_typedef
#     faithfully throws on a same-named non-typedef (type.cc:3825-3826).
#     The index-aware install is therefore the MB22 joint-debug domain
#     (the import boundary itself calls get_typedef there); the manifest
#     records those entries as `deferred_typedefs`, not errors.
#   - Conventional bool spellings (bool/_Bool) are excluded exactly like
#     parse_type_names' resolve_type exception (PRINTC-BOOLLITERAL-0001,
#     dwarf_conventional_bool typefactory.rs:730): the core bool drives
#     true/false literal printing; a factory typedef clone would break it.
# ---------------------------------------------------------------------------

TYPEDEF_HARVEST_RULE = (
    "DWARF DW_TAG_typedef graph restricted to the golden declaration "
    "layer's referenced names (identifiers in signature lines and "
    "decl-block declarators, intersected with the typedef name set), "
    "chain-closed over typedef-of-typedef targets; base targets mapped "
    "through the DWARFDataTypeManager initBaseDataTypes alias table "
    "(Rugra standard_base_alias mirror) to the factory's canonical core "
    "spellings with (size, metatype); dependency-ordered emission; "
    "composite/enum/array targets deferred to the MB22 joint-debug "
    "install (index-aware; get_typedef's same-name throw type.cc:3825 "
    "makes the master-side order impossible); conventional bool "
    "spellings excluded (core bool literal channel)"
)

# DWARF base-type spelling -> (core spelling, metatype). The importer's
# own alias table (initBaseDataTypes :499-548 / standard_base_alias); the
# driver mints these via TypeFactory::get_base_named(size, metatype,
# spelling), the same node parse_c_type's core arm returns.
TYPEDEF_BASE_ALIAS = {
    "char": ("char", "int"),  # chartype identity — see TYPEDEF_CHARLESS
    "signed char": ("char", "int"),
    "unsigned char": ("uchar", "uint"),
    "short": ("short", "int"),
    "short int": ("short", "int"),
    "signed short int": ("short", "int"),
    "unsigned short int": ("ushort", "uint"),
    "short unsigned int": ("ushort", "uint"),
    "int": ("int", "int"),
    "signed int": ("int", "int"),
    "unsigned int": ("uint", "uint"),
    "long": ("long", "int"),
    "long int": ("long", "int"),
    "signed long int": ("long", "int"),
    "unsigned long int": ("ulong", "uint"),
    "long unsigned int": ("ulong", "uint"),
    "long long": ("longlong", "int"),
    "long long int": ("longlong", "int"),
    "long long unsigned int": ("ulonglong", "uint"),
    "unsigned long long int": ("ulonglong", "uint"),
}
# parse_c_type's core arms that plain get_base_named cannot reproduce
# (the char arm resolves the factory's TypeChar identity through
# find_by_name/get_type_char_named, not a plain named base).
TYPEDEF_CHARLESS = {"char", "signed char", "unsigned char"}
# conventional boolean spellings: the core bool literal channel owns them
TYPEDEF_CONVENTIONAL_BOOL = {"bool", "_Bool"}
# metatype string -> driver TypeMetatype spelling (manifest contract)
TYPEDEF_METATYPES = {"int", "uint"}


def _golden_decl_layer_names(golden_text):
    """Identifiers in the golden's declaration layer: every signature
    line (column-0 `ret name(params)` before the body brace) plus every
    decl-block declarator's type part. Body statements are excluded."""
    names = set()
    for _addr, _name, lines in split_functions(golden_text):
        started = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if not started:
                if stripped == "{":
                    started = True
                    continue
                # signature region: column-0 lines before the brace
                if line[0].isspace():
                    continue
                names.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped))
                continue
            dm = DECL.match(line)
            if dm is None:
                dm = DECL_PAREN.match(line)
                if dm is not None:
                    continue
                break  # first statement ends the declaration block
            names.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", dm.group("type")))
    return names


def _typedef_target_dies(binary):
    """DWARF walk -> ordered [(name, unit, target_attr)] for every
    DW_TAG_typedef with a name (first DIE per name wins, DIE order)."""
    from elftools.elf.elffile import ELFFile

    entries = []
    seen = set()
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        for unit in dw.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag != "DW_TAG_typedef":
                    continue
                name = _attr_str(_die_attr(die, "DW_AT_name"))
                if not name or name in seen:
                    continue
                seen.add(name)
                entries.append((name, unit, _die_attr(die, "DW_AT_type")))
    return entries


def _die_of(unit, attr):
    if attr is None:
        return None
    return unit.get_DIE_from_refaddr(_ref_abs(unit, attr))


def _describe_target(unit, attr):
    """(kind, spelling, size, metatype, reason) for a typedef's immediate
    DW_AT_type: kind in {base, typedef, composite, enum, array, pointer,
    qualifier, none}; base spellings are the canonical core table's."""
    die = _die_of(unit, attr)
    if die is None:
        return ("none", None, None, None, "no DW_AT_type")
    if die.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(die, "DW_AT_name")) or ""
        size = _die_attr(die, "DW_AT_byte_size")
        size = size.value if size is not None else None
        if name in TYPEDEF_CONVENTIONAL_BOOL:
            return ("conventional-bool", name, size, None,
                    "core bool literal channel (PRINTC-BOOLLITERAL-0001)")
        if name in TYPEDEF_CHARLESS:
            return ("chartype", name, size, None,
                    "char arm resolves the factory TypeChar identity, not a "
                    "plain named base (parse_c_type special path)")
        alias = TYPEDEF_BASE_ALIAS.get(name)
        if alias is None:
            return ("base-unmapped", name, size, None,
                    "no initBaseDataTypes alias for `%s`" % name)
        return ("base", alias[0], size, alias[1], None)
    if die.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(die, "DW_AT_name")) or ""
        return ("typedef", name, None, None, None)
    if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type",
                   "DW_TAG_class_type"):
        name = _attr_str(_die_attr(die, "DW_AT_name"))
        return ("composite", name, None, None,
                "index-resolved install (parse_type_names alias boundary) "
                "is the MB22 joint-debug domain")
    if die.tag == "DW_TAG_enumeration_type":
        name = _attr_str(_die_attr(die, "DW_AT_name"))
        return ("enum", name, None, None,
                "index-resolved install (anon enums carry no name; named "
                "enums resolve through the DWARF index) is the MB22 "
                "joint-debug domain")
    if die.tag == "DW_TAG_array_type":
        elem = _die_of(unit, _die_attr(die, "DW_AT_type"))
        elem_name = _attr_str(_die_attr(elem, "DW_AT_name")) if elem else None
        return ("array", elem_name, None, None,
                "array target needs the element type from the DWARF index — "
                "MB22 joint-debug domain")
    if die.tag == "DW_TAG_pointer_type":
        return ("pointer", None, None, None,
                "pointer target needs the pointee from the DWARF index — "
                "MB22 joint-debug domain")
    if die.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type",
                   "DW_TAG_restrict_type"):
        inner = _describe_target(unit, _die_attr(die, "DW_AT_type"))
        if inner[0] in ("base", "typedef"):
            return inner
        return ("qualifier-" + inner[0], inner[1], inner[2], inner[3],
                inner[4] or "qualified unservable target")
    return (die.tag, None, None, None, "unservable target tag")


def harvest_typedef(binary, golden_path):
    """V4 typedef-def table: golden-decl-referenced DWARF typedef chains,
    split into installable entries (base/typedef-ref targets) and
    deferred entries (composite/enum/array/pointer targets — the MB22
    joint-debug install domain). Returns (typedefs, deferred, drops);
    `typedefs` is dependency-ordered (a typedef-ref target precedes its
    referencing entry)."""
    golden_text = open(golden_path, "r", encoding="utf-8").read()
    referenced = _golden_decl_layer_names(golden_text)
    typedef_dies = _typedef_target_dies(binary)
    by_name = dict((name, (unit, attr)) for name, unit, attr in typedef_dies)

    wanted = set(name for name in by_name if name in referenced)
    # chain closure: a servable typedef-ref target must be installed
    # before its referencer, so pulled-in dependencies join `wanted`
    frontier = list(wanted)
    while frontier:
        name = frontier.pop()
        unit, attr = by_name[name]
        kind, spelling, _sz, _mt, _why = _describe_target(unit, attr)
        if kind == "typedef" and spelling not in wanted:
            wanted.add(spelling)
            frontier.append(spelling)

    typedefs = []
    deferred = []
    drops = []
    installed_names = set()
    deferred_names = set()
    # two passes: dependencies (by name) first, then referencers — a
    # stable topological order for the chain depth this graph has
    remaining = sorted(wanted)
    for _pass in range(len(remaining) + 1):
        if not remaining:
            break
        progressed = False
        still = []
        for name in remaining:
            if name in TYPEDEF_CONVENTIONAL_BOOL:
                # the exception is keyed on the TYPEDEF name (parse_type_names
                # resolve_type: dwarf_conventional_bool(&name) with a 1-byte
                # inner), not the target spelling
                drops.append({"name": name, "reason":
                              "conventional boolean spelling resolves to the "
                              "core bool (PRINTC-BOOLLITERAL-0001, "
                              "dwarf_conventional_bool typefactory.rs:730); "
                              "a factory typedef clone would break the "
                              "true/false literal channel"})
                progressed = True
                continue
            unit, attr = by_name[name]
            kind, spelling, size, metatype, why = _describe_target(unit, attr)
            if kind == "base":
                if size is None or metatype not in TYPEDEF_METATYPES:
                    drops.append({"name": name, "reason":
                                  "base target `%s` without (size, metatype)"
                                  % spelling})
                    progressed = True
                    continue
                typedefs.append({
                    "name": name,
                    "target": {"kind": "base", "spelling": spelling,
                               "size": size, "metatype": metatype},
                    "source": "dwarf-typedef",
                })
                installed_names.add(name)
                progressed = True
            elif kind == "typedef":
                if spelling in installed_names:
                    typedefs.append({
                        "name": name,
                        "target": {"kind": "typedef", "spelling": spelling},
                        "source": "dwarf-typedef",
                    })
                    installed_names.add(name)
                    progressed = True
                else:
                    still.append(name)
                continue
            elif kind in ("conventional-bool", "chartype", "base-unmapped",
                          "none"):
                drops.append({"name": name, "reason": why})
                progressed = True
            else:
                deferred.append({
                    "name": name,
                    "target_kind": kind,
                    "target_name": spelling,
                    "reason": why,
                })
                deferred_names.add(name)
                progressed = True
        remaining = still
        if not progressed:
            for name in remaining:  # blocked chain: the dependency is
                # neither installable now nor scheduled for install
                unit, attr = by_name[name]
                _kind, spelling, _sz, _mt, _why = _describe_target(unit, attr)
                blocked = spelling in deferred_names
                drops.append({"name": name, "reason":
                              "typedef chain blocked at `%s` (%s)"
                              % (spelling, "deferred to the MB22 joint-debug "
                                 "install" if blocked else
                                 "dependency not installable")})
            break
    return typedefs, deferred, drops


def harvest_cmt(binary, golden_path, corpus):
    """CMT warning-comment table: canon-text-gated records with DWARF
    scope anchors plus the corpus calibration table. Returns (functions,
    applied_calibrations, drops); records are canon-address keyed
    (ELF vaddr + 0x100000), sorted for byte-deterministic output."""
    blocks = parse_cmt_blocks(golden_path)
    per_func = {}
    for fn, recs in blocks:
        per_func.setdefault(fn, []).append(recs)
    groups = collect_cmt_anchor_groups(binary)
    calibrations = CMT_CALIBRATIONS_CURL if corpus == "curl" else {}
    golden_text = open(golden_path, "r", encoding="utf-8").read()
    function_addresses = {}
    for addr, name, _lines in split_functions(golden_text):
        function_addresses.setdefault(name, addr)
    records = []
    applied = []
    drops = []
    for fn, recs_list in per_func.items():
        cands = [g for g in groups.get(fn, []) if g[0] is not None]
        used = set()
        for recs in recs_list:  # canon order
            names = [CMT_VAR_NAME.search(r).group(1) for r in recs]
            hit = None
            for i, (anc, gnames) in enumerate(cands):
                if i in used:
                    continue
                if gnames == names:
                    hit = (i, anc)
                    break
            if hit is None:
                drops.append(
                    {
                        "function": fn,
                        "names": names,
                        "reason": "no DWARF scope group with this var sequence",
                    }
                )
                continue
            used.add(hit[0])
            dwarf_anchor = hit[1]
            entry = (fn, dwarf_anchor, None, recs)
            if dwarf_anchor in calibrations:
                target, reason = calibrations[dwarf_anchor]
                applied.append(
                    {
                        "function": fn,
                        "dwarf_anchor": "0x%x" % (dwarf_anchor + 0x100000),
                        "anchor": "0x%x" % (target + 0x100000),
                        "reason": reason,
                    }
                )
                entry = (fn, dwarf_anchor, target, recs)
            records.append(entry)
    functions = {}
    for fn, dwarf_anchor, calibrated, recs in sorted(
        records,
        key=lambda r: (
            int(function_addresses.get(r[0], "0x0"), 16),
            r[1],
        ),
    ):
        fn_addr = function_addresses.get(fn)
        if fn_addr is None:
            drops.append(
                {"function": fn, "names": [], "reason": "no canon golden header address"}
            )
            continue
        anchor = calibrated if calibrated is not None else dwarf_anchor
        functions.setdefault(
            fn_addr, {"name": fn, "comments": []}
        )["comments"].append(
            {
                "addr": "0x%x" % (anchor + 0x100000),
                "dwarf_anchor": "0x%x" % (dwarf_anchor + 0x100000),
                "text": "\n".join(recs),
            }
        )
    for fn_entry in functions.values():
        fn_entry["comments"].sort(key=lambda c: int(c["addr"], 16))
    return functions, applied, drops


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--typedef":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        typedefs, deferred, drops = harvest_typedef(binary, golden)
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "typedef-def",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": TYPEDEF_HARVEST_RULE,
            "typedefs": typedefs,
            "deferred_typedefs": deferred,
            "harvest_drops": drops,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        print(
            "harvested %d typedef defs (%d deferred to the MB22 joint-debug "
            "install, %d drops) -> %s"
            % (len(typedefs), len(deferred), len(drops), out)
        )
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--cmt":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        funcs, applied, drops = harvest_cmt(binary, golden, corpus)
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "cmt-warning",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": CMT_HARVEST_RULE,
            "anchor_calibrations": applied,
            "functions": funcs,
            "harvest_drops": drops,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        nrecords = sum(len(f["comments"]) for f in funcs.values())
        nlines = sum(
            len(c["text"].split("\n"))
            for f in funcs.values()
            for c in f["comments"]
        )
        print(
            "harvested %d comment records / %d lines (%d calibrations, %d drops) -> %s"
            % (nrecords, nlines, len(applied), len(drops), out)
        )
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--callee":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        golden, corpus, oracle_commit, out = sys.argv[2:6]
        argv_rest = sys.argv[6:]
        target_names = None
        dwarf_types = None
        for arg in argv_rest:
            if arg.startswith("--targets="):
                target_names = set(
                    name for name in arg[len("--targets=") :].split(",") if name
                )
            elif arg.startswith("--dwarf-types="):
                dwarf_types = arg[len("--dwarf-types=") :]
        if target_names is None:
            target_names = {
                "main",
                "ap_fini_vhost_config",
                "ap_vhost_iterate_given_conn",
            }
        if dwarf_types is not None:
            load_dwarf_evidence_domain(dwarf_types)
        funcs, drops, _addresses = harvest_callee(golden, target_names)
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "callee-siglock",
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": CALLEE_SIGLOCK_RULE,
            "targets": sorted(target_names),
            "callees": funcs,
            "harvest_drops": drops,
        }
        if dwarf_types is not None:
            manifest["dwarf_types_source"] = dwarf_types
            manifest["dwarf_types_sha256"] = hashlib.sha256(
                open(dwarf_types, "rb").read()
            ).hexdigest()
            manifest["harvest_rule"] = (
                CALLEE_SIGLOCK_RULE
                + "; CURLPREP --dwarf-types extension: servable bases grow "
                "the corpus's DWARF-named composites/typedefs (the "
                "parse_type_names factory surface the driver's parse_c_type "
                "resolves FILE/Configurable against), casts carry any "
                "pointer-star count (scalar (long)x and multi-star "
                "(char **)0x0 alike), and ::global / "
                "&::global.member arg forms evidence from the DWARF "
                "file-scope static + struct member table (one member level)"
            )
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        n_input = sum(1 for c in funcs.values() if c["input_lock"])
        n_ret = sum(1 for c in funcs.values() if c["return"])
        print(
            "harvested %d callees (%d input-locked, %d return-locked, %d drops) -> %s"
            % (len(funcs), n_input, n_ret, len(drops), out)
        )
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--struct":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        funcs, drops = harvest_struct(binary, golden)
        nlocals = sum(len(f["locals"]) for f in funcs.values())
        # HSEED lane: the residual ledger below is curl-corpus truth (the
        # C3NEXT §12.4 registration); any other corpus must not inherit
        # curl's residual claims. Curl keeps the exact historical notes so
        # a re-harvest stays byte-identical to the committed manifest.
        if corpus == "curl":
            residual_notes = [
                "main `URLGlob glob` (canon-only inlined glob_url param): "
                "no DWARF variable location; C3+C4 residual",
                "match_url `glob` (by-value stack formal): C3 prototype domain",
                "main `Configurable *config` (register variable, no stack "
                "slot): localdb register-symbol domain residual",
                "sec_offset loc-list variables: Ghidra's own importer drops "
                "them (canon never names i/res/url); pre-registered domain",
                "canon `/* Unresolved local var */` comment blocks: Java "
                "front-end artifact (not in decompile/cpp), comment-channel "
                "residual",
            ]
        else:
            residual_notes = [
                "corpus residual ledger not yet established (non-curl "
                "first harvest); register per-residual after oracle "
                "prevalidation",
                "sec_offset loc-list variables: Ghidra's own importer drops "
                "them (corpus-independent domain)",
            ]
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "dwarf-struct",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": STRUCT_HARVEST_RULE,
            "functions": funcs,
            "harvest_drops": [
                {"function": f, "name": n or "<anon>", "reason": r}
                for f, n, r in drops
            ],
            "residual_notes": residual_notes,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        print(
            "harvested %d functions / %d struct-typed locals (%d drops) -> %s"
            % (len(funcs), nlocals, len(drops), out)
        )
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--dwarf":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        raw_types = "--dwarf-raw-types" in sys.argv[7:]
        funcs, drops = harvest_dwarf(binary, golden_path=golden, canon_types=not raw_types)
        nlocals = sum(len(f["locals"]) for f in funcs.values())
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "dwarf",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": DWARF_HARVEST_RULE
            + (" [raw DWARF typing]" if raw_types else ""),
            "functions": funcs,
            "harvest_drops": [
                {"function": f, "name": n or "<anon>", "reason": r}
                for f, n, r in drops
            ],
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        print(
            "harvested %d functions / %d DWARF-named locals (%d drops) -> %s"
            % (len(funcs), nlocals, len(drops), out)
        )
        return 0
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    golden, corpus, oracle_commit, out = sys.argv[1:5]
    typed_only = "--typed-only" in sys.argv[5:]
    funcs = harvest(golden)
    if typed_only:
        for fn in funcs.values():
            fn["locals"] = [l for l in fn["locals"] if not l["type"].startswith("undefined")]
        funcs = {k: v for k, v in funcs.items() if v["locals"]}
    nlocals = sum(len(f["locals"]) for f in funcs.values())
    manifest = {
        "oracle_commit": oracle_commit,
        "corpus": corpus,
        "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
        "harvest_rule": (
            "decl-block lines matching '(type)([*]*)local_[0-9a-f]+([N])*;' before "
            "first statement; offset = -int(name[6:],16); "
            "TYPESEEDARB lock classification (stage_seed_diag e40ed130 "
            "nameonly-agg experiment): array declarators ride the name-only "
            "transport (typelock=false, recovered aggregates are never "
            "typelocked in either oracle face), scalars keep the C1 locked "
            "bridge"
        ),
        "functions": funcs,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    print(
        "harvested %d functions / %d committed locals (%s) -> %s"
        % (len(funcs), nlocals, "typed-only" if typed_only else "all", out)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
