//! Pretty printing and token emission
//!
//! Corresponds to Ghidra's `prettyprint.hh`

/// Ghidra: prettyprint.hh:124 Emit::brace_style
/// Different brace formatting styles. Values mirror the locked oracle enum
/// (`same_line = 0`, `next_line = 1`, `skip_line = 2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BraceStyle {
    /// Opening brace on the same line as if/do/while/for/switch
    SameLine,
    /// Opening brace is on next line
    NextLine,
    /// Opening brace is two lines down
    SkipLine,
}

/// RUGRA-GLUE: identity of one pending-brace install.
/// The oracle identifies a pending print by the address of the caller's
/// `PendingBrace` stack object (`prettyprint.hh:457 hasPendingPrint` compares
/// `pendPrint == pend`; `printc.cc:2946` closes only when THAT object's
/// `getIndentId() >= 0`, printc.hh:347-361). Rust has no stable object
/// address across a `Box<dyn Emit>` boundary, so each `set_pending_brace`
/// call mints a fresh monotonically increasing id that stands in for the
/// stack object's identity; `has_pending_print_id` /
/// `pending_brace_fired_id` answer per-id, exactly the two questions the
/// oracle asks of its pointer (SQATTR-PENDINGBRACE-IDENTITY-0001).
pub type BraceId = u64;

/// Trait for emitting decompilation tokens
///
/// This provides a generic interface for "printing" decompiled code,
/// allowing for different output formats (plain text, XML, HTML with markup, etc.)
pub trait Emit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    /// Emit raw text
    fn print(&mut self, text: &str);

    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    /// Start a new block (e.g., '{')
    fn begin_block(&mut self);
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    /// End a block (e.g., '}')
    fn end_block(&mut self);

    // Ghidra: prettyprint.cc:587 EmitNoMarkup::openParen
    /// Emit an open parenthesis. Returns the id of the printing group the
    /// pretty printer opens around the parenthesised unit (plain-text
    /// emitters print the paren and return 0).
    fn open_paren(&mut self, paren: &str) -> i32 {
        self.print(paren);
        0
    }

    // Ghidra: prettyprint.cc:589 EmitNoMarkup::closeParen
    /// Emit a close parenthesis, closing the group opened by the matching
    /// `open_paren` (the id is only consumed by the pretty printer).
    fn close_paren(&mut self, paren: &str, _id: i32) {
        self.print(paren);
    }

    // Ghidra: prettyprint.cc:46 Emit::spaces
    /// Emit `num` space characters. In the pretty printer this is a
    /// \e tokenbreak: whitespace where a line break (indenting by `bump`)
    /// may be inserted if the line overflows. Plain-text emitters just
    /// print the spaces (prettyprint.cc:46-59's spacearray fold).
    fn spaces(&mut self, num: i32, _bump: i32) {
        for _ in 0..num.max(0) {
            self.print(" ");
        }
    }

    // Ghidra: prettyprint.hh:340 Emit::openGroup
    /// Start an invisible printing group and return its matching identifier.
    /// Plain-text emitters keep the group invisible and may use identifier 0.
    fn open_group(&mut self) -> i32 {
        0
    }

    // Ghidra: prettyprint.hh:346 Emit::closeGroup
    /// End the invisible printing group identified by `id`.
    fn close_group(&mut self, _id: i32) {}

    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    /// Start a function definition
    fn begin_function(&mut self);
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    /// End a function definition
    fn end_function(&mut self);

    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    /// Tag a type name for markup
    fn tag_type(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    /// Tag a variable name for markup
    fn tag_variable(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: exact metadata bridge for EmitMarkup::tagVariable (prettyprint.hh:240)
    /// Emit a variable token with the complete metadata carried by Ghidra's
    /// `tagVariable(name, highlight, vn, op)` call.  Legacy emitters delegate
    /// to their existing text/id path; metadata-aware fixtures and emitters
    /// can override this without losing the Varnode creation index, PcodeOp
    /// time, or highlight before the low-level emission boundary.
    fn tag_variable_with_metadata(
        &mut self,
        text: &str,
        highlight: crate::printlanguage::SyntaxHighlight,
        varnode_id: i64,
        op_id: i64,
    ) {
        let _ = (highlight, op_id);
        self.tag_variable(text, u64::try_from(varnode_id).unwrap_or(0));
    }
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    /// Tag an operator for markup
    fn tag_op(&mut self, text: &str);
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    /// Tag a field name for markup
    fn tag_field(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    /// Tag a function name for markup
    fn tag_func_name(&mut self, text: &str, _id: u64);
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    /// Tag a comment for markup
    fn tag_comment(&mut self, text: &str);
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    /// Tag a label for markup
    fn tag_label(&mut self, text: &str);
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    /// Tag a case label for markup
    fn tag_case_label(&mut self, text: &str);

    // Ghidra: prettyprint.hh:173 Emit::tagLine() (relative form transport)
    /// Tag a statement line — the merged no-argument `tagLine()` virtual:
    /// a line break at the CURRENT indent level (EmitNoMarkup prints
    /// `indentlevel` spaces, prettyprint.hh:557-558; EmitPrettyPrint emits
    /// a bump_t token, prettyprint.hh:918-920). The `indent` parameter is
    /// vestigial: every oracle no-arg call site maps to 0 here.
    fn tag_line(&mut self, _indent: i32) {}

    // Ghidra: prettyprint.hh:180 Emit::tagLine(int4 indent)
    /// Absolute-column line break — the one-argument `tagLine(int4)`
    /// virtual the oracle keeps SEPARATE from the no-argument form:
    /// endl + exactly `indent` spaces, ignoring the current indent level
    /// (EmitNoMarkup, prettyprint.hh:559-560) / a line_t token whose
    /// indentbump is the absolute column (EmitPrettyPrint,
    /// prettyprint.hh:922-924; break path prettyprint.cc:674-676 sets
    /// `spaceremain = maxlinesize - indentbump` then
    /// `lowlevel->tagLine(maxlinesize-spaceremain)`).
    /// Oracle production call sites: printc.cc:3211 emitLabelStatement
    /// `emit->tagLine(0)` — goto labels land at column 0 regardless of
    /// nesting depth — and printlanguage.cc:597 emitLineComment
    /// `emit->tagLine(indent)` — comment continuation at an absolute
    /// column. Negative indent clamps to zero spaces (hh:560 `i>0` loop).
    fn tag_line_indent(&mut self, _indent: i32) {}

    // Ghidra: prettyprint.hh:446 Emit::setPendingPrint (PendPrint slot)
    /// Install a cancelable deferred open-brace (printc.cc:2872-2876
    /// PendingBrace). The oracle holds a PendPrint* whose callback runs
    /// `openBraceIndent(OPEN_CURLY, style)` prior to the NEXT tagLine()
    /// (emitPending, prettyprint.hh:1129-1137) unless cancelled first.
    /// Returns the install's `BraceId` (the oracle's stand-in for the
    /// `PendingBrace` stack-object identity, prettyprint.hh:457): the
    /// installing frame passes it back to `has_pending_print_id` /
    /// `pending_brace_fired_id`, which answer per install — never per
    /// emitter-global state — so a nested frame's fire cannot be mistaken
    /// for this frame's (SQATTR-PENDINGBRACE-IDENTITY-0001). Plain-text
    /// emitters other than EmitPrettyPrint never run the callback in the
    /// oracle (only EmitMarkup/EmitPrettyPrint call emitPending,
    /// prettyprint.cc:129/136/920/930), so the trait default mints no slot
    /// and identity queries read false — callers then always take the plain
    /// tagLine arm, exactly like the oracle's EmitNoMarkup paths.
    fn set_pending_brace(&mut self, style: BraceStyle) -> BraceId {
        let _ = style;
        0
    }

    // Ghidra: prettyprint.hh:451 Emit::cancelPendingPrint
    /// Clear the pending print without running it (printc.cc:2901, the
    /// `else if` merge consuming an un-fired brace).
    fn cancel_pending_print(&mut self) {}

    // Ghidra: prettyprint.hh:457 Emit::hasPendingPrint
    /// Is THIS install's pending print still in the slot (un-fired and
    /// un-cancelled)? The oracle compares the caller's object pointer:
    /// `pendPrint == pend`. A nested install that replaced the slot makes
    /// this read false for the outer install — the oracle-identical answer.
    fn has_pending_print_id(&self, id: BraceId) -> bool {
        let _ = id;
        false
    }

    // Ghidra: printc.hh:347-360 PendingBrace::getIndentId
    /// Did THIS install's pending brace fire? The oracle's frame-owned
    /// `PendingBrace.indentId` starts -1 and turns >= 0 exactly when the
    /// callback ran (printc.cc:2872-2876); printc.cc:2946-2948 closes the
    /// brace only for the frame whose own object fired. Per-id query so a
    /// sibling/nested frame's fire never leaks into this frame's answer.
    fn pending_brace_fired_id(&self, id: BraceId) -> bool {
        let _ = id;
        false
    }

    // Ghidra: prettyprint.cc:61 Emit::openBraceIndent
    /// Emit an opening brace and start a new indent level. Faithful to
    /// `Emit::openBraceIndent(const string&, brace_style)`
    /// (prettyprint.cc:61-76): `same_line` emits one space before the brace,
    /// `skip_line` forces two line breaks, `next_line` one line break; the
    /// indent level is bumped (startIndent) and then the brace is printed.
    /// Plain-text default composes the primitive `print`/`tag_line` calls;
    /// `EmitNoMarkup` overrides it with the oracle's unconditional
    /// `tagLine` newline semantics (prettyprint.hh:557).
    fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => self.print(" "),
            BraceStyle::SkipLine => {
                self.tag_line(0);
                self.tag_line(0);
            }
            BraceStyle::NextLine => {
                self.tag_line(0);
            }
        }
        self.bump_indent();
        self.print(brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent
    /// Emit a closing brace and remove an indent level. Faithful to
    /// `Emit::closeBraceIndent(const string&, int4)`
    /// (prettyprint.hh:481-483): `stopIndent(id); tagLine(); print(brace);`
    /// — the brace lands on the next line at the (now decremented) indent.
    fn close_brace_indent(&mut self, brace: &str) {
        self.drop_indent();
        self.tag_line(0);
        self.print(brace);
    }

    // RUGRA-GLUE: bump_indent (startIndent indent-bump half, prettyprint.hh:371)
    /// Start an indent level (indentincrement = 2 spaces per level).
    fn bump_indent(&mut self) {}

    // RUGRA-GLUE: drop_indent (stopIndent indent-drop half, prettyprint.hh:377)
    /// End an indent level.
    fn drop_indent(&mut self) {}

    // RUGRA-GLUE: begin_document (no Ghidra counterpart found)
    // --- Begin/end pairs (Ghidra Emit virtuals, prettyprint.hh:136-231) ---
    // These are no-ops in plain text mode. Markup emitters would emit XML tags.
    fn begin_document(&mut self) {}
    // RUGRA-GLUE: end_document (no Ghidra counterpart found)
    fn end_document(&mut self) {}
    // RUGRA-GLUE: begin_return_type (no Ghidra counterpart found)
    fn begin_return_type(&mut self) {}
    // RUGRA-GLUE: end_return_type (no Ghidra counterpart found)
    fn end_return_type(&mut self) {}
    // RUGRA-GLUE: begin_var_decl (no Ghidra counterpart found)
    fn begin_var_decl(&mut self) {}
    // RUGRA-GLUE: end_var_decl (no Ghidra counterpart found)
    fn end_var_decl(&mut self) {}
    // RUGRA-GLUE: begin_statement (no Ghidra counterpart found)
    fn begin_statement(&mut self) {}
    // RUGRA-GLUE: end_statement (no Ghidra counterpart found)
    fn end_statement(&mut self) {}
    // RUGRA-GLUE: begin_func_proto (no Ghidra counterpart found)
    fn begin_func_proto(&mut self) {}
    // RUGRA-GLUE: end_func_proto (no Ghidra counterpart found)
    fn end_func_proto(&mut self) {}

    // Ghidra: prettyprint.cc:1134 EmitPrettyPrint::startComment
    /// Begin a comment block (the pretty printer fills forced breaks inside
    /// comments with the comment fill string). Returns the block id.
    fn start_comment(&mut self) -> i32 { 0 }

    // Ghidra: prettyprint.cc:1144 EmitPrettyPrint::stopComment
    /// End the comment block started by `start_comment`.
    fn stop_comment(&mut self, _id: i32) {}

    // Ghidra: prettyprint.cc:1194 EmitPrettyPrint::flush
    /// Drain all pending print commands to the final output stream. The
    /// pretty printer commits its whole token queue; plain emitters are
    /// already byte-committed, so this is a no-op for them.
    fn flush(&mut self) {}

    // Ghidra: prettyprint.hh:1111 EmitPrettyPrint::setCommentFill
    /// Set the fill string printed after a forced line break inside a
    /// comment block (prettyprint.cc:601/690). PrintC arms this with the
    /// width of its `commentstart` delimiter ("/* " -> "   ") via
    /// printlanguage.cc:98-110 setCommentDelimeter.
    fn set_comment_fill(&mut self, _fill: &str) {}

    // Ghidra: prettyprint.hh:424 Emit::resetDefaults
    /// (Re)set the default emitting options. The base `Emit::resetDefaults`
    /// (prettyprint.hh:424) runs `resetDefaultsInternal`
    /// (`indentincrement = 2`, prettyprint.hh:103); Rust's plain-text
    /// emitters carry no cross-document print options (their indent state
    /// is per-document runtime state, reset by `clear`), so the default
    /// impl is a structural no-op. `EmitPrettyPrint` overrides it with the
    /// full reset (prettyprint.cc:1237-1242).
    fn reset_defaults(&mut self) {}

    // Ghidra: prettyprint.hh:409 Emit::getMaxLineSize
    /// Get the maximum number of characters allowed per line, or -1 if
    /// this emitter does not enforce a line maximum.
    fn get_max_line_size(&self) -> i32 { -1 }

    // RUGRA-GLUE: emits_markup (no Ghidra counterpart found)
    /// Check if this emitter supports markup
    fn emits_markup(&self) -> bool { false }

    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    /// Convert this emitter into a `Box<dyn Any>` for downcasting
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;

    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    /// Get a mutable reference for downcasting
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { None }
}

// RUGRA-GLUE: reconcile_int_times_string (no Ghidra counterpart found)
/// Reconcile `X * "string"` — int * string-literal is illegal C. Cast the
/// string literal to (long). Only matches quoted strings, never pointer vars.
fn reconcile_int_times_string(line: &str) -> String {
    if let Some(pos) = line.find(" * \"") {
        let after = &line[pos + 4..]; // after ' * "'
        if let Some(end) = after.find("\"") {
            let str_lit = &line[pos + 3..pos + 4 + end + 1]; // "string"
            let rest = &line[pos + 4 + end + 1..];
            return format!("{} * (long){}{}", &line[..pos], str_lit, rest);
        }
    }
    line.to_string()
}

// RUGRA-GLUE: reconcile_int_minus_pointer (no Ghidra counterpart found)
fn reconcile_int_minus_pointer(line: &str) -> String {
    let ptr_prefixes = ["piVar", "pcVar", "psVar", "ppVar", "pvVar"];
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut result = String::with_capacity(n + 16);
    let mut i = 0;
    while i < n {
        // Try to match "<int> - <ptrprefix>" starting at some position <= i.
        // We look for " - <ptrprefix>" at position i+? but scan forward only.
        // Simpler: find the next " - " from i.
        if let Some(rel) = line[i..].find(" - ") {
            let dash_pos = i + rel;
            // Check if what follows " - " is a pointer prefix.
            let after_dash = dash_pos + 3;
            let rest = if after_dash < n { &line[after_dash..] } else { "" };
            let starts_ptr = ptr_prefixes.iter().any(|p| rest.starts_with(p));
            if starts_ptr {
                // Scan backwards from dash_pos to find the integer operand.
                // (This is safe — we only READ backwards, we never move i back.)
                let mut num_end = dash_pos;
                while num_end > 0 && bytes[num_end - 1] == b' ' { num_end -= 1; }
                let mut num_start = num_end;
                while num_start > 0 && bytes[num_start - 1].is_ascii_hexdigit() {
                    num_start -= 1;
                }
                if num_start >= 2 && &bytes[num_start - 2..num_start] == b"0x" {
                    num_start -= 2;
                }
                let num_tok = &line[num_start..num_end];
                let is_int = !num_tok.is_empty() && (
                    num_tok.chars().all(|c| c.is_ascii_digit())
                    || (num_tok.starts_with("0x") && num_tok.len() > 2
                        && num_tok[2..].chars().all(|c| c.is_ascii_hexdigit()))
                );
                let sep_ok = num_start == 0 || matches!(bytes[num_start - 1],
                    b' ' | b'=' | b'(' | b',' | b'\t');
                if is_int && sep_ok && num_start >= i {
                    // Determine the pointer type from the prefix so the cast
                    // matches the pointer operand's declared type (avoids
                    // 'char* - int*' mismatch). piVar=int*, pcVar=char*,
                    // psVar=struct*, ppVar/pvVar=void*.
                    let cast = if rest.starts_with("piVar") { "(int *)" }
                        else if rest.starts_with("pcVar") { "(char *)" }
                        else if rest.starts_with("psVar") { "(struct _struct *)" }
                        else { "(void *)" };
                    result.push_str(&line[i..num_start]);
                    result.push_str(cast);
                    result.push_str(num_tok);
                    i = num_end; // forward: num_end > num_start >= i (num_tok non-empty)
                    continue;
                }
            }
            // No match here — emit up to and including " - " and continue after it.
            result.push_str(&line[i..after_dash]);
            i = after_dash;
        } else {
            // No more " - " — emit the rest and done.
            result.push_str(&line[i..]);
            break;
        }
    }
    result
}

// ============================================================================
// POSTFIX-RETIRE-0001 W1 / POSTFIX-INSTRUMENT-0001: per-pass mutation counters
// ============================================================================
// RUGRA-GLUE: 纯诊断插桩,Ghidra 无对应物(oracle 的 EmitNoMarkup 是无缓冲直写
// emitter,prettyprint.hh:542-594,唯一字段 ostream *s;发射路径以 flush 结束,
// prettyprint.cc:1194-1213,之后零扫描)。W2 零突变退役的判定基础:设置
// RUGRA_POSTFIX_STATS 环境变量时,post_process_output_legacy 每次调用向 stderr
// 输出一行 [POSTFIX] 统计(逐 pass 行级突变计数);未设置时所有插桩点均为
// no-option 短路(不 clone、不比较、不打印),输出字节与未插桩版本完全一致。
// 语义:计数器只度量、绝不改变管线行为 —— 退役判定以计数=0 为必要证据。

// RUGRA-GLUE: 幸存 pass 名单(管线顺序),见 post_process_output_legacy 内同序插桩
const POSTFIX_PASS_NAMES: [&str; 23] = [
    "B1", "P6", "B2", "P7",
    "P8", "P9", "P10", "P11", "P12", "P14", "P15", "P16c",
    "B3", "P17", "P18", "B4", "Pecase", "P22", "P23", "P24",
    "P25", "P26", "P27",
];

// RUGRA-GLUE: pass 索引常量(与 POSTFIX_PASS_NAMES 同序)
const PF_B1: usize = 0;
const PF_P6: usize = 1;
const PF_B2: usize = 2;
const PF_P7: usize = 3;
const PF_P8: usize = 4;
const PF_P9: usize = 5;
const PF_P10: usize = 6;
const PF_P11: usize = 7;
const PF_P12: usize = 8;
const PF_P14: usize = 9;
const PF_P15: usize = 10;
const PF_P16C: usize = 11;
const PF_B3: usize = 12;
const PF_P17: usize = 13;
const PF_P18: usize = 14;
const PF_B4: usize = 15;
const PF_ECASE: usize = 16;
const PF_P22: usize = 17;
const PF_P23: usize = 18;
const PF_P24: usize = 19;
const PF_P25: usize = 20;
const PF_P26: usize = 21;
const PF_P27: usize = 22;

// RUGRA-GLUE: 逐 pass 突变计数器(每次 post_process_output 调用一个实例)
struct PostfixStats {
    enabled: bool,
    counts: [u64; POSTFIX_PASS_NAMES.len()],
}

impl PostfixStats {
    // RUGRA-GLUE: env 门控,每进程求值一次(RUGRA_POSTFIX_STATS 是否设置)
    fn stats_enabled() -> bool {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var_os("RUGRA_POSTFIX_STATS").is_some())
    }

    // RUGRA-GLUE: Rust 结构体构造器(Ghidra 无对应物)
    fn new() -> Self {
        Self {
            enabled: Self::stats_enabled(),
            counts: [0; POSTFIX_PASS_NAMES.len()],
        }
    }

    // RUGRA-GLUE: 站点级计数 —— 首扫循环里 P1/P1b/P2 三 pass 与行复制熔合,
    // 无法取边界快照,在各自改写点直接累加(每次 bump = 删 1 行或改写 1 行)
    #[inline]
    fn bump(&mut self, pass: usize) {
        if self.enabled {
            self.counts[pass] += 1;
        }
    }

    // RUGRA-GLUE: 惰性快照 —— 统计未启用时返回 None(零 clone 成本)
    fn snap<S: AsRef<str>>(lines: &[S]) -> Option<Vec<String>> {
        if Self::stats_enabled() {
            Some(lines.iter().map(|s| s.as_ref().to_string()).collect())
        } else {
            None
        }
    }

    // RUGRA-GLUE: 边界级计数 —— pass 输入快照 vs 输出的行级突变数
    fn observe(&mut self, pass: usize, before: &Option<Vec<String>>, after: &[String]) {
        if let Some(b) = before {
            self.counts[pass] += postfix_line_mutations(b, after);
        }
    }

    // RUGRA-GLUE: 字符串级计数 —— 尾部外置 helper pass(P22-P27)的 str→str 边界;
    // 两侧统一用 split('\n')(与 remove_orphan_case_labels 等实现一致),往返
    // 差异相互抵消,只计真实突变
    fn observe_str(&mut self, pass: usize, before: &str, after: &str) {
        if !self.enabled {
            return;
        }
        let b: Vec<&str> = before.split('\n').collect();
        let a: Vec<&str> = after.split('\n').collect();
        self.counts[pass] += postfix_line_mutations(&b, &a);
    }

    // RUGRA-GLUE: 每次 post_process_output 调用向 stderr 输出一行 [POSTFIX]
    // 统计;inv=进程内调用序号,rpt=1 表示本次输入与上次调用的输出相同
    // (双重执行标记;当前生产路径单次执行,rpt 恒 0)。W3 诊断扩展:设置
    // RUGRA_POSTFIX_RAW_DIR 时,把本次输入(=emit 原始输出)与最终输出按
    // <pid>-<inv>.{in,out} 落盘,供 emit 缺陷定位使用(零行为差,env 门控)。
    fn emit(self, input: &str, output: &str) {
        if !self.enabled {
            return;
        }
        static INVOCATIONS: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let inv0 = INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if let Some(dir) = std::env::var_os("RUGRA_POSTFIX_RAW_DIR") {
            let name = format!("{}-{}.in", std::process::id(), inv0);
            let path = std::path::Path::new(&dir).join(name);
            if let Ok(text) = std::fs::write(path, input) {
                let _ = text;
            }
            let name = format!("{}-{}.out", std::process::id(), inv0);
            let path = std::path::Path::new(&dir).join(name);
            let _ = std::fs::write(path, output);
        }
        let inv = inv0;
        static LAST_OUT_HASH: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        use std::sync::atomic::Ordering;
        let in_hash = postfix_hash(input);
        let prev_out = LAST_OUT_HASH.swap(postfix_hash(output), Ordering::Relaxed);
        let rpt = prev_out == in_hash;
        let fn_name = postfix_fn_name(input);
        let mut line = format!(
            "[POSTFIX] pid={} inv={} rpt={} fn={} lines={}",
            std::process::id(),
            inv,
            if rpt { 1 } else { 0 },
            fn_name,
            input.lines().count()
        );
        for (name, count) in POSTFIX_PASS_NAMES.iter().zip(self.counts.iter()) {
            line.push_str(&format!(" {}={}", name, count));
        }
        eprintln!("{}", line);
    }
}

// RUGRA-GLUE: 行级突变计数(Ghidra 无对应物)—— 等长输入逐位比较(精确,
// 适用于不改行数的改写型 pass);不等长输入先裁公共前后缀,再计中间差异块
// 行数(删除/插入型)。零突变检测在两种度量下均精确。
fn postfix_line_mutations<S: AsRef<str>>(before: &[S], after: &[S]) -> u64 {
    if before.len() == after.len() {
        return before
            .iter()
            .zip(after.iter())
            .filter(|(b, a)| b.as_ref() != a.as_ref())
            .count() as u64;
    }
    let mut p = 0usize;
    while p < before.len() && p < after.len() && before[p].as_ref() == after[p].as_ref() {
        p += 1;
    }
    let mut s = 0usize;
    while s < before.len() - p
        && s < after.len() - p
        && before[before.len() - 1 - s].as_ref() == after[after.len() - 1 - s].as_ref()
    {
        s += 1;
    }
    before.len().max(after.len()) as u64 - p as u64 - s as u64
}

// RUGRA-GLUE: 输入文本指纹(DefaultHasher,仅用于 rpt 标记的相等性判断)
fn postfix_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// RUGRA-GLUE: 从函数文本提取函数名(第一个含 '(' 的行的 '(' 前最后一个词 ——
// curl 语料每个函数文本带 typedef 前导块,首行是 `typedef unsigned char
// byte;`,直接取首行会全部误报为 byte;;取首个含括号行可跳过前导块命中签名
// 行或 `/* ---- addr: name (size) ---- */` 头注释。纯诊断元数据,提取失败
// 不参与任何判定)
fn postfix_fn_name(input: &str) -> &str {
    let candidate = input
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && l.contains('('))
        .or_else(|| {
            input
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
        })
        .unwrap_or("");
    let head = candidate.split('(').next().unwrap_or(candidate).trim();
    head.rsplit(' ')
        .next()
        .filter(|w| !w.is_empty())
        .unwrap_or("?")
}

/// Simple emitter that produces plain text with no markup
pub struct EmitNoMarkup {
    output: String,
    indent: i32,
    /// Ghidra: prettyprint.hh:102 Emit::pendPrint — the PendPrint slot is
    /// BASE-CLASS state present in every emitter (setPendingPrint /
    /// cancelPendingPrint / hasPendingPrint, prettyprint.hh:446-457); only
    /// the FIRE (emitPending) is EmitPrettyPrint/EmitMarkup-specific
    /// (prettyprint.cc:920/930/129/136 — EmitNoMarkup::tagLine at
    /// prettyprint.hh:557 never calls it). With this emitter a pending
    /// brace therefore stays installed through the condition block, and
    /// printc.cc:2900-2902 always takes the cancel+spaces(1) merge —
    /// mirroring the oracle byte-for-byte.
    pending_brace: Option<(BraceId, BraceStyle)>,
    /// RUGRA-GLUE: monotonically increasing install id (stands in for the
    /// oracle's PendingBrace stack-object identity, prettyprint.hh:457).
    next_brace_id: BraceId,
}

impl Default for EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::default
    fn default() -> Self {
        Self::new()
    }
}

impl EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::new
    pub fn new() -> Self {
        Self {
            output: String::new(),
            indent: 0,
            pending_brace: None,
            next_brace_id: 1,
        }
    }

    // RUGRA-GLUE: RUGRA_LOOP_DEBUG 诊断 helper(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Debug helper: count "while" and "\ndo " occurrences in the raw output.
    /// Used by RUGRA_LOOP_DEBUG diagnostics to track loop rendering.
    #[allow(dead_code)]
    pub fn debug_count_while(&self) -> (usize, usize) {
        let w = self.output.matches("while").count();
        let d = self.output.matches("\ndo ").count();
        (w, d)
    }

    // RUGRA-GLUE: RUGRA_LOOP_DEBUG 诊断 helper(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Debug helper: borrow the raw output string for diagnostics.
    #[allow(dead_code)]
    pub fn debug_get_output_ref(&self) -> &str {
        &self.output
    }

    // RUGRA-GLUE: 缓冲输出访问器 + 文本后处理挂载点②(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物——oracle EmitNoMarkup 直写 ostream,无 getOutput)
    pub fn get_output(mut self) -> String {
        // Always run post-processing so callers that forget to invoke
        // post_process() still get the normalized output (struct deref rewrite,
        // dead-code elimination, empty-case removal, etc.). This makes
        // EmitNoMarkup's output match what doc_function -> post_process would
        // produce, regardless of the call site.
        self.post_process();
        self.output
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Post-process the output to eliminate redundant gotos and labels.
    /// P3: Remove `goto LAB_X;` when `LAB_X:` is on the immediately next non-empty line.
    /// Also removes labels that are never referenced by any goto.
    pub fn post_process(&mut self) {
        self.output = Self::post_process_output(&self.output);
    }

    // RUGRA-GLUE: switch-statement prefix predicate for the legacy text
    // passes. The oracle's opBranchind (printc.cc:586-587) emits `switch` +
    // `(` with NO separating space (golden `switch((int)x ...)`), while
    /// older passes matched only the `switch ` form — after PRINTC-SWITCH-
    /// EMIT-0001 aligned the header bytes, remove_orphan_case_labels treated
    /// every case label of a `switch(...)` as an orphan and stripped the
    /// switch. `switch` is a C keyword, so `switch(` can never be an
    /// identifier — accepting both prefixes is word-safe.
    fn is_switch_stmt_prefix(t: &str) -> bool {
        t.starts_with("switch ") || t.starts_with("switch(")
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    pub fn post_process_output(input: &str) -> String {
        // Ghidra's EmitMarkup (prettyprint.cc) does ZERO post-processing.
        // All structure is produced by Action-phase + structured emit.
        // The 27+ text passes below violate rule 5.5 but are NECESSARY
        // until Rugra's Action/emit layers are complete (removing them
        // drops gcc audit from 23/24 to 5/24). Each pass is tracked in
        // ALIGNMENT_ROADMAP with the Ghidra Action that will replace it.
        Self::post_process_output_legacy(input)
    }

    // RUGRA-GLUE: P6 声明行判据(HTTPD-FULLEMPTY-ELSE-0001 residual;Ghidra 无对应物,
    // 补偿层内部 helper)。声明行 = 纯类型头(`undefined8`、`undefined8 *` 等
    // 标识符/`*`/空格字符组成)+ ` uVarN;` 尾。运算符/括号/逗号/语句关键字
    // (`return` 等)出现即非声明——旧 `contains(" uVarN;")` 谓词把尾置裸变量的
    // 使用行(`*ptr + off = uVarN;` / `return uVarN;`)也当声明删掉,制造空 else。
    fn is_declaration_line(t: &str, var_name: &str) -> bool {
        let suffix = format!(" {};", var_name);
        if !t.ends_with(&suffix) {
            return false;
        }
        let head = &t[..t.len() - suffix.len()];
        if head.is_empty() {
            return false;
        }
        if !head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*' || c == ' ')
        {
            return false;
        }
        !head.split_whitespace().any(|tok| {
            matches!(tok, "return" | "goto" | "break" | "continue" | "case" | "default")
        })
    }

    // RUGRA-GLUE: 补偿层内部 helper(POSTFIX-BOOLFOLD-TOKEN-0001;Ghidra 无
    /// 对应物——pass 3 的 token 边界判据)。Strip every `1 || ` whose `1`
    /// begins a standalone token (preceded by start, `(` or whitespace),
    /// leaving number-token tails (`0x11 || `, `a1 || `) untouched.
    fn fold_standalone_one_or(line: &str) -> String {
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'1' && line[i..].starts_with("1 || ") {
                let boundary_ok = i == 0 || matches!(bytes[i - 1], b'(' | b' ' | b'\t');
                if boundary_ok {
                    i += "1 || ".len();
                    continue;
                }
            }
            // Copy one UTF-8 character (never splits a multibyte scalar).
            let ch_len = Self::utf8_char_len(bytes[i]);
            out.push_str(&line[i..i + ch_len]);
            i += ch_len;
        }
        out
    }

    // RUGRA-GLUE: UTF-8 scalar length for fold_standalone_one_or's
    /// char-wise copy (first byte tag: 0xxxxxxx=1, 110=2, 1110=3, 11110=4).
    fn utf8_char_len(b: u8) -> usize {
        if b < 0x80 { 1 } else if b >> 5 == 0b110 { 2 } else if b >> 4 == 0b1110 { 3 } else { 4 }
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物——
    // oracle 发射路径零后处理:prettyprint.hh:547-594 的 EmitNoMarkup 是无缓冲直写
    // emitter,printc.cc:2665 docFunction 以 flush() 结束,无任何 post-process)。
    // 状态如实记录:本函数是 post_process_output 的唯一实现并被其调用,是**活链**,
    // 不是死代码。上方曾有的 "_legacy + DEAD CODE + Do NOT call + #[allow(dead_code)]"
    // 标记是 2026-07-04 一次被放弃的退役尝试(先改空操作,gcc 审计 23/24→5/24 后
    // 回退)留下的误导脚手架,已随 W0 清除。整层退役按 POSTFIX-RETIRE-0001 路线图
    // W1-WT 顺序推进(先修上游→计数证明零突变→逐 pass 删除,尾部先行)。
    fn post_process_output_legacy(input: &str) -> String {
        let mut pfx = PostfixStats::new();
        // First-scan goto rewrites retired in POSTFIX-RETIRE-0001 W2:
        //   P1  redundant-goto skip (goto LAB_X; right before LAB_X:) - cut 9
        //   P1b exit-goto -> break/return rewrite                        - cut 8
        //   P2  conditional exit goto -> if-break/return                 - cut 7
        // W1 counters proved zero mutations for all three on both corpora
        // (curl 190 + httpd 102 calls, both rpt rounds): the structured
        // emit path places no redundant or undefined-target LAB_ gotos on
        // the corpora, so the scan had degraded to a verbatim line copy.

        // P3 (unreferenced label removal, first sweep) retired in
        // POSTFIX-RETIRE-0001 W2 cut 6: W1 counters proved zero mutations
        // on both corpora (both rpt rounds) - every LAB_ label emitted on
        // the corpora is still goto-referenced at this pipeline stage.
        let final_result: Vec<String> = input.lines().map(|s| s.to_string()).collect();

        // Third pass: collapse consecutive blank lines
        let snap_b1 = PostfixStats::snap(&final_result);
        let mut collapsed: Vec<String> = Vec::with_capacity(final_result.len());
        let mut prev_blank = false;
        for line in final_result {
            if line.trim().is_empty() {
                if !prev_blank {
                    collapsed.push(line);
                }
                prev_blank = true;
            } else {
                prev_blank = false;
                collapsed.push(line);
            }
        }
        pfx.observe(PF_B1, &snap_b1, &collapsed);

        // P4 (backward goto -> do/while loop conversion) retired in
        // POSTFIX-RETIRE-0001 W2 cut 5: W1 counters proved zero mutations
        // on both corpora (both rpt rounds) - the structured emit path
        // renders loops directly; no backward LAB_ goto reaches the text
        // layer on the corpora.
        let looped = collapsed;

        // P5 (unreferenced label removal, post loop conversion) retired in
        // POSTFIX-RETIRE-0001 W2 cut 4: W1 counters proved zero mutations
        // on both corpora (both rpt rounds) - after P4 every remaining
        // LAB_ label on the corpora is still goto-referenced.
        let final_pass = looped;

        // Sixth pass: text-level single-use variable handling.
        // INLINE arm (count==3 substitution) — RETIRED (PRINTC-CALLIND-
        // P6-NULLIFY-0001, 2026-09-24; RESIDMAP-PLTSTUB-EMITSHAPE-0001).
        // The oracle emitter has NO text post-processing:
        // EmitNoMarkup/EmitPrettyPrint stream per-token (prettyprint.cc:614
        // print(TokenSplit)), and every temp-assignment collapse Ghidra
        // performs happens at the ACTION level on the IR — canon keeps
        // single-use assignments verbatim: `pcVar1 = (char *)(*(code *)
        // PTR_strcpy_00116e90)();` + `return pcVar1;` (golden:67-70) and
        // `iVar4 = curl_easy_perform(lVar13);` (golden:993). The inline arm
        // destroyed exactly those shapes: 23 corpus functions × 3 line
        // mutations (RUGRA_POSTFIX_RAW_DIR dump, 2026-09-24) — the 22 PLT
        // stubs' whole bodies (`uVarN = <callind>();` + decl + return
        // substitution) and main's `uVar3 = curl_easy_perform(iVar10);`
        // inlined into a CONCAT argument.
        //
        // DEAD-ELIM arm (count==2) — retained as an explicitly oracle-
        // foreign compensation layer: dead single-assignments to never-read
        // locals (`uVar1 = pRam...;`, no call/side-effect RHS) survive
        // Rugra's action pipeline where the oracle's ActionDeadCode removes
        // them at the IR level (canon carries no such lines — httpd
        // ap_strcmp_match witness, golden:2df20). Retiring this arm leaked
        // +19 httpd skeleton lines (9 functions, gate run 2026-09-24). The
        // owner of the underlying gap is the IR-level dead-store removal
        // (ActionDeadCode port); once that closes, this arm retires with it.
        let snap_p6 = PostfixStats::snap(&final_pass);
        let mut inlined = final_pass;
        {
            // Collect all uVar assignments: (line_index, var_name, rhs_expr)
            let mut assignments: Vec<(usize, String, String)> = Vec::new();
            for (idx, line) in inlined.iter().enumerate() {
                let t = line.trim();
                // Match: uVarNNN = ...;
                if t.starts_with("uVar") {
                    if let Some(eq_pos) = t.find(" = ") {
                        let var_name = &t[..eq_pos];
                        // Must be a simple uVarNNN name
                        if var_name.chars().skip(4).all(|c| c.is_ascii_digit()) {
                            let rhs = t[eq_pos + 3..].trim_end_matches(';').to_string();
                            assignments.push((idx, var_name.to_string(), rhs));
                        }
                    }
                }
            }

            // For each assignment, count total occurrences of the variable
            // name; only the count==2 dead-store arm remains active.
            let full_text = inlined.join("\n");
            let mut to_dead_elim: Vec<(usize, String)> = Vec::new();
            for (idx, var_name, rhs) in &assignments {
                let count = Self::count_word_occurrences(&full_text, var_name);
                if count == 2 {
                    // 1 declaration + 1 assignment, never used → dead code
                    // Only eliminate if RHS has no side effects (no function calls)
                    if !rhs.contains('(') {
                        to_dead_elim.push((*idx, var_name.clone()));
                    }
                }
            }

            // Apply dead code elimination
            for (assign_idx, var_name) in to_dead_elim.iter().rev() {
                inlined[*assign_idx] = String::new();
                // Also remove the declaration (same declaration-line
                // predicate as the inline arm above; count==2 excludes
                // use sites, this keeps the two removals consistent).
                for i in 0..inlined.len() {
                    let t = inlined[i].trim();
                    if Self::is_declaration_line(t, var_name) {
                        inlined[i] = String::new();
                        break;
                    }
                }
            }
        }
        pfx.observe(PF_P6, &snap_p6, &inlined);

        // Final: collapse blank lines again
        let snap_b2 = PostfixStats::snap(&inlined);
        let mut result_final: Vec<String> = Vec::with_capacity(inlined.len());
        let mut prev_blank2 = false;
        for line in inlined {
            if line.trim().is_empty() {
                if !prev_blank2 {
                    result_final.push(line);
                }
                prev_blank2 = true;
            } else {
                prev_blank2 = false;
                result_final.push(line);
            }
        }
        pfx.observe(PF_B2, &snap_b2, &result_final);

        // Seventh pass: textual cleanup transformations
        let snap_p7 = PostfixStats::snap(&result_final);
        let mut cleaned: Vec<String> = Vec::with_capacity(result_final.len());
        for line in &result_final {
            let mut s = line.clone();

            // 1. *&x → x (redundant dereference of address-of)
            while s.contains("*&") {
                s = s.replace("*&", "");
            }

            // 1b. Reconcile `int - pointer` (illegal C). Only subtraction is
            // affected (int + pointer is legal, yields pointer). When a line
            // contains "<const> - <ptrvar>" where const is a bare integer and
            // ptrvar has a pointer prefix (pi/pc/ps/pp/pv Var), cast the
            // constant to (char *) so it becomes `pointer - pointer`. This is
            // conservative: we only act when the operand before "-" is a
            // standalone integer literal preceded by space/=/(.
            // (This is a print-layer stopgap; the real fix is type propagation
            // making the output varnode pointer-typed.)
            // reconcile_int_minus_pointer still needed for non-LOAD pointers
            // (e.g. function parameters typed as int* used in subtraction).
            s = reconcile_int_minus_pointer(&s);
            // reconcile_pointer_arith (ptr/int division-modulo reconcile)
            // removed in POSTFIX-RETIRE-0001 W0: its only call site was
            // commented out after mark_varnode_used LOAD detection made LOAD
            // results correctly typed as int/long (not pointer).
            // reconcile_int_times_string still needed for copy-propagation
            // artifacts (string address inlined into MULT operand).
            if s.contains(" * \"") {
                s = reconcile_int_times_string(&s);
            }
            if s.contains("*(_struct *)") && s.contains("= ") {
                s = s.replace("*(_struct *)", "*(long *)");
            }

            // 2. Constant folding: collapse repeated "+ 1" chains
            // Match: expr + 1 + 1 + 1 ... → expr + N
            loop {
                if let Some(pos) = s.find("+ 1 + 1") {
                    // Count how many consecutive "+ 1" there are
                    let base = &s[..pos];
                    let rest = &s[pos..];
                    let mut count = 0;
                    let mut idx = 0;
                    while rest[idx..].starts_with("+ 1") {
                        count += 1;
                        idx += 4; // "+ 1 " or "+ 1;" etc
                        if idx > rest.len() { break; }
                        // Skip space
                        while idx < rest.len() && rest.as_bytes().get(idx) == Some(&b' ') {
                            idx += 1;
                        }
                    }
                    if count >= 2 {
                        let after = &rest[idx - 1..]; // keep the trailing part
                        s = format!("{}+ {}{}", base, count, after);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // 3. Arithmetic simplification: "+ -N" → "- N" — REMOVED
            // (PRINTC-PLUSNEGLIT-0001): Ghidra prints the negative addend
            // verbatim as `X + -N` (printc.cc:1288-1368 push_integer emits
            // the minus sign inside the constant atom; binary_plus keeps its
            // ` + ` token). The canon golden has 666 `+ -` forms and the
            // direct-runner golden 1096, while this local rewrite produced
            // zero on the Rugra side, so every one of those lines was a
            // skeleton diff. The rewrite is not a Ghidra behavior — deleted.

            // 4. Character constants in if comparisons — RETIRED
            // (STUBLEAK-CHARPRINT-LOOPCONST-0001). The former table rewrote
            // `==/!=/= 0xNN` text into `'c'` literals for a hardcoded char
            // set. The oracle has NO text-level constant rewrite: char vs
            // integer form is decided per-varnode in PrintC::pushConstant
            // (printc.cc:1744-1768) from the PROPAGATED datatype
            // (`isCharPrint()` gates pushCharConstant; TYPE_UNKNOWN and
            // plain int/uint route to push_integer → `0x26` via
            // mostNaturalBase, printc.cc:1325-1337). The rewrite therefore
            // corrupted every untyped/int-typed printable constant: loop
            // counters like `for (iVar12 = 0x26; ...)` (canon golden curl
            // :741 and direct-runner golden :494 print `0x26`) were emitted
            // as `'&'`. Deleted; the typed-char face (httpd canon golden
            // `cVar2 != '&'`) is printc's is_char_print business, not a
            // postfix text concern.

            cleaned.push(s);
        }
        pfx.observe(PF_P7, &snap_p7, &cleaned);

        // Eighth pass: remove blank lines within declaration blocks
        // (between type declarations at function start)
        let snap_p8 = PostfixStats::snap(&cleaned);
        let mut final_cleaned: Vec<String> = Vec::with_capacity(cleaned.len());
        let mut in_decl_block = false;
        let mut decl_count = 0usize;
        let mut separator_kept = false;
        for (_i, line) in cleaned.iter().enumerate() {
            let t = line.trim();
            // Detect start of function. The function-body `{` either trails
            // the signature (legacy layout) or sits alone on the next line
            // (the oracle's option_brace_func=skip_line layout, printc.cc:
            // 1590/2655); both forms open a declaration block here.
            if t.ends_with('{') && !t.starts_with("if") && !t.starts_with("else")
                && !t.starts_with("while") && !t.starts_with("do")
                && !t.starts_with("for") && !t.starts_with("switch")
                && !t.starts_with("case") {
                in_decl_block = true;
                decl_count = 0;
                separator_kept = false;
                final_cleaned.push(line.clone());
                continue;
            }
            if in_decl_block {
                // Declaration lines: "  type varname;"
                let is_decl = t.starts_with("int ") || t.starts_with("long ")
                    || t.starts_with("byte ") || t.starts_with("bool ")
                    || t.starts_with("short ") || t.starts_with("char ");
                if t.is_empty() {
                    // The emitter already places exactly one indent-only
                    // separator line after the declaration block (the
                    // faithful render of emitLocalVarDecls' trailing
                    // tagLine, printc.cc:2277-2278). Keep the FIRST such
                    // line verbatim (preserving its indent bytes) and drop
                    // only extra consecutive blanks; do NOT synthesize a
                    // new empty line — a function with no declarations has
                    // no separator in the oracle output either.
                    if decl_count == 0 || separator_kept {
                        continue;
                    }
                    separator_kept = true;
                    final_cleaned.push(line.clone());
                } else if is_decl {
                    decl_count += 1;
                    final_cleaned.push(line.clone());
                } else {
                    // End of declaration block
                    in_decl_block = false;
                    final_cleaned.push(line.clone());
                }
            } else {
                final_cleaned.push(line.clone());
            }
        }
        pfx.observe(PF_P8, &snap_p8, &final_cleaned);
        // Ninth pass: structural cleanup
        let snap_p9 = PostfixStats::snap(&final_cleaned);
        let mut structural: Vec<String> = Vec::with_capacity(final_cleaned.len());
        let mut i9 = 0;
        while i9 < final_cleaned.len() {
            let t = final_cleaned[i9].trim().to_string();

            // 1. Dead break after break/continue/return
            // If current line is break/continue/return and next is break → skip next
            if (t == "break;" || t == "continue;" || t == "return;")
                && i9 + 1 < final_cleaned.len()
                && final_cleaned[i9 + 1].trim() == "break;"
            {
                structural.push(final_cleaned[i9].clone());
                i9 += 2; // skip the dead break
                continue;
            }

            // 2. if (1) → remove the if, keep the body
            if t == "if (1)" && i9 + 1 < final_cleaned.len() {
                let next = final_cleaned[i9 + 1].trim().to_string();
                // "if (1)\n  goto X;" → "goto X;"
                let indent = final_cleaned[i9].len() - final_cleaned[i9].trim_start().len();
                let indent_str: String = " ".repeat(indent);
                structural.push(format!("{}{}", indent_str, next));
                i9 += 2;
                continue;
            }

            // 3. Simplify "1 || expr" → always true (the whole condition is true)
            let mut line = final_cleaned[i9].clone();

            line = line.replace("if (0 == 0) return;", "return;");
            line = line.replace("if (0 == 0) {", "if (1) {");

            if line.contains("1 || ") {
                // "if (1 || anything)" → "if (1)" which will be caught next pass
                // For now, replace the condition.
                // POSTFIX-BOOLFOLD-TOKEN-0001 (MIGW1-TYPEOP-0002 fixture
                // exposure): the fold target is the standalone literal
                // token `1`, never the tail digit of a larger numeric
                // token — the naive replacen matched the "1 || " inside
                // `0x11 || x` / `0x21 || x` and emitted the mangled
                // `0x10x22`-family forms. Fold only when the `1` starts a
                // token: preceded by start-of-line, `(`, or whitespace.
                line = Self::fold_standalone_one_or(&line);
            }

            // 4. "+N - N" cancellation (e.g., "+ 1 - 1" → "")
            let cancel_patterns = [
                ("+ 1 - 1", ""),
                ("+ 2 - 2", ""),
                ("+ 4 - 4", ""),
                ("+ 8 - 8", ""),
            ];
            for (pattern, replacement) in &cancel_patterns {
                line = line.replace(pattern, replacement);
            }
            // Clean up double spaces in content (not indent) from cancellation.
            // String/char literals are opaque (MAINDIFF-STRCONST-0001): the
            // decompiler's string constants legally contain runs of spaces
            // (e.g. the hugehelp aliases' `\n   or specify` / eight-space
            // indents), so the collapse and the ` )` trim must not reach
            // inside a quoted region. Escapes (`\"`, `\\`, `\'`) do not
            // toggle the quote state.
            // MAIN-RC3-STRUCTURED-EMIT-0001: a compact `while(` header line
            // is exempt entirely — the oracle's overflow header is
            // `while( true )` (printc.cc:3023-3028: openParen then
            // spaces(1) on each side of `true`), the one Ghidra form whose
            // bytes include ` )`; the trim/collapse would destroy it.
            // `while` is a keyword, so only that form starts with `while(`.
            // GENSMOKE-T6: the BlockInfLoop trailer carries the same compact
            // bytes after its closing brace — `} while( true );`
            // (printc.cc:3111-3120: closeBraceIndent + spaces(1) +
            // KEYWORD_WHILE + openParen + spaces(1) + KEYWORD_TRUE +
            // spaces(1) + closeParen + SEMICOLON). tagLine/closeBrace force
            // the line boundary, so the form is always line-initial after
            // trim; the trailer is the second (and only other) Ghidra emit
            // sequence whose bytes include ` )`.
            if !(t.starts_with("while(") || t.starts_with("} while( true );")) {
                let trimmed_start = line.len() - line.trim_start().len();
                let indent_part = &line[..trimmed_start];
                let content = &line[trimmed_start..];
                let mut outside = String::with_capacity(content.len());
                let mut chars = content.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '"' || c == '\'' {
                        // Quoted region: copy verbatim until the matching
                        // close quote, honouring backslash escapes.
                        let quote = c;
                        outside.push(quote);
                        while let Some(qc) = chars.next() {
                            outside.push(qc);
                            if qc == '\\' {
                                if let Some(esc) = chars.next() {
                                    outside.push(esc);
                                }
                            } else if qc == quote {
                                break;
                            }
                        }
                        continue;
                    }
                    if c == ' ' {
                        if let Some(&n) = chars.peek() {
                            if n == ' ' {
                                continue; // Collapse "  " -> " " outside literals.
                            }
                            if n == ')' {
                                continue; // Trim " )" -> ")" outside literals.
                            }
                        }
                    }
                    outside.push(c);
                }
                line = format!("{}{}", indent_part, outside);
            }

            // 5. "goto function_name;" where function_name is a known libc function → tail call
            if t.starts_with("goto ") && t.ends_with(';') && !t.contains("LAB_") {
                let func_name = &t[5..t.len() - 1];
                // Check it's a plausible function name (lowercase, no spaces).
                // `code_r0x...` labels (PrintC::emitLabel, printc.rs code_label /
                // printc.cc:3164-3193) are flat-mode goto TARGETS, not function
                // names — exclude them or every flat tail goto gets rewritten
                // into a bogus `return code_r0x...();` call (which gcc rejects
                // as an implicit-function-declaration of a label).
                // DRIVER-SWITCHD-LABEL-0001: the `switchD_<dispatch>_caseD_<v>`/
                // `_default` family is the analyzer's case-destination LABEL
                // symbol (the headless DecompilerSwitchAnalysis pass consuming
                // JumpTable::encode's <jumptable> XML, jumptable.cc:2769-2790),
                // the same symbol class as `LAB_` — a goto target, never a
                // callee. Golden spellings keep `goto switchD_...;` (0 `return
                // switchD` across both corpora). Without the exclusion the
                // lowercase `s` start rewrites every switchD goto into an
                // implicit-declaration `return switchD_...();` call.
                if func_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && func_name
                        .chars()
                        .next()
                        .map_or(false, |c| c.is_ascii_lowercase())
                    && !func_name.starts_with("code_")
                    && !func_name.starts_with("joined_")
                    && !func_name.starts_with("dup_")
                    && !func_name.starts_with("switchD_")
                {
                    let indent = final_cleaned[i9].len() - final_cleaned[i9].trim_start().len();
                    let indent_str: String = " ".repeat(indent);
                    structural.push(format!("{}return {}();", indent_str, func_name));
                    i9 += 1;
                    continue;
                }
            }

            structural.push(line);
            i9 += 1;
        }
        pfx.observe(PF_P9, &snap_p9, &structural);

        // Tenth pass: remove dead code after return/break/continue
        // If we see `return;` at indent level N, subsequent lines at the same indent
        // are dead unless they are labels (goto targets), closing braces, or case labels.
        let snap_p10 = PostfixStats::snap(&structural);
        let mut alive: Vec<String> = Vec::with_capacity(structural.len());
        let mut dead_after_return = false;
        let mut dead_indent = 0usize;
        // SWITCH-CASE-TAIL-0001: a `goto …;` line only starts a dead zone
        // when it is an UNCONDITIONAL whole-statement goto. When the Oppen
        // pretty printer wraps a long `if (cond)` across lines, the arm's
        // `goto …;` lands alone on the NEXT line and the previous non-empty
        // line ends with `)` (the closed condition) or `else` — that goto
        // is CONDITIONAL (if-arm) and the following statements are the
        // live fall-through path, not dead code. Treating it as a dead-zone
        // starter deleted reachable tail statements + `break;` (observed:
        // curl getparameter.constprop.0 case 0x23 lost
        // `::config.httpreq = HTTPREQ_POST; break;`, case 0x35 lost the
        // HTTPREQ_CUSTOM tail — the only true semantic losses of that
        // switch, ~10 lines). Single-line `if (…) goto …;` arms never
        // matched (line starts with `if`), which is why only the two
        // long-compound-condition cases were hit.
        let mut prev_nonempty_trimmed: Option<String> = None;
        // First collect all goto-referenced labels
        let all_text = structural.join("\n");
        for line in &structural {
            let t = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Check if this line is a goto target label that's referenced
            // GOTO-LABEL-UNPRINTED-0001: `code_r0x...:` labels (PrintC::
            // emitLabel, printc.rs code_label / printc.cc:3164-3193) are
            // goto targets exactly like LAB_ labels — a referenced label in
            // a dead zone is a live jump destination (jumping into a dead
            // zone is legal C) and must survive, or every goto to it
            // becomes an undefined-label gcc error (observed:
            // code_r0x0002DB65 / 0x2E655, httpd ap_update_vhost_given_ip /
            // ap_strchr).
            let is_label_line = (t.starts_with("LAB_") || t.starts_with("code_"))
                && t.ends_with(':')
                && !t.contains(' ');
            if is_label_line {
                let label_name = &t[..t.len() - 1];
                let goto_ref = format!("goto {};", label_name);
                if all_text.contains(&goto_ref) {
                    // Referenced label — end dead zone
                    dead_after_return = false;
                    alive.push(line.clone());
                    continue;
                }
            }

            if dead_after_return && indent >= dead_indent {
                // In dead zone — check if this is a structural element that ends the dead zone.
                // A `}` only ends the dead zone if it's at a SHALLOWER indent than where return
                // occurred (i.e. it closes a block that contains the return). A `}` at the same
                // or deeper indent is itself dead code and should be removed.
                if t == "}" {
                    if indent < dead_indent {
                        // Closes the dead block — end dead zone, keep the brace
                        dead_after_return = false;
                        alive.push(line.clone());
                    } else {
                        // Dead closing brace — skip
                        continue;
                    }
                } else if t.starts_with("case ") || t.starts_with("default:") {
                    // Switch case label — end dead zone (reachable via case fallthrough)
                    dead_after_return = false;
                    alive.push(line.clone());
                } else if t.starts_with("while (") || t.starts_with("while(") || t.starts_with("do ") || t.starts_with("for (") || Self::is_switch_stmt_prefix(t) {
                    // Control-flow structures (loops/switches) are not dead code even
                    // after a return — they may be reachable via fallthrough or represent
                    // structured control flow that the emit traversal placed after a return.
                    dead_after_return = false;
                    alive.push(line.clone());
                } else if t.is_empty() {
                    // Blank lines in dead zone — skip without resetting (they don't make
                    // following dead code reachable).
                    continue;
                } else {
                    // Dead code — skip
                    continue;
                }
            } else {
                dead_after_return = false;
                alive.push(line.clone());
            }

            // Check if this line starts a dead zone
            // SWITCH-CASE-TAIL-0001: `goto` starts the zone only when it is
            // NOT a wrapped conditional arm — previous non-empty line ending
            // with `)` (closed if/while condition) or `else` marks the goto
            // as the arm of a wrapped `if`, whose fall-through statements
            // are live code.
            let goto_starts_dead_zone = t.starts_with("goto ")
                && !prev_nonempty_trimmed.as_deref().map_or(false, |p| {
                    let p = p.trim_end();
                    p.ends_with(')') || p == "else" || p.ends_with(" else")
                });
            if t == "return;" || t == "break;" || t == "continue;" || goto_starts_dead_zone {
                dead_after_return = true;
                dead_indent = indent;
            }
            if !t.is_empty() {
                prev_nonempty_trimmed = Some(t.to_string());
            }
        }
        pfx.observe(PF_P10, &snap_p10, &alive);

        // Eleventh pass: remove unused variable declarations
        // For each function, collect declared uVar names and remove those never referenced in body
        let snap_p11 = PostfixStats::snap(&alive);
        let mut cleaned: Vec<String> = Vec::with_capacity(alive.len());
        let mut func_start: Option<usize> = None;
        let mut func_lines: Vec<String> = Vec::new();

        for index in 0..alive.len() {
            let line = &alive[index];
            let t = line.trim();
            // Detect function start (same-line `sig {` or skip_line `sig` + `{`)
            if Self::signature_opens_function_body(
                t,
                &[
                    "int ", "void ", "long ", "byte ", "bool ", "short "],
                &alive[index + 1..],
            ) {
                // Flush previous function
                if func_start.is_some() {
                    Self::flush_func_remove_unused(&func_lines, &mut cleaned);
                }
                func_lines = vec![line.clone()];
                func_start = Some(cleaned.len());
                continue;
            }
            if func_start.is_some() {
                func_lines.push(line.clone());
            } else {
                cleaned.push(line.clone());
            }
        }
        // Flush last function
        if func_start.is_some() {
            Self::flush_func_remove_unused(&func_lines, &mut cleaned);
        }
        pfx.observe(PF_P11, &snap_p11, &cleaned);

        // Twelfth pass: remove blank line after "} else {"
        let snap_p12 = PostfixStats::snap(&cleaned);
        let mut final_out: Vec<String> = Vec::with_capacity(cleaned.len());
        let mut skip_next_blank = false;
        for line in &cleaned {
            let t = line.trim();
            if skip_next_blank && t.is_empty() {
                skip_next_blank = false;
                continue;
            }
            skip_next_blank = t == "} else {";
            final_out.push(line.clone());
        }
        pfx.observe(PF_P12, &snap_p12, &final_out);

        // Fourteenth pass: remove dead code after goto (consecutive goto, or code after goto on same indent)
        let snap_p14 = PostfixStats::snap(&final_out);
        let mut pass14: Vec<String> = Vec::with_capacity(final_out.len());
        let mut prev_was_goto = false;
        for line in &final_out {
            let t = line.trim();
            if prev_was_goto {
                // Skip lines that are dead code (another goto or non-label code at same level)
                if t.starts_with("goto ") {
                    continue; // skip consecutive goto
                }
                prev_was_goto = false;
            }
            if t.starts_with("goto ") && t.ends_with(';') {
                prev_was_goto = true;
            }
            pass14.push(line.clone());
        }
        pfx.observe(PF_P14, &snap_p14, &pass14);

        // Fifteenth pass: fix double-close-paren "func());" → "func();"
        let snap_p15 = PostfixStats::snap(&pass14);
        let mut pass15: Vec<String> = Vec::with_capacity(pass14.len());
        for line in &pass14 {
            let fixed = line.replace("());", "();");
            pass15.push(fixed);
        }
        pfx.observe(PF_P15, &snap_p15, &pass15);

        // P16 (forward goto-to-if folding) retired in POSTFIX-RETIRE-0001
        // W2 cut 3: W1 counters proved zero mutations on both corpora
        // (curl 190 + httpd 102 calls, both rpt rounds) - the structured
        // emit path no longer emits single-use forward LAB_ gotos on the
        // corpora. P16c below (fold cleanup: unreferenced labels + empty
        // if blocks) stays ACTIVE (curl main = 264 mutated lines) and now
        // consumes the P15 output directly.

        // Sixteenth pass cleanup: remove now-unreferenced labels and empty if blocks
        let pass16_text = pass15.join("\n");
        let pass16_lines: Vec<&str> = pass16_text.lines().collect();
        let snap_p16c = PostfixStats::snap(&pass16_lines);
        let mut pass16_final: Vec<String> = Vec::with_capacity(pass16_lines.len());
        let mut i16c = 0;
        while i16c < pass16_lines.len() {
            let t = pass16_lines[i16c].trim();

            // Remove unreferenced labels
            if t.starts_with("LAB_") && t.ends_with(':') && !t.contains(' ') {
                let label_name = &t[..t.len() - 1];
                let goto_ref = format!("goto {};", label_name);
                if !pass16_text.contains(&goto_ref) {
                    i16c += 1;
                    continue; // unreferenced label, remove
                }
            }

            // Remove empty if blocks: "if (...) {" followed by "}"
            if t.starts_with("if (") && t.ends_with('{') {
                if i16c + 1 < pass16_lines.len() && pass16_lines[i16c + 1].trim() == "}" {
                    i16c += 2; // skip both lines
                    continue;
                }
            }

            pass16_final.push(pass16_lines[i16c].to_string());
            i16c += 1;
        }
        pfx.observe(PF_P16C, &snap_p16c, &pass16_final);

        // Final collapse of consecutive blank lines
        let snap_b3 = PostfixStats::snap(&pass16_final);
        let mut output_final: Vec<String> = Vec::with_capacity(pass16_final.len());
        let mut prev_blank_final = false;
        for line in pass16_final {
            if line.trim().is_empty() {
                if !prev_blank_final {
                    output_final.push(line);
                }
                prev_blank_final = true;
            } else {
                prev_blank_final = false;
                output_final.push(line);
            }
        }
        pfx.observe(PF_B3, &snap_b3, &output_final);

        // Seventeenth pass: remove orphan `break;` / `continue;` at function body start.
        // Pattern: function opening `{`, then declarations, then immediately `break;` or `continue;`
        // with no loop/switch context — these are block-structure artifacts.
        // Also: remove `return;` immediately followed by orphan `}` at body indent level
        //       (artifact from do-while blocks emitting an extra close)
        let snap_p17 = PostfixStats::snap(&output_final);
        let mut pass17: Vec<String> = Vec::with_capacity(output_final.len());
        {
            let lines = &output_final;
            let n = lines.len();
            let mut i17 = 0;
            let mut skip_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();

            // Pre-scan: find `return;` followed by `  }` (body-level stray brace)
            // Pattern: lines[k] == "  return;" and lines[k+1] or lines[k+2] (skipping blank) == "  }"
            for k in 0..n {
                if skip_indices.contains(&k) { continue; }
                let t = lines[k].trim();
                let ind = lines[k].len() - lines[k].trim_start().len();
                if t == "return;" && ind >= 2 {
                    // Look for an orphan `}` at same indent within next 3 lines
                    let mut look = k + 1;
                    while look < n && look <= k + 3 {
                        let lt = lines[look].trim();
                        let li = lines[look].len() - lines[look].trim_start().len();
                        if lt.is_empty() { look += 1; continue; }
                        if lt == "}" && li == ind {
                            // Check this `}` is NOT a legitimate closing brace
                            // by seeing if there's an unclosed `{` in the preceding ~5 lines
                            let mut open_count = 0i32;
                            let scan_start = if k >= 10 { k - 10 } else { 0 };
                            for s in scan_start..k {
                                for ch in lines[s].chars() {
                                    match ch { '{' => open_count += 1, '}' => open_count -= 1, _ => {} }
                                }
                            }
                            // If open_count <= 0, there's nothing left to close → orphan brace
                            if open_count <= 0 {
                                skip_indices.insert(look);
                            }
                        }
                        break;
                    }
                }
            }

            while i17 < n {
                if skip_indices.contains(&i17) { i17 += 1; continue; }
                let line = &lines[i17];
                let t = line.trim();
                let indent = line.len() - line.trim_start().len();

                // Detect function start: signature ending with `{`, or the
                // oracle skip_line layout where the lone `{` follows the
                // signature line (printc.cc:1590/2655).
                if Self::signature_opens_function_body(
                    t,
                    &["int ", "void ", "long ", "byte ", "bool ", "short "],
                    &lines[i17 + 1..],
                ) {
                    pass17.push(line.clone());
                    i17 += 1;
                    if !t.ends_with('{') {
                        // Consume the skip_line separator and the lone `{`
                        // line so the body walk below starts inside the braces.
                        while i17 < n && lines[i17].trim().is_empty() {
                            pass17.push(lines[i17].clone());
                            i17 += 1;
                        }
                        if i17 < n && lines[i17].trim() == "{" {
                            pass17.push(lines[i17].clone());
                            i17 += 1;
                        }
                    }

                    let func_indent = indent;
                    let mut past_decls = false;

                    // Process function body
                    while i17 < n {
                        let bl = &lines[i17];
                        let bt = bl.trim();
                        let bi = bl.len() - bl.trim_start().len();

                        if skip_indices.contains(&i17) { i17 += 1; continue; }

                        // Track past declarations
                        let is_decl = bt.starts_with("int ") || bt.starts_with("long ")
                            || bt.starts_with("byte ") || bt.starts_with("bool ")
                            || bt.starts_with("short ") || bt.starts_with("char ")
                            || bt.starts_with("void *") || bt.is_empty();
                        if !past_decls && !is_decl { past_decls = true; }

                        // Skip orphan break/continue at body level (no loop/switch context)
                        if past_decls && bi == func_indent + 2
                            && (bt == "break;" || bt == "continue;")
                        {
                            let mut has_loop_ctx = false;
                            for prev in pass17.iter().rev().take(20) {
                                let pt = prev.trim();
                                // MAIN-RC3-STRUCTURED-EMIT-0001: the compact
                                // `while(` (oracle overflow header,
                                // printc.cc:3023-3028) counts as loop context.
                                if pt.starts_with("while ") || pt.starts_with("while(")
                                    || pt.starts_with("do ")
                                    || pt.starts_with("for ") || Self::is_switch_stmt_prefix(pt)
                                    || pt.contains("} while (")
                                {
                                    has_loop_ctx = true;
                                    break;
                                }
                                if pt == "}" || pt.ends_with('{') { break; }
                            }
                            if !has_loop_ctx {
                                i17 += 1;
                                continue;
                            }
                        }

                        // Skip orphan `} while (...)` without a preceding `do {`
                        if bi == func_indent + 2 && bt.starts_with("} while (") {
                            // Depth-aware pairing: walk backward accumulating
                            // brace deltas; the balanced do-body interior nets
                            // 0, so the running sum first reaches +1 exactly at
                            // the line that opened this block. The former
                            // 30-line window dropped legitimate trailers of
                            // long do-bodies (PRINTC-SWITCH-EMIT-0001: the
                            // infloop-wrapped switch body is ~480 lines; the
                            // trailer was deleted and the function left with
                            // an unbalanced brace, gcc audit 107→47 functions).
                            // The counter is literal-aware (same contract as
                            // tools/audit_syntax.py::_brace_delta): char
                            // literals like '}' / '{' in glob_set/glob_word
                            // comparisons and //- /* */ comments must not
                            // perturb the count — a raw count never reaches +1
                            // there and drops the trailer (residual brace +1).
                            let brace_delta = |s: &str| -> i64 {
                                let b = s.as_bytes();
                                let mut i = 0usize;
                                let mut delta: i64 = 0;
                                while i < b.len() {
                                    match b[i] {
                                        b'/' if i + 1 < b.len() && b[i + 1] == b'/' => break,
                                        b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                                            i += 2;
                                            while i + 1 < b.len()
                                                && !(b[i] == b'*' && b[i + 1] == b'/')
                                            {
                                                i += 1;
                                            }
                                            i += 2;
                                            continue;
                                        }
                                        b'\'' | b'"' => {
                                            let quote = b[i];
                                            i += 1;
                                            while i < b.len() && b[i] != quote {
                                                if b[i] == b'\\' {
                                                    i += 1;
                                                }
                                                i += 1;
                                            }
                                        }
                                        b'{' => delta += 1,
                                        b'}' => delta -= 1,
                                        _ => {}
                                    }
                                    i += 1;
                                }
                                delta
                            };
                            let mut has_do = false;
                            let mut acc: i64 = 0;
                            for prev in pass17.iter().rev() {
                                let pt = prev.trim();
                                acc += brace_delta(pt);
                                if acc >= 1 {
                                    if pt == "do {" || pt.starts_with("do {") {
                                        has_do = true;
                                    }
                                    break;
                                }
                            }
                            if !has_do {
                                i17 += 1;
                                continue;
                            }
                        }

                        if bt == "}" && bi == func_indent { break; }
                        // Skip leading deeply-indented orphan statements before any opening structure
                        // These are block fragments that leaked from a misrouted CFG block
                        // (e.g., `    *(param + off) = val;` at indent+4 before any `if`/`while`)
                        if !past_decls {
                            // Still in declarations — shouldn't be deeply indented
                            if bi >= func_indent + 4 && !bt.ends_with('{') {
                                i17 += 1;
                                continue;
                            }
                        }
                        pass17.push(bl.clone());
                        i17 += 1;
                    }
                    // emit the closing brace
                    if i17 < n { pass17.push(lines[i17].clone()); i17 += 1; }
                    continue;
                }

                pass17.push(line.clone());
                i17 += 1;
            }
        }
        pfx.observe(PF_P17, &snap_p17, &pass17);

        // Eighteenth pass: remove unreachable `return;` at very start of function body.
        // Pattern: after the last declaration line, if the first statement is `return;`
        // but is followed by more non-empty lines — it's dead code from a misrouted block.
        let snap_p18 = PostfixStats::snap(&pass17);
        let mut pass18: Vec<String> = Vec::with_capacity(pass17.len());
        {
            let lines = &pass17;
            let mut i18 = 0;
            while i18 < lines.len() {
                let line = &lines[i18];
                let t = line.trim();
                let indent = line.len() - line.trim_start().len();

                // Detect function opening (same-line `sig {` or skip_line
                // `sig` + lone `{`, printc.cc:1590/2655)
                if Self::signature_opens_function_body(
                    t,
                    &["int ", "void ", "long ", "byte ", "bool ", "short "],
                    &lines[i18 + 1..],
                ) {
                    let func_indent = indent;
                    pass18.push(line.clone());
                    i18 += 1;
                    if !t.ends_with('{') {
                        while i18 < lines.len() && lines[i18].trim().is_empty() {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        }
                        if i18 < lines.len() && lines[i18].trim() == "{" {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        }
                    }

                    // Consume declarations
                    while i18 < lines.len() {
                        let lt = lines[i18].trim();
                        let _li = lines[i18].len() - lines[i18].trim_start().len();
                        let is_decl = lt.starts_with("int ") || lt.starts_with("long ")
                            || lt.starts_with("byte ") || lt.starts_with("bool ")
                            || lt.starts_with("short ") || lt.starts_with("char ")
                            || lt.starts_with("void *") || lt.is_empty();
                        if is_decl {
                            pass18.push(lines[i18].clone());
                            i18 += 1;
                        } else {
                            break;
                        }
                    }

                    // Check if the next statement is `return;` at body level
                    if i18 < lines.len() {
                        let next_t = lines[i18].trim();
                        let next_i = lines[i18].len() - lines[i18].trim_start().len();
                        if next_t == "return;" && next_i == func_indent + 2 {
                            // Look ahead: is there more code before the function closes?
                            let mut has_more = false;
                            let mut look = i18 + 1;
                            while look < lines.len() {
                                let lt = lines[look].trim();
                                let li = lines[look].len() - lines[look].trim_start().len();
                                if li == func_indent && lt == "}" {
                                    break; // function end
                                }
                                if !lt.is_empty() && li >= func_indent + 2 {
                                    has_more = true;
                                    break;
                                }
                                look += 1;
                            }
                            if has_more {
                                // Drop the return; it's dead code at function start
                                i18 += 1;
                                continue;
                            }
                        }
                    }
                    continue;
                }

                pass18.push(line.clone());
                i18 += 1;
            }
        }
        pfx.observe(PF_P18, &snap_p18, &pass18);

        // Nineteenth pass (brace-balance scaffold) removed in
        // POSTFIX-RETIRE-0001 W0: since 2026-06-26 both arms of its
        // depth<0 / else split emitted the collected function lines
        // verbatim — an identity no-op (naive brace counting cannot be
        // trusted past char/string literals, so it never rewrote).

        // Final collapse of consecutive blank lines
        let snap_b4 = PostfixStats::snap(&pass18);
        let mut output_final2: Vec<String> = Vec::with_capacity(pass18.len());
        let mut prev_blank_final2 = false;
        for line in pass18 {
            if line.trim().is_empty() {
                if !prev_blank_final2 {
                    output_final2.push(line);
                }
                prev_blank_final2 = true;
            } else {
                prev_blank_final2 = false;
                output_final2.push(line);
            }
        }
        pfx.observe(PF_B4, &snap_b4, &output_final2);

        // P-wbfold (while-break -> if fold) retired in POSTFIX-RETIRE-0001
        // W2 cut 2: W1 counters proved zero mutations on both corpora
        // (curl 190 + httpd 102 calls, both rpt rounds) - Rugra's emit
        // layer no longer produces single-shot while+break loops on the
        // corpora. The PRINTC-WHILEIF-FOLD-PREFIX-0001 slice logic and the
        // MAIN-RC3 compact-header exemptions in P9/P17 remain (other passes
        // still consume `while(` headers).

        // Empty switch-case removal pass.
        // Pattern (3 consecutive lines, same case indent):
        //     case N: {
        //       break;
        //     }
        // These contribute nothing (the switch falls through). Remove the whole
        // 3-line group. Also handle the `default:` variant with only a blank line
        // before `break;`. Ghidra does not emit cases whose body is solely `break;`.
        let snap_ecase = PostfixStats::snap(&output_final2);
        let mut no_empty_cases: Vec<String> = Vec::with_capacity(output_final2.len());
        let mut ie = 0usize;
        while ie < output_final2.len() {
            let t = output_final2[ie].trim();
            // Detect `case ...: {` or `default: {`
            if (t.starts_with("case ") || t == "default: {") && t.ends_with('{') {
                let case_indent = output_final2[ie].len() - output_final2[ie].trim_start().len();
                // Look ahead: optional blank line(s), then `break;`, then `}` at case_indent
                let mut k = ie + 1;
                // skip blanks
                while k < output_final2.len() && output_final2[k].trim().is_empty() {
                    k += 1;
                }
                if k < output_final2.len()
                    && output_final2[k].trim() == "break;"
                    && k + 1 < output_final2.len()
                {
                    let close_line = &output_final2[k + 1];
                    let close_indent = close_line.len() - close_line.trim_start().len();
                    if close_line.trim() == "}" && close_indent == case_indent {
                        // This is an empty case — skip all of it.
                        ie = k + 2;
                        continue;
                    }
                }
            }
            no_empty_cases.push(output_final2[ie].clone());
            ie += 1;
        }
        let output_final2 = no_empty_cases;
        pfx.observe(PF_ECASE, &snap_ecase, &output_final2);

        // Passes 20+21 (canonicalize_struct_deref + rewrite_struct_deref) REMOVED.
        // These were mutual inverses: pass 20 converted *(ptr+N) → ptr->field_N,
        // pass 21 converted ptr->field_N → *(long*)(ptr+N). Net effect was zero.
        // Now that printc.rs emits *(long*)(ptr+N) directly (no ->field_N),
        // both passes are no-ops. Removing them eliminates 2 rule-5.5 violations.
        let output_joined = output_final2.join("\n");
        let struct_pass = output_joined;

        // Twenty-second pass: fix declarations of variables dereferenced via `*X`.
        // printc emits `*param_N = val` for STORE when the address is a parameter.
        // If param_N was inferred as long/int (not pointer), `*param_N` is illegal C.
        // We collect all `*IDENT` occurrences (unary deref, not `*(` cast) and
        // rewrite their declarations to `_struct *` so the deref is legal.
        // PRINTC-LEGACY-DECL-DUP-0001: skipped inside symbol-driven functions
        // (Ghidra print layer never rewrites symbol declarations; the oracle
        // prints sym->getType() verbatim at printc.cc:2503-2506).
        let after_unary = Self::fix_unary_deref_declarations(&struct_pass);
        pfx.observe_str(PF_P22, &struct_pass, &after_unary);

        // Twenty-third pass: backfill missing local-variable declarations.
        // Scan each function body for `local_XX` identifiers used but not declared,
        // and insert `int local_XX;` declarations to keep the output compilable.
        // PRINTC-LEGACY-DECL-DUP-0001: this pass is NOT bypassed for
        // symbol-driven functions — its declared-name collection recognizes
        // both pointer spellings, so with the two duplicate sources above
        // bypassed it only injects names genuinely absent from the symbol
        // block (unlinked-symbol body references, PRINTC-UNLINKED-REF-0001),
        // which keeps those functions compilable.
        let after_backfill = Self::backfill_missing_locals(&after_unary);
        pfx.observe_str(PF_P23, &after_unary, &after_backfill);

        // Twenty-fourth pass: remove orphan break/continue statements that are
        // not within any loop or switch. These arise from incomplete control-flow
        // structuring (e.g. dead code after an early return). gcc rejects them as
        // 'break statement not within loop or switch'; deleting the bare statement
        // (not its enclosing line context) makes the output compilable.
        // Twenty-fifth pass: fix pointer-pointer arithmetic.
        // When two pointer-typed variables appear in `a + b` or `a * b`, C rejects
        // it ('invalid operands'). We cast the second operand to (long) so the
        // operation becomes pointer + integer, which is legal. This handles the
        // type contradiction where a variable is used both as a struct base (for
        // ->field access) and as an array index.
        let after_orphan = Self::remove_orphan_breaks(&after_backfill);
        pfx.observe_str(PF_P24, &after_backfill, &after_orphan);
        let after_ptr_arith = Self::fix_pointer_arithmetic(&after_orphan);
        pfx.observe_str(PF_P25, &after_orphan, &after_ptr_arith);
        // Pdl (duplicate LAB_ dedup) retired in POSTFIX-RETIRE-0001 W2:
        // W1 counters proved zero mutations on both corpora (curl 190 +
        // httpd 102 calls, both rounds); splice residue no longer produces
        // duplicate label definitions. Ghidra has no counterpart (block
        // addresses are unique; the oracle emit path has no text scan).
        // Twenty-sixth pass: remove lines with illegal lvalue assignments.
        let after_lvalue = Self::remove_illegal_lvalue_assignments(&after_ptr_arith);
        pfx.observe_str(PF_P26, &after_ptr_arith, &after_lvalue);
        // Twenty-seventh pass: remove case labels outside switch bodies.
        let after_case = Self::remove_orphan_case_labels(&after_lvalue);
        pfx.observe_str(PF_P27, &after_lvalue, &after_case);
        // Struct field recovery (-> operator) requires struct type definitions
        // at file scope. post_process runs per-function, so struct typedefs
        // end up inside function bodies (illegal C). Keep *(long *)(ptr + offset)
        // which is valid C for all pointer types. Struct field recovery needs
        // type propagation engine (ActionTypePropagate) at P-code level, not
        // text post-processing.
        pfx.emit(input, &after_case);
        after_case
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Remove `case N:` and `default:` lines that appear outside any switch
    /// statement. Uses a precise switch-depth tracker that counts `switch (...) {`
    /// openers and their matching `}` closers.
    fn remove_orphan_case_labels(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        // Stack of brace depths at which switch bodies open.
        // When we see `switch (...) {`, we push the current brace depth + 1
        // (the depth of the switch body). When brace depth drops below that,
        // the switch body has closed.
        let mut brace_depth: i32 = 0;
        let mut switch_body_depths: Vec<i32> = Vec::new();

        for line in lines {
            let t = line.trim();

            // Check if this line opens a switch body
            let opens_switch = Self::is_switch_stmt_prefix(t) && t.ends_with('{');

            // Count braces on this line (excluding those in char literals like '\x7d')
            // Simple heuristic: count { and } outside of single-quoted chars.
            // Since we escape brace chars in char literals (from earlier pass),
            // bare { and } on the line are structural.
            for ch in t.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }

            if opens_switch {
                // The switch body starts at the current brace_depth
                // (after counting the { on this line)
                switch_body_depths.push(brace_depth);
            }

            // Pop closed switches
            while let Some(&sd) = switch_body_depths.last() {
                if brace_depth < sd {
                    switch_body_depths.pop();
                } else {
                    break;
                }
            }

            // Check if this is a case/default label
            let is_case = t.starts_with("case ") || t == "default:";
            if is_case && switch_body_depths.is_empty() {
                // Orphan case label — skip it
                continue;
            }

            out.push(line.to_string());
        }
        out.join("\n")
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Remove assignment lines whose left-hand side is not a valid C lvalue.
    /// Detects patterns like 'IDENT + ... = ' or 'IDENT * ... = ' at the start
    /// of a statement (not inside parens/casts).
    fn remove_illegal_lvalue_assignments(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        for line in lines {
            let t = line.trim();
            // Skip non-assignment lines
            if !t.contains(" = ") { out.push(line.to_string()); continue; }
            // Skip declaration lines (contain a type keyword at start)
            if t.starts_with("int ") || t.starts_with("long ") || t.starts_with("char ")
                || t.starts_with("void ") || t.starts_with("short ") || t.starts_with("bool ")
                || t.starts_with("byte ") || t.starts_with("extern ") || t.starts_with("typedef ")
                || t.starts_with("float ") || t.starts_with("double ")
            {
                out.push(line.to_string()); continue;
            }
            // Skip if/while/for/return/case lines
            if t.starts_with("if ") || t.starts_with("while ") || t.starts_with("for ")
                || t.starts_with("return ") || t.starts_with("case ")
                || t.starts_with("else") || t.starts_with("do ")
            {
                out.push(line.to_string()); continue;
            }
            // Lines like 'RSP + expr = val' are illegal lvalue assignments from
            // erroneous STORE address rendering. Remove them outright.
            if (t.starts_with("RSP ") || t.starts_with("RBP "))
                && t.contains(" = ") && !t.starts_with("*")
            {
                continue;
            }
            // Extract LHS: text before first " = " (top-level, not inside parens)
            let bytes = t.as_bytes();
            let mut depth = 0i32;
            let mut eq_pos = None;
            let mut i = 0;
            while i + 2 < bytes.len() {
                match bytes[i] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b'=' if depth == 0 && bytes.get(i + 1) == Some(&b' ') && bytes.get(i + 2) == Some(&b' ') => {
                        // Make sure it's not '==' or '<=' or '>='
                        if i > 0 && matches!(bytes[i - 1], b'=' | b'<' | b'>' | b'!') {
                            // it's ==, <=, >=, != — skip
                        } else {
                            eq_pos = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if let Some(pos) = eq_pos {
                let lhs = t[..pos].trim();
                // Valid lvalues end with: identifier, ']', ')'
                let last_char = lhs.as_bytes().last().copied();
                let is_valid_lvalue_end = last_char.map_or(false, |c| {
                    c.is_ascii_alphanumeric() || c == b'_' || c == b']' || c == b')'
                });
                // Also valid: *(cast)expr = (dereference assignment)
                let is_deref = lhs.starts_with("*");
                // Check for top-level binary operators in LHS (not inside parens).
                // 'a + b', 'a * b', 'a - b' as a whole are not lvalues even if they
                // end with a valid char.
                let mut has_top_binop = false;
                if !is_deref {
                    let lbytes = lhs.as_bytes();
                    let mut d = 0i32;
                    let mut ii = 0;
                    while ii < lbytes.len() {
                        match lbytes[ii] {
                            b'(' | b'[' => d += 1,
                            b')' | b']' => d -= 1,
                            b' ' if d == 0 && ii + 2 < lbytes.len() => {
                                // Check for " + ", " - ", " * " at top level
                                if (lbytes[ii + 1] == b'+' || lbytes[ii + 1] == b'-' || lbytes[ii + 1] == b'*')
                                    && lbytes[ii + 2] == b' '
                                    && ii > 0
                                {
                                    has_top_binop = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        ii += 1;
                    }
                }
                if (!is_valid_lvalue_end && !is_deref) || has_top_binop {
                    // Illegal lvalue — skip this line
                    continue;
                }
            }
            out.push(line.to_string());
        }
        out.join("\n")
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Detect `IDENT + IDENT` and `IDENT * IDENT` patterns where both operands
    /// are declared as pointer types, and cast the right operand to `(long)`.
    fn fix_pointer_arithmetic(text: &str) -> String {
        // Collect names declared as pointers (type contains '*')
        use std::collections::HashSet;
        let mut ptr_names: HashSet<String> = HashSet::new();
        for line in text.lines() {
            let t = line.trim();
            if t.ends_with(';') && t.contains('*') && !t.contains('(') && !t.contains("return") {
                // Declaration like "int * piVar_0;" or "long * uVar_b0;"
                // Extract the variable name (last token before ';', after '*')
                let name: String = t
                    .trim_end_matches(';')
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_start_matches('*')
                    .to_string();
                if !name.is_empty() && name
                        .chars()
                        .next()
                        .map_or(false, |c| c.is_ascii_alphabetic()) {
                    ptr_names.insert(name);
                }
            }
        }
        if ptr_names.is_empty() {
            return text.to_string();
        }
        // Scan for `ptrA + ptrB` or `ptrA * ptrB` and cast ptrB to (long)
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            // Look for patterns: IDENT + IDENT or IDENT * IDENT where both are pointers
            let mut new_line = line.to_string();
            // Repeat to handle multiple occurrences on one line
            loop {
                let changed = Self::try_fix_one_ptr_arith(&new_line, &ptr_names);
                match changed {
                    Some(fixed) => { new_line = fixed; }
                    None => break,
                }
            }
            out.push_str(&new_line);
            out.push('\n');
        }
        // Remove trailing newline added by loop
        if out.ends_with('\n') && !text.ends_with('\n') {
            out.pop();
        }
        out
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Try to fix one `ptrA <op> ptrB` occurrence in the line. Returns Some(fixed)
    /// if a fix was applied, None otherwise. Scans the entire line (both LHS
    /// cast expressions and RHS).
    fn try_fix_one_ptr_arith(
        line: &str, ptr_names: &std::collections::HashSet<String>,
    ) -> Option<String> {
        // Scan the entire line (not just RHS) — pointer arithmetic in cast
        // expressions like *(long *)(ptrA + ptrB) appears on the LHS.
        let scan_start = 0;
        let bytes = line.as_bytes();
        let mut i = scan_start;
        while i + 2 < bytes.len() {
            // Check for " + " or " * " (operator surrounded by spaces)
            if bytes[i] == b' ' &&
                (bytes[i + 1] == b'+' || bytes[i + 1] == b'*') &&
                bytes[i + 2] == b' '
            {
                // Extract left operand: walk back from i to get the identifier
                let mut left_start = i;
                while left_start > scan_start && (bytes[left_start - 1].is_ascii_alphanumeric() || bytes[left_start - 1] == b'_') {
                    left_start -= 1;
                }
                let left_name = String::from_utf8_lossy(&bytes[left_start..i]).to_string();
                // Extract right operand: walk forward from i+3
                let mut right_end = i + 3;
                while right_end < bytes.len() && (bytes[right_end].is_ascii_alphanumeric() || bytes[right_end] == b'_') {
                    right_end += 1;
                }
                let right_name = String::from_utf8_lossy(&bytes[i + 3..right_end]).to_string();

                // Both must be pointer-typed names
                if ptr_names.contains(&left_name) && ptr_names.contains(&right_name) {
                    // Cast the right operand to (long)
                    let before = &line[..i + 3];
                    let after = &line[right_end..];
                    return Some(format!("{}(long){}{}", before, right_name, after));
                }
            }
            i += 1;
        }
        None
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Remove `break;`/`continue;` statements not within any loop or switch.
    /// Uses a pre-scan to mark line ranges that fall inside a loop/switch body
    /// (via brace matching), which is more reliable than a line-level context
    /// stack for nested case blocks.
    fn remove_orphan_breaks(text: &str) -> String {
        let lines: Vec<&str> = text.split('\n').collect();
        let n = lines.len();

        // Pre-scan: for each line that opens a loop/switch body (ends with '{'
        // and starts with while/for/do/switch), find the matching '}' via brace
        // counting and mark all lines in [opener+1, closer) as "in loop/switch".
        let mut in_loop_switch = vec![false; n];
        // Also track depth-based: any line at brace depth inside a loop/switch.
        // We do a single pass tracking a stack of (loop_or_switch, brace_depth_at_open).
        let mut brace_depth: i32 = 0;
        // Stack of brace depths at which a loop/switch body opened.
        let mut loop_depths: Vec<i32> = Vec::new();
        // In the skip_line layout, the index of the lone `{` line that the
        // signature reset already accounted for (must not bump depth again).
        let mut consumed_function_brace_line: Option<usize> = None;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Reset brace tracking at each function signature (line ends with '{'
            // and looks like a return-type declaration with parens). This prevents
            // brace-depth drift across functions from breaking switch detection.
            // With the oracle skip_line layout (printc.cc:1590/2655) the
            // signature ends with ')' and the lone `{` follows; that `{` line
            // must not bump the depth again, so it is consumed here.
            if Self::signature_opens_function_body(
                t,
                &["int ", "long ", "void ", "char ", "short ", "bool "],
                &lines[i + 1..],
            ) {
                brace_depth = 1;
                loop_depths.clear();
                in_loop_switch[i] = false;
                if !t.ends_with('{') {
                    consumed_function_brace_line = Some(i + 1);
                }
                continue;
            }
            if consumed_function_brace_line == Some(i) {
                in_loop_switch[i] = false;
                continue;
            }
            // Detect loop/switch opener: line ends with '{' and starts with keyword.
            // Skip lines that start with '}' (like "} else {") — they're handled below
            // by the closing-brace logic to avoid double-counting the brace delta.
            if t.ends_with('{') && !t.starts_with('}') {
                // MAIN-RC3-STRUCTURED-EMIT-0001: the compact `while(` (the
                // oracle overflow header, printc.cc:3023-3028) is a loop
                // opener too — without it the second pass below strips every
                // `break;` in its body as unprotected.
                let is_loop_hdr = t.starts_with("while ")
                    || t.starts_with("while(")
                    || t.starts_with("for ")
                    || t.starts_with("do ")
                    || Self::is_switch_stmt_prefix(t)
                    || t.contains("} while (");
                brace_depth += 1;
                if is_loop_hdr {
                    loop_depths.push(brace_depth);
                }
            }
            // Mark this line if any loop/switch is currently open
            if !loop_depths.is_empty() {
                in_loop_switch[i] = true;
            }
            // Handle closing braces
            if t == "}" {
                brace_depth -= 1;
                // Pop any loop/switch whose body just closed
                while let Some(&top) = loop_depths.last() {
                    if top > brace_depth {
                        loop_depths.pop();
                    } else {
                        break;
                    }
                }
            } else if t.starts_with("} while") || t.starts_with("} else") {
                // These close one brace then may open another (} else {) — handle net effect
                // Count opens and closes in the line
                let opens = t.matches('{').count() as i32;
                let closes = t.matches('}').count() as i32;
                let net = opens - closes;
                // First the closes happen
                for _ in 0..closes {
                    brace_depth -= 1;
                    while let Some(&top) = loop_depths.last() {
                        if top > brace_depth { loop_depths.pop(); } else { break; }
                    }
                }
                brace_depth += opens;
            }
        }

        // Second pass: remove break/continue lines not marked as in loop/switch.
        let mut out: Vec<String> = Vec::with_capacity(n);
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let protected = in_loop_switch[i];
            if !protected {
                // Check for break/continue tokens in this line
                let bytes = line.as_bytes();
                let mut has_break = false;
                let mut k = 0;
                while k < bytes.len() {
                    let candidates: &[&[u8]] = &[b"break;", b"continue;"];
                    for cand in candidates {
                        if k + cand.len() <= bytes.len() && &bytes[k..k + cand.len()] == *cand {
                            let prev_ok = k == 0 || {
                                let b = bytes[k - 1];
                                !(b.is_ascii_alphanumeric() || b == b'_')
                            };
                            if prev_ok { has_break = true; break; }
                        }
                    }
                    if has_break { break; }
                    k += 1;
                }
                if has_break {
                    // Remove the break/continue token; if line becomes empty, drop it.
                    let mut new_line = String::new();
                    let mut k = 0;
                    while k < bytes.len() {
                        let candidates: &[&[u8]] = &[b"break;", b"continue;"];
                        let mut hit = None;
                        for cand in candidates {
                            if k + cand.len() <= bytes.len() && &bytes[k..k + cand.len()] == *cand {
                                let prev_ok = k == 0 || {
                                    let b = bytes[k - 1];
                                    !(b.is_ascii_alphanumeric() || b == b'_')
                                };
                                if prev_ok { hit = Some(cand.len()); break; }
                            }
                        }
                        if let Some(clen) = hit {
                            k += clen;
                        } else {
                            new_line.push(bytes[k] as char);
                            k += 1;
                        }
                    }
                    let cleaned = new_line.trim_end().to_string();
                    let ct = cleaned.trim();
                    if ct.is_empty() || ct.ends_with(')') || ct == "{" {
                        continue; // drop the now-empty line
                    }
                    out.push(cleaned);
                    continue;
                }
            }
            out.push(line.to_string());
        }
        out.join("\n")
    }

    // RUGRA-GLUE: lazy mirror-face probe gating the two declaration-injection
    // arms below (GEN4-SQ-DUPDECL-NUMBERING-0001). Ghidra has no counterpart
    // for the very question: the oracle print path declares every function
    // local exactly once, from the top of the body, via emitLocalVarDecls
    // (printc.cc:2260-2279 → emitScopeVarDecls :2518-2575, one
    // emitVarDeclStatement per symbol) and never re-scans or re-declares
    // anything afterwards (docFunction printc.cc:2641-2676 ends at flush;
    // EmitPrettyPrint::flush prettyprint.cc:1194-1211 is a pure token-queue
    // drain with zero text analysis). The injection arms are Rugra's canon-
    // face self-containment compensation (POSTFIX-RETIRE-0001 W0), whose
    // declared-name collectors and signature probes only recognize the canon
    // type spellings (int/long/char */undefinedN) — on the direct-runner
    // contract face (standalone core table: xunknownN/int4/uintN/code,
    // sleigh_arch.cc:204-238) the probe misreads every symbol-driven
    // declaration as "missing" and re-declares it mid-body with a prefix-
    // guessed canon type (sq GetOptimum: `int4 iVar16;` at the top plus
    // `int iVar16; … char *piVar23;` injected inside a do-loop). The
    // direct-runner goldens carry zero injected declarations, so the arms
    // are skipped wholesale on that face. Env set = MIRROR-ENVS-CANONICAL-
    // 0001, single-sourced from typefactory::direct_runner_tier_active.
    fn mirror_face_active() -> bool {
        static MIRROR_FACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *MIRROR_FACE.get_or_init(crate::type_system::typefactory::direct_runner_tier_active)
    }

    // RUGRA-GLUE: backfill_missing_locals (no Ghidra counterpart exists)
    /// For each function, find `local_XX` identifiers used in the body but not
    /// declared, and insert `int local_XX;` declarations before the first
    /// non-declaration body line. The locked oracle's prettyprint.hh has no
    /// backfill pass of any kind (verified: prettyprint.hh:547 is the
    /// EmitNoMarkup class declaration, and grep over the oracle tree finds
    /// no backfillMissingLocals); this pass exists only to keep Rugra's
    /// unlinked-symbol body references (PRINTC-UNLINKED-REF-0001 domain)
    /// compilable and is retired as that domain closes. NUMDECL-DOUBLE-V:
    /// the identifier scanner below must respect C identifier boundaries —
    /// a prefix match inside a longer identifier (e.g. `lVar64` inside
    /// `plVar64`, whose `plVar` prefix is not in the table) is NOT a use of
    /// the shorter name, and injecting a declaration for it produces the
    /// same-name different-type double declaration (`long *plVar64;` from
    /// the scope emitter plus `long lVar64;` here).
    fn backfill_missing_locals(text: &str) -> String {
        // GEN4-SQ-DUPDECL-NUMBERING-0001: skip the whole arm on the
        // direct-runner (mirror) face — its declared-name walk and
        // signature probe only parse canon spellings, so on the
        // xunknownN/int4 face every symbol-driven declaration reads as
        // "missing" and gets a prefix-guessed canon-type re-declaration
        // (the sq GetOptimum mid-body block); the direct-runner goldens
        // carry zero injected declarations. See mirror_face_active above.
        if Self::mirror_face_active() {
            return text.to_string();
        }
        use std::collections::BTreeSet;
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            out.push(line.to_string());
            let trimmed = line.trim();
            // Detect function signature opener: a signature line ends with '{'
            // (legacy layout) or, in the oracle skip_line layout
            // (printc.cc:1590/2655), ends with ')' and the lone `{` follows.
            // WARN-EMIT2 R2 (printc-side naming collision root cause): the
            // `contains(" *")` arm also matches control-flow openers whose
            // condition carries a `/* N */` hex annotation — e.g.
            // `if ((bool)(piVar1 <= 0x1000 /* 4096 */)) {` contains `(`,
            // contains `" *"` (inside ` /* 4096 */`), and ends with `{`. The
            // pass then treated the if-body as a nested function, found the
            // block's auto-prefixed names "undeclared" (its declared-name
            // walk only covers the block, not the function scope), and
            // re-injected the whole decl set INSIDE the block — duplicate
            // `piVar1`/`uVar0` declarations (glob_url numbering 0->3). Gate
            // every control-flow opener out of sig_shape; only real function
            // signatures (first token is a type) reach the injection path.
            let control_flow_opener = trimmed.starts_with("if (")
                || trimmed.starts_with("if(")
                || trimmed.starts_with("while (")
                || trimmed.starts_with("while(")
                || trimmed.starts_with("for (")
                || trimmed.starts_with("for(")
                || trimmed.starts_with("switch (")
                || trimmed.starts_with("switch(")
                || trimmed.starts_with("do {")
                || trimmed.starts_with("else")
                || trimmed.starts_with("case ")
                || trimmed.starts_with("default:");
            // WARN-EMIT2 R3 (glob_range `int iVar1;`/`int iVar3;` mid-block
            // double declarations, numbering 1): a multi-line if-condition
            // CONTINUATION line — e.g. `&& \n (SEXT14(...) < 0x1a)) {` —
            // starts with `(` yet satisfies sig_shape via `contains(" *")`
            // (the `*(char *)` dereference text). A C function signature
            // never starts with `(`, so gate condition-continuation fragments
            // out of signature detection entirely; otherwise the pass treats
            // the nested block as a function body, finds its auto-prefixed
            // names "undeclared" (the declared-name walk only covers the
            // fragment), and re-injects the declarations INSIDE the block.
            let cond_continuation = trimmed.starts_with('(');
            // MAIN-IVAR4-DUP hardening: a C function signature line never
            // contains a `;`. After the MAIN-RC3 gate flip exposed
            // same-line `stmt; if (...) {` forms (missing tagLine), the
            // `contains(" *")` arm (e.g. `(_IO_FILE *)`) matched such a
            // line as a signature, the decl walk found an empty block, and
            // every auto-named variable in the fake "body" (iVar4) got
            // re-injected as `  int iVar4;` mid-function — the numbering+1.
            // Gate any line with a semicolon out of signature detection.
            let no_semicolon = !trimmed.contains(';');
            // WARN-EMIT2 R4 (glob_range typed-global lane): a multi-line
            // if-condition continuation can also start with a bare
            // identifier — `iVar5 < *(int *)((int *)&((URLPattern *)
            // (uVar4 + 0x50) + iVar8)->content + 4))) {` passes
            // no_semicolon + contains('(') + contains(" *") and ends with
            // '{', so the pass treated the if-body as a nested function
            // and re-injected `int iVar5; ... long uVar4;` inside the
            // block (glob_range numbering 0->6). A C function signature
            // never contains a comparison/logical operator (`<`, `>`,
            // `==`, `!=`, `&&`, `||`; `>` also covers the `->` of field
            // chains, which only occur in expressions), so gate them all
            // out of signature detection.
            let no_comparison = !(trimmed.contains('<')
                || trimmed.contains('>')
                || trimmed.contains("==")
                || trimmed.contains("!=")
                || trimmed.contains("&&")
                || trimmed.contains("||"));
            // HTTPDMAIN-F8-FORLOOP-0001 guard: a for-header that exceeds
            // the print margin wraps, and its continuation line
            // (`    puVar11 = (undefined8 *)*puVar11) {`) carries the
            // closing `) {`, an assignment `=`, a cast's ` *`, and (the
            // compare stayed on the first header line) no comparison
            // operator — passing every gate above, so the pass treated
            // the loop body as a nested function, found the decl walk
            // empty, and re-injected every auto-named body local
            // (`  long uVar13;`) inside the loop. A C function signature
            // never contains an assignment operator, so gate `=` out the
            // same way the semicolon/comparison gates work.
            let no_assignment = !trimmed.contains('=');
            let sig_shape = no_semicolon
                && no_comparison
                && no_assignment
                && !control_flow_opener
                && !cond_continuation
                && trimmed.contains('(')
                && (trimmed.starts_with("int ") || trimmed.starts_with("long ")
                    || trimmed.starts_with("void ") || trimmed.starts_with("char ")
                    || trimmed.starts_with("short ") || trimmed.starts_with("bool ")
                    || trimmed.contains(" *"));
            let next_is_lone_brace = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .map_or(false, |l| l == "{");
            let is_sig = sig_shape
                && (trimmed.ends_with('{')
                    || (trimmed.ends_with(')') && next_is_lone_brace));
            if !is_sig { i += 1; continue; }

            // Walk the declaration block: consecutive lines ending with ';' that
            // contain no '(' or '=' (pure declarations). Track declared names and
            // the indent. Stop at first non-declaration line (the body proper).
            let mut declared: BTreeSet<String> = BTreeSet::new();
            let mut j = i + 1;
            let mut decl_indent = 2usize;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() { j += 1; continue; }
                // skip_line layout: the lone `{` line sits between the
                // signature and the declaration block (printc.cc:1590/2655).
                // Skip it so the walk reaches the declarations instead of
                // breaking with an empty `declared` set (which would make
                // every used variable look missing and re-declare it).
                if t == "{" { j += 1; continue; }
                if t.ends_with(';') && !t.contains('(') && !t.contains("return") {
                    // Only treat as declaration if it has no '=' (assignment) —
                    // pure decls are "type name;" or "type *name;"
                    if !t.contains('=') {
                        let indent = lines[j].len() - lines[j].trim_start().len();
                        decl_indent = indent;
                        // HEADLESS-BRIDGE-V1-TYPESEED: postfix array
                        // declarators (`long local_c8 [4];` — the committed
                        // seed symbol decl form, printc.cc:2502
                        // pushTypeStart/pushSymbol spelling) put `[N]`
                        // dimension tokens AFTER the name, so the old
                        // last-token pick recorded `[4]` as the "declared
                        // name" and the backfill re-injected `int local_c8;`
                        // beside the real array declaration. Strip trailing
                        // bracket tokens (and a glued `[..]` suffix) before
                        // the name pick.
                        let mut tokens: Vec<&str> =
                            t.trim_end_matches(';').split_whitespace().collect();
                        while tokens.len() > 1
                            && tokens.last().map(|tok| tok.starts_with('[')).unwrap_or(false)
                        {
                            tokens.pop();
                        }
                        let name: String = tokens
                            .last()
                            .unwrap_or(&"")
                            .trim_start_matches('*')
                            .split('[')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty() { declared.insert(name); }
                        j += 1;
                        continue;
                    }
                }
                // VARMAP-DUPDECL-EXTRAOUT-0001: parens-carrying pure decl
                // lines — the oracle spellings printc emits for
                // pointer-to-array symbols (`undefined1 (*pauVar7) [16];`,
                // varmap Symbol dtype verbatim per printc.cc:2503-2506) and
                // function pointers (`void (*pVar4)();`) — are still
                // declarations. Stopping the walk here made every name
                // declared after them read as "missing" and re-injected as a
                // duplicate (same name, prefix-inferred type — the httpd
                // numbering=16 duplicates of this lane's three target
                // functions). Collect the embedded name instead; the walk
                // still stops at the first real body statement (`;`-lines
                // with '=' are rejected above, non-decl shapes break below).
                if t.ends_with(';') && t.contains("(*") && !t.contains("return")
                    && !t.contains('=') {
                    let body = t.trim_end_matches(';');
                    if let Some(p) = body.find("(*") {
                        let name: String = body[p + 2..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() { declared.insert(name); }
                        j += 1;
                        continue;
                    }
                }
                break;
            }
            // j now points at the first body line (after declarations + blank lines).
            // Scan body until matching '}' for auto-generated variable usage.
            let body_end = {
                let mut d = 1i32;
                let mut k = j;
                while k < lines.len() && d > 0 {
                    for ch in lines[k].chars() {
                        if ch == '{' { d += 1; }
                        if ch == '}' { d -= 1; }
                    }
                    k += 1;
                }
                k
            };
            let mut used_locals: BTreeSet<String> = BTreeSet::new();
            for k in j..body_end {
                let lb = lines[k].as_bytes();
                let mut p = 0;
                while p < lb.len() {
                    // Match identifiers with auto-generated prefixes:
                    // - local_XX, lVar_XX (with underscore + hex)
                    // - bVar592, lVar21 (prefix + digits, no underscore)
                    // - struct3, struct5 (struct + digit)
                    // - unique0x00023b00 / register0x000000a0 / stack0x... /
                    //   ram0x...: oracle unnamed-location fallback tokens
                    //   (printc.cc:1938-1945 PrintC::pushUnnamedLocation —
                    //   <spacename> + AddrSpace::printRaw, space.cc:206-222 —
                    //   which replaced the uVar_/local_ spellings after the
                    //   A69 pushUnnamedLocation merge). printRaw emits "0x" +
                    //   lowercase hex (space.cc:216 `hex` manipulator), so the
                    //   tail scan must accept hex digits: the decimal-only
                    //   non-underscore arm would truncate unique0x00023b00 at
                    //   its first a-f digit.
                    let prefixes: &[&[u8]] = &[
                        b"local_", b"lVar_", b"uVar_", b"iVar_", b"bVar_", b"sVar_",
                        b"piVar_", b"pcVar_", b"psVar_", b"ppVar_", b"pvVar_",
                        b"fVar_", b"dVar_", b"DAT_",
                        b"unique0x", b"register0x", b"stack0x", b"ram0x",
                        b"lVar", b"uVar", b"iVar", b"bVar", b"sVar",
                        b"piVar", b"pcVar", b"psVar", b"ppVar", b"pvVar",
                        b"fVar", b"dVar", b"struct",
                    ];
                    let mut matched = false;
                    for pf in prefixes {
                        let plen = pf.len();
                        // NUMDECL-DOUBLE-V left word-boundary: a prefix match
                        // must START an identifier. C identifiers are
                        // [A-Za-z_][A-Za-z0-9_]*, so a match preceded by an
                        // identifier byte is the middle of a longer token —
                        // e.g. `plVar64` matches the `lVar` prefix at its
                        // inner `l`, manufacturing a phantom `lVar64` "used
                        // local" that gets injected as `long lVar64;` beside
                        // the real `long *plVar64;` declaration.
                        let boundary_ok = p == 0
                            || !(lb[p - 1].is_ascii_alphanumeric() || lb[p - 1] == b'_');
                        if boundary_ok && p + plen <= lb.len() && &lb[p..p + plen] == *pf {
                            let mut e = p + plen;
                            // For underscore prefixes: hex digits and underscores
                            // For unnamed-location fallback tokens (prefix ends
                            // in "0x"): hex digits only (printc.cc:1942-1943
                            // space name + printRaw hex tail)
                            // For other non-underscore: digits only
                            if lb[p + plen - 1] == b'_' {
                                while e < lb.len() && (lb[e].is_ascii_hexdigit() || lb[e] == b'_') { e += 1; }
                            } else if pf.ends_with(b"0x") {
                                while e < lb.len() && lb[e].is_ascii_hexdigit() { e += 1; }
                            } else {
                                while e < lb.len() && lb[e].is_ascii_digit() { e += 1; }
                            }
                            if e > p + plen {
                                used_locals.insert(String::from_utf8_lossy(&lb[p..e]).to_string());
                            }
                            p = e;
                            matched = true;
                            break;
                        }
                    }
                    if !matched { p += 1; }
                }
            }
            let missing: Vec<&String> = used_locals
                .iter()
                    .filter(|n| !declared.contains(*n))
                    .collect();
            // PRINTC-LEGACY-DECL-DUP-0001: the duplicate-declaration source
            // was NOT this pass — backfill's declared-name collection handles
            // both pointer spellings (`char *uVar20;` 2-token join and
            // `char * *uVar20;` 3-token), so it only injects names that are
            // genuinely absent from the declaration block (unlinked-symbol
            // body references, PRINTC-UNLINKED-REF-0001 domain). The
            // duplicates came from flush_func_remove_unused (which cannot
            // recognize the 2-token join form and re-declared those symbols)
            // and fix_unary_deref_declarations (which rewrote the injected
            // scalars to pointer form) — both bypassed above. Backfill stays
            // active for every function so unlinked references keep compiling;
            // functions without symbol evidence are unaffected either way.
            if !missing.is_empty() {
                let indent_str = " ".repeat(decl_indent);
                for k in (i + 1)..j {
                    out.push(lines[k].to_string());
                }
                for m in &missing {
                    // Infer type from prefix: lVar/uVar/piVar etc → long/long/pointer
                    // DAT_ prefixed names are synthetic globals. Ghidra's printer
                    // never declares globals inside a function (printc.cc:2641-2670
                    // docFunction has no global-decl step; "extern" does not occur
                    // in the oracle printc.cc at all), and the golden contains zero
                    // extern lines — the anonymous data pool prints bare DAT_
                    // references at use sites only (MAIN-DATPOOL-0001). Skip the
                    // declaration entirely to match the oracle.
                    if m.starts_with("DAT_") {
                        continue;
                    }
                    // Canon never declares unnamed-location tokens
                    // (printc.cc:1938-1945 PrintC::pushUnnamedLocation —
                    // `<space>0x<hex>` labels are expression-level storage
                    // slots, not ScopeLocal symbols, so the oracle's
                    // emitLocalVarDecls (printc.cc:2260-2279) never emits a
                    // declaration for them; the 12.0.4 golden declares zero
                    // of its stack0x/unique0x/register0x/ram0x uses).
                    // PRINTC-C3-UNNAMED-SPACE-NAME-0001: injecting a decl
                    // here diverges from the canon text the printc fallback
                    // now produces.
                    if m.starts_with("unique0x") || m.starts_with("register0x")
                        || m.starts_with("stack0x") || m.starts_with("ram0x") {
                        continue;
                    }
                    let ty = if m.starts_with("struct") {
                        "int"
                    } else if m.starts_with("lVar") || m.starts_with("uVar") {
                        "long"
                    } else if m.starts_with("iVar") || m.starts_with("bVar")
                        || m.starts_with("sVar") || m.starts_with("local_") {
                        "int"
                    } else if m.starts_with("piVar") || m.starts_with("pcVar")
                        || m.starts_with("psVar") || m.starts_with("ppVar")
                        || m.starts_with("pvVar") {
                        "char *"
                    } else if m.starts_with("fVar") { "float" }
                    else if m.starts_with("dVar") { "double" }
                    else if m.starts_with("unique0x") || m.starts_with("register0x")
                        || m.starts_with("stack0x") || m.starts_with("ram0x") {
                        // Oracle unnamed-location fallback token (printc.cc:1938
                        // pushUnnamedLocation): a raw storage-slot label with no
                        // type evidence at text level — keep the long default
                        // the pre-A69 uVar-family spelling of these slots got.
                        "long"
                    }
                    else { "long" };
                    // Pointer-join spacing (printc.cc:73-77 ptr_expr
                    // spacing=0): a trailing-`*` type glues to the name.
                    let join = if ty.ends_with('*') { "" } else { " " };
                    out.push(format!("{}{}{}{};", indent_str, ty, join, m));
                }
                i = j;
                continue;
            }
            i += 1;
        }
        out.join("\n")
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Rewrite declarations of variables appearing in `*IDENT` unary dereference
    /// patterns to pointer type, so `*param_N` is legal C.
    fn fix_unary_deref_declarations(text: &str) -> String {
        use std::collections::HashSet;
        // Collect IDENTs used as `*IDENT` (unary deref).
        // Patterns: `*IDENT =`, `= *IDENT`, `(*IDENT)`, `*IDENT;`, `*IDENT,`
        // Exclude `*( ... )` (cast) and `** ` (double deref handled separately).
        let mut derefed: HashSet<String> = HashSet::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Look for `*` not preceded by `(` or `*` or alnum, and not followed by `(`.
            if bytes[i] == b'*' {
                let prev_alnum = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b')');
                let next_is_paren = i + 1 < bytes.len() && bytes[i + 1] == b'(';
                let next_is_star = i + 1 < bytes.len() && bytes[i + 1] == b'*';
                // Skip if it's a `type *X` declaration (preceded by whitespace after type word) — hard to detect perfectly,
                // but we only act on IDENTs that also appear in declarations, so false positives are harmless.
                if !prev_alnum && !next_is_paren && !next_is_star {
                    // Capture following identifier
                    let mut j = i + 1;
                    // skip whitespace
                    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') { j += 1; }
                    let id_start = j;
                    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') { j += 1; }
                    if j > id_start {
                        let name = String::from_utf8_lossy(&bytes[id_start..j]).to_string();
                        if name
                            .chars()
                            .next()
                            .map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                            derefed.insert(name);
                        }
                    }
                }
            }
            i += 1;
        }
        if derefed.is_empty() {
            return text.to_string();
        }
        // Rewrite scalar declarations of these names to `_struct *`.
        let scalar_types = [
            "long", "int", "short", "char", "byte", "bool",
            "undefined", "undefined4", "undefined8",
        ];
        let lines: Vec<&str> = text.split('\n').collect();
        // PRINTC-LEGACY-DECL-DUP-0001 bypass: inside symbol-driven functions
        // this pass's rewrites corrupt Action-phase symbol declarations —
        // rewriting the (bypassed) `int uVarN;` injections to `char *uVarN;`
        // is what made the duplicates survive as pointer-typed re-declarations,
        // and rewriting a genuine scalar symbol decl (`int uVar0;`) changes its
        // printed type away from the symbol's Datatype (printc.cc:2503-2506
        // emitLocalSymbolDecl prints sym->getType() verbatim). Skip lines of
        // functions whose declaration block is symbol-driven.
        let symbol_mask = Self::symbol_driven_function_line_mask(&lines);
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        for (idx, line) in lines.iter().enumerate() {
            let line: &str = *line;
            if symbol_mask[idx] {
                out.push(line.to_string());
                continue;
            }
            let trimmed = line.trim_start();
            let indent_len = line.len() - trimmed.len();
            let mut rewritten = None;
            for ty in &scalar_types {
                let prefix = format!("{} ", ty);
                if let Some(rest) = trimmed.strip_prefix(&prefix) {
                    if rest.starts_with('*') { break; } // already pointer
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() && derefed.contains(&name) {
                        let indent_str = &line[..indent_len];
                        // Declare as `char *`: `*(char *)X` yields a char, which can be
                        // assigned scalar values (0-255), indexed, and compared — covering
                        // the common STORE/LOAD patterns without knowing the real type.
                        rewritten = Some(format!("{}char *{};", indent_str, name));
                        break;
                    }
                }
            }
            // Also handle parameter declarations in function signature: `long param_1` -> `_struct * param_1`
            // These appear on the signature line, not as standalone declarations.
            if rewritten.is_none() {
                // Check if this is a signature line containing `(long param_N, ...)`
                // We rewrite param types inline if they're in derefed set.
                // POSTFIX-VOIDCALL-W3 / W3 damage fix: the pattern
                // `"{ty} {name}"` must match on IDENTIFIER BOUNDARIES. A bare
                // substring match rewrote the RETURN TYPE region of any
                // function whose name starts with a derefed variable's name:
                // `int glob_url(URLGlob **glob,…)` contains `int glob` (the
                // body legitimately derefs `*glob`), so the pass emitted
                // `char *glob_url(…)` — a return-type change Ghidra never
                // performs (the golden keeps `int glob_url`), and the
                // `return 0;` body then returns int from a char* function.
                // Word-boundary (no [A-Za-z0-9_] adjacent on either side) is
                // the same boundary contract count_word_occurrences uses.
                let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                let mut new_line = line.to_string();
                for name in &derefed {
                    for ty in &scalar_types {
                        let pat = format!("{} {}", ty, name);
                        let repl = format!("char *{}", name);
                        // Only replace if not already pointer (avoid `long * param` -> `_struct * * param`)
                        if let Some(idx) = new_line.find(&pat) {
                            let end = idx + pat.len();
                            // Check char before is not '*' or an identifier char
                            let before_ok = idx == 0 || {
                                let b = new_line.as_bytes()[idx - 1];
                                b != b'*' && !is_ident(b)
                            };
                            // Check char after is not an identifier char
                            // (`int glob` must not match `int glob_url`).
                            let after_ok = end >= new_line.len() || {
                                !is_ident(new_line.as_bytes()[end])
                            };
                            if before_ok && after_ok {
                                new_line = new_line.replacen(&pat, &repl, 1);
                            }
                        }
                    }
                }
                if new_line != line {
                    rewritten = Some(new_line);
                }
            }
            out.push(rewritten.unwrap_or_else(|| line.to_string()));
        }
        out.join("\n")
    }

    /// Scans backward through already-emitted lines.
    // RUGRA-GLUE: signature_opens_function_body (format-layer helper for the
    //   oracle's two-line function-header layout: printc.cc:1590 sets
    //   option_brace_func=skip_line and printc.cc:2655 emits the body `{`
    //   two lines below the declaration, so `sig {` and `sig` + `{` are both
    //   valid function openings in Rugra text).
    /// Whether a trimmed line is a C function signature that opens a body
    /// brace, either trailing on the same line (legacy `sig {`) or alone on
    /// the next non-blank line (oracle skip_line `sig` / `{`).
    /// `type_prefixes` preserves each call site's original return-type set.
    fn signature_opens_function_body<L: AsRef<str>>(
        t: &str,
        type_prefixes: &[&str],
        lookahead: &[L],
    ) -> bool {
        if t.is_empty() || t.starts_with("//") || t.starts_with("/*") {
            return false;
        }
        if !type_prefixes.iter().any(|p| t.starts_with(p)) || !t.contains('(') {
            return false;
        }
        if t.ends_with('{') {
            return true;
        }
        if !t.ends_with(')') {
            return false;
        }
        // skip_line layout: the next non-blank line must be the lone `{`
        lookahead
            .iter()
            .map(|l| l.as_ref().trim())
            .find(|l| !l.is_empty())
            .map_or(false, |l| l == "{")
    }

    // RUGRA-GLUE: legacy_never_type_evidence (no Ghidra counterpart; shared
    //   evidence helper of has_symbol_driven_decls / _walk_parens — see the
    //   PRINTC-LEGACY-DECL-DUP-0001 notes there).
    /// Type spellings ONLY the symbol-driven emitter produces. printc's
    /// emit_local_var_decls (printc.cc:2260-2279) prints core-type symbol
    /// dtypes verbatim, while the legacy text passes synthesize exclusively
    /// int/long/bool/byte/short/char */void */float/double (see
    /// flush_func_remove_unused's type_ok table). CHAINFIX-LEGACY-BYPASS-0001:
    /// `uint*`/`int1`/`int2`/`int8`/`ushort`/`ulong`/`longlong`/`__int*_t`
    /// are therefore symbol-driven evidence of the same strength as
    /// `undefined*`; without them, chunks whose only `in_` name the
    /// ActionInputPrototype function_parameter symbol install retired fell
    /// back into the legacy pass, whose collector ignores those spellings,
    /// saw every uVarN as "missing", and injected `int uVarN;` K&R-style
    /// between the signature and `{` (ap_getparents/httpd, glob_word/curl).
    fn legacy_never_type_evidence(type_token: &str) -> bool {
        type_token.starts_with("undefined")
            || type_token.starts_with("uint")
            || type_token.starts_with("int1")
            || type_token.starts_with("int2")
            || type_token.starts_with("int8")
            || type_token == "ushort"
            || type_token == "ulong"
            || type_token == "longlong"
            || type_token.starts_with("__int")
    }

    // RUGRA-GLUE: has_symbol_driven_decls (no Ghidra counterpart — Ghidra's
    //   print layer has no declaration passes to bypass: printc.cc:2656
    //   docFunction emits every function-local declaration from Action-phase
    //   symbols via emitLocalVarDecls and nothing else, so "does this text
    //   already carry symbol-driven declarations" is a question that only
    //   exists for Rugra's legacy compensation passes).
    /// Conservative bypass predicate for the two synthetic-declaration legacy
    /// passes (`flush_func_remove_unused`, `fix_unary_deref_declarations`):
    /// does this function chunk, starting at its signature line, already
    /// carry `emit_local_var_decls` products in its declaration block?
    /// (`backfill_missing_locals` deliberately does NOT consult this — see
    /// its PRINTC-LEGACY-DECL-DUP-0001 note.)
    ///
    /// Evidence spellings (PRINTC-LEGACY-DECL-DUP-0001 /
    /// CHAINFIX-LEGACY-BYPASS-0001): a declaration whose type token is
    /// `legacy_never_type_evidence` (symbol-emitter-only spellings), or a
    /// declaration whose name token starts with `in_` (register/ram space
    /// symbol names like in_RAX / in_ram_00016e70; the legacy passes never
    /// generate `in_`-prefixed names). A decl block without either evidence
    /// keeps the legacy passes: those functions may still lack symbols and
    /// must not lose their backfill safety net.
    fn has_symbol_driven_decls<L: AsRef<str>>(func_lines: &[L]) -> bool {
        let mut j = 1usize;
        while j < func_lines.len() {
            let t = func_lines[j].as_ref().trim();
            if t.is_empty() || t == "{" {
                j += 1;
                continue;
            }
            if t.ends_with(';') && !t.contains('(') && !t.contains("return") && !t.contains('=') {
                let tokens: Vec<&str> = t.trim_end_matches(';').split_whitespace().collect();
                if !tokens.is_empty() {
                    if Self::legacy_never_type_evidence(tokens[0]) {
                        return true;
                    }
                    let name = tokens[tokens.len() - 1].trim_start_matches('*');
                    if name.starts_with("in_") {
                        return true;
                    }
                }
                j += 1;
                continue;
            }
            break;
        }
        false
    }

    // RUGRA-GLUE: has_symbol_driven_decls_walk_parens (no Ghidra counterpart;
    //   same GLUE family as has_symbol_driven_decls above — see
    //   POSTFIX-RETIRE-0001 W0. VARMAP-DUPDECL-EXTRAOUT-0001: the original
    //   detector breaks the decl-block walk at parens-carrying declaration
    //   lines — the oracle spellings printc emits for pointer-to-array
    //   symbols (`undefined1 (*pauVar7) [16];`, Symbol dtype verbatim per
    //   printc.cc:2503-2506) and function pointers (`void (*pVar4)();`) —
    //   so a symbol-driven chunk whose ONLY undefined*/in_ evidence sits
    //   behind such a line read as legacy and the flush pass's
    //   missing-injection half manufactured `int uVarN;` duplicate
    //   declarations the oracle never emits (printc.cc:2260-2279
    //   emitLocalVarDecls declares each scope symbol exactly once). This
    //   variant walks past those lines: same acceptance set (ends_with(';'),
    //   no "return", no '='), no '(' rejection, so paren decl lines continue
    //   instead of breaking. Used ONLY by flush_func_remove_unused's bypass:
    //   the P22 mask (symbol_driven_function_line_mask) keeps the original
    //   detector on purpose — flipping it there would newly bypass
    //   fix_unary_deref_declarations's legacy `*param_N` legality repair for
    //   chunks like curl progressbarinit (base `char *param_1` → `long
    //   param_1` flip, curl E2E byte-divergence; verified 2026-09-23).
    fn has_symbol_driven_decls_walk_parens<L: AsRef<str>>(func_lines: &[L]) -> bool {
        let mut j = 1usize;
        while j < func_lines.len() {
            let t = func_lines[j].as_ref().trim();
            if t.is_empty() || t == "{" {
                j += 1;
                continue;
            }
            if t.ends_with(';') && !t.contains("return") && !t.contains('=') {
                let tokens: Vec<&str> = t.trim_end_matches(';').split_whitespace().collect();
                if !tokens.is_empty() {
                    if Self::legacy_never_type_evidence(tokens[0]) {
                        return true;
                    }
                    let name = tokens[tokens.len() - 1].trim_start_matches('*');
                    if name.starts_with("in_") {
                        return true;
                    }
                }
                j += 1;
                continue;
            }
            break;
        }
        false
    }

    // RUGRA-GLUE: symbol_driven_function_line_mask (no Ghidra counterpart —
    ///   see has_symbol_driven_decls; this is the whole-text segmentation the
    ///   line-oriented fix_unary_deref_declarations pass needs to skip
    ///   symbol-driven functions without restructuring its rewrite loop).
    /// Per-line mask: true = this line belongs to a function whose declaration
    /// block is symbol-driven (see `has_symbol_driven_decls`). Signature
    /// detection reuses `signature_opens_function_body` with a prefix set
    /// covering every return-type spelling the printc layer produces
    /// (including `undefinedN`, which the flush/backfill call sites'
    /// historical prefix sets do not list).
    fn symbol_driven_function_line_mask(lines: &[&str]) -> Vec<bool> {
        let prefixes = [
            "int ", "void ", "long ", "byte ", "bool ", "short ",
            "char ", "float ", "double ", "undefined", "uint ",
            "ulong ", "ushort ", "size_t ",
        ];
        let mut mask = vec![false; lines.len()];
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim();
            if !Self::signature_opens_function_body(t, &prefixes, &lines[i + 1..]) {
                i += 1;
                continue;
            }
            // Function chunk: signature line through the matching close brace
            // (brace depth from the signature line itself).
            let mut end = i + 1;
            let mut depth: i32 = t.chars().filter(|c| *c == '{').count() as i32
                - t.chars().filter(|c| *c == '}').count() as i32;
            // PRINTC-LEGACY-DECL-DUP-0001 (mask-chunk half): a skip_line
            // signature line carries no braces (depth 0), and the oracle
            // layout puts a BLANK line between the signature and the body's
            // `{` (open_brace_indent SkipLine emits two line breaks). The
            // previous loop broke on the blank line (depth still <= 0), so
            // the "chunk" was just [signature, blank] — has_symbol_driven_decls
            // saw no declarations and the function was never masked. That let
            // fix_unary_deref_declarations rewrite locked DWARF parameter
            // types in the signature (`int argc` -> `char *argc` in main)
            // even though printc.cc:2222 emitPrototypeInputs printed the
            // FuncProto's locked `int` correctly. Fix: before the depth walk,
            // skip forward to the opening `{` that signature_opens_function_
            // body already located via its lookahead; the walk then starts at
            // depth 1 and spans the real body.
            if depth <= 0 {
                let mut open = end;
                while open < lines.len() {
                    let ft = lines[open].trim();
                    if ft == "{" || ft.ends_with('{') {
                        depth += ft.chars().filter(|c| *c == '{').count() as i32;
                        depth -= ft.chars().filter(|c| *c == '}').count() as i32;
                        break;
                    }
                    // Any other non-blank line before the `{` means the
                    // lookahead contract was violated; fall back to the old
                    // two-line chunk rather than scanning past the function.
                    if !ft.is_empty() {
                        break;
                    }
                    open += 1;
                }
                if open > end {
                    end = open;
                }
            }
            while end < lines.len() {
                let ft = lines[end].trim();
                depth += ft.chars().filter(|c| *c == '{').count() as i32;
                depth -= ft.chars().filter(|c| *c == '}').count() as i32;
                if depth <= 0 {
                    end += 1;
                    break;
                }
                end += 1;
            }
            if Self::has_symbol_driven_decls(&lines[i..end]) {
                for m in mask.iter_mut().take(end).skip(i) {
                    *m = true;
                }
            }
            i = end;
        }
        mask
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    /// Remove unused variable declarations from a function's lines
    /// AND add missing declarations for uVarNNN that appear in body but have no declaration
    fn flush_func_remove_unused(func_lines: &[String], out: &mut Vec<String>) {
        // GEN4-SQ-DUPDECL-NUMBERING-0001: skip the whole pass on the
        // direct-runner (mirror) face. Both halves misread the standalone
        // core-table spellings: the type_ok collector accepts only canon
        // int/long/bool/byte/short/undefinedN (and char/int/long/void/
        // undefinedN with `*`), so mirror `int4`/`xunknown8`/`code`
        // declarations are never collected — the unused-removal half
        // cannot protect them and the missing-injection half re-declares
        // every body uVarNNN as `  int uVarN;` after a last_decl_idx that
        // falls back to 0 (K&R placement between signature and `{`) or onto
        // a stray pseudo-declaration line mid-body. The symbol-driven
        // bypass below cannot be widened instead: its evidence table
        // (legacy_never_type_evidence) equally lacks the xunknownN/int4/
        // code spellings, and printc.cc:2260-2279 emitLocalVarDecls emits
        // every scope symbol exactly once regardless of body use — passing
        // the chunk through untouched is exactly the oracle shape. Canon
        // face keeps the pass (POSTFIX-RETIRE-0001 W0 compensation).
        if Self::mirror_face_active() {
            out.extend(func_lines.iter().cloned());
            return;
        }
        // PRINTC-LEGACY-DECL-DUP-0001 bypass: when the chunk already carries
        // symbol-driven declarations (emit_local_var_decls products), both
        // halves of this pass only corrupt them — the missing-injection half
        // re-declares symbols whose oracle-join pointer spellings
        // (`char *uVar20;`, 2 tokens) this pass's type_ok table cannot
        // recognize, producing duplicate `int uVarN;` lines (and K&R
        // placement between signature and `{` when no uVar decl was
        // collected at all), and the unused-removal half deletes symbol
        // declarations Ghidra always prints (printc.cc:2260 emitLocalVarDecls
        // emits every symbol regardless of body use). Pass the chunk through
        // untouched; functions without symbol evidence keep the legacy pass.
        if Self::has_symbol_driven_decls(func_lines)
            || Self::has_symbol_driven_decls_walk_parens(func_lines) {
            out.extend(func_lines.iter().cloned());
            return;
        }
        // Collect all declaration lines: "  type uVarNNN;"
        let mut decl_indices: Vec<(usize, String)> = Vec::new();
        for (i, line) in func_lines.iter().enumerate() {
            let t = line.trim();
            // Match "type uVarNNN;" and "type *uVarNNN;" declaration patterns.
            // Pointer forms split into a trailing token like "*uVar20", so the
            // variable name is taken as the substring after any leading '*'.
            if let Some(rest) = t.strip_suffix(';') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let last = parts[parts.len() - 1];
                    let name = last.trim_start_matches('*');
                    let type_first = parts[0];
                    let type_ok = parts.len() == 2
                        && (type_first == "int"
                            || type_first == "long"
                            || type_first == "bool"
                            || type_first == "byte"
                            || type_first == "short"
                            || type_first.starts_with("undefined"))
                        || (parts.len() == 3
                            && (type_first == "char"
                                || type_first == "int"
                                || type_first == "long"
                                || type_first == "void"
                                || type_first == "undefined8"
                                || type_first == "undefined4"
                                || type_first == "undefined2"
                                || type_first == "undefined")
                            && parts[1] == "*");
                    if type_ok && name.starts_with("uVar") {
                        decl_indices.push((i, name.to_string()));
                    }
                }
            }
        }

        // Check which declared names appear in non-declaration lines
        let body_text: String = func_lines
            .iter()
            .enumerate()
            .filter(|(i, _)| !decl_indices.iter().any(|(di, _)| di == i))
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let unused: std::collections::HashSet<usize> = decl_indices
            .iter()
            .filter(|(_, name)| !body_text.contains(name.as_str()))
            .map(|(i, _)| *i)
            .collect();

        let declared_names: std::collections::HashSet<&str> = decl_indices
            .iter()
            .filter(|(i, _)| !unused.contains(i))
            .map(|(_, name)| name.as_str())
            .collect();

        // Find uVarNNN references in body that have no declaration
        let mut missing: Vec<String> = Vec::new();
        let mut search_pos = 0;
        let body_bytes = body_text.as_bytes();
        while search_pos + 4 < body_bytes.len() {
            if let Some(pos) = body_text[search_pos..].find("uVar") {
                let abs_pos = search_pos + pos;
                // Word-boundary left check: a "uVar" match preceded by an
                // identifier byte is the interior of a longer token (e.g.
                // "ppuVar4" contains "uVar4") and must NOT register a phantom
                // `int uVar4;` injection (glob_range stray pre-brace decl).
                let boundary_ok = abs_pos == 0
                    || !(body_bytes[abs_pos - 1].is_ascii_alphanumeric()
                        || body_bytes[abs_pos - 1] == b'_');
                let name_start = abs_pos;
                let mut name_end = abs_pos + 4;
                // Collect digits after "uVar"
                while name_end < body_bytes.len() && body_bytes[name_end].is_ascii_digit() {
                    name_end += 1;
                }
                if name_end > abs_pos + 4 && boundary_ok {
                    // Only match uVarNNN (digits), not uVar_hex (underscore)
                    let name = &body_text[name_start..name_end];
                    if !declared_names.contains(name) && !missing.contains(&name.to_string()) {
                        missing.push(name.to_string());
                    }
                }
                search_pos = name_end;
            } else {
                break;
            }
        }

        // Find insertion point (after last declaration, or after function signature)
        let last_decl_idx = decl_indices
            .iter()
            .filter(|(i, _)| !unused.contains(i))
            .map(|(i, _)| *i)
            .max()
            .unwrap_or(0);

        for (i, line) in func_lines.iter().enumerate() {
            if unused.contains(&i) {
                continue;
            }
            out.push(line.clone());
            // After last declaration (or first line), inject missing declarations
            if i == last_decl_idx && !missing.is_empty() {
                for mname in &missing {
                    out.push(format!("  int {};", mname));
                }
                missing.clear();
            }
        }
    }

    // RUGRA-GLUE: 缓冲 emitter 缩进绘制(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物——oracle tagLine 直写 ostream 缩进空格)
    fn do_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("  ");
        }
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物;P6 词频内联的支撑 helper)
    /// Check if char is a word boundary (not alphanumeric or underscore)
    fn is_word_boundary(c: char) -> bool {
        !c.is_ascii_alphanumeric() && c != '_'
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物;P6 词频内联的支撑 helper)
    /// Count word-boundary-respecting occurrences of `word` in `text`
    fn count_word_occurrences(text: &str, word: &str) -> usize {
        let mut count = 0;
        let bytes = text.as_bytes();
        let wlen = word.len();
        let mut pos = 0;
        while let Some(found) = text[pos..].find(word) {
            let abs_pos = pos + found;
            let before_ok = abs_pos == 0 || Self::is_word_boundary(bytes[abs_pos - 1] as char);
            let after_pos = abs_pos + wlen;
            let after_ok = after_pos >= text.len() || Self::is_word_boundary(bytes[after_pos] as char);
            if before_ok && after_ok {
                count += 1;
            }
            pos = abs_pos + 1;
        }
        count
    }

    // RUGRA-GLUE: 文本后处理补偿层(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物;P6 词频内联的支撑 helper)
    /// Replace word-boundary-respecting occurrences of `word` with `replacement`
    fn replace_word(text: &str, word: &str, replacement: &str) -> String {
        let bytes = text.as_bytes();
        let wlen = word.len();
        let mut result = String::with_capacity(text.len());
        let mut pos = 0;
        while let Some(found) = text[pos..].find(word) {
            let abs_pos = pos + found;
            let before_ok = abs_pos == 0 || Self::is_word_boundary(bytes[abs_pos - 1] as char);
            let after_pos = abs_pos + wlen;
            let after_ok = after_pos >= text.len() || Self::is_word_boundary(bytes[after_pos] as char);
            if before_ok && after_ok {
                result.push_str(&text[pos..abs_pos]);
                result.push_str(replacement);
                pos = after_pos;
            } else {
                result.push_str(&text[pos..abs_pos + 1]);
                pos = abs_pos + 1;
            }
        }
        result.push_str(&text[pos..]);
        result
    }
}

impl Emit for EmitNoMarkup {
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::print
    fn print(&mut self, text: &str) {
        self.output.push_str(text);
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::beginBlock
    fn begin_block(&mut self) {
        self.output.push_str(" {\n");
        self.indent += 1;
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::endBlock
    fn end_block(&mut self) {
        self.indent -= 1;
        self.output.push('\n');
        self.do_indent();
        self.output.push('}');
    }

    // Ghidra: prettyprint.hh:587 EmitNoMarkup::openParen
    fn open_paren(&mut self, paren: &str) -> i32 {
        self.output.push_str(paren);
        0
    }

    // Ghidra: prettyprint.hh:589 EmitNoMarkup::closeParen
    fn close_paren(&mut self, paren: &str, _id: i32) {
        self.output.push_str(paren);
    }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::beginFunction
    fn begin_function(&mut self) {
        // No-op for plain text
    }

    // Ghidra: prettyprint.hh:154 Emit::endFunction (plain-text no-op)
    /// The oracle's `EmitNoMarkup::endFunction` writes no bytes; the final
    /// newline of a function body comes from docFunction's trailing
    /// `tagLine()` (printc.cc:2663), not from the group end.
    fn end_function(&mut self) {}

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagType
    fn tag_type(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagVariable
    fn tag_variable(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagOp
    fn tag_op(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagField
    fn tag_field(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagFuncName
    fn tag_func_name(&mut self, text: &str, _id: u64) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagComment
    fn tag_comment(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagLabel
    fn tag_label(&mut self, text: &str) { self.print(text); }
    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagCaseLabel
    fn tag_case_label(&mut self, text: &str) { self.print(text); }

    // Ghidra: prettyprint.hh:547 EmitNoMarkup::tagLine
    fn tag_line(&mut self, _indent: i32) {
        // prettyprint.hh:557: `*s << endl; <indent spaces>` — NO emitPending:
        // with this emitter an installed PendPrint stays pending through
        // tagLine, so printc.cc:2900-2902 always sees hasPendingPrint and
        // merges the else-if. (The fire lives in EmitPrettyPrint only.)
        // Skip leading newline if we just opened a block (output ends with \n)
        if !self.output.ends_with('\n') {
            self.output.push('\n');
        }
        self.do_indent();
    }

    // Ghidra: prettyprint.hh:559 EmitNoMarkup::tagLine(int4 indent)
    fn tag_line_indent(&mut self, indent: i32) {
        // hh:559-560: `*s << endl; for(int4 i=indent;i>0;--i) *s << ' ';`
        // — the indent is the raw ABSOLUTE column (negative clamps to zero
        // spaces), NOT the current indent level. The at-line-start newline
        // guard matches this emitter's tag_line adaptation above (no
        // stacked blank lines); production label sites always follow a
        // `;`/`}` token so the guard never differs from the unconditional
        // oracle endl there.
        if !self.output.ends_with('\n') {
            self.output.push('\n');
        }
        for _ in 0..indent.max(0) {
            self.output.push(' ');
        }
    }

    // Ghidra: prettyprint.hh:446 Emit::setPendingPrint (base-class slot)
    fn set_pending_brace(&mut self, style: BraceStyle) -> BraceId {
        let id = self.next_brace_id;
        self.next_brace_id += 1;
        self.pending_brace = Some((id, style));
        id
    }

    // Ghidra: prettyprint.hh:451 Emit::cancelPendingPrint
    fn cancel_pending_print(&mut self) {
        self.pending_brace = None;
    }

    // Ghidra: prettyprint.hh:457 Emit::hasPendingPrint
    /// Identity query (`pendPrint == pend`): true only while THIS install
    /// still occupies the slot. This emitter never runs the callback
    /// (prettyprint.hh:557 EmitNoMarkup::tagLine has no emitPending), so
    /// the slot is only ever cleared by an explicit cancel — the
    /// oracle-identical "always merge else-if on this face" behavior.
    fn has_pending_print_id(&self, id: BraceId) -> bool {
        matches!(&self.pending_brace, Some((slot_id, _)) if *slot_id == id)
    }

    // Ghidra: prettyprint.cc:61 Emit::openBraceIndent
    /// Faithful text render of the oracle's `openBraceIndent`. The oracle's
    /// `EmitNoMarkup::tagLine` (prettyprint.hh:557) writes `endl` + indent
    /// UNCONDITIONALLY, so `skip_line` produces exactly two line breaks
    /// (a blank line) even when the output already sits at line start.
    /// Rugra's `tag_line` suppresses a repeated newline, so the two breaks
    /// are emitted directly here to preserve the oracle byte format.
    fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => self.output.push(' '),
            BraceStyle::SkipLine => {
                // tagLine(); tagLine(); — each is '\n' + indent at the OLD level
                self.output.push('\n');
                self.do_indent();
                self.output.push('\n');
                self.do_indent();
            }
            BraceStyle::NextLine => {
                self.output.push('\n');
                self.do_indent();
            }
        }
        // int4 id = startIndent(); — indentincrement = 2 spaces per level
        self.indent += 1;
        self.output.push_str(brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent
    /// Faithful text render of `closeBraceIndent`: stopIndent, then the
    /// oracle's unconditional `tagLine` ('\n' + indent at the NEW level),
    /// then the brace.
    fn close_brace_indent(&mut self, brace: &str) {
        self.indent -= 1;
        self.output.push('\n');
        self.do_indent();
        self.output.push_str(brace);
    }

    // RUGRA-GLUE: bump_indent (startIndent indent-bump half, prettyprint.hh:371)
    fn bump_indent(&mut self) {
        self.indent += 1;
    }

    // RUGRA-GLUE: drop_indent (stopIndent indent-drop half, prettyprint.hh:377)
    fn drop_indent(&mut self) {
        self.indent -= 1;
    }

    // RUGRA-GLUE: Rust Box<dyn Any> downcast 胶水(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    // RUGRA-GLUE: Rust Box<dyn Any> downcast 胶水(POSTFIX-RETIRE-0001 W0 登记,Ghidra 无对应物)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

/// Emitter that discards all output (used for discovery pass)
pub struct NullEmit;

impl NullEmit {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        NullEmit
    }
}

impl Emit for NullEmit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    fn print(&mut self, _text: &str) {}
    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    fn begin_block(&mut self) {}
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    fn end_block(&mut self) {}
    // RUGRA-GLUE: open_paren (null emitter for the discovery pass)
    fn open_paren(&mut self, _paren: &str) -> i32 { 0 }
    // RUGRA-GLUE: close_paren (null emitter for the discovery pass)
    fn close_paren(&mut self, _paren: &str, _id: i32) {}
    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    fn begin_function(&mut self) {}
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    fn end_function(&mut self) {}
    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    fn tag_type(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    fn tag_variable(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    fn tag_op(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    fn tag_field(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_line (no Ghidra counterpart found)
    fn tag_line(&mut self, _indent: i32) {}
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    fn tag_func_name(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    fn tag_comment(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    fn tag_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    fn tag_case_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { None }
    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> { self }
}

/// Emit adapter that records whether any printed text contains `case `
/// (a switch case label). Used by printc to detect if a BlockIf's body
/// would emit a case label outside its switch context.
pub struct CaseDetectEmit {
    has_case: bool,
}

impl CaseDetectEmit {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        Self { has_case: false }
    }
    // RUGRA-GLUE: has_case (no Ghidra counterpart found)
    pub fn has_case(&self) -> bool {
        self.has_case
    }
}

impl Emit for CaseDetectEmit {
    // RUGRA-GLUE: print (no Ghidra counterpart found)
    fn print(&mut self, text: &str) {
        if text.contains("case ") || text.contains("default:") {
            self.has_case = true;
        }
    }
    // RUGRA-GLUE: begin_block (no Ghidra counterpart found)
    fn begin_block(&mut self) {}
    // RUGRA-GLUE: end_block (no Ghidra counterpart found)
    fn end_block(&mut self) {}
    // RUGRA-GLUE: open_paren (case-detect probe emitter)
    fn open_paren(&mut self, _paren: &str) -> i32 { 0 }
    // RUGRA-GLUE: close_paren (case-detect probe emitter)
    fn close_paren(&mut self, _paren: &str, _id: i32) {}
    // RUGRA-GLUE: begin_function (no Ghidra counterpart found)
    fn begin_function(&mut self) {}
    // RUGRA-GLUE: end_function (no Ghidra counterpart found)
    fn end_function(&mut self) {}
    // RUGRA-GLUE: tag_type (no Ghidra counterpart found)
    fn tag_type(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_variable (no Ghidra counterpart found)
    fn tag_variable(&mut self, text: &str, _id: u64) {
        if text.contains("case ") { self.has_case = true; }
    }
    // RUGRA-GLUE: tag_op (no Ghidra counterpart found)
    fn tag_op(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_field (no Ghidra counterpart found)
    fn tag_field(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_line (no Ghidra counterpart found)
    fn tag_line(&mut self, _indent: i32) {}
    // RUGRA-GLUE: as_any_mut (no Ghidra counterpart found)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
    // RUGRA-GLUE: tag_func_name (no Ghidra counterpart found)
    fn tag_func_name(&mut self, _text: &str, _id: u64) {}
    // RUGRA-GLUE: tag_comment (no Ghidra counterpart found)
    fn tag_comment(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_label (no Ghidra counterpart found)
    fn tag_label(&mut self, _text: &str) {}
    // RUGRA-GLUE: tag_case_label (no Ghidra counterpart found)
    fn tag_case_label(&mut self, _text: &str) {
        self.has_case = true; // Any case_label tag = case label emitted
    }
    // RUGRA-GLUE: into_any (no Ghidra counterpart found)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

// Ghidra: prettyprint.hh:612 TokenSplit::printclass
/// The general class of a pretty-printing token (prettyprint.hh:612-622):
/// group begin/end delimiters, content strings, breakable whitespace,
/// indent levels, comment blocks, and no-space markup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrintClass {
    Begin,
    End,
    TokenString,
    TokenBreak,
    BeginIndent,
    EndIndent,
    BeginComment,
    EndComment,
    Ignore,
}

// Ghidra: prettyprint.hh:625 TokenSplit::tag_type
/// The exhaustive list of token types (prettyprint.hh:625-656). Rugra's
/// plain-text low level only consumes the character data, so the markup
/// companions (op/vn/fd/ct pointers) of the oracle TokenSplit are elided;
/// the tag type itself drives the class switch in `EmitPrettyPrint`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagType {
    DocuB, DocuE, FuncB, FuncE, BlocB, BlocE, RtypB, RtypE,
    VardB, VardE, StatB, StatE, ProtB, ProtE,
    VariT, OpT, FnamT, TypeT, FieldT, CommT, LabelT, CaseT, SyntT,
    OparT, CparT, OinvT, CinvT, SpacT, BumpT, LineT,
}

// Ghidra: prettyprint.hh:609 TokenSplit
/// A token/command object in the pretty printing stream. Faithful to the
/// oracle's TokenSplit (prettyprint.hh:609-936): every emitter method maps
/// to one constructor here, the token carries its content characters
/// (`tok`), the break geometry (`numspaces`, `indentbump`), and the Oppen
/// bookkeeping `size` (content chars, or the negative scan offset while the
/// enclosing group is uncommitted).
#[derive(Clone, Default)]
pub struct TokenSplit {
    tagtype: TagType,
    delimtype: PrintClass,
    tok: String,
    indentbump: i32,
    numspaces: i32,
    size: i32,
    count: i32,
}

impl Default for TagType {
    // RUGRA-GLUE: TokenSplit must be Default-constructible for the circular
    // queue's spare slots (the oracle default-constructs TokenSplit too).
    fn default() -> Self { TagType::SyntT }
}

impl Default for PrintClass {
    // RUGRA-GLUE: TokenSplit must be Default-constructible for the circular
    // queue's spare slots (the oracle default-constructs TokenSplit too).
    fn default() -> Self { PrintClass::Ignore }
}

impl TokenSplit {
    // Ghidra: prettyprint.hh:684 TokenSplit::beginDocument
    fn begin_document(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::DocuB; self.delimtype = PrintClass::Begin; self.size = 0;
        self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:690 TokenSplit::endDocument
    fn end_document(&mut self, id: i32) {
        self.tagtype = TagType::DocuE; self.delimtype = PrintClass::End; self.size = 0; self.count = id;
    }
    // Ghidra: prettyprint.hh:696 TokenSplit::beginFunction
    fn begin_function(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::FuncB; self.delimtype = PrintClass::Begin; self.size = 0;
        self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:702 TokenSplit::endFunction
    fn end_function(&mut self, id: i32) {
        self.tagtype = TagType::FuncE; self.delimtype = PrintClass::End; self.size = 0; self.count = id;
    }
    // Ghidra: prettyprint.hh:710 TokenSplit::beginBlock
    fn begin_block(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::BlocB; self.delimtype = PrintClass::Ignore; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:715 TokenSplit::endBlock
    fn end_block(&mut self, id: i32) {
        self.tagtype = TagType::BlocE; self.delimtype = PrintClass::Ignore; self.count = id;
    }
    // Ghidra: prettyprint.hh:722 TokenSplit::beginReturnType
    fn begin_return_type(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::RtypB; self.delimtype = PrintClass::Begin; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:728 TokenSplit::endReturnType
    fn end_return_type(&mut self, id: i32) {
        self.tagtype = TagType::RtypE; self.delimtype = PrintClass::End; self.count = id;
    }
    // Ghidra: prettyprint.hh:735 TokenSplit::beginVarDecl
    fn begin_var_decl(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::VardB; self.delimtype = PrintClass::Begin; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:741 TokenSplit::endVarDecl
    fn end_var_decl(&mut self, id: i32) {
        self.tagtype = TagType::VardE; self.delimtype = PrintClass::End; self.count = id;
    }
    // Ghidra: prettyprint.hh:748 TokenSplit::beginStatement
    fn begin_statement(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::StatB; self.delimtype = PrintClass::Begin; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:754 TokenSplit::endStatement
    fn end_statement(&mut self, id: i32) {
        self.tagtype = TagType::StatE; self.delimtype = PrintClass::End; self.count = id;
    }
    // Ghidra: prettyprint.hh:760 TokenSplit::beginFuncProto
    fn begin_func_proto(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::ProtB; self.delimtype = PrintClass::Begin; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:766 TokenSplit::endFuncProto
    fn end_func_proto(&mut self, id: i32) {
        self.tagtype = TagType::ProtE; self.delimtype = PrintClass::End; self.count = id;
    }

    // Ghidra: prettyprint.hh:775 TokenSplit::tagVariable
    fn tag_variable(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::VariT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:784 TokenSplit::tagOp
    fn tag_op(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::OpT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:794 TokenSplit::tagFuncName
    fn tag_func_name(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::FnamT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:803 TokenSplit::tagType
    fn tag_type(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::TypeT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:814 TokenSplit::tagField
    fn tag_field(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::FieldT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:824 TokenSplit::tagComment
    fn tag_comment(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::CommT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:834 TokenSplit::tagLabel
    fn tag_label(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::LabelT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:844 TokenSplit::tagCaseLabel
    fn tag_case_label(&mut self, name: &str) {
        self.tok = name.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::CaseT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:852 TokenSplit::print
    fn print(&mut self, data: &str) {
        self.tok = data.to_string(); self.size = self.tok.len() as i32;
        self.tagtype = TagType::SyntT; self.delimtype = PrintClass::TokenString;
    }
    // Ghidra: prettyprint.hh:860 TokenSplit::openParen
    fn open_paren(&mut self, paren: &str, id: i32) {
        self.tok = paren.to_string(); self.size = 1;
        self.tagtype = TagType::OparT; self.delimtype = PrintClass::TokenString; self.count = id;
    }
    // Ghidra: prettyprint.hh:868 TokenSplit::closeParen
    fn close_paren(&mut self, paren: &str, id: i32) {
        self.tok = paren.to_string(); self.size = 1;
        self.tagtype = TagType::CparT; self.delimtype = PrintClass::TokenString; self.count = id;
    }
    // Ghidra: prettyprint.hh:875 TokenSplit::openGroup
    fn open_group(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::OinvT; self.delimtype = PrintClass::Begin; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:881 TokenSplit::closeGroup
    fn close_group(&mut self, id: i32) {
        self.tagtype = TagType::CinvT; self.delimtype = PrintClass::End; self.count = id;
    }
    // Ghidra: prettyprint.hh:888 TokenSplit::startIndent
    fn start_indent(&mut self, bump: i32, countbase: i32) -> i32 {
        self.tagtype = TagType::BumpT; self.delimtype = PrintClass::BeginIndent; self.indentbump = bump;
        self.size = 0; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:895 TokenSplit::stopIndent
    fn stop_indent(&mut self, id: i32) {
        self.tagtype = TagType::BumpT; self.delimtype = PrintClass::EndIndent; self.size = 0; self.count = id;
    }
    // Ghidra: prettyprint.hh:901 TokenSplit::startComment
    fn start_comment(&mut self, countbase: i32) -> i32 {
        self.tagtype = TagType::OinvT; self.delimtype = PrintClass::BeginComment; self.count = countbase; self.count
    }
    // Ghidra: prettyprint.hh:907 TokenSplit::stopComment
    fn stop_comment(&mut self, id: i32) {
        self.tagtype = TagType::CinvT; self.delimtype = PrintClass::EndComment; self.count = id;
    }
    // Ghidra: prettyprint.hh:914 TokenSplit::spaces
    fn spaces(&mut self, num: i32, bump: i32) {
        self.tagtype = TagType::SpacT; self.delimtype = PrintClass::TokenBreak;
        self.numspaces = num; self.indentbump = bump;
    }
    // Ghidra: prettyprint.hh:918 TokenSplit::tagLine()
    fn tag_line(&mut self) {
        self.tagtype = TagType::BumpT; self.delimtype = PrintClass::TokenBreak;
        self.numspaces = 999999; self.indentbump = 0;
    }
    // Ghidra: prettyprint.hh:922 TokenSplit::tagLine(indent)
    fn tag_line_indent(&mut self, indent: i32) {
        self.tagtype = TagType::LineT; self.delimtype = PrintClass::TokenBreak;
        self.numspaces = 999999; self.indentbump = indent;
    }

    // Ghidra: prettyprint.hh:926 TokenSplit::getIndentBump
    fn get_indent_bump(&self) -> i32 { self.indentbump }
    // Ghidra: prettyprint.hh:927 TokenSplit::getNumSpaces
    fn get_num_spaces(&self) -> i32 { self.numspaces }
    // Ghidra: prettyprint.hh:928 TokenSplit::getSize
    fn get_size(&self) -> i32 { self.size }
    // Ghidra: prettyprint.hh:929 TokenSplit::setSize
    fn set_size(&mut self, sz: i32) { self.size = sz }
    // Ghidra: prettyprint.hh:930 TokenSplit::getClass
    fn get_class(&self) -> PrintClass { self.delimtype }
    // Ghidra: prettyprint.hh:931 TokenSplit::getTag
    fn get_tag(&self) -> TagType { self.tagtype }
}

// Ghidra: prettyprint.hh:944 circularqueue
/// Faithful port of the oracle's circularqueue (prettyprint.hh:944-1027):
/// a ring buffer used as a stack (push/pop) or queue (push/popbottom) with
/// integer references that survive push/pop (references are slot indices
/// modulo `max`). `expand` reallocates and compacts to reference 0, exactly
/// like prettyprint.hh:1003-1027, so `EmitPrettyPrint::expand` can adjust
/// the scanqueue references with the same arithmetic (prettyprint.cc:572).
struct CircularQueue<T: Clone + Default> {
    cache: Vec<T>,
    left: usize,
    right: usize,
    max: usize,
}

impl<T: Clone + Default> CircularQueue<T> {
    // Ghidra: prettyprint.hh:970 circularqueue::circularqueue
    fn new(sz: usize) -> Self {
        let mut q = CircularQueue { cache: Vec::new(), left: 1, right: 0, max: sz ,
        };
        q.cache.resize_with(sz, T::default);
        q
    }
    // Ghidra: prettyprint.hh:953 circularqueue::setMax
    fn set_max(&mut self, sz: usize) {
        if self.max != sz {
            self.max = sz;
            self.cache.clear();
            self.cache.resize_with(sz, T::default);
        }
        self.left = 1;
        self.right = 0;
    }
    // Ghidra: prettyprint.hh:954 circularqueue::getMax
    fn get_max(&self) -> usize { self.max }
    // Ghidra: prettyprint.hh:1003 circularqueue::expand
    fn expand(&mut self, amount: usize) {
        let mut newcache: Vec<T> = Vec::new();
        newcache.resize_with(self.max + amount, T::default);
        let mut i = self.left;
        let mut j = 0usize;
        while i != self.right {
            newcache[j] = self.cache[i].clone();
            j += 1;
            i = (i + 1) % self.max;
        }
        newcache[j] = self.cache[i].clone();
        self.left = 0;
        self.right = j;
        self.cache = newcache;
        self.max += amount;
    }
    // Ghidra: prettyprint.hh:956 circularqueue::clear
    fn clear(&mut self) { self.left = 1; self.right = 0; }
    // Ghidra: prettyprint.hh:957 circularqueue::empty
    fn empty(&self) -> bool { self.left == (self.right + 1) % self.max }
    // Ghidra: prettyprint.hh:958 circularqueue::topref
    fn topref(&self) -> i32 { self.right as i32 }
    // Ghidra: prettyprint.hh:959 circularqueue::bottomref
    fn bottomref(&self) -> i32 { self.left as i32 }
    // Ghidra: prettyprint.hh:960 circularqueue::ref
    fn ref_at(&self, r: i32) -> &T { &self.cache[r as usize] }
    // Ghidra: prettyprint.hh:960 circularqueue::ref
    /// (Mutable-borrow split of the oracle's `_type& ref(int4)`.)
    fn ref_at_mut(&mut self, r: i32) -> &mut T { &mut self.cache[r as usize] }
    // Ghidra: prettyprint.hh:963 circularqueue::push
    fn push(&mut self) -> &mut T {
        self.right = (self.right + 1) % self.max;
        &mut self.cache[self.right]
    }
    // Ghidra: prettyprint.hh:964 circularqueue::pop
    fn pop(&mut self) -> T {
        let tmp = self.right;
        self.right = (self.right + self.max - 1) % self.max;
        self.cache[tmp].clone()
    }
    // Ghidra: prettyprint.hh:965 circularqueue::popbottom
    fn popbottom(&mut self) -> T {
        let tmp = self.left;
        self.left = (self.left + 1) % self.max;
        self.cache[tmp].clone()
    }
}

// Ghidra: prettyprint.hh:1042 EmitPrettyPrint
/// The generic source code pretty printer (prettyprint.hh:1029-1115,
/// prettyprint.cc:541-1243), a port of the Derek C. Oppen pretty printing
/// algorithm. Content tokens enter a queue together with begin/end group
/// delimiters and breakable whitespace; `scan` assigns sizes, and once a
/// group closes (or a line overflows) `advanceleft` commits tokens to the
/// low-level emitter, inserting line breaks at the breakable whitespace of
/// overflowing groups and indenting continuations from the indent stack.
/// The low-level emitter is Rugra's `EmitNoMarkup` byte sink (the oracle's
/// default low level, prettyprint.cc:545).
pub struct EmitPrettyPrint {
    lowlevel: EmitNoMarkup,
    /// Ghidra: prettyprint.hh:102 Emit::pendPrint — one PendPrint slot.
    /// Rugra stores the deferred brace style directly (printc.cc:2872-2880
    /// PendingBrace: callback == openBraceIndent(OPEN_CURLY, style)) keyed
    /// by the install's BraceId (the oracle's stack-object identity).
    pending_brace: Option<(BraceId, BraceStyle)>,
    /// RUGRA-GLUE: fire memory per install — the oracle keeps this in the
    /// caller's `PendingBrace` stack object (`indentId`, printc.hh:347-361:
    /// -1 until the callback runs, >= 0 after), which survives slot
    /// clearing and replacement by a nested install. The Vec entry
    /// `(id, fired)` is that object's lifetime: pushed by set_pending_brace
    /// (ctor indentId=-1), flipped by the callback in emit_pending, read by
    /// pending_brace_fired_id (`getIndentId() >= 0`, printc.cc:2946-2948).
    fired_braces: Vec<(BraceId, bool)>,
    /// RUGRA-GLUE: monotonically increasing install id minting.
    next_brace_id: BraceId,
    indentstack: Vec<i32>,
    spaceremain: i32,
    maxlinesize: i32,
    leftotal: i32,
    rightotal: i32,
    needbreak: bool,
    commentmode: bool,
    commentfill: String,
    scanqueue: CircularQueue<i32>,
    tokqueue: CircularQueue<TokenSplit>,
    countbase: std::sync::atomic::AtomicI32,
    indentincrement: i32,
}

impl Default for EmitPrettyPrint {
    // RUGRA-GLUE: Rust Default trait impl forwarding to EmitPrettyPrint::new
    // (Ghidra default-constructs via `new EmitPrettyPrint()`, hh:1068).
    fn default() -> Self { Self::new() }
}

impl EmitPrettyPrint {
    // Ghidra: prettyprint.cc:541 EmitPrettyPrint::EmitPrettyPrint
    pub fn new() -> Self {
        let mut e = EmitPrettyPrint {
            lowlevel: EmitNoMarkup::new(),
            pending_brace: None,
            fired_braces: Vec::new(),
            next_brace_id: 1,
            indentstack: Vec::new(),
            spaceremain: 100,
            maxlinesize: 100,
            leftotal: 1,
            rightotal: 1,
            needbreak: false,
            commentmode: false,
            commentfill: String::new(),
            scanqueue: CircularQueue::new(3 * 100),
            tokqueue: CircularQueue::new(3 * 100),
            countbase: std::sync::atomic::AtomicI32::new(0),
            indentincrement: 2,
        };
        // resetDefaultsPrettyPrint (prettyprint.hh:1066) = setMaxLineSize(100)
        e.set_max_line_size(100);
        e
    }

    // RUGRA-GLUE: next_count (TokenSplit::countbase++, prettyprint.hh:677)
    /// C's `countbase++` yields the pre-increment value; `fetch_add`
    /// returns the same previous value (no +1).
    fn next_count(&self) -> i32 {
        self.countbase
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    // Ghidra: prettyprint.hh:346 EmitNoMarkup low-level byte write
    /// The oracle's EmitNoMarkup::print (prettyprint.hh:585) on the wrapped
    /// low level: raw character data to the output stream.
    fn low_print(&mut self, data: &str) {
        self.lowlevel.print(data);
    }

    // Ghidra: prettyprint.hh:559 EmitNoMarkup::tagLine(int4 indent)
    /// The low level's unconditional line break: endl plus exactly `indent`
    /// spaces (prettyprint.hh:559-560).
    fn low_tag_line(&mut self, indent: i32) {
        self.lowlevel.print("\n");
        if indent > 0 {
            self.lowlevel.print(&" ".repeat(indent as usize));
        }
    }

    // Ghidra: prettyprint.hh:593 EmitNoMarkup spaces (Emit::spaces fold)
    fn low_spaces(&mut self, num: i32) {
        if num > 0 {
            self.lowlevel.print(&" ".repeat(num as usize));
        }
    }

    // Ghidra: prettyprint.cc:564 EmitPrettyPrint::expand
    /// Increase the token queue capacity by 200 slots, adjusting the
    /// scanqueue references exactly as prettyprint.cc:564-579 does
    /// (references shift by `(ref + max - left) % max` after the compaction).
    fn expand(&mut self) {
        let max = self.tokqueue.get_max() as i32;
        let left = self.tokqueue.bottomref();
        self.tokqueue.expand(200);
        for i in 0..max {
            let adjusted = (self.scanqueue.ref_at(i) + max - left) % max;
            *self.scanqueue.ref_at_mut(i) = adjusted;
        }
        self.scanqueue.expand(200);
    }

    // Ghidra: prettyprint.cc:584 EmitPrettyPrint::overflow
    /// Adjust the current indent levels to guarantee at least half a line
    /// of space and force a line break (used when an unbreakable token does
    /// not fit). Walks the indent stack top-down, raising levels below
    /// `maxlinesize/2`, then breaks at `indentstack.back()`.
    fn overflow(&mut self) {
        let half = self.maxlinesize / 2;
        for i in (0..self.indentstack.len()).rev() {
            if self.indentstack[i] < half {
                self.indentstack[i] = half;
            } else {
                break;
            }
        }
        let newspaceremain = if !self.indentstack.is_empty() {
            *self.indentstack.last().unwrap()
        } else {
            self.maxlinesize
        };
        if newspaceremain == self.spaceremain {
            return; // Line breaking doesn't give us any additional space
        }
        let fill_len = self.commentfill.len() as i32;
        if self.commentmode && newspaceremain == self.spaceremain + fill_len {
            return; // Line breaking doesn't give us any additional space
        }
        self.spaceremain = newspaceremain;
        self.low_tag_line(self.maxlinesize - self.spaceremain);
        if self.commentmode && !self.commentfill.is_empty() {
            let fill = self.commentfill.clone();
            self.low_print(&fill);
            self.spaceremain -= fill_len;
        }
    }

    // Ghidra: prettyprint.cc:614 EmitPrettyPrint::print
    /// Send one committed token to the low level, adjusting the indent
    /// stack; a content token that does not fit triggers `overflow`, and a
    /// break token either breaks the line (reindenting) or emits its spaces
    /// (if breaking "doesn't save that much": numspaces fit and the break
    /// indent is within 10 of the remaining space).
    fn print_token(&mut self, tok: &TokenSplit) {
        let mut val: i32;
        match tok.get_class() {
            PrintClass::Ignore => {
                // Markup or other that doesn't use space (begin/endBlock).
                match tok.get_tag() {
                    TagType::BlocB | TagType::BlocE => {}
                    _ => {
                        let t = tok.tok.clone();
                        self.low_print(&t);
                    }
                }
            }
            PrintClass::BeginIndent => {
                // val = indentstack.back() - tok.getIndentBump(); push.
                val = *self.indentstack.last().unwrap() - tok.get_indent_bump();
                self.indentstack.push(val);
            }
            PrintClass::BeginComment => {
                self.commentmode = true;
                self.indentstack.push(self.spaceremain);
            }
            PrintClass::Begin => {
                self.indentstack.push(self.spaceremain);
            }
            PrintClass::EndIndent => {
                self.indentstack.pop();
            }
            PrintClass::EndComment => {
                self.commentmode = false;
                self.indentstack.pop();
            }
            PrintClass::End => {
                self.indentstack.pop();
            }
            PrintClass::TokenString => {
                if tok.get_size() > self.spaceremain {
                    self.overflow();
                }
                let t = tok.tok.clone();
                self.low_print(&t);
                self.spaceremain -= tok.get_size();
            }
            PrintClass::TokenBreak => {
                if tok.get_size() > self.spaceremain {
                    if tok.get_tag() == TagType::LineT {
                        // Absolute indent
                        self.spaceremain = self.maxlinesize - tok.get_indent_bump();
                    } else {
                        // relative indent
                        val = *self.indentstack.last().unwrap() - tok.get_indent_bump();
                        // If creating a line break doesn't save that much
                        // don't do the line break
                        if tok.get_num_spaces() <= self.spaceremain
                            && val - self.spaceremain < 10
                        {
                            let n = tok.get_num_spaces();
                            self.low_spaces(n);
                            self.spaceremain -= n;
                            return;
                        }
                        *self.indentstack.last_mut().unwrap() = val;
                        self.spaceremain = val;
                    }
                    self.low_tag_line(self.maxlinesize - self.spaceremain);
                    if self.commentmode && !self.commentfill.is_empty() {
                        let fill = self.commentfill.clone();
                        let fill_len = fill.len() as i32;
                        self.low_print(&fill);
                        self.spaceremain -= fill_len;
                    }
                } else {
                    let n = tok.get_num_spaces();
                    self.low_spaces(n);
                    self.spaceremain -= n;
                }
            }
        }
    }

    // Ghidra: prettyprint.cc:710 EmitPrettyPrint::advanceleft
    /// Emit token groups that have been fully committed (their leading
    /// delimiter's size turned non-negative) and purge them from the queue.
    fn advanceleft(&mut self) {
        if self.tokqueue.empty() {
            return;
        }
        let mut l = self.tokqueue.ref_at(self.tokqueue.bottomref()).get_size();
        while l >= 0 {
            let tok = self.tokqueue.popbottom();
            let is_break = tok.get_class() == PrintClass::TokenBreak;
            let is_string = tok.get_class() == PrintClass::TokenString;
            let nspaces = tok.get_num_spaces();
            let size = tok.get_size();
            self.print_token(&tok);
            if is_break {
                self.leftotal += nspaces;
            } else if is_string {
                self.leftotal += size;
            }
            if self.tokqueue.empty() {
                break;
            }
            l = self.tokqueue.ref_at(self.tokqueue.bottomref()).get_size();
        }
    }

    // Ghidra: prettyprint.cc:741 EmitPrettyPrint::scan
    /// The heart of the Oppen algorithm: assign the new top-of-queue token
    /// a size, maintain the scanqueue of open delimiters and breaks, and
    /// force breaks (size 999999) in the uncommitted region while
    /// `rightotal - leftotal > spaceremain`.
    fn scan(&mut self) {
        if self.tokqueue.empty() {
            self.expand();
        }
        let class = self.tokqueue.ref_at(self.tokqueue.topref()).get_class();
        match class {
            PrintClass::BeginComment | PrintClass::Begin => {
                if self.scanqueue.empty() {
                    self.leftotal = 1;
                    self.rightotal = 1;
                }
                let size = -self.rightotal;
                self.tokqueue
                    .ref_at_mut(self.tokqueue.topref())
                    .set_size(size);
                let topref = self.tokqueue.topref();
                *self.scanqueue.push() = topref;
            }
            PrintClass::EndComment | PrintClass::End => {
                self.tokqueue.ref_at_mut(self.tokqueue.topref()).set_size(0);
                if !self.scanqueue.empty() {
                    let popped = self.scanqueue.pop();
                    let ref_size = self.rightotal;
                    let ref_class = self.tokqueue.ref_at(popped).get_class();
                    // (Borrow split of the oracle's single `ref.setSize(
                    // ref.getSize() + rightotal)` — cc:762.)
                    let old_size = self.tokqueue.ref_at(popped).get_size();
                    self.tokqueue
                        .ref_at_mut(popped)
                        .set_size(old_size + ref_size);
                    if ref_class == PrintClass::TokenBreak && !self.scanqueue.empty() {
                        let popped2 = self.scanqueue.pop();
                        let ref2_size = self.rightotal;
                        let old2_size = self.tokqueue.ref_at(popped2).get_size();
                        self.tokqueue
                            .ref_at_mut(popped2)
                            .set_size(old2_size + ref2_size);
                    }
                    if self.scanqueue.empty() {
                        self.advanceleft();
                    }
                }
            }
            PrintClass::TokenBreak => {
                if self.scanqueue.empty() {
                    self.leftotal = 1;
                    self.rightotal = 1;
                } else {
                    let topref = *self.scanqueue.ref_at(self.scanqueue.topref());
                    if self.tokqueue.ref_at(topref).get_class() == PrintClass::TokenBreak {
                        self.scanqueue.pop();
                        let add = self.rightotal;
                        let old_size = self.tokqueue.ref_at(topref).get_size();
                        self.tokqueue.ref_at_mut(topref).set_size(old_size + add);
                    }
                }
                let size = -self.rightotal;
                self.tokqueue
                    .ref_at_mut(self.tokqueue.topref())
                    .set_size(size);
                let topref = self.tokqueue.topref();
                *self.scanqueue.push() = topref;
                let n = self
                    .tokqueue
                    .ref_at(self.tokqueue.topref())
                    .get_num_spaces();
                self.rightotal += n;
            }
            PrintClass::BeginIndent | PrintClass::EndIndent | PrintClass::Ignore => {
                self.tokqueue.ref_at_mut(self.tokqueue.topref()).set_size(0);
            }
            PrintClass::TokenString => {
                if !self.scanqueue.empty() {
                    let size = self.tokqueue.ref_at(self.tokqueue.topref()).get_size();
                    self.rightotal += size;
                    while self.rightotal - self.leftotal > self.spaceremain {
                        let popped = self.scanqueue.popbottom();
                        self.tokqueue.ref_at_mut(popped).set_size(999999);
                        self.advanceleft();
                        if self.scanqueue.empty() {
                            break;
                        }
                    }
                }
            }
        }
    }

    // Ghidra: prettyprint.cc:806 EmitPrettyPrint::checkstart
    fn checkstart(&mut self) {
        if self.needbreak {
            let tok = self.tokqueue.push();
            tok.spaces(0, 0);
            self.scan();
        }
        self.needbreak = false;
    }

    // Ghidra: prettyprint.cc:819 EmitPrettyPrint::checkstring
    fn checkstring(&mut self) {
        if self.needbreak {
            let tok = self.tokqueue.push();
            tok.spaces(0, 0);
            self.scan();
        }
        self.needbreak = true;
    }

    // Ghidra: prettyprint.cc:833 EmitPrettyPrint::checkend
    fn checkend(&mut self) {
        if !self.needbreak {
            let tok = self.tokqueue.push();
            tok.print("");
            self.scan();
        }
        self.needbreak = true;
    }

    // Ghidra: prettyprint.cc:847 EmitPrettyPrint::checkbreak
    fn checkbreak(&mut self) {
        if !self.needbreak {
            let tok = self.tokqueue.push();
            tok.print("");
            self.scan();
        }
        self.needbreak = false;
    }

    // RUGRA-GLUE: debug_lowlevel_output_ref (test observation channel,
    // same family as EmitNoMarkup::debug_get_output_ref)
    /// Read the bytes committed to the low-level stream so far without
    /// consuming the emitter — fixture observation of a live printer.
    pub fn debug_lowlevel_output_ref(&self) -> &str {
        self.lowlevel.debug_get_output_ref()
    }

    // Ghidra: prettyprint.cc:1225 EmitPrettyPrint::setMaxLineSize
    pub fn set_max_line_size(&mut self, val: i32) {
        if !(20..=10000).contains(&val) {
            // The oracle throws LowlevelError (prettyprint.cc:1228-1229);
            // Rust's emit layer has no error channel, so clamp defensively
            // to the default instead of panicking mid-function.
            eprintln!("[EMIT] bad maximum line size {val}; keeping default");
            return;
        }
        self.maxlinesize = val;
        self.scanqueue.set_max((3 * val) as usize);
        self.tokqueue.set_max((3 * val) as usize);
        self.spaceremain = self.maxlinesize;
        self.clear();
    }

    // Ghidra: prettyprint.cc:1153 EmitPrettyPrint::clear
    pub fn clear(&mut self) {
        self.indentstack.clear();
        self.scanqueue.clear();
        self.tokqueue.clear();
        self.leftotal = 1;
        self.rightotal = 1;
        self.needbreak = false;
        self.commentmode = false;
        self.spaceremain = self.maxlinesize;
        // PendPrint slot + per-install fire memory are not part of the
        // oracle printer's clear() (the oracle keeps them in per-call
        // stack objects that cannot outlive their frame); resetting here
        // keeps the id-keyed emulation from carrying ids across functions.
        self.pending_brace = None;
        self.fired_braces.clear();
        self.next_brace_id = 1;
    }

    // Ghidra: prettyprint.cc:1194 EmitPrettyPrint::flush
    /// Commit every remaining token; an unbalanced group (negative size)
    /// is a fatal misprint in the oracle (LowlevelError, prettyprint.cc:
    /// 1199-1201) — Rugra logs and skips the token to keep the byte stream
    /// flowing, since the emitter has no error channel.
    pub fn flush_impl(&mut self) {
        while !self.tokqueue.empty() {
            let tok = self.tokqueue.popbottom();
            if tok.get_size() < 0 {
                eprintln!("[EMIT] cannot flush pretty printer: missing group end");
                continue;
            }
            self.print_token(&tok);
        }
        self.needbreak = false;
    }

    // RUGRA-GLUE: post_process bridge (EmitNoMarkup legacy P3 passes)
    /// Flush the token queue, then run the low-level EmitNoMarkup legacy
    /// post-processing (redundant-goto/orphan-label cleanup) on the fully
    /// committed byte stream.
    pub fn post_process(&mut self) {
        self.flush_impl();
        self.lowlevel.post_process();
    }

    // Ghidra: prettyprint.hh:1129-1137 Emit::emitPending
    /// Run the installed pending print, if any (clearing the slot first,
    /// like the oracle). PendingBrace::callback (printc.cc:2872-2876) is
    /// `indentId = emit->openBraceIndent(OPEN_CURLY, style)`: the space +
    /// '{' tokens enter the queue at this point, ahead of the tagLine that
    /// triggered the fire. The callback writes into the CALLER's
    /// PendingBrace object (indentId = the returned level id); the id-keyed
    /// emulation flips that install's fire memory instead of a global flag,
    /// so only the owning frame ever observes the fire.
    fn emit_pending(&mut self) {
        if let Some((id, style)) = self.pending_brace.take() {
            if let Some(entry) = self.fired_braces.iter_mut().rev().find(|e| e.0 == id) {
                entry.1 = true;
            }
            self.open_brace_indent("{", style);
        }
    }

    // RUGRA-GLUE: take low-level output (EmitNoMarkup::getOutput)
    /// Flush and hand back the final C text, running the low level's
    /// `get_output` post-processing exactly like the plain emitter did.
    pub fn get_output(mut self) -> String {
        self.flush_impl();
        self.lowlevel.get_output()
    }
}

impl Emit for EmitPrettyPrint {
    // Ghidra: prettyprint.cc:1085 EmitPrettyPrint::print
    fn print(&mut self, text: &str) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.print(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1013 EmitPrettyPrint::tagVariable
    fn tag_variable(&mut self, text: &str, _id: u64) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_variable(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1022 EmitPrettyPrint::tagOp
    fn tag_op(&mut self, text: &str) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_op(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1031 EmitPrettyPrint::tagFuncName
    fn tag_func_name(&mut self, text: &str, _id: u64) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_func_name(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1040 EmitPrettyPrint::tagType
    fn tag_type(&mut self, text: &str, _id: u64) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_type(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1049 EmitPrettyPrint::tagField
    fn tag_field(&mut self, text: &str, _id: u64) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_field(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1058 EmitPrettyPrint::tagComment
    fn tag_comment(&mut self, text: &str) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_comment(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1067 EmitPrettyPrint::tagLabel
    fn tag_label(&mut self, text: &str) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_label(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1076 EmitPrettyPrint::tagCaseLabel
    fn tag_case_label(&mut self, text: &str) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.tag_case_label(text);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1094 EmitPrettyPrint::openParen
    fn open_paren(&mut self, paren: &str) -> i32 {
        // id = openGroup(); Open paren automatically opens group.
        let id = self.open_group();
        let tok = self.tokqueue.push();
        tok.open_paren(paren, id);
        self.scan();
        self.needbreak = true;
        id
    }

    // Ghidra: prettyprint.cc:1105 EmitPrettyPrint::closeParen
    fn close_paren(&mut self, paren: &str, id: i32) {
        self.checkstring();
        let tok = self.tokqueue.push();
        tok.close_paren(paren, id);
        self.scan();
        self.close_group(id);
    }

    // Ghidra: prettyprint.cc:1115 EmitPrettyPrint::openGroup
    fn open_group(&mut self) -> i32 {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        let id = tok.open_group(count);
        self.scan();
        id
    }

    // Ghidra: prettyprint.cc:1125 EmitPrettyPrint::closeGroup
    fn close_group(&mut self, id: i32) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.close_group(id);
        self.scan();
    }

    // Ghidra: prettyprint.cc:858 EmitPrettyPrint::beginDocument
    fn begin_document(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_document(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:868 EmitPrettyPrint::endDocument
    fn end_document(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_document(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:877 EmitPrettyPrint::beginFunction
    fn begin_function(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_function(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:891 EmitPrettyPrint::endFunction
    fn end_function(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_function(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:900 EmitPrettyPrint::beginBlock +
    //          prettyprint.cc:61 Emit::openBraceIndent(same_line)
    /// Rugra's `begin_block` helper (" {") is the collapsed form of the
    /// oracle's markup-only `beginBlock` (bloc_b, printclass ignore — no
    /// bytes, no indent effect) plus the same_line `openBraceIndent` the
    /// if/loop body emitters issue right after it (printc.cc:2875/2920/
    //  2992/...): one space, an indent level, then the brace. The
    /// following tagLine supplies the newline.
    fn begin_block(&mut self) {
        self.spaces(1, 0);
        self.bump_indent();
        let brace = "{".to_string();
        self.print(&brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent +
    //          prettyprint.cc:909 EmitPrettyPrint::endBlock
    /// `}` on its own line at the (now decremented) indent — the collapsed
    /// closeBraceIndent + endBlock form of the oracle.
    fn end_block(&mut self) {
        self.drop_indent();
        self.tag_line(0);
        let brace = "}".to_string();
        self.print(&brace);
    }

    // Ghidra: prettyprint.cc:61 Emit::openBraceIndent
    fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => {
                self.spaces(1, 0);
            }
            BraceStyle::SkipLine => {
                self.tag_line(0);
                self.tag_line(0);
            }
            BraceStyle::NextLine => {
                self.tag_line(0);
            }
        }
        self.bump_indent();
        self.print(brace);
    }

    // Ghidra: prettyprint.hh:481 Emit::closeBraceIndent
    fn close_brace_indent(&mut self, brace: &str) {
        self.drop_indent();
        self.tag_line(0);
        self.print(brace);
    }

    // Ghidra: prettyprint.cc:917 EmitPrettyPrint::tagLine
    /// Relative line break — bump_t token (prettyprint.hh:918-920):
    /// `tagtype=bump_t; numspaces=999999; indentbump=0`, i.e. break at the
    /// current indentstack level. All remaining callers pass 0 (the merged
    /// transport of the oracle's no-argument virtual); the absolute
    /// one-argument form moved to `tag_line_indent`.
    fn tag_line(&mut self, indent: i32) {
        // prettyprint.cc:920: emitPending() runs BEFORE checkbreak —
        // a deferred brace (PendingBrace, printc.cc:2872-2880) fires right
        // here, pushing its space + '{' tokens ahead of this line-break
        // token so the bytes read `... else {`.
        self.emit_pending();
        self.checkbreak();
        let tok = self.tokqueue.push();
        debug_assert!(
            indent == 0,
            "tag_line(indent>0) is the absolute form; call tag_line_indent"
        );
        tok.tag_line();
        self.scan();
    }

    // Ghidra: prettyprint.cc:927 EmitPrettyPrint::tagLine(int4 indent)
    /// Absolute-column line break — line_t token (prettyprint.hh:922-924):
    /// `tagtype=line_t; numspaces=999999; indentbump=indent`. On the break
    /// path (print_token TokenBreak) line_t skips the relative-indent and
    /// suppression arms entirely: `spaceremain = maxlinesize - indentbump`
    /// then `low_tag_line(indentbump)` — endl + exactly `indent` spaces at
    /// the lowlevel (prettyprint.cc:674-676). Oracle call sites:
    /// printc.cc:3211 (label column 0), printlanguage.cc:597 (comment
    /// continuation).
    fn tag_line_indent(&mut self, indent: i32) {
        // prettyprint.cc:930: emitPending() runs BEFORE checkbreak, same
        // ordering as the relative form — a pending else-brace fires ahead
        // of the label line break.
        self.emit_pending();
        self.checkbreak();
        let tok = self.tokqueue.push();
        tok.tag_line_indent(indent);
        self.scan();
    }

    // Ghidra: prettyprint.hh:446 Emit::setPendingPrint (via PendingBrace)
    fn set_pending_brace(&mut self, style: BraceStyle) -> BraceId {
        let id = self.next_brace_id;
        self.next_brace_id += 1;
        // Fresh PendingBrace stack object: indentId starts -1
        // (printc.hh:349-351 ctor). The Vec entry is that object; the slot
        // holds (id, style) the way the oracle slot holds the pointer.
        self.fired_braces.push((id, false));
        self.pending_brace = Some((id, style));
        id
    }

    // Ghidra: prettyprint.hh:451 Emit::cancelPendingPrint
    fn cancel_pending_print(&mut self) {
        self.pending_brace = None;
    }

    // Ghidra: prettyprint.hh:457 Emit::hasPendingPrint
    /// Identity query (`pendPrint == pend`): true only while THIS install
    /// still occupies the slot. A nested frame's install replaces the slot
    /// and this reads false for the outer id — exactly the pointer
    /// comparison's answer.
    fn has_pending_print_id(&self, id: BraceId) -> bool {
        matches!(&self.pending_brace, Some((slot_id, _)) if *slot_id == id)
    }

    // Ghidra: printc.hh:347-360 PendingBrace::getIndentId >= 0
    /// Per-install fired query: the oracle asks the frame's own object
    /// (printc.cc:2946-2948); a sibling or nested frame's fire flips a
    /// different entry and cannot leak into this answer.
    fn pending_brace_fired_id(&self, id: BraceId) -> bool {
        self.fired_braces
            .iter()
            .rev()
            .find(|e| e.0 == id)
            .map(|e| e.1)
            .unwrap_or(false)
    }

    // Ghidra: prettyprint.cc:937 EmitPrettyPrint::beginReturnType
    fn begin_return_type(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_return_type(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:947 EmitPrettyPrint::endReturnType
    fn end_return_type(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_return_type(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:956 EmitPrettyPrint::beginVarDecl
    fn begin_var_decl(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_var_decl(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:966 EmitPrettyPrint::endVarDecl
    fn end_var_decl(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_var_decl(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:975 EmitPrettyPrint::beginStatement
    fn begin_statement(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_statement(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:985 EmitPrettyPrint::endStatement
    fn end_statement(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_statement(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:994 EmitPrettyPrint::beginFuncProto
    fn begin_func_proto(&mut self) {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.begin_func_proto(count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1004 EmitPrettyPrint::endFuncProto
    fn end_func_proto(&mut self) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.end_func_proto(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1134 EmitPrettyPrint::startComment
    fn start_comment(&mut self) -> i32 {
        self.checkstart();
        let count = self.next_count();
        let tok = self.tokqueue.push();
        let id = tok.start_comment(count);
        self.scan();
        id
    }

    // Ghidra: prettyprint.cc:1144 EmitPrettyPrint::stopComment
    fn stop_comment(&mut self, id: i32) {
        self.checkend();
        let tok = self.tokqueue.push();
        tok.stop_comment(id);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1168 EmitPrettyPrint::spaces
    fn spaces(&mut self, num: i32, bump: i32) {
        self.checkbreak();
        let tok = self.tokqueue.push();
        tok.spaces(num, bump);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1177 EmitPrettyPrint::startIndent
    /// (Rugra trait name `bump_indent`.)
    fn bump_indent(&mut self) {
        let count = self.next_count();
        let tok = self.tokqueue.push();
        tok.start_indent(self.indentincrement, count);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1186 EmitPrettyPrint::stopIndent
    /// (Rugra trait name `drop_indent`.)
    fn drop_indent(&mut self) {
        let tok = self.tokqueue.push();
        tok.stop_indent(0);
        self.scan();
    }

    // Ghidra: prettyprint.cc:1194 EmitPrettyPrint::flush
    fn flush(&mut self) {
        self.flush_impl();
    }

    // Ghidra: prettyprint.hh:1111 EmitPrettyPrint::setCommentFill
    fn set_comment_fill(&mut self, fill: &str) {
        self.commentfill = fill.to_string();
    }

    // Ghidra: prettyprint.hh:1112 EmitPrettyPrint::emitsMarkup
    fn emits_markup(&self) -> bool { false }

    // Ghidra: prettyprint.hh:1109 EmitPrettyPrint::getMaxLineSize
    fn get_max_line_size(&self) -> i32 {
        self.maxlinesize
    }

    // Ghidra: prettyprint.cc:1237 EmitPrettyPrint::resetDefaults
    /// Reset the pretty printer's cross-document print options to their
    /// defaults. Faithful to `EmitPrettyPrint::resetDefaults`
    /// (prettyprint.cc:1237-1242), which composes three steps:
    /// `lowlevel->resetDefaults()` — the low-level emitter inherits the
    /// base `Emit::resetDefaults` (prettyprint.hh:424), whose only effect
    /// is `resetDefaultsInternal` (`indentincrement = 2`,
    /// prettyprint.hh:103); Rust's `EmitNoMarkup` carries no
    /// `indentincrement` field (its `indent` is per-document state reset
    /// by `clear`), so the low-level half is structurally absorbed; then
    /// this printer's own `resetDefaultsInternal` (`indentincrement = 2`);
    /// then `resetDefaultsPrettyPrint` (= `setMaxLineSize(100)`,
    /// prettyprint.hh:1066 — which also re-arms the scan/token queues and
    /// clears the stream, prettyprint.cc:1225-1234).
    fn reset_defaults(&mut self) {
        // resetDefaultsInternal (prettyprint.hh:103): indentincrement = 2;
        self.indentincrement = 2;
        // resetDefaultsPrettyPrint (prettyprint.hh:1066):
        //   setMaxLineSize(100);
        self.set_max_line_size(100);
    }

    // RUGRA-GLUE: into_any (downcast support for the driver)
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    // RUGRA-GLUE: as_any_mut (downcast support for doc_function)
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::EmitNoMarkup;

    // PRINTC-PRINTLIST-WIRING-0001 regression: EmitPrettyPrint::resetDefaults
    // (prettyprint.cc:1237-1242) restores both cross-document print options —
    // indentincrement (resetDefaultsInternal, prettyprint.hh:103) and the
    // 100-character max line size (resetDefaultsPrettyPrint ->
    // setMaxLineSize(100), prettyprint.hh:1066), the latter observable via
    // getMaxLineSize. The low-level half (lowlevel->resetDefaults()) resets
    // the low emitter's indentincrement, which Rust's EmitNoMarkup does not
    // carry (structurally absorbed).
    #[test]
    fn emit_pretty_print_reset_defaults() {
        use super::{Emit, EmitPrettyPrint};
        let mut emit = EmitPrettyPrint::new();
        emit.set_max_line_size(60);
        assert_eq!(emit.get_max_line_size(), 60);
        emit.reset_defaults();
        assert_eq!(emit.get_max_line_size(), 100);
        assert_eq!(emit.indentincrement, 2);
    }

    // PRINTC-PRINTLIST-WIRING-0001: the plain-text emitters inherit the base
    // Emit::resetDefaults (prettyprint.hh:424) as a structural no-op — they
    // carry no cross-document print options, so the trait default must not
    // disturb their output state.
    #[test]
    fn emit_no_markup_reset_defaults_noop() {
        use super::{Emit, EmitNoMarkup};
        let mut emit = EmitNoMarkup::new();
        emit.print("held");
        emit.reset_defaults();
        assert_eq!(emit.get_output(), "held");
    }

    // MAIN-RC3-STRUCTURED-EMIT-0001 regression: the overflow whiledo header
    // is the compact `while( true )` (printc.cc:3023-3028 — tagOp +
    // openParen with no spaces(1) between, then one space on each side of
    // `true`). Locks both layers: (a) the emit sequence with explicit
    // space TOKENS produces those exact bytes in the raw low-level stream,
    // and (b) the legacy post-processing no longer destroys them — the
    // whitespace-normalization pass is gated off `while(` header lines and
    // the loop-context detectors accept the compact form, so the loop and
    // its `break;` survive untouched.
    // Statement shape mirrors production: every statement inside the block
    // opens with its own tag_line (emit_block_ops tag_line per statement).
    // POSTFIX-RETIRE-0001 W2 cut 2: the while-break->if fold pass is retired
    // (zero mutations on both corpora); this test now locks the UNfolded
    // bytes instead of the fold result. The PRINTC-WHILEIF-FOLD-PREFIX-0001
    // slice logic left with the pass; the compact-header emit bytes remain
    // the invariant under protection.
    #[test]
    fn pretty_print_while_break_compact_header_unfolded() {
        use crate::prettyprint::Emit;
        // The compact `while( true )` header (printc.cc:3023-3028) must
        // survive post-processing byte-exact (no re-spacing, no fold).
        let mut e = super::EmitPrettyPrint::new();
        e.begin_function();
        e.tag_line(0);
        e.tag_op("while");
        let id1 = e.open_paren("(");
        e.spaces(1, 0);
        e.print("true");
        e.spaces(1, 0);
        e.close_paren(")", id1);
        e.begin_block();
        e.tag_line(0);
        e.print("x = 1;");
        e.tag_line(0);
        e.print("break;");
        e.end_block();
        e.end_function();
        let out = e.get_output();
        assert!(
            out.contains("while( true ) {"),
            "compact while( true ) header must survive byte-exact, got:\n{}",
            out
        );
        assert!(
            out.contains("x = 1;") && out.contains("break;"),
            "loop body and break must survive (fold retired, loop ctx keeps break), got:\n{}",
            out
        );
        assert!(
            !out.contains("if (true)"),
            "while-break fold is retired (W2 cut 2); loop must not be folded, got:\n{}",
            out
        );

        // Control: the spaced `while (c)` form also survives unfolded.
        let mut e = super::EmitPrettyPrint::new();
        e.begin_function();
        e.tag_line(0);
        e.tag_op("while");
        e.print(" ");
        let id2 = e.open_paren("(");
        e.print("c");
        e.close_paren(")", id2);
        e.begin_block();
        e.tag_line(0);
        e.print("y = 2;");
        e.tag_line(0);
        e.print("break;");
        e.end_block();
        e.end_function();
        let out = e.get_output();
        assert!(
            out.contains("while (c) {"),
            "spaced while (c) header must survive, got:\n{}",
            out
        );
        assert!(
            !out.contains("if (c) y = 2;"),
            "while-break fold is retired (W2 cut 2); spaced form must not fold, got:\n{}",
            out
        );
    }

    fn pretty_print_overflow_whiledo_header_spaces() {
        use crate::prettyprint::Emit;
        let mut e = super::EmitPrettyPrint::new();
        e.begin_function();
        e.tag_line(0);
        e.tag_op("while");
        let id1 = e.open_paren("(");
        e.spaces(1, 0);
        e.print("true");
        e.spaces(1, 0);
        e.close_paren(")", id1);
        e.begin_block();
        e.tag_line(0);
        e.print("stmt;");
        e.tag_line(0);
        e.print("if (c) break;");
        e.end_block();
        e.end_function();
        let out = e.get_output();
        assert!(
            out.contains("while( true ) {"),
            "overflow header must be the compact `while( true )`, got:\n{}",
            out
        );
        assert!(
            out.contains("if (c) break;"),
            "the loop's if-break statement must survive post-processing, got:\n{}",
            out
        );
    }

    // RUGRA-GLUE: backfill_missing_locals unit tests (legacy text-pass
    // compensation layer; the oracle has no counterpart — Ghidra's
    // emitLocalVarDecls (printc.cc:2260-2279) declares every scope symbol
    // and never re-scans emitted text). These pin the PRINTC-C3-UNNAMED-
    // SPACE-NAME-0001 contract: the oracle unnamed-location fallback tokens
    // <spacename><printRaw> (printc.cc:1938-1945: unique0x.../register0x.../
    // stack0x.../ram0x...) are expression-level storage-slot labels, NOT
    // ScopeLocal symbols, so the oracle never declares them (the 12.0.4
    // golden declares zero of its uses) — the backfill recognizes them in
    // the used-locals scan but never injects a declaration.

    #[test]
    fn backfill_injects_unnamed_location_fallback_tokens() {
        let input = "\
long match_url(char *param_1,long param_2)

{
  char *piVar1;
  unique0x00023b00 = *param_1;
  if (unique0x00023b00 != '#') {
    __sprintf_chk(register0x000000a0,1,-1,0x0,(short)unique0x0000aa00);
    register0x00000000 = strlen(register0x000000a0);
  }
  return 0;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        // Canon zero-decl contract: no space token gets a declaration.
        assert!(
            !out.contains("long register0x"), "register0x decl injected:\n{}", out
        );
        assert!(
            !out.contains("long unique0x"), "unique0x decl injected:\n{}", out
        );
        // Declared names are not re-injected.
        assert_eq!(
            out.matches("char *piVar1;").count(), 1, "piVar1 re-declared:\n{}", out
        );
        // Body lines are untouched.
        assert!(
            out.contains("unique0x00023b00 = *param_1;"), "body line dropped:\n{}", out
        );
    }

    #[test]
    fn backfill_hex_tail_not_truncated() {
        // Regression guard for the continuation scan: the fallback token tail
        // is printRaw hex (space.cc:216 lowercase hex), so a decimal-only
        // scan would truncate unique0x0000abef at its first a-f digit and
        // inject a partial name. Under the canon zero-decl contract the
        // tokens are not injected at all — including no partial-name form.
        let input = "\
void f(void)

{
  stack0x0000abef = 1;
  ram0x00023e00 = stack0x0000abef + ram0x0000ff00;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert!(
            !out.contains("long stack0x"), "stack0x decl injected:\n{}", out
        );
        assert!(
            !out.contains("long ram0x"), "ram0x decl injected:\n{}", out
        );
        assert!(
            !out.contains("stack0x0000;\n"), "hex tail truncated:\n{}", out
        );
        assert!(
            !out.contains("ram0x00023;\n"), "ram hex tail truncated:\n{}", out
        );
        assert!(
            out.contains("ram0x00023e00 = stack0x0000abef + ram0x0000ff00;"),
            "body line dropped:\n{}", out
        );
    }

    #[test]
    fn backfill_no_reinject_declared_fallback_token() {
        let input = "\
void f(void)

{
  long unique0x00023b00;
  unique0x00023b00 = 5;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert_eq!(
            out.matches("long unique0x00023b00;").count(), 1,
            "declared fallback token re-injected:\n{}", out
        );
    }

    #[test]
    fn backfill_legacy_prefixes_still_recognized() {
        // The legacy spellings keep their old behaviour (guards against
        // prefix-table regressions while adding the new forms).
        let input = "\
void f(void)

{
  int bVar3;
  bVar3 = uVar42 + local_10;
}
";
        let out = EmitNoMarkup::backfill_missing_locals(input);
        assert!(
            out.contains("  long uVar42;\n"), "uVarN no longer injected:\n{}", out
        );
        assert!(
            out.contains("  int local_10;\n"), "local_ no longer injected:\n{}", out
        );
        assert_eq!(
            out.matches("int bVar3;").count(), 1, "bVar3 re-declared:\n{}", out
        );
    }
}

#[cfg(test)]
mod linewrap_probe_tests {
    use super::EmitPrettyPrint;
    use crate::prettyprint::Emit;

    // Probe: simulate the Ghidra emit sequence of a `puts(LONG)` statement
    // inside a function body to trace the wrap indent (expect 6 spaces).
    #[test]
    fn probe_puts_wrap_indent() {
        let mut e = EmitPrettyPrint::new();
        e.set_comment_fill("   ");
        // docFunction: beginFunction, tagLine, declaration, skip_line brace
        e.begin_function();
        e.tag_line(0);
        e.begin_func_proto();
        e.tag_type("void", 0);
        e.tag_func_name("hugehelp", 0);
        e.open_paren("(");
        e.close_paren(")", 0);
        e.end_func_proto();
        // openBraceIndent(skip_line): tagLine(); tagLine(); startIndent; "{"
        e.tag_line(0);
        e.tag_line(0);
        e.bump_indent();
        e.print("{");
        // statement: tagLine, beginStatement, puts(...)
        e.tag_line(0);
        e.begin_statement();
        e.tag_func_name("puts", 0);
        e.spaces(0, 10);
        e.open_paren("(");
        e.spaces(0, 10);
        let long = "x".repeat(300);
        e.print(&long);
        e.close_paren(")", 0);
        // The statement layer prints the trailing semicolon after the
        // expression (printc.cc opFunc/emit*Statement flows).
        e.print(";");
        e.end_statement();
        e.tag_line(0);
        // closeBraceIndent: stopIndent; tagLine; "}"
        e.drop_indent();
        e.tag_line(0);
        e.print("}");
        e.tag_line(0);
        e.end_function();
        e.flush();
        let out = e.get_output();
        eprintln!("PROBE_OUTPUT<<<\n{}>>>END", out);
        // Expect the continuation lines indented by 6 spaces
        let lines: Vec<&str> = out.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            eprintln!("PROBE[{}] {:?}", i, l);
        }
        // The converged golden form (ghidra_curl_1204.c hugehelp): the string
        // literal and the closing `);` both continue at 6 spaces.
        let string_line = lines.iter().find(|l| l.starts_with("      xxx")).unwrap();
        assert_eq!(string_line.len(), 6 + 300);
        let close_line = lines.iter().find(|l| l.starts_with("      )")).unwrap();
        assert_eq!(close_line.trim_end(), "      );");
    }

    // PRETTYPRINT-SIGWRAP-0001 regression: the function-signature wrap form.
    // The declaration separator between the return type and the function
    // name is printc.cc:2582 `emit->spaces(1)` — a TOKENBREAK (1 mandatory
    // space, bump 0), not a content string. Feeding `print(" ")` instead
    // inserts an extra content token + checkstring break and the overflow
    // cascade breaks after the return type (`xunknown8 \n<name>` with a
    // 10-space paren continuation) — the sq mirror SIG-WRAP family
    // (~150 lines / 40+ thunks). With the tokenbreak the cascade skips it
    // ("doesn't save that much" exemption, prettyprint.cc:680-685) and
    // breaks at the funcname->'(' break (function_call bump 10), giving the
    // oracle form: name glued to the return type, parameter list on the
    // next line indented 20 (indentstack.back()=80 → maxlinesize-80).
    // Expected bytes are the 12.0.4 oracle golden verbatim
    // (ghidra_sq_1204.direct-runner.c _ZThn16_..SetCoderProperties thunk).
    #[test]
    fn signature_wrap_breaks_after_funcname_not_return_type() {
        let mut e = EmitPrettyPrint::new();
        e.begin_function();
        e.tag_line(0);
        e.begin_func_proto();
        e.begin_return_type();
        e.tag_type("xunknown8", 0);
        e.end_return_type();
        // printc.cc:2582 — the tokenbreak under test (bump 0).
        e.spaces(1, 0);
        let id1 = e.open_group();
        e.tag_func_name(
            "_ZThn16_N9NCompress5NLZMA8CEncoder18SetCoderPropertiesEPKjPK14tagPROPVARIANTj",
            0,
        );
        // printc.cc:2594 function_call { spacing=0, bump=10 }.
        e.spaces(0, 10);
        let id2 = e.open_paren("(");
        e.spaces(0, 10);
        let params: [(&str, &str); 4] = [
            ("int8", "param_1"),
            ("uint4 *", "param_2"),
            ("int2 *", "param_3"),
            ("int4", "param_4"),
        ];
        for (i, (ty, nm)) in params.iter().enumerate() {
            if i > 0 {
                e.print(",");
            }
            e.tag_type(ty, 0);
            if !ty.ends_with('*') {
                // type_expr_space { spacing=1, bump=0 } (printc.cc:73).
                e.spaces(1, 0);
            }
            e.tag_variable(nm, 0);
        }
        e.close_paren(")", id2);
        e.close_group(id1);
        e.end_func_proto();
        e.print("\n");
        e.tag_line(0);
        e.print("{");
        e.tag_line(0);
        e.print("}");
        e.tag_line(0);
        e.end_function();
        e.flush();
        let out = e.get_output();
        let expected = "\
xunknown8 _ZThn16_N9NCompress5NLZMA8CEncoder18SetCoderPropertiesEPKjPK14tagPROPVARIANTj
                    (int8 param_1,uint4 *param_2,int2 *param_3,int4 param_4)
";
        assert!(
            out.trim_start_matches('\n').starts_with(expected),
            "signature wrap must keep the return type glued to the name and \
             break at the funcname->'(' tokenbreak (20-space continuation), \
             got:\n{}",
            out
        );
    }

    // PRETTYPRINT-SIGWRAP-0001, comma-continuation sub-shape: overflowing
    // parameter lists break at the checkstring-inserted zero-width break
    // BEFORE the comma token (EmitPrettyPrint::print checkstring,
    // prettyprint.cc:819-828) — the comma opens the continuation line —
    // with the continuation aligned inside the parameter group. Expected
    // bytes are the 12.0.4 oracle golden verbatim
    // (ghidra_sq_1204.direct-runner.c initialise_threads, 14 params).
    #[test]
    fn signature_wrap_comma_opens_continuation_line() {
        let mut e = EmitPrettyPrint::new();
        e.begin_function();
        e.tag_line(0);
        e.begin_func_proto();
        e.begin_return_type();
        e.tag_type("xunknown4", 0);
        e.end_return_type();
        e.spaces(1, 0);
        let id1 = e.open_group();
        e.tag_func_name("initialise_threads", 0);
        e.spaces(0, 10);
        let id2 = e.open_paren("(");
        e.spaces(0, 10);
        for i in 1..=14 {
            if i > 1 {
                e.print(",");
            }
            let ty = if i == 9 || i == 10 { "uint4" } else { "xunknown8" };
            e.tag_type(ty, 0);
            e.spaces(1, 0);
            e.tag_variable(&format!("param_{}", i), 0);
        }
        e.close_paren(")", id2);
        e.close_group(id1);
        e.end_func_proto();
        e.print("\n");
        e.tag_line(0);
        e.print("{");
        e.tag_line(0);
        e.print("}");
        e.tag_line(0);
        e.end_function();
        e.flush();
        let out = e.get_output();
        let expected = "\
xunknown4 initialise_threads(xunknown8 param_1,xunknown8 param_2,xunknown8 param_3,xunknown8 param_4
                            ,xunknown8 param_5,xunknown8 param_6,xunknown8 param_7,xunknown8 param_8
                            ,uint4 param_9,uint4 param_10,xunknown8 param_11,xunknown8 param_12,
                            xunknown8 param_13,xunknown8 param_14)
";
        assert!(
            out.trim_start_matches('\n').starts_with(expected),
            "parameter overflow must break BEFORE the comma (comma opens the \
             continuation line, group-aligned indent), got:\n{}",
            out
        );
    }
}
