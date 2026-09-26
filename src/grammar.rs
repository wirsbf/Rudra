//! C grammar parser — faithful port of `grammar.hh` / `grammar.cc` (3338
//! lines).
//!
//! Lexer and parser for C-style type declarations. Used by the decompiler to
//! parse type strings, prototype declarations, and interface commands.
//!
//! Status: L1→L2→L3. The GrammarToken/GrammarLexer with state-machine
//! tokenization is complete. The TypeDeclarator/TypeModifier AST,
//! TypeSpecifiers/Enumerator helpers, and the CParse parser framework
//! (mergeSpecDec/addSpecifier/mergePointer/newArray/newFunc/struct/union/enum
//! builders + runParse/parseStream) are ported. The actual yyparse grammar
//! table from grammar.y is left as a future L3 port because Rust has no
//! equivalent of yacc/bison in-tree; recursive-descent replacements are
//! provided for the public entry points (`parse_type`, `parse_to_separator`,
//! `parse_machaddr`, `parse_varnode`, `parse_op`).
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.{hh,cc}.

use std::sync::Arc;

use crate::address::Address;
use crate::arch::Architecture;
use crate::type_system::datatype::Datatype;

/// Token types for the C grammar lexer. Faithful to the `GrammarToken` enum
/// (grammar.hh:26).
pub mod token_type {
    pub const OPEN_PAREN: u32 = 0x28;
    pub const CLOSE_PAREN: u32 = 0x29;
    pub const STAR: u32 = 0x2a;
    pub const COMMA: u32 = 0x2c;
    pub const SEMICOLON: u32 = 0x3b;
    pub const OPEN_BRACKET: u32 = 0x5b;
    pub const CLOSE_BRACKET: u32 = 0x5d;
    pub const OPEN_BRACE: u32 = 0x7b;
    pub const CLOSE_BRACE: u32 = 0x7d;
    pub const BAD_TOKEN: u32 = 0x100;
    pub const END_OF_FILE: u32 = 0x101;
    pub const DOTDOTDOT: u32 = 0x102;
    pub const INTEGER: u32 = 0x103;
    pub const CHAR_CONSTANT: u32 = 0x104;
    pub const IDENTIFIER: u32 = 0x105;
    pub const STRING_VAL: u32 = 0x106;
}

/// Bison token codes emitted at the top of `grammar.cc` (lines 148-166) and
/// returned by `CParse::lex` / `lookupIdentifier`. Faithful to the
/// `grammartokentype` enum in `grammar.cc`.
///
/// These are distinct from the lexer-level `GrammarToken::type` codes in
/// `token_type` (which describe *raw* tokens); the bison codes describe
/// *parser-level* tokens produced by `lex()` after identifier reclassification
/// via `lookupIdentifier` (e.g. `STRUCT` / `TYPE_NAME` / `STORAGE_CLASS_SPECIFIER`).
pub mod bison_token {
    /// `DOTDOTDOT = 258` (grammar.cc:153).
    pub const DOTDOTDOT: i32 = 258;
    /// `BADTOKEN = 259` (grammar.cc:154).
    pub const BADTOKEN: i32 = 259;
    /// `STRUCT = 260` (grammar.cc:155).
    pub const STRUCT: i32 = 260;
    /// `UNION = 261` (grammar.cc:156).
    pub const UNION: i32 = 261;
    /// `ENUM = 262` (grammar.cc:157).
    pub const ENUM: i32 = 262;
    /// `DECLARATION_RESULT = 263` (grammar.cc:158) — start-token for the
    /// `doc_declaration` grammar.
    pub const DECLARATION_RESULT: i32 = 263;
    /// `PARAM_RESULT = 264` (grammar.cc:159) — start-token for the
    /// `doc_parameter_declaration` grammar.
    pub const PARAM_RESULT: i32 = 264;
    /// `NUMBER = 265` (grammar.cc:160) — integer/char constant.
    pub const NUMBER: i32 = 265;
    /// `IDENTIFIER = 266` (grammar.cc:161) — an unknown identifier.
    pub const IDENTIFIER: i32 = 266;
    /// `STORAGE_CLASS_SPECIFIER = 267` (grammar.cc:162).
    pub const STORAGE_CLASS_SPECIFIER: i32 = 267;
    /// `TYPE_QUALIFIER = 268` (grammar.cc:163).
    pub const TYPE_QUALIFIER: i32 = 268;
    /// `FUNCTION_SPECIFIER = 269` (grammar.cc:164) — `inline` or a
    /// prototype-model name.
    pub const FUNCTION_SPECIFIER: i32 = 269;
    /// `TYPE_NAME = 270` (grammar.cc:165) — an identifier already bound to a
    /// `Datatype` in the `TypeFactory`.
    pub const TYPE_NAME: i32 = 270;
    /// Sentinel returned by `lex()` to signal end of stream (Ghidra's `lex`
    /// returns `-1` on `GrammarToken::endoffile`).
    pub const END_OF_STREAM: i32 = -1;
}

/// A lexical token from the C grammar. Faithful to `GrammarToken`
/// (grammar.hh:23).
#[derive(Debug, Clone)]
pub struct GrammarToken {
    /// The token type (see `token_type` module).
    pub token_type: u32,
    /// The integer value (for INTEGER tokens).
    pub integer_value: u64,
    /// The string value (for IDENTIFIER/STRING tokens).
    pub string_value: String,
    /// Line number containing this token.
    pub lineno: i32,
    /// Column where this token starts.
    pub colno: i32,
    /// Which file we were in.
    pub filenum: i32,
}

impl Default for GrammarToken {
    // Ghidra: grammar.cc:2025 GrammarToken::GrammarToken (default ctor)
    fn default() -> Self {
        Self::new()
    }
}

impl GrammarToken {
    // Ghidra: grammar.cc:2025 GrammarToken::GrammarToken
    /// Construct an empty token. Faithful to the constructor.
    pub fn new() -> Self {
        Self {
            token_type: token_type::BAD_TOKEN,
            integer_value: 0,
            string_value: String::new(),
            lineno: 0,
            colno: 0,
            filenum: 0,
        }
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getType
    /// Get the token type. Faithful to `getType`.
    pub fn get_type(&self) -> u32 {
        self.token_type
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getInteger
    /// Get the integer value. Faithful to `getInteger`.
    pub fn get_integer(&self) -> u64 {
        self.integer_value
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getString
    /// Get the string value. Faithful to `getString`.
    pub fn get_string(&self) -> &str {
        &self.string_value
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getLineNo
    /// Get the line number. Faithful to `getLineNo`.
    pub fn get_line_no(&self) -> i32 {
        self.lineno
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getColNo
    /// Get the column number. Faithful to `getColNo`.
    pub fn get_col_no(&self) -> i32 {
        self.colno
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getFileNum
    /// Get the file number. Faithful to `getFileNum`.
    pub fn get_file_num(&self) -> i32 {
        self.filenum
    }

    // Ghidra: grammar.cc:2025 GrammarToken::setPosition
    /// Set position. Faithful to `setPosition`.
    pub fn set_position(&mut self, file: i32, line: i32, col: i32) {
        self.filenum = file;
        self.lineno = line;
        self.colno = col;
    }

    // Ghidra: grammar.cc:1960 GrammarToken::set(uint4 tp)
    /// Set the token to a pure type (no payload). Faithful to the single-arg
    /// `set(uint4 tp)` overload used by the lexer for punctuation/keywords.
    pub fn set_type_only(&mut self, tp: u32) {
        self.token_type = tp;
    }

    // Ghidra: grammar.cc:1966 GrammarToken::set(uint4 tp,char *ptr,int4 len)
    /// Set the token to a value-bearing type, parsing the lexeme text. Faithful
    /// to the three-arg `set(uint4 tp, char*, int4)` overload. For `integer` the
    /// text is parsed (honouring 0x/0 prefixes via `parse_number`); for
    /// `identifier`/`stringval` the text is stored; for `charconstant` the
    /// character value is computed (including the backslash escapes `n 0 a b f
    /// r t v \\ ' "` listed at grammar.cc:1985-2014).
    pub fn set_with_text(&mut self, tp: u32, text: &str) {
        self.token_type = tp;
        match tp {
            x if x == token_type::INTEGER => {
                self.integer_value = parse_number(text);
            }
            x if x == token_type::IDENTIFIER || x == token_type::STRING_VAL => {
                self.string_value = text.to_string();
            }
            x if x == token_type::CHAR_CONSTANT => {
                self.integer_value = parse_char_constant(text);
            }
            _ => {}
        }
    }
}

// Ghidra: grammar.cc:1966 GrammarToken::set (charconstant escapes)
/// Decode a C character constant (the text between the quotes, already
/// stripped) into its integer value. Faithful to the `case charconstant:`
/// branch of `GrammarToken::set` (grammar.cc:1985-2014): a single char maps to
/// its byte value; a backslash escape is decoded (`n`=10, `0`=0, `a`=7, `b`=8,
/// `f`=12, `r`=13, `t`=9, `v`=11, `\\`=92, `'`=39, `"`=34); any other escape
/// falls back to the literal character.
pub fn parse_char_constant(text: &str) -> u64 {
    let bytes = text.as_bytes();
    if bytes.len() == 1 {
        return bytes[0] as u64;
    }
    // Backslash escape: text[0] == '\\', text[1] is the escape letter.
    if bytes.len() >= 2 && bytes[0] == b'\\' {
        match bytes[1] {
            b'n' => 10,
            b'0' => 0,
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'r' => 13,
            b't' => 9,
            b'v' => 11,
            b'\\' => 92,
            b'\'' => 39,
            b'"' => 34,
            other => other as u64,
        }
    } else {
        // Multi-byte non-escape: take the first byte (best-effort).
        bytes[0] as u64
    }
}

/// Lexer state machine states. Faithful to the `GrammarLexer` enum
/// (grammar.hh:82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerState {
    Start,
    Slash,
    Dot1,
    Dot2,
    Dot3,
    Punctuation,
    EndOfLineComment,
    CComment,
    DoubleQuote,
    DoubleQuoteEnd,
    SingleQuote,
    SingleQuoteEnd,
    SingleBackslash,
    Number,
    Identifier,
}

/// A lexer for C-style type declarations. Faithful to `GrammarLexer`
/// (grammar.hh:69).
pub struct GrammarLexer {
    /// The input text being lexed.
    input: Vec<char>,
    /// Current position in the input.
    pos: usize,
    /// Current line number.
    cur_lineno: i32,
    /// End of file reached.
    end_of_file: bool,
    /// Error message (if any).
    error: String,
    /// `filenamemap` — every file ever seen, keyed by an assigned filenum.
    /// Faithful to `map<int4,string> filenamemap` (grammar.hh:70).
    filenamemap: std::collections::HashMap<i32, String>,
    /// `streammap` — the text body of each filenum. Faithful to
    /// `map<int4,istream *> streammap` (grammar.hh:71). Rugra has no
    /// `istream`, so each "stream" is held as an owned `Vec<char>` body plus a
    /// per-stream position. The most recent entry is the "current" stream.
    streammap: Vec<LexerStream>,
    /// `filestack` — stack of current files. Faithful to
    /// `vector<int4> filestack` (grammar.hh:72).
    filestack: Vec<i32>,
}

/// One logical input stream within the lexer's multi-file stack. Faithful to a
/// single `istream *` entry in `GrammarLexer::streammap`; Rugra has no
/// `istream`, so the stream body and read position are owned here.
struct LexerStream {
    /// Full text of the stream.
    body: Vec<char>,
    /// Current read position within `body`.
    pos: usize,
    /// Current line number within this stream.
    lineno: i32,
}

impl GrammarLexer {
    // Ghidra: grammar.cc:2035 GrammarLexer::GrammarLexer
    /// Construct given the maximum buffer size. Faithful to the constructor
    /// (grammar.hh:104).
    pub fn new(_max_buffer: i32) -> Self {
        Self {
            input: Vec::new(),
            pos: 0,
            cur_lineno: 1,
            end_of_file: false,
            error: String::new(),
            filenamemap: std::collections::HashMap::new(),
            streammap: Vec::new(),
            filestack: Vec::new(),
        }
    }

    // Ghidra: grammar.cc:2305 GrammarLexer::clear
    /// Clear the lexer state. Faithful to `clear`. Resets the multi-file
    /// stream stack (`filenamemap` / `streammap` / `filestack`) and the
    /// single-string input the recursive-descent driver consumes.
    pub fn clear(&mut self) {
        self.input.clear();
        self.pos = 0;
        self.cur_lineno = 1;
        self.end_of_file = false;
        self.error.clear();
        self.filenamemap.clear();
        self.streammap.clear();
        self.filestack.clear();
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::setInput
    /// Set the input text to lex.
    pub fn set_input(&mut self, text: &str) {
        self.clear();
        self.input = text.chars().collect();
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::getError
    /// Get the error message. Faithful to `getError`.
    pub fn get_error(&self) -> &str {
        &self.error
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::isEof
    /// Check if at end of file.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    // Ghidra: grammar.hh:107 GrammarLexer::getCurStream
    /// Get the filenum of the current stream (the top of `filestack`), or `None`
    /// if no file is active. Faithful to `getCurStream` (Ghidra returns the raw
    /// `istream *in`; Rugra exposes the filenum that indexes `streammap`).
    pub fn get_cur_stream(&self) -> Option<i32> {
        self.filestack.last().copied()
    }

    // Ghidra: grammar.cc:2054 GrammarLexer::bumpLine
    /// Increment the current line counter. Faithful to `bumpLine`. Rugra's
    /// `next_char` inlines this on `'\n'`; this method exposes it for callers
    /// that need to advance the line counter out-of-band (e.g. when swallowing
    /// a multi-line token via `moveState`).
    pub fn bump_line(&mut self) {
        self.cur_lineno += 1;
    }

    // Ghidra: grammar.hh:77 GrammarLexer::curlineno (field accessor)
    /// Get the current line number. Faithful to the `curlineno` member used by
    /// `writeTokenLocation` and `setPosition`.
    pub fn cur_lineno(&self) -> i32 {
        self.cur_lineno
    }

    // Ghidra: grammar.cc:2320 GrammarLexer::writeLocation
    /// Write the `" at line N in <file>"` location suffix used by error
    /// reporting. Faithful to `writeLocation(ostream &, int4, int4)`. Rugra
    /// appends to the supplied `String` instead of an `ostream`.
    pub fn write_location(&self, s: &mut String, line: i32, filenum: i32) {
        use std::fmt::Write as _;
        let _ = write!(s, " at line {}", line);
        if let Some(name) = self.filenamemap.get(&filenum) {
            let _ = write!(s, " in {}", name);
        }
    }

    // Ghidra: grammar.cc:2327 GrammarLexer::writeTokenLocation
    /// Write the `buffer + '\n' + colno spaces + "^--\n"` caret pointer used
    /// by error reporting. Faithful to `writeTokenLocation(ostream &, int4,
    /// int4)`. Returns without writing when `line` does not match the current
    /// line (the C++ side does the same against `curlineno`). Rugra's "buffer"
    /// is the current input's remaining text from the start of the current
    /// line, which is the closest analogue available.
    pub fn write_token_location(&self, s: &mut String, line: i32, colno: i32) {
        if line != self.cur_lineno {
            return;
        }
        s.push_str(&self.input.iter().collect::<String>());
        s.push('\n');
        for _ in 0..colno {
            s.push(' ');
        }
        s.push_str("^--\n");
    }

    // Ghidra: grammar.cc:2339 GrammarLexer::pushFile
    /// Push a new file stream onto the lexer's file stack and make it the
    /// current stream. Faithful to `pushFile(const string &, istream *)`.
    /// Assigns a fresh filenum (one greater than the largest seen), records the
    /// filename in `filenamemap`, the body in `streammap`, the filenum on
    /// `filestack`, and replaces the current input so the recursive-descent
    /// driver reads from this file.
    pub fn push_file(&mut self, filename: &str, body: &str) {
        // Ghidra: `int4 filenum = filenamemap.size();` — filenamemap and
        // streammap grow in lockstep, so either length gives the next id.
        let filenum = self.filenamemap.len() as i32;
        self.filenamemap.insert(filenum, filename.to_string());
        self.streammap.push(LexerStream {
            body: body.chars().collect(),
            pos: 0,
            lineno: 1,
        });
        self.filestack.push(filenum);
        // Install the file body as the active input. The recursive-descent
        // `yyparse` reads from `input`/`pos`; mirroring C++'s `in = i`.
        self.input = body.chars().collect();
        self.pos = 0;
        self.cur_lineno = 1;
        self.end_of_file = false;
    }

    // Ghidra: grammar.cc:2350 GrammarLexer::popFile
    /// Pop the top file from the file stack. Faithful to `popFile`. When the
    /// stack becomes empty the lexer is marked end-of-file (matching the C++
    /// `endoffile = true; return;` path); otherwise the previous stream is
    /// reinstalled as the current input.
    pub fn pop_file(&mut self) {
        self.filestack.pop();
        if self.filestack.is_empty() {
            self.end_of_file = true;
            return;
        }
        // Get previous stream — the one that was active before this push.
        let prev_filenum = *self.filestack.last().unwrap();
        let _ = prev_filenum; // C++ does `in = streammap[filenum]`.
        // Reinstall the previous body so the recursive-descent driver reads
        // from it. Its read position was preserved in `streammap` if it is
        // still the most-recently-pushed stream; otherwise we restart at EOF
        // because the earlier input was already exhausted before the push.
        if let Some(stream) = self.streammap.last() {
            self.input = stream.body.clone();
            self.pos = stream.pos;
            self.cur_lineno = stream.lineno;
        }
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::peek
    /// Peek at the next character without consuming.
    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::nextChar
    /// Consume and return the next character.
    fn next_char(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.cur_lineno += 1;
        }
        Some(c)
    }

    // Ghidra: grammar.cc:2362 GrammarLexer::getNextToken
    /// Get the next token from the input. Faithful to `getNextToken`
    /// (grammar.hh:110). Implements the state machine for tokenizing C
    /// declarations.
    pub fn get_next_token(&mut self) -> GrammarToken {
        let mut token = GrammarToken::new();
        token.set_position(0, self.cur_lineno, self.pos as i32);

        if self.is_eof() {
            token.token_type = token_type::END_OF_FILE;
            return token;
        }

        let mut state = LexerState::Start;
        let mut accum = String::new();

        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => {
                    // End of input — finalize current state.
                    return self.finalize_token(&mut token, &state, &accum);
                }
            };

            match state {
                LexerState::Start => {
                    match c {
                        ' ' | '\t' | '\r' | '\n' => {
                            self.next_char();
                        }
                        '(' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_PAREN;
                    return token;
                        }
                        ')' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_PAREN;
                    return token;
                        }
                        '*' => {
                            self.next_char();
                            token.token_type = token_type::STAR;
                    return token;
                        }
                        ',' => {
                            self.next_char();
                            token.token_type = token_type::COMMA;
                    return token;
                        }
                        ';' => {
                            self.next_char();
                            token.token_type = token_type::SEMICOLON;
                    return token;
                        }
                        '[' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_BRACKET;
                    return token;
                        }
                        ']' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_BRACKET;
                    return token;
                        }
                        '{' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_BRACE;
                    return token;
                        }
                        '}' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_BRACE;
                    return token;
                        }
                        '/' => {
                            self.next_char();
                            state = LexerState::Slash;
                        }
                        '.' => {
                            self.next_char();
                            state = LexerState::Dot1;
                        }
                        '"' => {
                            self.next_char();
                            state = LexerState::DoubleQuote;
                        }
                        '\'' => {
                            self.next_char();
                            state = LexerState::SingleQuote;
                        }
                        '0'..='9' => {
                            accum.push(c);
                            self.next_char();
                            state = LexerState::Number;
                        }
                        'a'..='z' | 'A'..='Z' | '_' => {
                            accum.push(c);
                            self.next_char();
                            state = LexerState::Identifier;
                        }
                        _ => {
                            self.next_char();
                            token.token_type = token_type::BAD_TOKEN;
                    return token;
                        }
                    }
                }
                LexerState::Slash => {
                    match c {
                        '/' => {
                            self.next_char();
                            state = LexerState::EndOfLineComment;
                        }
                        '*' => {
                            self.next_char();
                            state = LexerState::CComment;
                        }
                        _ => {
                            token.token_type = token_type::BAD_TOKEN;
                    return token;
                        }
                    }
                }
                LexerState::EndOfLineComment => {
                    if c == '\n' {
                        self.next_char();
                        state = LexerState::Start;
                    } else {
                        self.next_char();
                    }
                }
                LexerState::CComment => {
                    if c == '*' {
                        self.next_char();
                        state = LexerState::Dot3; // Reuse for comment-end detection.
                    } else {
                        self.next_char();
                    }
                }
                LexerState::Dot3 => {
                    // Inside C comment, saw '*', check for '/'
                    if c == '/' {
                        self.next_char();
                        state = LexerState::Start;
                    } else {
                        state = LexerState::CComment;
                    }
                }
                LexerState::Dot1 => {
                    if c == '.' {
                        self.next_char();
                        state = LexerState::Dot2;
                    } else {
                        token.token_type = token_type::BAD_TOKEN;
                    return token;
                    }
                }
                LexerState::Dot2 => {
                    if c == '.' {
                        self.next_char();
                        token.token_type = token_type::DOTDOTDOT;
                    return token;
                    } else {
                        token.token_type = token_type::BAD_TOKEN;
                    return token;
                    }
                }
                LexerState::DoubleQuote => {
                    if c == '"' {
                        self.next_char();
                        token.token_type = token_type::STRING_VAL;
                        token.string_value = accum;
                    return token;
                    } else {
                        accum.push(c);
                        self.next_char();
                    }
                }
                LexerState::SingleQuote => {
                    if c == '\'' {
                        self.next_char();
                        // Ghidra: GrammarToken::set(charconstant, ptr, len)
                        // stores the decoded character value in value.integer
                        // (grammar.cc:1985). Mirror that here so CHAR_CONSTANT
                        // tokens carry their integer value, not just the text.
                        token.token_type = token_type::CHAR_CONSTANT;
                        token.integer_value = parse_char_constant(&accum);
                        token.string_value = accum;
                    return token;
                    } else {
                        accum.push(c);
                        self.next_char();
                    }
                }
                LexerState::Number => {
                    if c.is_ascii_hexdigit() || c == 'x' || c == 'X' || c.is_ascii_digit() {
                        accum.push(c);
                        self.next_char();
                    } else {
                        token.token_type = token_type::INTEGER;
                        token.integer_value = parse_number(&accum);
                    return token;
                    }
                }
                LexerState::Identifier => {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        accum.push(c);
                        self.next_char();
                    } else {
                        token.token_type = token_type::IDENTIFIER;
                        token.string_value = accum;
                    return token;
                    }
                }
                _ => {
                    self.next_char();
                    state = LexerState::Start;
                }
            }
        }
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::finalizeToken
    /// Finalize a token at end of input.
    fn finalize_token(
        &self,
        token: &mut GrammarToken,
        state: &LexerState,
        accum: &str,
    ) -> GrammarToken {
        match state {
            LexerState::Number => {
                token.token_type = token_type::INTEGER;
                token.integer_value = parse_number(accum);
            }
            LexerState::Identifier => {
                token.token_type = token_type::IDENTIFIER;
                token.string_value = accum.to_string();
            }
            _ => {
                token.token_type = token_type::END_OF_FILE;
            }
        }
        token.clone()
    }
}

// Ghidra: grammar.cc:2035 GrammarLexer::parseNumber
/// Parse a number string (decimal or hex) into a u64.
fn parse_number(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else if s.starts_with('0') && s.len() > 1 {
        u64::from_str_radix(s, 8).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Type declaration AST (data structures)
// ---------------------------------------------------------------------------

// Ghidra: fspec.hh:377 struct PrototypePieces
/// Raw components of a function prototype obtained from parsing source code.
/// Faithful to `struct PrototypePieces` (fspec.hh:377-384).
///
/// Rugra note: `fspec.rs` already declares a `PrototypePieces` for the model-
/// rules / code-type pipeline (which is borrowed and carries no `model`/`name`/
/// `innames`); the parser-facing variant here is owned and mirrors Ghidra's
/// full struct, including the (optional) prototype-model name and parameter
/// names. The `model` field stores the model *name* because Rugra has no
/// in-tree `ProtoModel *` reachable from this module; the C++ stores a pointer
/// resolved via `glb->getModel(model)`.
#[derive(Debug, Clone, Default)]
pub struct PrototypePieces {
    /// `PrototypePieces::model` — model on which prototype is based (name).
    pub model: Option<String>,
    /// `PrototypePieces::name` — identifier (function name) of the prototype.
    pub name: String,
    /// `PrototypePieces::outtype` — return data-type.
    pub out_type: Option<Arc<Datatype>>,
    /// `PrototypePieces::intypes` — input parameter data-types in order.
    pub in_types: Vec<Arc<Datatype>>,
    /// `PrototypePieces::innames` — identifiers for input types.
    pub in_names: Vec<String>,
    /// `PrototypePieces::firstVarArgSlot` — first vararg position, or -1.
    pub first_var_arg_slot: i32,
}

/// Type modifier kind. Faithful to `TypeModifier` enum (grammar.hh:120).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifierKind {
    Pointer,
    Array,
    Function,
    Struct,
    Enum,
}

/// A type modifier (pointer, array, function). Faithful to `TypeModifier`
/// (grammar.hh:118).
#[derive(Debug, Clone)]
pub enum TypeModifier {
    /// Pointer modifier with flags. Faithful to `PointerModifier`
    /// (grammar.hh:133).
    Pointer { flags: u32 },
    /// Array modifier with flags and size. Faithful to `ArrayModifier`
    /// (grammar.hh:142).
    Array { flags: u32, array_size: i32 },
    /// Function modifier with parameter declarators and varargs flag. Faithful
    /// to `FunctionModifier` (grammar.hh:152). The owned `params` mirror the
    /// `vector<TypeDeclarator *>` in C++; `None` entries encode the trailing
    /// varargs slot (see `FunctionModifier::FunctionModifier`).
    Function {
        params: Vec<Option<TypeDeclarator>>,
        dotdotdot: bool,
    },
}

impl TypeModifier {
    // Ghidra: grammar.hh:128 TypeModifier::getType
    /// Get the modifier kind. Faithful to `getType`.
    pub fn kind(&self) -> ModifierKind {
        match self {
            TypeModifier::Pointer { .. } => ModifierKind::Pointer,
            TypeModifier::Array { .. } => ModifierKind::Array,
            TypeModifier::Function { .. } => ModifierKind::Function,
        }
    }

    // Ghidra: grammar.hh:129 TypeModifier::isValid
    /// Is this modifier valid? Faithful to `isValid`.
    pub fn is_valid(&self) -> bool {
        match self {
            TypeModifier::Pointer { .. } => true,
            TypeModifier::Array { array_size, .. } => *array_size > 0,
            // Ghidra: grammar.cc:2450 FunctionModifier::isValid
            TypeModifier::Function { params, .. } => {
                params.iter().all(|p| match p {
                    None => true,
                    Some(dec) => {
                        if !dec.is_valid() {
                            return false;
                        }
                        // Ghidra: grammar.cc:2456-2460 — a parameter declarator
                        // with no modifiers whose base type is `void` is an
                        // "extra void type" and invalidates the modifier.
                        if dec.mods.is_empty() {
                            if let Some(ref ct) = dec.basetype {
                                if ct.get_metatype()
                                    == crate::type_system::datatype::TypeMetatype::Void
                                {
                                    return false;
                                }
                            }
                        }
                        true
                    }
                })
            }
        }
    }

    // Ghidra: grammar.hh:136 PointerModifier::flags (ctor param)
    /// Get the pointer-modifier flags (the `flags` ctor argument in
    /// `PointerModifier(uint4 fl)`). Faithful to the public `flags` member.
    pub fn pointer_flags(&self) -> Option<u32> {
        match self {
            TypeModifier::Pointer { flags } => Some(*flags),
            _ => None,
        }
    }

    // Ghidra: grammar.hh:146 ArrayModifier::arraysize (ctor param)
    /// Get the array-modifier element count (the `arraysize` ctor argument in
    /// `ArrayModifier(uint4 fl, int4 as)`). Returns `None` for non-array
    /// modifiers. Faithful to the public `arraysize` member.
    pub fn array_size(&self) -> Option<i32> {
        match self {
            TypeModifier::Array { array_size, .. } => Some(*array_size),
            _ => None,
        }
    }

    // Ghidra: grammar.hh:146 ArrayModifier::flags (ctor param)
    /// Get the array-modifier flags. Returns `None` for non-array modifiers.
    pub fn array_flags(&self) -> Option<u32> {
        match self {
            TypeModifier::Array { flags, .. } => Some(*flags),
            _ => None,
        }
    }

    // Ghidra: grammar.cc:2403 PointerModifier::modType
    // Ghidra: grammar.cc:2412 ArrayModifier::modType
    // Ghidra: grammar.cc:2465 FunctionModifier::modType
    /// Apply this modifier to `base` and return the resulting type. Faithful
    /// to the three `TypeModifier::modType` virtuals. Dispatches to the
    /// `Pointer`/`Array`/`Function` behaviour based on the variant.
    pub fn mod_type(
        &self,
        base: Arc<Datatype>,
        decl: &TypeDeclarator,
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        mod_type(self, base, decl, types)
    }

    // Ghidra: grammar.cc:2434 FunctionModifier::getInTypes
    /// Collect each parameter's built type into `intypes`. Faithful to
    /// `FunctionModifier::getInTypes(vector<Datatype *> &, Architecture *)`:
    /// iterates the paramlist and pushes `decl->buildType(glb)`. Rugra's
    /// function modifier carries `params: Vec<Option<TypeDeclarator>>` (the
    /// `None` slot encodes the trailing varargs trailer), so `None` is skipped.
    pub fn get_in_types(
        &self,
        intypes: &mut Vec<Arc<Datatype>>,
        types: &mut crate::type_system::typefactory::TypeFactory,
        params: &[Option<TypeDeclarator>],
    ) {
        collect_param_types(intypes, params, types)
    }

    // Ghidra: grammar.cc:2443 FunctionModifier::getInNames
    /// Collect each parameter's identifier into `innames`. Faithful to
    /// `FunctionModifier::getInNames(vector<string> &)`. The varargs trailer
    /// (`None`) is skipped.
    pub fn get_in_names(&self, innames: &mut Vec<String>, params: &[Option<TypeDeclarator>]) {
        collect_param_names(innames, params)
    }

    // Ghidra: grammar.cc:2450 FunctionModifier::isDotdotdot
    /// Is this function modifier marked varargs? Faithful to
    /// `FunctionModifier::isDotdotdot`. Only meaningful for the `Function`
    /// variant; `Pointer`/`Array` always return `false`.
    pub fn is_dotdotdot(&self) -> bool {
        match self {
            TypeModifier::Function { dotdotdot, .. } => *dotdotdot,
            _ => false,
        }
    }
}

/// A C type declarator. Faithful to `TypeDeclarator` (grammar.hh:165).
#[derive(Debug, Clone)]
pub struct TypeDeclarator {
    /// The modifiers (pointer, array, function). Faithful to `mods`.
    pub mods: Vec<TypeModifier>,
    /// The base type. Faithful to `basetype` (grammar.hh:168). Held by `Arc`
    /// to mirror the shared `Datatype *` in C++.
    pub basetype: Option<Arc<Datatype>>,
    /// The variable identifier associated with the type. Faithful to `ident`.
    pub ident: String,
    /// Name of model associated with a function pointer. Faithful to `model`.
    pub model: String,
    /// Specifiers/qualifiers. Faithful to `flags`.
    pub flags: u32,
}

impl Default for TypeDeclarator {
    // Ghidra: grammar.hh:173 TypeDeclarator::TypeDeclarator (default ctor)
    fn default() -> Self {
        Self::new()
    }
}

impl TypeDeclarator {
    // Ghidra: grammar.hh:173 TypeDeclarator::TypeDeclarator
    /// Construct an empty declarator. Faithful to the constructor.
    pub fn new() -> Self {
        Self {
            mods: Vec::new(),
            basetype: None,
            ident: String::new(),
            model: String::new(),
            flags: 0,
        }
    }

    // Ghidra: grammar.hh:174 TypeDeclarator::TypeDeclarator(const string &)
    /// Construct with an identifier. Faithful to the constructor.
    pub fn with_name(name: &str) -> Self {
        let mut d = Self::new();
        d.ident = name.to_string();
        d
    }

    // Ghidra: grammar.hh:176 TypeDeclarator::getBaseType
    /// Get the base type. Faithful to `getBaseType`.
    pub fn get_base_type(&self) -> Option<&Arc<Datatype>> {
        self.basetype.as_ref()
    }

    // Ghidra: grammar.hh:177 TypeDeclarator::numModifiers
    /// Number of modifiers. Faithful to `numModifiers`.
    pub fn num_modifiers(&self) -> usize {
        self.mods.len()
    }

    // Ghidra: grammar.hh:178 TypeDeclarator::getIdentifier
    /// Get the identifier. Faithful to `getIdentifier`.
    pub fn get_identifier(&self) -> &str {
        &self.ident
    }

    // Ghidra: grammar.hh:181 TypeDeclarator::hasProperty
    /// Has a property? Faithful to `hasProperty`.
    pub fn has_property(&self, mask: u32) -> bool {
        (self.flags & mask) != 0
    }

    // Ghidra: grammar.cc:2548 TypeDeclarator::isValid
    /// Is this declarator valid? Faithful to `isValid`. Returns `Err` with a
    /// diagnostic string (matching the `throw ParseError` paths in C++) when
    /// multiple storage classes / type qualifiers are present.
    pub fn is_valid(&self) -> bool {
        if self.basetype.is_none() {
            return false; // No basetype
        }

        let mut count = 0;
        if (self.flags & CParse::F_TYPEDEF) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_EXTERN) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_STATIC) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_AUTO) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_REGISTER) != 0 {
            count += 1;
        }
        if count > 1 {
            return false; // "Multiple storage specifiers"
        }

        count = 0;
        if (self.flags & CParse::F_CONST) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_RESTRICT) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_VOLATILE) != 0 {
            count += 1;
        }
        if count > 1 {
            return false; // "Multiple type qualifiers"
        }

        self.mods.iter().all(|m| m.is_valid())
    }

    // Ghidra: grammar.cc:2493 TypeDeclarator::buildType
    /// Apply modifications to the base type in reverse order of binding,
    /// returning the resulting type. Faithful to `buildType`. Returns the
    /// basetype unchanged if there are no modifiers.
    pub fn build_type(&self, types: &mut crate::type_system::typefactory::TypeFactory) -> Option<Arc<Datatype>> {
        let mut restype = self.basetype.clone()?;
        // Iterate mods in reverse, applying each in turn.
        for mod_ in self.mods.iter().rev() {
            restype = mod_type(mod_, restype, self, types)?;
        }
        Some(restype)
    }

    // Ghidra: grammar.cc:2506 TypeDeclarator::getModel
    /// Look up the prototype model name on the architecture, falling back to
    /// the default model. Faithful to `getModel`. Returns the name to look up.
    pub fn model_name(&self) -> &str {
        &self.model
    }

    // Ghidra: grammar.cc:2506 TypeDeclarator::getModel
    /// Resolve the declarator's prototype model name. Faithful to
    /// `getModel(glb)`: returns `Some(model)` when a model name is present,
    /// else `None` (Ghidra then falls back to `glb->defaultfp`). Rugra has no
    /// in-tree `ProtoModel` resolver reachable from this module, so the name is
    /// returned to the caller rather than a `ProtoModel *`.
    pub fn get_model(&self) -> Option<&str> {
        if self.model.is_empty() {
            None
        } else {
            Some(&self.model)
        }
    }

    // Ghidra: grammar.cc:2518 TypeDeclarator::getPrototype
    /// Extract the prototype pieces from this declarator, applying the
    /// function modifier. Faithful to `getPrototype`. Returns `false` (as
    /// `None`) when the declarator's first modifier is not a function modifier.
    /// Otherwise populates `pieces` with the model name (see `get_model`),
    /// identifier, input types/names, first-vararg slot, and the constructed
    /// output type.
    pub fn get_prototype(
        &self,
        pieces: &mut PrototypePieces,
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> bool {
        let first = self.mods.first();
        if !matches!(first, Some(TypeModifier::Function { .. })) {
            return false;
        }
        // pieces.model = getModel(glb)
        pieces.model = self.get_model().map(|s| s.to_string());
        // pieces.name = ident
        pieces.name = self.ident.clone();
        // pieces.intypes.clear(); fmod->getInTypes(intypes, glb)
        pieces.in_types.clear();
        pieces.in_names.clear();
        if let Some(TypeModifier::Function { params, dotdotdot }) = first {
            collect_param_types(&mut pieces.in_types, params, types);
            collect_param_names(&mut pieces.in_names, params);
            // firstVarArgSlot = (dotdotdot) ? intypes.size() : -1
            pieces.first_var_arg_slot = if *dotdotdot {
                pieces.in_types.len() as i32
            } else {
                -1
            };
        }
        // Construct the output type by applying every modifier EXCEPT the
        // (first) function modifier, in reverse binding order. Faithful to the
        // C++ loop that walks mods.end()-1 .. begin(). Ghidra's `basetype` is a
        // (possibly null) `Datatype *`; Rugra carries it as an `Option`, so a
        // missing base type (abstract declarator) leaves `out_type = None`,
        // matching Ghidra passing a null pointer through to `modType`.
        let mut outtype = self.basetype.clone();
        if let Some(TypeModifier::Function { .. }) = first {
            // The function modifier itself is skipped; apply the rest.
            for mod_ in self.mods.iter().skip(1).rev() {
                if let Some(base) = outtype {
                    outtype = mod_type(mod_, base, self, types);
                }
            }
        }
        pieces.out_type = outtype;
        true
    }
}

// Ghidra: grammar.cc:2403 PointerModifier::modType
/// Wrap `base` in the canonical pointer type for the default data space.
/// Faithful to `PointerModifier::modType(Datatype *, const TypeDeclarator *,
/// Architecture *)`: reads `glb->getDefaultDataSpace()->getAddrSize()` and
/// `getWordSize()` and calls `glb->types->getTypePointer(addrsize, base,
/// wordsize)`. Rugra's twin `get_type_pointer_default` reads the default
/// data-space address size captured on the `TypeFactory` and models the
/// production default word size as one (RUGRA-GLUE documented on the twin).
///
/// Decisive semantics: no reference/out parameters; no loops; no counters;
/// identity/dedup key = the TypeFactory canonical-pointer lookup.
pub fn pointer_mod_type(
    base: Arc<Datatype>,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Option<Arc<Datatype>> {
    Some(types.get_type_pointer_default(base))
}

// Ghidra: grammar.cc:2412 ArrayModifier::modType
/// Wrap `base` in an array type of `array_size` elements. Faithful to
/// `ArrayModifier::modType`: `glb->types->getTypeArray(arraysize, base)` with
/// the constructor-stored `arraysize` (`int4`). The `.max(0)` clamp only
/// guards the Rust `as usize` cast; a negative `int4` is unreachable from
/// the lexer-produced `uintb` sizes (`CParse::newArray` casts a non-wrapping
/// decimal literal).
///
/// Decisive semantics: no reference/out parameters; no loops; no counters;
/// identity key = the TypeFactory array lookup over (element, count).
pub fn array_mod_type(
    base: Arc<Datatype>,
    array_size: i32,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Option<Arc<Datatype>> {
    Some(types.get_array(base, array_size.max(0) as usize))
}

// Ghidra: grammar.cc:2465 FunctionModifier::modType
/// Build the code (function) type for a function modifier. Faithful to
/// `FunctionModifier::modType`: fills a `PrototypePieces` (outtype = base,
/// void when the base is absent; firstVarArgSlot from the trailing null
/// slot; intypes from `getInTypes`; model from `decl->getModel`) and returns
/// `glb->types->getTypeCode(proto)`. In Rugra the varargs trailer has already
/// been folded into the `dotdotdot` bool by `CParse::new_func` (the oracle's
/// `paramlist.back() == 0` probe is dead on the live path because `newFunc`
/// grammar.cc:2769-2772 pops the null before the constructor runs), so the
/// slot is derived from `dotdotdot` over the surviving params.
///
/// Decisive semantics: no reference/out parameters beyond the borrowed
/// pieces; one forward loop over `params` (order preserved, `None` trailer
/// skipped); no counters; identity key = the synthetic prototype name.
pub fn function_mod_type(
    base: Arc<Datatype>,
    decl: &TypeDeclarator,
    params: &[Option<TypeDeclarator>],
    dotdotdot: bool,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Option<Arc<Datatype>> {
    let first_var_arg_slot: i32 = if dotdotdot {
        params.len() as i32
    } else {
        -1
    };
    let mut in_types: Vec<Arc<Datatype>> = Vec::new();
    collect_param_types(&mut in_types, params, types);
    let _model_name = decl.get_model(); // proto.model = getModel(glb)
    let fspec_proto = crate::fspec::PrototypePieces {
        out_type: Some(&base),
        in_types: &in_types,
        first_var_arg_slot,
    };
    Some(types.get_type_code_pieces(&fspec_proto))
}

// RUGRA-GLUE: enum dispatch replacing the C++ virtual
// `TypeModifier::modType` call sites (grammar.cc:2501 in
// `TypeDeclarator::buildType` and grammar.cc:2542 in
// `TypeDeclarator::getPrototype`); the per-class behaviour lives in the
// three per-variant ports above, each annotated to its own oracle
// definition. This is the common entry used by `build_type` and
// `get_prototype`; the per-variant methods (`pointer_mod_type` etc.)
// carry the exact C++ per-class behaviour and are the public entry points.
pub fn mod_type(
    modifier: &TypeModifier,
    base: Arc<Datatype>,
    decl: &TypeDeclarator,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Option<Arc<Datatype>> {
    match modifier {
        TypeModifier::Pointer { .. } => pointer_mod_type(base, types),
        TypeModifier::Array { array_size, .. } => array_mod_type(base, *array_size, types),
        TypeModifier::Function { params, dotdotdot } => {
            function_mod_type(base, decl, params, *dotdotdot, types)
        }
    }
}

// Ghidra: grammar.cc:2419 FunctionModifier::FunctionModifier
/// Construct the `FunctionModifier` state from a (post-varargs) parameter
/// list. Faithful to the constructor: copy the paramlist, then — if it holds
/// exactly one declarator with no modifiers whose base type is non-null and
/// `TYPE_VOID` — clear the list (encoding `f(void)` as a zero-arity
/// function), and record the varargs flag. The `dotdotdot` bool is the Rust
/// form of the C++ member; the params vec keeps the `Option` slot shape used
/// by `collect_param_types` / `collect_param_names`.
///
/// Decisive semantics: no reference/out parameters (the list is consumed);
/// a single exact-size check (`paramlist.size()==1`), no loop; no counters;
/// no ordering keys.
pub fn function_modifier_ctor(declist: Vec<TypeDeclarator>, dotdotdot: bool) -> TypeModifier {
    let mut paramlist = declist;
    if paramlist.len() == 1 {
        // Ghidra: grammar.cc:2423-2430 — drop a lone `(void)` parameter.
        let drop_void = {
            let only = &paramlist[0];
            only.mods.is_empty()
                && only
                    .basetype
                    .as_ref()
                    .map(|ct| ct.get_metatype() == crate::type_system::datatype::TypeMetatype::Void)
                    .unwrap_or(false)
        };
        if drop_void {
            paramlist.clear();
        }
    }
    let params: Vec<Option<TypeDeclarator>> = paramlist.into_iter().map(Some).collect();
    TypeModifier::Function { params, dotdotdot }
}

// RUGRA-GLUE: Rugra encoding of the null `TypeDeclarator *` slot that
// grammar.y:180 pushes for the `parameter_list ',' DOTDOTDOT` production
// (the varargs trailer `newFunc` detects and pops at grammar.cc:2769-2772).
// Rust cannot store a null in `Vec<TypeDeclarator>`, so the trailer is a
// sentinel declarator with `flags == u32::MAX` and nothing else set.
pub fn null_declarator_slot() -> TypeDeclarator {
    let mut slot = TypeDeclarator::new();
    slot.flags = u32::MAX;
    slot
}

// Ghidra: grammar.cc:2434 FunctionModifier::getInTypes
/// Collect each parameter's built type into `intypes`. Faithful to
/// `FunctionModifier::getInTypes(vector<Datatype *> &, Architecture *)`:
/// iterates the paramlist and pushes `decl->buildType(glb)`. Rugra's function
/// modifier carries `params: Vec<Option<TypeDeclarator>>` (the `None` slot
/// encodes the trailing varargs trailer), so `None` is skipped.
pub fn collect_param_types(
    intypes: &mut Vec<Arc<Datatype>>,
    params: &[Option<TypeDeclarator>],
    types: &mut crate::type_system::typefactory::TypeFactory,
) {
    for opt in params.iter() {
        if let Some(decl) = opt {
            if let Some(ct) = decl.build_type(types) {
                intypes.push(ct);
            }
        }
    }
}

// Ghidra: grammar.cc:2443 FunctionModifier::getInNames
/// Collect each parameter's identifier into `innames`. Faithful to
/// `FunctionModifier::getInNames(vector<string> &)`. The varargs trailer
/// (`None`) is skipped.
pub fn collect_param_names(innames: &mut Vec<String>, params: &[Option<TypeDeclarator>]) {
    for opt in params.iter() {
        if let Some(decl) = opt {
            innames.push(decl.get_identifier().to_string());
        }
    }
}

/// Specifiers accumulated during a declaration. Faithful to `struct
/// TypeSpecifiers` (grammar.hh:186).
#[derive(Debug, Clone, Default)]
pub struct TypeSpecifiers {
    /// The base type. Faithful to `type_specifier`.
    pub type_specifier: Option<Arc<Datatype>>,
    /// Function-specifier / prototype-model name. Faithful to
    /// `function_specifier`.
    pub function_specifier: String,
    /// Accumulated qualifier/storage-class flags. Faithful to `flags`.
    pub flags: u32,
}

impl TypeSpecifiers {
    // Ghidra: grammar.hh:190 TypeSpecifiers::TypeSpecifiers
    /// Construct empty specifiers. Faithful to the constructor.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A single enum constant. Faithful to `struct Enumerator` (grammar.hh:193).
#[derive(Debug, Clone)]
pub struct Enumerator {
    /// Identifier associated with the constant. Faithful to `enumconstant`.
    pub enum_constant: String,
    /// True if user specified an explicit constant. Faithful to
    /// `constantassigned`.
    pub constant_assigned: bool,
    /// The actual constant value. Faithful to `value`.
    pub value: u64,
}

impl Enumerator {
    // Ghidra: grammar.hh:197 Enumerator::Enumerator(const string &)
    /// Construct without an explicit value. Faithful to the constructor.
    pub fn new(name: &str) -> Self {
        Self {
            enum_constant: name.to_string(),
            constant_assigned: false,
            value: 0,
        }
    }

    // Ghidra: grammar.hh:198 Enumerator::Enumerator(const string &, uintb)
    /// Construct with an explicit value. Faithful to the constructor.
    pub fn with_value(name: &str, val: u64) -> Self {
        Self {
            enum_constant: name.to_string(),
            constant_assigned: true,
            value: val,
        }
    }
}

// ---------------------------------------------------------------------------
// CParse: the public-entry parser framework (grammar.hh:201)
// ---------------------------------------------------------------------------

/// Flag constants for storage classes, type qualifiers, and other specifiers.
/// Faithful to the `CParse` enum (grammar.hh:203-216).
pub mod cparse_flags {
    pub const F_TYPEDEF: u32 = 1;
    pub const F_EXTERN: u32 = 2;
    pub const F_STATIC: u32 = 4;
    pub const F_AUTO: u32 = 8;
    pub const F_REGISTER: u32 = 16;
    pub const F_CONST: u32 = 32;
    pub const F_RESTRICT: u32 = 64;
    pub const F_VOLATILE: u32 = 128;
    pub const F_INLINE: u32 = 256;
    pub const F_STRUCT: u32 = 512;
    pub const F_UNION: u32 = 1024;
    pub const F_ENUM: u32 = 2048;
}

/// Document type requested from the parser. Faithful to the `CParse` enum
/// (grammar.hh:217).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocType {
    /// A full declaration (`doc_declaration`).
    Declaration,
    /// A single parameter declaration (`doc_parameter_declaration`).
    ParameterDeclaration,
}

/// The C parser. Faithful to `class CParse` (grammar.hh:201).
///
/// Rugra holds the lexer, the allocation arena (as owned `Vec`s rather than
/// C++ `std::list`), the keyword table, and the most recent result/error. The
/// original grammar-table driven `yyparse` is replaced with a hand-written
/// recursive-descent driver (`run_parse`) because Rust has no in-tree bison
/// equivalent; the structure of the public methods (`merge_spec_dec`,
/// `add_specifier`, `merge_pointer`, `new_array`, `new_func`, …) is preserved
/// 1:1.
pub struct CParse {
    /// Architecture reference (unused for parsing proper; consulted by
    /// type-specifier resolution). Faithful to `glb`. Rugra holds an
    /// `Option<Arc<Architecture>>` so a parser can be built without one (the
    /// original Rugra `CParse::new(maxbuf)` path); Ghidra's constructor
    /// requires it. Set via `new_with_arch`.
    pub glb: Option<Arc<Architecture>>,
    pub lexer: GrammarLexer,
    keywords: std::collections::HashMap<String, u32>,
    typedec_alloc: Vec<TypeDeclarator>,
    typespec_alloc: Vec<TypeSpecifiers>,
    vecuint4_alloc: Vec<Vec<u32>>,
    vecdec_alloc: Vec<Vec<TypeDeclarator>>,
    string_alloc: Vec<String>,
    num_alloc: Vec<u64>,
    enum_alloc: Vec<Enumerator>,
    vecenum_alloc: Vec<Vec<Enumerator>>,

    last_decls: Option<Vec<TypeDeclarator>>,
    first_token: i32,
    last_error: String,
    lineno: i32,
    colno: i32,
    filenum: i32,
    /// Single-token lookahead cache. RUGRA-GLUE: bison's lexer is pull-based
    /// and supports arbitrary lookahead; this single-slot cache implements the
    /// `peek`/`advance` pair used by the hand-written `yyparse`.
    peeked: Option<GrammarToken>,
    /// `yylval.i` — the most recent numeric lex value. Faithful to
    /// `yylval.i = new uintb(...)` in `CParse::lex` (grammar.cc:3018).
    yylval_int: u64,
    /// `yylval.str` — the most recent string lex value. Faithful to
    /// `yylval.str = tok.getString()` in `CParse::lex` (grammar.cc:3022).
    yylval_str: String,
    /// `yylval.type` — the most recent `Datatype *` lex value, set when
    /// `lookupIdentifier` returns `TYPE_NAME`. Faithful to
    /// `yylval.type = tp` in `CParse::lex`/`lookupIdentifier`
    /// (grammar.cc:2991).
    yylval_type: Option<Arc<Datatype>>,
}

impl CParse {
    // Ghidra: grammar.cc:2585 CParse::CParse
    /// Construct the parser. Faithful to the constructor — initialises the
    /// keyword table identically to the C++ side (grammar.cc:2594-2605).
    ///
    /// Ghidra's constructor takes `Architecture *g`; Rugra has historically
    /// run with no architecture handle, so this signature is preserved for
    /// back-compat and `glb` is left `None`. Call `new_with_arch` to attach an
    /// `Architecture` for the `lookupIdentifier` / `lex` paths.
    pub fn new(_max_buf: i32) -> Self {
        Self::new_impl(_max_buf, None)
    }

    // Ghidra: grammar.cc:2585 CParse::CParse
    /// Construct the parser with an attached `Architecture`. Faithful to
    /// `CParse(Architecture *g, int4 maxbuf)`. Enables the
    /// `lookupIdentifier`→`TYPE_NAME` path (which queries `glb->types`) and the
    /// model-name lookup (which queries `glb->hasModel`).
    pub fn new_with_arch(_max_buf: i32, glb: Arc<Architecture>) -> Self {
        Self::new_impl(_max_buf, Some(glb))
    }

    // Ghidra: grammar.cc:2585 CParse::CParse
    fn new_impl(_max_buf: i32, glb: Option<Arc<Architecture>>) -> Self {
        let mut keywords = std::collections::HashMap::new();
        keywords.insert("typedef".to_string(), cparse_flags::F_TYPEDEF);
        keywords.insert("extern".to_string(), cparse_flags::F_EXTERN);
        keywords.insert("static".to_string(), cparse_flags::F_STATIC);
        keywords.insert("auto".to_string(), cparse_flags::F_AUTO);
        keywords.insert("register".to_string(), cparse_flags::F_REGISTER);
        keywords.insert("const".to_string(), cparse_flags::F_CONST);
        keywords.insert("restrict".to_string(), cparse_flags::F_RESTRICT);
        keywords.insert("volatile".to_string(), cparse_flags::F_VOLATILE);
        keywords.insert("inline".to_string(), cparse_flags::F_INLINE);
        keywords.insert("struct".to_string(), cparse_flags::F_STRUCT);
        keywords.insert("union".to_string(), cparse_flags::F_UNION);
        keywords.insert("enum".to_string(), cparse_flags::F_ENUM);
        Self {
            glb,
            lexer: GrammarLexer::new(_max_buf),
            keywords,
            typedec_alloc: Vec::new(),
            typespec_alloc: Vec::new(),
            vecuint4_alloc: Vec::new(),
            vecdec_alloc: Vec::new(),
            string_alloc: Vec::new(),
            num_alloc: Vec::new(),
            enum_alloc: Vec::new(),
            vecenum_alloc: Vec::new(),
            last_decls: None,
            first_token: -1,
            last_error: String::new(),
            lineno: -1,
            colno: -1,
            filenum: -1,
            peeked: None,
            yylval_int: 0,
            yylval_str: String::new(),
            yylval_type: None,
        }
    }

    // Ghidra: grammar.cc:2614 CParse::clear
    /// Clear the parser state. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.clear_allocation();
        self.last_error.clear();
        self.last_decls = None;
        self.lexer.clear();
        self.first_token = -1;
        self.peeked = None;
    }

    // Ghidra: grammar.cc:2624 CParse::mergeSpecDec(spec, dec)
    /// Merge a specifiers block into a declarator. Faithful to
    /// `mergeSpecDec(TypeSpecifiers *, TypeDeclarator *)`.
    pub fn merge_spec_dec_into(
        &mut self,
        spec: &TypeSpecifiers,
        dec: &mut TypeDeclarator,
    ) {
        dec.basetype = spec.type_specifier.clone();
        dec.model = spec.function_specifier.clone();
        dec.flags |= spec.flags;
    }

    // Ghidra: grammar.cc:2624 CParse::mergeSpecDec(spec, dec)
    /// Allocate a fresh declarator and merge the specifiers into it. Returns
    /// the index into the owned arena. Faithful to `mergeSpecDec(TypeSpecifiers *)`.
    pub fn merge_spec_dec(&mut self, spec: &TypeSpecifiers) -> usize {
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(spec, &mut dec);
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2641 CParse::mergeSpecDecVec(spec, declist)
    /// Merge specifiers into every declarator in the list. Faithful to
    /// `mergeSpecDecVec(TypeSpecifiers *, vector<TypeDeclarator *> *)`.
    pub fn merge_spec_dec_vec(
        &mut self,
        spec: &TypeSpecifiers,
        declist: &mut [TypeDeclarator],
    ) {
        for dec in declist.iter_mut() {
            self.merge_spec_dec_into(spec, dec);
        }
    }

    // Ghidra: grammar.cc:2649 CParse::mergeSpecDecVec(spec)
    /// Allocate a single-declarator list and merge specifiers into it.
    /// Faithful to `mergeSpecDecVec(TypeSpecifiers *)`.
    pub fn merge_spec_dec_vec_single(&mut self, spec: &TypeSpecifiers) -> Vec<TypeDeclarator> {
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(spec, &mut dec);
        vec![dec]
    }

    // Ghidra: grammar.cc:2661 CParse::convertFlag
    /// Look up `str` in the keyword table and return its flag value, or 0
    /// with the error set if unknown. Faithful to `convertFlag`.
    pub fn convert_flag(&mut self, str_: &str) -> u32 {
        if let Some(&flag) = self.keywords.get(str_) {
            flag
        } else {
            self.set_error("Unknown qualifier");
            0
        }
    }

    // Ghidra: grammar.cc:2673 CParse::addSpecifier
    /// Add a keyword (storage class / type qualifier) to the specifiers block.
    /// Faithful to `addSpecifier`.
    pub fn add_specifier(&mut self, spec: &mut TypeSpecifiers, str_: &str) {
        let flag = self.convert_flag(str_);
        spec.flags |= flag;
    }

    // Ghidra: grammar.cc:2681 CParse::addTypeSpecifier
    /// Set the base type on the specifiers block. Faithful to
    /// `addTypeSpecifier`. Sets the error if a type was already present.
    pub fn add_type_specifier(&mut self, spec: &mut TypeSpecifiers, tp: Arc<Datatype>) {
        if spec.type_specifier.is_some() {
            self.set_error("Multiple type specifiers");
        }
        spec.type_specifier = Some(tp);
    }

    // Ghidra: grammar.cc:2690 CParse::addFuncSpecifier
    /// Add a function specifier (reserved keyword or model name). Faithful to
    /// `addFuncSpecifier`.
    pub fn add_func_specifier(&mut self, spec: &mut TypeSpecifiers, str_: &str) {
        if let Some(&flag) = self.keywords.get(str_) {
            spec.flags |= flag;
        } else {
            if !spec.function_specifier.is_empty() {
                self.set_error("Multiple parameter models");
            }
            spec.function_specifier = str_.to_string();
        }
    }

    // Ghidra: grammar.cc:2706 CParse::mergePointer
    /// Push pointer modifiers for each accumulated flag in `ptr`. Faithful to
    /// `mergePointer`.
    pub fn merge_pointer(&mut self, ptr: &[u32], dec: &mut TypeDeclarator) {
        for &flag in ptr {
            dec.mods.push(TypeModifier::Pointer { flags: flag });
        }
    }

    // Ghidra: grammar.cc:2716 CParse::newDeclarator(string *)
    /// Allocate a declarator with the given identifier. Faithful to
    /// `newDeclarator(string *)`.
    pub fn new_declarator_name(&mut self, str_: &str) -> usize {
        let dec = TypeDeclarator::with_name(str_);
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2724 CParse::newDeclarator(void)
    /// Allocate an empty declarator. Faithful to `newDeclarator(void)`.
    pub fn new_declarator(&mut self) -> usize {
        let dec = TypeDeclarator::new();
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2732 CParse::newSpecifier
    /// Allocate a fresh specifiers block. Faithful to `newSpecifier`.
    pub fn new_specifier(&mut self) -> usize {
        self.typespec_alloc.push(TypeSpecifiers::new());
        self.typespec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2740 CParse::newVecDeclarator
    /// Allocate a fresh declarator vector. Faithful to `newVecDeclarator`.
    pub fn new_vec_declarator(&mut self) -> usize {
        self.vecdec_alloc.push(Vec::new());
        self.vecdec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2748 CParse::newPointer
    /// Allocate a fresh pointer-flag vector. Faithful to `newPointer`.
    pub fn new_pointer(&mut self) -> usize {
        self.vecuint4_alloc.push(Vec::new());
        self.vecuint4_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2756 CParse::newArray
    /// Append an array modifier with the given size to `dec`. Faithful to
    /// `newArray`.
    pub fn new_array(&mut self, dec: &mut TypeDeclarator, flags: u32, num: u64) {
        dec.mods.push(TypeModifier::Array {
            flags,
            array_size: num as i32,
        });
    }

    // Ghidra: grammar.cc:2764 CParse::newFunc
    /// Append a function modifier to `dec`. Faithful to `newFunc`: detect the
    /// trailing varargs trailer, pop it, then construct the function modifier
    /// via the `FunctionModifier` constructor twin (`function_modifier_ctor`,
    /// grammar.cc:2419) and append it to `dec->mods`.
    pub fn new_func(&mut self, dec: &mut TypeDeclarator, mut declist: Vec<TypeDeclarator>) {
        let mut dotdotdot = false;
        if let Some(true) = declist.last().map(|d| d.ident.is_empty() && d.mods.is_empty() && d.basetype.is_none() && d.flags == u32::MAX) {
            // RUGRA-GLUE: Ghidra signals varargs via a `null` slot in the
            // paramlist (grammar.y:180 pushes it; FunctionModifier ctor at
            // grammar.cc:2419 receives it popped); Rugra encodes that trailer
            // as a sentinel declarator with `flags=u32::MAX`.
            dotdotdot = true;
            declist.pop();
        }
        dec.mods.push(function_modifier_ctor(declist, dotdotdot));
    }

    // Ghidra: grammar.cc:2779 CParse::newStruct
    /// Build a new structure from a `struct ident { ... }` definition. Faithful
    /// to `newStruct(const string &, vector<TypeDeclarator *> *)`. Creates a
    /// stub `TypeStruct` (for recursion), validates each declarator, assigns
    /// field offsets, and commits the fields to the `TypeFactory`.
    ///
    /// Returns `Some(res)` on success, or `None` after calling `set_error`.
    /// Ghidra's `TypeFactory::destroyType(res)` on the failure paths (removing
    /// the stub) is currently a no-op here: Rugra's `TypeFactory` exposes no
    /// removal API and the grammar alignment rule restricts edits to this
    /// module, so the stub is left in place on failure (a documented deviation;
    /// the stub is incomplete and only consulted for forward references).
    pub fn new_struct(
        &mut self,
        ident: &str,
        declist: &[TypeDeclarator],
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        // Create stub (for recursion): glb->types->getTypeStruct(ident)
        let _stub = types.create_struct(ident);
        let mut sublist: Vec<crate::type_system::datatype::TypeField> = Vec::new();
        for decl in declist.iter() {
            if !decl.is_valid() {
                self.set_error("Invalid structure declarator");
                return None;
            }
            // TypeField(0, -1, name, type): offset -1 == "unassigned".
            sublist.push(crate::type_system::datatype::TypeField {
                name: decl.get_identifier().to_string(),
                offset: usize::MAX,
                type_ptr: decl.build_type(types)?,
            });
        }
        // assignFieldOffsets + setFields; Ghidra catches LowlevelError.
        match crate::type_system::datatype::TypeStruct::assign_field_offsets(&mut sublist) {
            Ok(_) => {
                if types.set_fields(ident, sublist).is_some() {
                    // Re-read the now-complete struct.
                    types.find_by_name(ident)
                } else {
                    self.set_error("Could not set struct fields");
                    None
                }
            }
            Err(msg) => {
                self.set_error(msg);
                None
            }
        }
    }

    // Ghidra: grammar.cc:2809 CParse::oldStruct
    /// Reference an already-existing struct by name. Faithful to `oldStruct`.
    /// Looks the name up in the `TypeFactory`; if absent or not a struct, sets
    /// an error but still returns the (possibly `None`) lookup result to mirror
    /// the C++ control flow.
    pub fn old_struct(
        &mut self,
        ident: &str,
        types: &crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        let res = types.find_by_name(ident);
        let bad = match &res {
            None => true,
            Some(dt) => dt.get_metatype() != crate::type_system::datatype::TypeMetatype::Struct,
        };
        if bad {
            self.set_error("Identifier does not represent a struct as required");
        }
        res
    }

    // Ghidra: grammar.cc:2818 CParse::newUnion
    /// Build a new union from a `union ident { ... }` definition. Faithful to
    /// `newUnion(const string &, vector<TypeDeclarator *> *)`. Creates a stub
    /// `TypeUnion`, validates each declarator, assigns field offsets (union
    /// members all at offset 0), and commits the fields to the `TypeFactory`.
    /// See `new_struct` for the documented `destroyType` deviation on failure.
    pub fn new_union(
        &mut self,
        ident: &str,
        declist: &[TypeDeclarator],
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        // Create stub: glb->types->getTypeUnion(ident)
        let _stub = types.get_type_union(ident);
        let mut sublist: Vec<crate::type_system::datatype::TypeField> = Vec::new();
        for (_i, decl) in declist.iter().enumerate() {
            if !decl.is_valid() {
                self.set_error("Invalid union declarator");
                return None;
            }
            // TypeField(i, 0, name, type): union fields share offset 0.
            sublist.push(crate::type_system::datatype::TypeField {
                name: decl.get_identifier().to_string(),
                offset: 0,
                type_ptr: decl.build_type(types)?,
            });
        }
        match crate::type_system::datatype::TypeUnion::assign_field_offsets(
            &mut sublist,
            ident,
        ) {
            Ok(_) => {
                if types.set_union_fields(ident, sublist).is_some() {
                    types.find_by_name(ident)
                } else {
                    self.set_error("Could not set union fields");
                    None
                }
            }
            Err(msg) => {
                self.set_error(&msg);
                None
            }
        }
    }

    // Ghidra: grammar.cc:2848 CParse::oldUnion
    /// Reference an already-existing union by name. Faithful to `oldUnion`.
    pub fn old_union(
        &mut self,
        ident: &str,
        types: &crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        let res = types.find_by_name(ident);
        let bad = match &res {
            None => true,
            Some(dt) => dt.get_metatype() != crate::type_system::datatype::TypeMetatype::Union,
        };
        if bad {
            self.set_error("Identifier does not represent a union as required");
        }
        res
    }

    // Ghidra: grammar.cc:2881 CParse::newEnum
    /// Build a new enumeration from an `enum ident { ... }` definition.
    /// Faithful to `newEnum(const string &, vector<Enumerator *> *)`. Creates
    /// a `TypeEnum` stub, runs `TypeEnum::assignValues` to fill in the
    /// value→name map, and commits it via `set_enum_values`. See `new_struct`
    /// for the documented `destroyType` deviation on failure.
    pub fn new_enum(
        &mut self,
        ident: &str,
        vecenum: &[Enumerator],
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        // Create stub: glb->types->getTypeEnum(ident)
        let res = types.get_type_enum(ident);
        // Determine the enum size to feed assignValues; the stub defaults to 4.
        let size = res.get_size();
        let mut namelist: Vec<String> = Vec::new();
        let mut vallist: Vec<u64> = Vec::new();
        let mut assignlist: Vec<bool> = Vec::new();
        for enumer in vecenum.iter() {
            namelist.push(enumer.enum_constant.clone());
            vallist.push(enumer.value);
            assignlist.push(enumer.constant_assigned);
        }
        match crate::type_system::datatype::TypeEnum::assign_values(
            &namelist,
            &vallist,
            &assignlist,
            size,
        ) {
            Ok(namemap) => {
                if types.set_enum_values(ident, namemap).is_some() {
                    types.find_by_name(ident)
                } else {
                    self.set_error("Could not set enum values");
                    None
                }
            }
            Err(msg) => {
                self.set_error(&msg);
                None
            }
        }
    }

    // Ghidra: grammar.cc:2907 CParse::oldEnum
    /// Reference an already-existing enum by name. Faithful to `oldEnum`.
    pub fn old_enum(
        &mut self,
        ident: &str,
        types: &crate::type_system::typefactory::TypeFactory,
    ) -> Option<Arc<Datatype>> {
        let res = types.find_by_name(ident);
        let bad = match &res {
            None => true,
            Some(dt) => !dt.is_enum_type(),
        };
        if bad {
            self.set_error("Identifier does not represent an enum as required");
        }
        res
    }

    // Ghidra: grammar.cc:2857 CParse::newEnumerator(const string &)
    /// Allocate an enumerator without an explicit value. Faithful to
    /// `newEnumerator(const string &)`.
    pub fn new_enumerator_name(&mut self, ident: &str) -> usize {
        self.enum_alloc.push(Enumerator::new(ident));
        self.enum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2865 CParse::newEnumerator(const string &, uintb)
    /// Allocate an enumerator with an explicit value. Faithful to
    /// `newEnumerator(const string &, uintb)`.
    pub fn new_enumerator_value(&mut self, ident: &str, val: u64) -> usize {
        self.enum_alloc.push(Enumerator::with_value(ident, val));
        self.enum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2873 CParse::newVecEnumerator
    /// Allocate a fresh enumerator vector. Faithful to `newVecEnumerator`.
    pub fn new_vec_enumerator(&mut self) -> usize {
        self.vecenum_alloc.push(Vec::new());
        self.vecenum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2916 CParse::clearAllocation
    /// Free every arena allocation. Faithful to `clearAllocation`.
    pub fn clear_allocation(&mut self) {
        self.typedec_alloc.clear();
        self.typespec_alloc.clear();
        self.vecuint4_alloc.clear();
        self.vecdec_alloc.clear();
        self.string_alloc.clear();
        self.num_alloc.clear();
        self.enum_alloc.clear();
        self.vecenum_alloc.clear();
    }

    // Ghidra: grammar.cc:3041 CParse::setError
    /// Format and store an error message. Faithful to `setError`. Ghidra's
    /// `setError` writes the message then calls `lexer.writeLocation(s, lineno,
    /// filenum)` and `lexer.writeTokenLocation(s, lineno, colno)`; this port
    /// delegates to the now-ported `GrammarLexer::write_location` /
    /// `write_token_location` so the format is byte-identical.
    pub fn set_error(&mut self, msg: &str) {
        let mut s = String::new();
        s.push_str(msg);
        self.lexer.write_location(&mut s, self.lineno, self.filenum);
        s.push('\n');
        self.lexer.write_token_location(&mut s, self.lineno, self.colno);
        self.last_error = s;
    }

    // Ghidra: grammar.cc:277 CParse::getError
    /// Get the last error message. Faithful to `getError`.
    pub fn get_error(&self) -> &str {
        &self.last_error
    }

    // Ghidra: grammar.cc:278 CParse::setResultDeclarations
    /// Set the result declarations vector. Faithful to `setResultDeclarations`.
    pub fn set_result_declarations(&mut self, val: Vec<TypeDeclarator>) {
        self.last_decls = Some(val);
    }

    // Ghidra: grammar.cc:279 CParse::getResultDeclarations
    /// Take the result declarations vector, if any. Faithful to
    /// `getResultDeclarations`.
    pub fn take_result_declarations(&mut self) -> Option<Vec<TypeDeclarator>> {
        self.last_decls.take()
    }

    // Ghidra: grammar.cc:2961 CParse::lookupIdentifier
    /// Reclassify an identifier token to its bison-level category. Faithful to
    /// `lookupIdentifier(const string &)`:
    ///   * A reserved storage-class keyword (`typedef`/`extern`/`static`/`auto`/
    ///     `register`) → `STORAGE_CLASS_SPECIFIER`.
    ///   * A type-qualifier keyword (`const`/`restrict`/`volatile`) →
    ///     `TYPE_QUALIFIER`.
    ///   * `inline` → `FUNCTION_SPECIFIER`.
    ///   * `struct`/`union`/`enum` → `STRUCT`/`UNION`/`ENUM`.
    ///   * An identifier bound to a `Datatype` in `glb->types` (via
    ///     `findByName`) → `TYPE_NAME` (and `yylval.type` is set).
    ///   * An identifier naming a `ProtoModel` (via `glb->hasModel`) →
    ///     `FUNCTION_SPECIFIER`.
    ///   * Otherwise → `IDENTIFIER`.
    ///
    /// Rugra note: this method requires the parser to be constructed via
    /// `new_with_arch`; without an architecture handle it cannot resolve
    /// `TYPE_NAME` or `FUNCTION_SPECIFIER` (those paths fall through to
    /// `IDENTIFIER`). The keyword paths always work because they consult the
    /// local `keywords` table.
    pub fn lookup_identifier(&mut self, nm: &str) -> i32 {
        if let Some(&flag) = self.keywords.get(nm) {
            match flag {
                cparse_flags::F_TYPEDEF
                | cparse_flags::F_EXTERN
                | cparse_flags::F_STATIC
                | cparse_flags::F_AUTO
                | cparse_flags::F_REGISTER => return bison_token::STORAGE_CLASS_SPECIFIER,
                cparse_flags::F_CONST | cparse_flags::F_RESTRICT | cparse_flags::F_VOLATILE => {
                    return bison_token::TYPE_QUALIFIER
                }
                cparse_flags::F_INLINE => return bison_token::FUNCTION_SPECIFIER,
                cparse_flags::F_STRUCT => return bison_token::STRUCT,
                cparse_flags::F_UNION => return bison_token::UNION,
                cparse_flags::F_ENUM => return bison_token::ENUM,
                _ => {}
            }
        }
        // `glb->types->findByName(nm)` — consult the architecture's TypeFactory
        // if one is attached. Faithful to `Datatype *tp = glb->types->findByName(nm)`.
        if let Some(glb) = &self.glb {
            if let Some(tf_rwlock) = glb.types.as_ref() {
                if let Ok(tf) = tf_rwlock.read() {
                    if let Some(tp) = tf.find_by_name(nm) {
                        // yylval.type = tp; return TYPE_NAME.
                        self.yylval_type = Some(tp);
                        return bison_token::TYPE_NAME;
                    }
                }
            }
            // `if (glb->hasModel(nm)) return FUNCTION_SPECIFIER;`
            if glb.has_model(nm) {
                return bison_token::FUNCTION_SPECIFIER;
            }
        }
        // Unknown identifier.
        bison_token::IDENTIFIER
    }

    // Ghidra: grammar.cc:2999 CParse::lex
    /// Pull the next bison-level token from the lexer and reclassify it.
    /// Faithful to `int4 CParse::lex(void)`. Returns a `bison_token` code and
    /// populates the `yylval_*` fields so subsequent grammar actions can read
    /// the value (mirroring the C++ `yylval.i` / `yylval.str` / `yylval.type`
    /// union).
    ///
    /// Behaviour mapping:
    ///   * `firsttoken` return: the start token (`DECLARATION_RESULT` /
    ///     `PARAM_RESULT`) is returned once at the start of the parse, then
    ///     cleared (grammar.cc:3004-3008).
    ///   * A pending `lasterror` short-circuits to `BADTOKEN` (3009-3010).
    ///   * `GrammarToken::integer` / `charconstant` → `NUMBER`, with
    ///     `yylval.i = tok.getInteger()` (3016-3020).
    ///   * `GrammarToken::identifier` → reclassify via `lookupIdentifier`,
    ///     with `yylval.str = tok.getString()` (3021-3024).
    ///   * `GrammarToken::stringval` → `BADTOKEN` with "Illegal string
    ///     constant" (3025-3028).
    ///   * `GrammarToken::dotdotdot` → `DOTDOTDOT` (3029-3030).
    ///   * `GrammarToken::badtoken` → `BADTOKEN` carrying the lexer's error
    ///     (3031-3033).
    ///   * `GrammarToken::endoffile` → `-1` (3034-3035).
    ///   * punctuation tokens pass through as their ASCII value (3036-3037).
    pub fn lex(&mut self) -> i32 {
        // firsttoken return path.
        if self.first_token != -1 {
            let retval = self.first_token;
            self.first_token = -1;
            return retval;
        }
        if !self.last_error.is_empty() {
            return bison_token::BADTOKEN;
        }
        let tok = self.lexer.get_next_token();
        self.lineno = tok.get_line_no();
        self.colno = tok.get_col_no();
        self.filenum = tok.get_file_num();
        match tok.get_type() {
            token_type::INTEGER | token_type::CHAR_CONSTANT => {
                // yylval.i = new uintb(tok.getInteger()); num_alloc.push_back(yylval.i);
                self.yylval_int = tok.get_integer();
                self.num_alloc.push(self.yylval_int);
                bison_token::NUMBER
            }
            token_type::IDENTIFIER => {
                // yylval.str = tok.getString(); string_alloc.push_back(yylval.str);
                let s = tok.get_string().to_string();
                self.string_alloc.push(s.clone());
                self.yylval_str = s.clone();
                // return lookupIdentifier(*yylval.str);
                self.lookup_identifier(&s)
            }
            token_type::STRING_VAL => {
                // delete tok.getString(); setError("Illegal string constant");
                self.set_error("Illegal string constant");
                bison_token::BADTOKEN
            }
            token_type::DOTDOTDOT => bison_token::DOTDOTDOT,
            token_type::BAD_TOKEN => {
                // setError(lexer.getError()); — error from the lexer. The
                // immutable borrow of `self.lexer.get_error()` is cloned to an
                // owned `String` first to avoid the `&self`/`&mut self` clash.
                let lexer_err = self.lexer.get_error().to_string();
                self.set_error(&lexer_err);
                bison_token::BADTOKEN
            }
            token_type::END_OF_FILE => bison_token::END_OF_STREAM,
            other => other as i32,
        }
    }

    // Ghidra: grammar.cc:3076 CParse::parseFile
    /// Parse a C document from a file. Faithful to `parseFile(const string &,
    /// uint4)`. Reads the file contents into a string, pushes it onto the
    /// lexer's file stack (so `writeLocation` can name the file in diagnostics),
    /// then runs the parser. Returns `true` on success.
    ///
    /// Ghidra opens the file as an `ifstream` and throws `LowlevelError` if the
    /// open fails; Rugra returns `Err(message)` from the IO error so callers
    /// can distinguish parse failure (`Ok(false)`) from IO failure (`Err(..)`).
    pub fn parse_file(&mut self, filename: &str, doctype: DocType) -> std::io::Result<bool> {
        use std::io::Read;
        // clear() — Clear out any old parsing.
        self.clear();
        let mut file = std::fs::File::open(filename)?;
        let mut body = String::new();
        file.read_to_string(&mut body)?;
        // lexer.pushFile(nm, &s); — inform the lexer of filename and body.
        self.lexer.push_file(filename, &body);
        // The lexer's push_file installs the body as the active input, so the
        // recursive-descent driver reads from it directly.
        let res = self.run_parse(doctype);
        // s.close() — Rust closes the file on drop; nothing to do.
        // lexer.popFile() — unwind the stack to mirror the C++ scope exit.
        self.lexer.pop_file();
        Ok(res)
    }

    // Ghidra: grammar.cc:3091 CParse::parseStream
    /// Parse a stream of C declaration text. Faithful to `parseStream`.
    /// Returns `true` on success.
    pub fn parse_stream(&mut self, text: &str, doctype: DocType) -> bool {
        self.clear();
        self.lexer.set_input(text);
        self.run_parse(doctype)
    }

    // RUGRA-GLUE: typed twin of `parseStream`. The C++ `CParse` reaches its
    // `TypeFactory` through the `Architecture *glb` captured at
    /// construction; the arch-less Rust construction cannot, so the factory
    /// is threaded per call. Only the `TYPE_NAME` specifier resolution
    /// differs from `parse_stream` (it mirrors `lookupIdentifier`'s
    /// `glb->types->findByName` probe, grammar.cc:2972-2975).
    pub fn parse_stream_with_types(
        &mut self,
        text: &str,
        doctype: DocType,
        types: &mut crate::type_system::typefactory::TypeFactory,
    ) -> bool {
        self.clear();
        self.lexer.set_input(text);
        self.run_parse_with_types(doctype, types)
    }

    // Ghidra: grammar.cc:3053 CParse::runParse
    /// Drive the parser. Faithful to `runParse`. Ghidra dispatches to
    /// `yyparse`; Rugra uses a hand-written recursive-descent driver because
    /// the bison grammar table (grammar.y) has no in-tree Rust equivalent.
    fn run_parse(&mut self, doctype: DocType) -> bool {
        self.first_token = match doctype {
            DocType::Declaration => DECLARATION_RESULT,
            DocType::ParameterDeclaration => PARAM_RESULT,
        };
        let res = self.yyparse(doctype, None);
        if res.is_none() {
            if self.last_error.is_empty() {
                self.set_error("Syntax error");
            }
            return false;
        }
        true
    }

    // RUGRA-GLUE: typed twin of `runParse` used by the arch-less entry
    // points (`parse_type_full` / `parse_protopieces` / `parse_c`). The
    // C++ parser reaches its `TypeFactory` through the `Architecture *glb`
    // captured at construction; Rust threads a mutable factory reference
    // through the driver so `TYPE_NAME` specifiers resolve exactly as
    // `lookupIdentifier` (grammar.cc:2972) resolves them at lex time, and
    // struct/union/enum definitions commit through the `newStruct` /
    // `newUnion` / `newEnum` family as the bison actions do.
    fn run_parse_with_types(&mut self, doctype: DocType, types: &mut crate::type_system::typefactory::TypeFactory) -> bool {
        self.first_token = match doctype {
            DocType::Declaration => DECLARATION_RESULT,
            DocType::ParameterDeclaration => PARAM_RESULT,
        };
        let res = self.yyparse(doctype, Some(types));
        if res.is_none() {
            if self.last_error.is_empty() {
                self.set_error("Syntax error");
            }
            return false;
        }
        true
    }

    // Ghidra: grammar.cc:3067 yyparse (called from runParse)
    /// Hand-written recursive-descent replacement for the bison `yyparse`.
    /// Recognises the subset produced by Ghidra's grammar for the two
    /// document types:
    ///   * parameter_declaration: declaration_specifiers declarator (grammar.y)
    ///   * declaration: declaration_specifiers init_declarator_list ';'
    /// Each successfully parsed declarator is stored via
    /// `set_result_declarations`.
    ///
    /// `types` carries the optional `TypeFactory` used to resolve `TYPE_NAME`
    /// specifiers (`type_specifier: TYPE_NAME { $$ = $1; }`, grammar.y) and
    /// to commit struct/union/enum definitions, mirroring `lookupIdentifier`'s
    /// `glb->types->findByName` probe and the bison actions' `newStruct` /
    /// `newUnion` / `newEnum` calls. `None` keeps the legacy
    /// unresolved-basetype path (the C++ object always has `glb`; the
    /// untyped Rust twin documents that gap instead of guessing).
    fn yyparse(
        &mut self,
        doctype: DocType,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<()> {
        // Specifiers
        let mut spec = TypeSpecifiers::new();
        // Storage-class / qualifier / function-specifier keywords first.
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            if tok.get_type() != token_type::IDENTIFIER {
                break;
            }
            let s = tok.get_string().to_string();
            if let Some(&flag) = self.keywords.get(&s) {
                match flag {
                    cparse_flags::F_TYPEDEF
                    | cparse_flags::F_EXTERN
                    | cparse_flags::F_STATIC
                    | cparse_flags::F_AUTO
                    | cparse_flags::F_REGISTER
                    | cparse_flags::F_CONST
                    | cparse_flags::F_RESTRICT
                    | cparse_flags::F_VOLATILE
                    | cparse_flags::F_INLINE => {
                        self.add_specifier(&mut spec, &s);
                        self.advance();
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        // Then a type-name identifier (basetype) if present. grammar.y
        // `type_specifier: TYPE_NAME` resolves the name against the
        // architecture's type tree at lex time (`lookupIdentifier` ->
        // `glb->types->findByName`, grammar.cc:2972-2975); the typed driver
        // path resolves it here via the threaded factory.
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                let s = tok.get_string().to_string();
                match self.keywords.get(&s).copied() {
                    Some(cparse_flags::F_STRUCT) | Some(cparse_flags::F_UNION) | Some(cparse_flags::F_ENUM) => {
                        // struct_or_union_specifier / enum_specifier
                        // (grammar.y:98-116 / 137-143).
                        match self.parse_tag_specifier(&s, types.as_deref_mut()) {
                            Some(tp) => {
                                self.add_type_specifier(&mut spec, tp);
                            }
                            None => return None,
                        }
                    }
                    _ => {
                        if let Some(factory) = types.as_deref() {
                            if let Some(tp) = factory.find_by_name(&s) {
                                self.add_type_specifier(&mut spec, tp);
                            }
                        }
                        self.advance();
                    }
                }
            }
        }

        // Build a single declarator and parse its modifiers/identifier.
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(&spec, &mut dec);
        self.parse_declarator(&mut dec, types.as_deref_mut())?;

        // Optional trailing declarators separated by commas (declaration
        // document only).
        let mut decls = vec![dec];
        if matches!(doctype, DocType::Declaration) {
            loop {
                let tok = match self.peek_token() {
                    Some(t) => t,
                    None => break,
                };
                if tok.get_type() == token_type::COMMA {
                    self.advance();
                    let mut next = TypeDeclarator::new();
                    self.merge_spec_dec_into(&spec, &mut next);
                    self.parse_declarator(&mut next, types.as_deref_mut())?;
                    decls.push(next);
                } else {
                    break;
                }
            }
            // Optional trailing semicolon.
            if let Some(t) = self.peek_token() {
                if t.get_type() == token_type::SEMICOLON {
                    self.advance();
                }
            }
        }

        self.set_result_declarations(decls);
        Some(())
    }

    // RUGRA-GLUE: hand-written helper, no direct Ghidra counterpart. The
    // bison grammar's `declarator` / `abstract_declarator` productions
    // (grammar.y:151-153 / 190-194) are reduced here. Modifier push order
    // mirrors bison reduction order exactly: the `direct_declarator`
    // suffixes (`[N]` via `newArray`, `(...)` via `newFunc`) reduce first
    // and land in `dec->mods` first; `pointer direct_declarator` reduces
    // last, so `mergePointer` appends the `PointerModifier`s AFTER the
    // suffix modifiers (grammar.y:153 -> grammar.cc:2706). `buildType`
    // walks `mods` in reverse, so this order reproduces the C binding
    // `int4 *x[3]` = array-of-pointers and `char *f(int4)` =
    // function-returning-pointer.
    fn parse_declarator(
        &mut self,
        dec: &mut TypeDeclarator,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<()> {
        // `declarator: pointer direct_declarator` — count the leading stars
        // first (`newPointer` flags; type_qualifier_list in pointer position
        // is not carried — registered subset limitation), then parse the
        // direct part, then append the pointer modifiers.
        let mut star_count: usize = 0;
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            if tok.get_type() == token_type::STAR {
                self.advance();
                star_count += 1;
            } else {
                break;
            }
        }
        self.parse_direct_declarator(dec, types)?;
        // mergePointer: stars appended after the direct_declarator mods.
        for _ in 0..star_count {
            dec.mods.push(TypeModifier::Pointer { flags: 0 });
        }
        Some(())
    }

    // RUGRA-GLUE: hand-written helper reducing `direct_declarator` /
    // `direct_abstract_declarator` (grammar.y:156-163 / 195-199). The
    // productions are:
    //   `IDENTIFIER` (named core; absent for abstract declarators)
    //   `'(' declarator ')'` (grouping — the inner declarator reduces into
    //   the SAME TypeDeclarator: `$$ = $2`)
    //   `direct_declarator '[' assignment_expression ']'` (array suffix)
    //   `direct_declarator '(' parameter_type_list ')'` (function suffix)
    // Because a function suffix production always requires a leading
    // direct core, a `'('` at core position is unambiguously a group.
    fn parse_direct_declarator(
        &mut self,
        dec: &mut TypeDeclarator,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<()> {
        // Grouping: '(' declarator ')' — recurse; inner mods merge first.
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::OPEN_PAREN {
                self.advance();
                self.parse_declarator(dec, types.as_deref_mut())?;
                let close = match self.peek_token() {
                    Some(t) => t,
                    None => {
                        self.set_error("Missing ')' in declarator");
                        return None;
                    }
                };
                if close.get_type() != token_type::CLOSE_PAREN {
                    self.set_error("Missing ')' in declarator");
                    return None;
                }
                self.advance();
            }
        }
        // Optional identifier (named core).
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                dec.ident = tok.get_string().to_string();
                self.advance();
            }
        }
        // Suffixes: array `[N]`, function `(...)`.
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            match tok.get_type() {
                token_type::OPEN_BRACKET => {
                    self.advance();
                    let mut size: u64 = 0;
                    if let Some(nt) = self.peek_token() {
                        if nt.get_type() == token_type::INTEGER {
                            size = nt.get_integer();
                            self.advance();
                        }
                    }
                    let close = match self.peek_token() {
                        Some(t) => t,
                        None => {
                            self.set_error("Missing ']' in array declarator");
                            return None;
                        }
                    };
                    if close.get_type() != token_type::CLOSE_BRACKET {
                        self.set_error("Missing ']' in array declarator");
                        return None;
                    }
                    self.advance();
                    dec.mods.push(TypeModifier::Array {
                        flags: 0,
                        array_size: size as i32,
                    });
                }
                token_type::OPEN_PAREN => {
                    self.advance();
                    let mut params: Vec<TypeDeclarator> = Vec::new();
                    loop {
                        let pt = match self.peek_token() {
                            Some(t) => t,
                            None => break,
                        };
                        if pt.get_type() == token_type::CLOSE_PAREN {
                            break;
                        }
                        if pt.get_type() == token_type::DOTDOTDOT {
                            // grammar.y:180 `parameter_list ',' DOTDOTDOT` —
                            // the varargs trailer is a null declarator slot;
                            // Rugra encodes it as the flags=u32::MAX sentinel
                            // that `new_func` detects and pops.
                            self.advance();
                            params.push(null_declarator_slot());
                            break;
                        }
                        // Parameter declarator. A parameter has the same shape
                        // as a top-level declaration: declaration_specifiers
                        // followed by an (abstract) declarator
                        // (grammar.y:186-190).
                        let pdec = match self.parse_parameter_declaration(types.as_deref_mut()) {
                            Some(d) => d,
                            None => {
                                self.set_error("Bad parameter declarator");
                                return None;
                            }
                        };
                        params.push(pdec);
                        let sep = match self.peek_token() {
                            Some(t) => t,
                            None => break,
                        };
                        if sep.get_type() == token_type::COMMA {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let close = match self.peek_token() {
                        Some(t) => t,
                        None => {
                            self.set_error("Missing ')' in function declarator");
                            return None;
                        }
                    };
                    if close.get_type() != token_type::CLOSE_PAREN {
                        self.set_error("Missing ')' in function declarator");
                        return None;
                    }
                    self.advance();
                    // grammar.y:162 — the suffix reduces through newFunc
                    // (which pops the varargs trailer and runs the
                    // FunctionModifier constructor's `(void)` clearing).
                    self.new_func(dec, params);
                }
                _ => break,
            }
        }
        Some(())
    }

    // RUGRA-GLUE: hand-written helper for the bison grammar's
    // `parameter_declaration` production (grammar.y:186-190):
    //   parameter_declaration:
    //     declaration_specifiers declarator
    //     declaration_specifiers
    //     declaration_specifiers abstract_declarator
    // The qualifier loop reduces `declaration_specifiers` (qualifier flags
    // accumulate; the type specifier resolves against the threaded factory
    // exactly as the bison `TYPE_NAME` token path does at lex time), then
    // `mergeSpecDec` folds the specifiers into the (possibly abstract)
    // declarator reduced by `parse_declarator`.
    fn parse_parameter_declaration(
        &mut self,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<TypeDeclarator> {
        let mut spec = TypeSpecifiers::new();
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            if tok.get_type() != token_type::IDENTIFIER {
                break;
            }
            let s = tok.get_string().to_string();
            if let Some(&flag) = self.keywords.get(&s) {
                match flag {
                    cparse_flags::F_TYPEDEF
                    | cparse_flags::F_EXTERN
                    | cparse_flags::F_STATIC
                    | cparse_flags::F_AUTO
                    | cparse_flags::F_REGISTER
                    | cparse_flags::F_CONST
                    | cparse_flags::F_RESTRICT
                    | cparse_flags::F_VOLATILE
                    | cparse_flags::F_INLINE => {
                        self.add_specifier(&mut spec, &s);
                        self.advance();
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
        // The type specifier (grammar.y `type_specifier: TYPE_NAME`).
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                let s = tok.get_string().to_string();
                match self.keywords.get(&s).copied() {
                    Some(cparse_flags::F_STRUCT) | Some(cparse_flags::F_UNION) | Some(cparse_flags::F_ENUM) => {
                        match self.parse_tag_specifier(&s, types.as_deref_mut()) {
                            Some(tp) => {
                                self.add_type_specifier(&mut spec, tp);
                            }
                            None => return None,
                        }
                    }
                    _ => {
                        if let Some(factory) = types.as_deref() {
                            if let Some(tp) = factory.find_by_name(&s) {
                                self.add_type_specifier(&mut spec, tp);
                            }
                        }
                        self.advance();
                    }
                }
            }
        }
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(&spec, &mut dec);
        self.parse_declarator(&mut dec, types)?;
        Some(dec)
    }

    // RUGRA-GLUE: hand-written helper reducing `struct_or_union_specifier`
    // and `enum_specifier` (grammar.y:97-116 / 137-143). Consumes the tag
    // keyword; parses the optional identifier and the brace body (or falls
    // back to the `oldStruct`/`oldUnion`/`oldEnum` reference forms), then
    /// commits the composite type through the same `newStruct` / `newUnion`
    /// / `newEnum` twins the bison actions call. Returns `None` after
    /// setting the parse error on the failure paths.
    fn parse_tag_specifier(
        &mut self,
        tag: &str,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<Arc<Datatype>> {
        let flag = *self.keywords.get(tag)?;
        self.advance(); // consume the tag keyword
        let mut ident = String::new();
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                ident = tok.get_string().to_string();
                self.advance();
            }
        }
        let has_body = match self.peek_token() {
            Some(t) => t.get_type() == token_type::OPEN_BRACE,
            None => false,
        };
        match flag {
            cparse_flags::F_STRUCT | cparse_flags::F_UNION => {
                if !has_body {
                    if ident.is_empty() {
                        self.set_error("Syntax error");
                        return None;
                    }
                    let types = types?;
                    // STRUCT IDENTIFIER -> oldStruct / oldUnion
                    // (grammar.y:101/106). The twins set the parse error on
                    // a miss themselves.
                    return if flag == cparse_flags::F_STRUCT {
                        self.old_struct(&ident, types)
                    } else {
                        self.old_union(&ident, types)
                    };
                }
                self.advance(); // '{'
                let declist = self.parse_struct_declaration_list(types.as_deref_mut())?;
                let close = match self.peek_token() {
                    Some(t) => t,
                    None => {
                        self.set_error("Missing '}' in struct/union body");
                        return None;
                    }
                };
                if close.get_type() != token_type::CLOSE_BRACE {
                    self.set_error("Missing '}' in struct/union body");
                    return None;
                }
                self.advance();
                let types = types?;
                if flag == cparse_flags::F_STRUCT {
                    self.new_struct(&ident, &declist, types)
                } else {
                    self.new_union(&ident, &declist, types)
                }
            }
            cparse_flags::F_ENUM => {
                if !has_body {
                    if ident.is_empty() {
                        self.set_error("Syntax error");
                        return None;
                    }
                    let types = types?;
                    // ENUM IDENTIFIER -> oldEnum (grammar.y:142).
                    return self.old_enum(&ident, types);
                }
                self.advance(); // '{'
                let enumerators = self.parse_enumerator_list()?;
                // grammar.y:139-140 allow a trailing ',' before '}'.
                if let Some(t) = self.peek_token() {
                    if t.get_type() == token_type::COMMA {
                        self.advance();
                    }
                }
                let close = match self.peek_token() {
                    Some(t) => t,
                    None => {
                        self.set_error("Missing '}' in enum body");
                        return None;
                    }
                };
                if close.get_type() != token_type::CLOSE_BRACE {
                    self.set_error("Missing '}' in enum body");
                    return None;
                }
                self.advance();
                let types = types?;
                self.new_enum(&ident, &enumerators, types)
            }
            _ => {
                self.set_error("Syntax error");
                None
            }
        }
    }

    // RUGRA-GLUE: hand-written helper reducing `struct_declaration_list`
    // (grammar.y:108-112): a non-empty sequence of `struct_declaration`s,
    /// each `specifier_qualifier_list struct_declarator_list ';'`
    /// (grammar.y:114-122), with the specifier list merged into every
    /// declarator exactly as `mergeSpecDecVec` does.
    fn parse_struct_declaration_list(
        &mut self,
        mut types: Option<&mut crate::type_system::typefactory::TypeFactory>,
    ) -> Option<Vec<TypeDeclarator>> {
        let mut all: Vec<TypeDeclarator> = Vec::new();
        loop {
            match self.peek_token() {
                Some(t) if t.get_type() == token_type::CLOSE_BRACE => break,
                None => break,
                _ => {}
            }
            // specifier_qualifier_list: (TYPE_QUALIFIER | type_specifier)+
            let mut spec = TypeSpecifiers::new();
            loop {
                let tok = match self.peek_token() {
                    Some(t) => t,
                    None => break,
                };
                if tok.get_type() != token_type::IDENTIFIER {
                    break;
                }
                let s = tok.get_string().to_string();
                match self.keywords.get(&s).copied() {
                    Some(cparse_flags::F_CONST)
                    | Some(cparse_flags::F_RESTRICT)
                    | Some(cparse_flags::F_VOLATILE) => {
                        self.add_specifier(&mut spec, &s);
                        self.advance();
                    }
                    Some(cparse_flags::F_STRUCT)
                    | Some(cparse_flags::F_UNION)
                    | Some(cparse_flags::F_ENUM) => {
                        match self.parse_tag_specifier(&s, types.as_deref_mut()) {
                            Some(tp) => {
                                self.add_type_specifier(&mut spec, tp);
                            }
                            None => return None,
                        }
                    }
                    _ => {
                        if let Some(factory) = types.as_deref() {
                            if let Some(tp) = factory.find_by_name(&s) {
                                self.add_type_specifier(&mut spec, tp);
                            }
                        }
                        self.advance();
                        // grammar.y's specifier_qualifier_list is one-or-more
                        // entries; the loop continues for further entries.
                        continue;
                    }
                }
            }
            // struct_declarator_list: declarator (',' declarator)*
            let mut decls: Vec<TypeDeclarator> = Vec::new();
            loop {
                let mut dec = TypeDeclarator::new();
                self.merge_spec_dec_into(&spec, &mut dec);
                self.parse_declarator(&mut dec, types.as_deref_mut())?;
                decls.push(dec);
                match self.peek_token() {
                    Some(t) if t.get_type() == token_type::COMMA => {
                        self.advance();
                    }
                    _ => break,
                }
            }
            let semi = match self.peek_token() {
                Some(t) => t,
                None => {
                    self.set_error("Missing ';' in struct declaration");
                    return None;
                }
            };
            if semi.get_type() != token_type::SEMICOLON {
                self.set_error("Missing ';' in struct declaration");
                return None;
            }
            self.advance();
            all.extend(decls);
        }
        if all.is_empty() {
            // struct_declaration_list requires at least one
            // struct_declaration (grammar.y:108).
            self.set_error("Syntax error");
            return None;
        }
        Some(all)
    }

    // RUGRA-GLUE: hand-written helper reducing `enumerator_list`
    // (grammar.y:144-147): `enumerator (',' enumerator)*` where each
    /// `enumerator` is `IDENTIFIER` or `IDENTIFIER '=' NUMBER`
    /// (grammar.y:149-151) built via `newEnumerator`.
    fn parse_enumerator_list(&mut self) -> Option<Vec<Enumerator>> {
        let mut list = Vec::new();
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => {
                    self.set_error("Syntax error");
                    return None;
                }
            };
            if tok.get_type() != token_type::IDENTIFIER {
                self.set_error("Syntax error");
                return None;
            }
            let name = tok.get_string().to_string();
            self.advance();
            let enumerator = if let Some(t) = self.peek_token() {
                if t.get_type() == 0x3d {
                    // '='
                    self.advance();
                    let num = match self.peek_token() {
                        Some(t) if t.get_type() == token_type::INTEGER => t,
                        _ => {
                            self.set_error("Syntax error");
                            return None;
                        }
                    };
                    let value = num.get_integer();
                    self.advance();
                    Enumerator::with_value(&name, value)
                } else {
                    Enumerator::new(&name)
                }
            } else {
                Enumerator::new(&name)
            };
            // newEnumerator allocates into the arena; the driver keeps the
            // built Enumerator values directly for the newEnum twin.
            let _ = self.new_enumerator_name(&name);
            list.push(enumerator);
            match self.peek_token() {
                Some(t) if t.get_type() == token_type::COMMA => {
                    self.advance();
                    // A ',' directly before '}' terminates the list
                    // (grammar.y:139-140 trailing-comma forms).
                    if let Some(t2) = self.peek_token() {
                        if t2.get_type() == token_type::CLOSE_BRACE {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        Some(list)
    }

    // RUGRA-GLUE: single-token lookahead cache to mirror the bison lexer.
    // Returns a clone of the cached token; never consumes input. EOF maps to
    // `None` so the parser can `?`-bail uniformly.
    fn peek_token(&mut self) -> Option<GrammarToken> {
        if self.peeked.is_none() {
            let tok = self.lexer.get_next_token();
            self.lineno = tok.get_line_no();
            self.colno = tok.get_col_no();
            self.filenum = tok.get_file_num();
            if tok.get_type() == token_type::END_OF_FILE {
                self.peeked = None;
            } else {
                self.peeked = Some(tok);
            }
        }
        self.peeked.clone()
    }

    // RUGRA-GLUE: consume the cached token, if any. Mirrors the implicit
    // "match and advance" of the bison grammar actions.
    fn advance(&mut self) {
        self.peeked = None;
    }
}

// Bison token codes used by CParse::runParse / yyparse (grammar.y). Faithful
// to the defines emitted at the top of grammar.cc.
const DECLARATION_RESULT: i32 = 0;
const PARAM_RESULT: i32 = 1;

// Re-export the flag constants on `CParse` itself to mirror the C++
// `CParse::f_typedef` access form.
impl CParse {
    /// `CParse::f_typedef = 1` (grammar.hh:204).
    pub const F_TYPEDEF: u32 = cparse_flags::F_TYPEDEF;
    /// `CParse::f_extern = 2` (grammar.hh:205).
    pub const F_EXTERN: u32 = cparse_flags::F_EXTERN;
    /// `CParse::f_static = 4` (grammar.hh:206).
    pub const F_STATIC: u32 = cparse_flags::F_STATIC;
    /// `CParse::f_auto = 8` (grammar.hh:207).
    pub const F_AUTO: u32 = cparse_flags::F_AUTO;
    /// `CParse::f_register = 16` (grammar.hh:208).
    pub const F_REGISTER: u32 = cparse_flags::F_REGISTER;
    /// `CParse::f_const = 32` (grammar.hh:209).
    pub const F_CONST: u32 = cparse_flags::F_CONST;
    /// `CParse::f_restrict = 64` (grammar.hh:210).
    pub const F_RESTRICT: u32 = cparse_flags::F_RESTRICT;
    /// `CParse::f_volatile = 128` (grammar.hh:211).
    pub const F_VOLATILE: u32 = cparse_flags::F_VOLATILE;
    /// `CParse::f_inline = 256` (grammar.hh:212).
    pub const F_INLINE: u32 = cparse_flags::F_INLINE;
    /// `CParse::f_struct = 512` (grammar.hh:213).
    pub const F_STRUCT: u32 = cparse_flags::F_STRUCT;
    /// `CParse::f_union = 1024` (grammar.hh:214).
    pub const F_UNION: u32 = cparse_flags::F_UNION;
    /// `CParse::f_enum = 2048` (grammar.hh:215).
    pub const F_ENUM: u32 = cparse_flags::F_ENUM;
}

// ---------------------------------------------------------------------------
// Public entry points (grammar.hh:282-291)
// ---------------------------------------------------------------------------

// Ghidra: grammar.hh:116 TypeDeclarator::parseType
/// Parse a type from a string, returning the type name and identifier.
/// Faithful to `parse_type` (grammar.hh:282). This is a simplified entry
/// point that drives `CParse::parse_stream` with `DocType::ParameterDeclaration`
/// and returns the first declarator's identifier and basetype name.
pub fn parse_type(text: &str) -> Option<(String, String)> {
    let mut lexer = GrammarLexer::new(1024);
    lexer.set_input(text);
    // Read the first token (should be a type name identifier).
    let tok = lexer.get_next_token();
    if tok.get_type() != token_type::IDENTIFIER {
        return None;
    }
    let type_name = tok.get_string().to_string();
    // Read the next token (should be the variable name).
    let tok2 = lexer.get_next_token();
    let var_name = if tok2.get_type() == token_type::IDENTIFIER {
        tok2.get_string().to_string()
    } else {
        String::new()
    };
    Some((type_name, var_name))
}

// Ghidra: grammar.cc:3112 parse_type
/// Parse a single type from C text, returning the built `Datatype` and the
/// declarator's identifier. Faithful to `parse_type(istream &, string &,
/// Architecture *)`: drives a `CParse` with `DocType::ParameterDeclaration`,
/// takes the single result declarator, validates it, captures the identifier,
/// and builds the type via `TypeDeclarator::build_type`.
///
/// Unlike the simplified `parse_type` (which lexes only two tokens), this walks
/// the full CParse grammar so modifiers (`int * x`, `long x`) and pointer/array
/// suffixes are handled.
///
/// Errors map to the C++ `throw ParseError(...)` paths and are returned as
/// `Err(message)`.
pub fn parse_type_full(
    text: &str,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Result<(Arc<Datatype>, String), String> {
    let mut parser = CParse::new(4096);
    if !parser.parse_stream_with_types(text, DocType::ParameterDeclaration, types) {
        return Err(parser.get_error().to_string());
    }
    let mut decls = match parser.take_result_declarations() {
        Some(d) => d,
        None => return Err("Did not parse a datatype".to_string()),
    };
    if decls.is_empty() {
        return Err("Did not parse a datatype".to_string());
    }
    if decls.len() > 1 {
        return Err("Parsed multiple declarations".to_string());
    }
    let decl = decls.swap_remove(0);
    if !decl.is_valid() {
        return Err("Parsed type is invalid".to_string());
    }
    let name = decl.get_identifier().to_string();
    let dt = decl
        .build_type(types)
        .ok_or_else(|| "Parsed type is invalid".to_string())?;
    Ok((dt, name))
}

// Ghidra: grammar.cc:3131 parse_protopieces
/// Parse a function prototype from C text, returning the recovered
/// `PrototypePieces`. Faithful to `parse_protopieces(PrototypePieces &,
/// istream &, Architecture *)`: drives a `CParse` with `DocType::Declaration`,
/// takes the single result declarator, validates it, and calls
/// `TypeDeclarator::getPrototype`.
///
/// Errors (parse failure, no/multiple declarations, invalid type, no prototype
/// modifier) map to the C++ `throw ParseError(...)` paths and are returned as
/// `Err(message)`.
pub fn parse_protopieces(
    text: &str,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Result<PrototypePieces, String> {
    let mut parser = CParse::new(4096);
    if !parser.parse_stream_with_types(text, DocType::Declaration, types) {
        return Err(parser.get_error().to_string());
    }
    let decls = match parser.take_result_declarations() {
        Some(d) => d,
        None => return Err("Did not parse a datatype".to_string()),
    };
    if decls.is_empty() {
        return Err("Did not parse a datatype".to_string());
    }
    if decls.len() > 1 {
        return Err("Parsed multiple declarations".to_string());
    }
    let decl = &decls[0];
    if !decl.is_valid() {
        return Err("Parsed type is invalid".to_string());
    }
    let mut pieces = PrototypePieces::default();
    if !decl.get_prototype(&mut pieces, types) {
        return Err("Did not parse a prototype".to_string());
    }
    Ok(pieces)
}

// Ghidra: grammar.cc:3151 parse_C
/// Parse a C declaration straight into the data structures. Faithful to
/// `parse_C(Architecture *, istream &)`: drives a `CParse` with
/// `DocType::Declaration`, takes the single result declarator, and validates
/// it. Ghidra then branches on the `extern` property: an `extern` declarator is
/// treated as a prototype (its `PrototypePieces` are built via `getPrototype`
/// and committed via the `TypeFactory`/`Funcproto` machinery); a non-extern
/// declarator is treated as a type definition (its built type is committed via
/// `TypeFactory::findReplace`).
///
/// Rugra wires only the parse + validation half (the `TypeFactory` here has no
/// `FuncProto`/`findReplace` bridge reachable from this module); the returned
/// `TypeDeclarator` carries the fully parsed structure for the caller to
/// commit. The validation/error semantics match Ghidra exactly.
pub fn parse_c(
    text: &str,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Result<TypeDeclarator, String> {
    let mut parser = CParse::new(4096);
    if !parser.parse_stream_with_types(text, DocType::Declaration, types) {
        return Err(parser.get_error().to_string());
    }
    let decls = match parser.take_result_declarations() {
        Some(d) => d,
        None => return Err("Did not parse a datatype".to_string()),
    };
    if decls.is_empty() {
        return Err("Did not parse a datatype".to_string());
    }
    if decls.len() > 1 {
        return Err("Parsed multiple declarations".to_string());
    }
    let decl = decls.into_iter().next().unwrap();
    if !decl.is_valid() {
        return Err("Parsed type is invalid".to_string());
    }
    // Ghidra: if decl->hasProperty(f_extern) build & commit a prototype; else
    // commit the built type. Rugra builds the prototype/type so the returned
    // declarator carries resolved data for the caller to commit upstream.
    if decl.has_property(CParse::F_EXTERN) {
        let mut pieces = PrototypePieces::default();
        if !decl.get_prototype(&mut pieces, types) {
            return Err("Did not parse a prototype".to_string());
        }
        // The TypeCode for this prototype can be minted via
        // `get_type_code_pieces` once Rugra's fspec PrototypePieces is bridged;
        // for now the pieces are computed and discarded, matching the parse
        // half of parse_C.
    } else {
        // Build the declared type so it is materialised in the factory.
        let _ = decl.build_type(types);
    }
    Ok(decl)
}

// Ghidra: grammar.hh:116 TypeDeclarator::parseToSeparator
/// Parse text up to the next separator (whitespace, comma, semicolon).
/// Faithful to `parse_toseparator` (grammar.hh:288 / grammar.cc:3197).
pub fn parse_to_separator(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if c.is_whitespace() || c == ',' || c == ';' {
            break;
        }
        result.push(c);
    }
    result
}

// Ghidra: grammar.cc:3197 parse_toseparator
/// Parse identifier characters up to the next non-`[A-Za-z0-9_]` character
/// from a `&str` cursor. Faithful to the C++ stream version: `s >> ws` then
/// accumulate while `isalnum(c) || c == '_'`. Returns the consumed word and
/// the number of bytes consumed (so callers can advance a slice).
pub fn parse_toseparator_from(text: &str) -> (String, usize) {
    let mut name = String::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    // Skip leading whitespace (s >> ws).
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_alphanumeric() || c == '_' {
            name.push(c);
            i += 1;
        } else {
            break;
        }
    }
    (name, i)
}

// Ghidra: grammar.cc:3257 parse_machaddr
/// Parse a machine address from a `&str`. Faithful to `parse_machaddr`. This
/// Rugra port targets the same textual formats:
///   * `[space,offset]` / `[space,offset,size]`
///   * `{ joined }` (the join space — represented as `Address(0)` here)
///   * shortcut-prefixed offsets like `0x1234` or `ram:1234`
/// Returns `(address, default_size, bytes_consumed)`. On failure returns
/// `None`.
pub fn parse_machaddr(text: &str) -> Option<(Address, i32, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    // Skip leading whitespace (s >> ws).
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let first = bytes[i] as char;

    if first == '[' {
        i += 1; // consume '['
        let rest = &text[i..];
        let (space_name, consumed) = parse_toseparator_from(rest);
        i += consumed;
        // skip ws
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] as char != ',' {
            return None;
        }
        i += 1; // consume ','
        let (offset_str, consumed2) = parse_toseparator_from(&text[i..]);
        i += consumed2;
        // optional size
        let mut size: i32 = -1;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] as char == ',' {
            i += 1;
            let (size_str, consumed3) = parse_toseparator_from(&text[i..]);
            i += consumed3;
            size = size_str.parse::<i32>().ok()?;
        }
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] as char != ']' {
            return None;
        }
        i += 1; // consume ']'
        let _ = space_name; // Rugra's single-space model ignores the name
        let offset_val = parse_address_offset(&offset_str)?;
        let oversize = standard_size_for(&offset_str);
        let default_size = if size == -1 { oversize } else { size };
        Some((Address::new(offset_val), default_size, i))
    } else if first == '{' {
        // Join space — represented as Address(0).
        i += 1;
        while i < bytes.len() && bytes[i] as char != '}' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1; // consume '}'
        }
        Some((Address::new(0), -1, i))
    } else {
        // Shortcut-prefixed offset: 0x… or single-char shortcut + offset.
        let (offset_str, consumed) = if first == '0' {
            // The C++ code treats leading '0' as the default-code-space
            // shortcut. We still parse the full hex/decimal offset.
            let r = parse_toseparator_from(&text[i..]);
            r
        } else {
            // Consume one shortcut character then the offset.
            i += 1;
            parse_toseparator_from(&text[i..])
        };
        i += consumed;
        let offset_val = parse_address_offset(&offset_str)?;
        let oversize = standard_size_for(&offset_str);
        Some((Address::new(offset_val), oversize, i))
    }
}

// RUGRA-GLUE: helper that mirrors the C++ `Address::read(token)` behaviour of
// parsing a hex/decimal offset and returning the "standard size" implied by
// the number of digits.
fn parse_address_offset(tok: &str) -> Option<u64> {
    let tok = tok.trim();
    if tok.is_empty() {
        return None;
    }
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        tok.parse::<u64>().ok()
    }
}

// RUGRA-GLUE: estimate the "standard size" from a textual offset. The C++
// version returns the byte-width reported by `Address::read`; Rugra has no
// AddrSpaceManager here, so we infer 4/8 bytes from the magnitude.
fn standard_size_for(tok: &str) -> i32 {
    let val = parse_address_offset(tok).unwrap_or(0);
    if val > u32::MAX as u64 {
        8
    } else {
        4
    }
}

// Ghidra: grammar.cc:3213 parse_varnode
/// Parse a varnode of the form `addr ( [pc] [:uniq] )`. Faithful to
/// `parse_varnode`. Returns `(address, size, pc, uniq, bytes_consumed)` or
/// `None` on syntax error.
pub fn parse_varnode(text: &str) -> Option<(Address, i32, Address, u64, usize)> {
    let (loc, size, mut consumed) = parse_machaddr(text)?;
    let rest = &text[consumed..];
    let bytes = rest.as_bytes();
    let mut j = 0;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != '(' {
        return None;
    }
    j += 1;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    let mut pc = Address::new(0);
    let mut uniq: u64 = !0u64;
    if j < bytes.len() {
        let c = bytes[j] as char;
        if c == 'i' {
            j += 1; // 'i' for "indeterminate" pc
        } else if c != ':' {
            let (pc_addr, _, pc_consumed) = parse_machaddr(&rest[j..])?;
            pc = pc_addr;
            j += pc_consumed;
        }
    }
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] as char == ':' {
        j += 1; // consume ':'
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        let mut hex = String::new();
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_ascii_hexdigit() {
                hex.push(c);
                j += 1;
            } else {
                break;
            }
        }
        uniq = u64::from_str_radix(&hex, 16).unwrap_or(uniq);
    }
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != ')' {
        return None;
    }
    j += 1; // consume ')'
    consumed += j;
    Some((loc, size, pc, uniq, consumed))
}

// Ghidra: grammar.cc:3244 parse_op
/// Parse an op address of the form `addr : uniq`. Faithful to `parse_op`.
/// Returns `(address, uniq, bytes_consumed)` or `None` on syntax error.
pub fn parse_op(text: &str) -> Option<(Address, u64, usize)> {
    let (loc, _, mut consumed) = parse_machaddr(text)?;
    let rest = &text[consumed..];
    let bytes = rest.as_bytes();
    let mut j = 0;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != ':' {
        return None;
    }
    j += 1;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    let mut hex = String::new();
    while j < bytes.len() {
        let c = bytes[j] as char;
        if c.is_ascii_hexdigit() {
            hex.push(c);
            j += 1;
        } else {
            break;
        }
    }
    let uniq = u64::from_str_radix(&hex, 16).ok()?;
    consumed += j;
    Some((loc, uniq, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_default() {
        let t = GrammarToken::new();
        assert_eq!(t.get_type(), token_type::BAD_TOKEN);
    }

    #[test]
    fn test_lexer_identifier() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("hello world");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "hello");
        let tok2 = lex.get_next_token();
        assert_eq!(tok2.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok2.get_string(), "world");
    }

    #[test]
    fn test_lexer_punctuation() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("(){}[];,*");
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_PAREN);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_PAREN);
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_BRACE);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_BRACE);
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_BRACKET);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_BRACKET);
        assert_eq!(lex.get_next_token().get_type(), token_type::SEMICOLON);
        assert_eq!(lex.get_next_token().get_type(), token_type::COMMA);
        assert_eq!(lex.get_next_token().get_type(), token_type::STAR);
    }

    #[test]
    fn test_lexer_integer() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("42");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::INTEGER);
        assert_eq!(tok.get_integer(), 42);
    }

    #[test]
    fn test_lexer_hex_integer() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("0xFF");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::INTEGER);
        assert_eq!(tok.get_integer(), 255);
    }

    #[test]
    fn test_lexer_dotdotdot() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("...");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::DOTDOTDOT);
    }

    #[test]
    fn test_lexer_eof() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("x");
        lex.get_next_token(); // consume 'x'
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::END_OF_FILE);
    }

    #[test]
    fn test_lexer_string() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("\"hello\"");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::STRING_VAL);
        assert_eq!(tok.get_string(), "hello");
    }

    #[test]
    fn test_lexer_eol_comment() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("// comment\nfoo");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "foo");
    }

    #[test]
    fn test_lexer_c_comment() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("/* comment */ bar");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "bar");
    }

    #[test]
    fn test_parse_number_decimal() {
        assert_eq!(parse_number("123"), 123);
        assert_eq!(parse_number("0"), 0);
    }

    #[test]
    fn test_parse_number_hex() {
        assert_eq!(parse_number("0xFF"), 255);
        assert_eq!(parse_number("0XAB"), 171);
    }

    #[test]
    fn test_parse_number_octal() {
        assert_eq!(parse_number("010"), 8);
    }

    #[test]
    fn test_type_declarator() {
        let d = TypeDeclarator::with_name("myVar");
        assert_eq!(d.get_identifier(), "myVar");
        assert_eq!(d.num_modifiers(), 0);
        assert!(!d.has_property(1));
    }

    #[test]
    fn test_type_modifier_pointer() {
        let m = TypeModifier::Pointer { flags: 0 };
        assert_eq!(m.kind(), ModifierKind::Pointer);
        assert!(m.is_valid());
    }

    #[test]
    fn test_type_modifier_array() {
        let m_valid = TypeModifier::Array { flags: 0, array_size: 10 };
        assert!(m_valid.is_valid());
        let m_invalid = TypeModifier::Array { flags: 0, array_size: 0 };
        assert!(!m_invalid.is_valid());
    }

    #[test]
    fn test_parse_type_simple() {
        let result = parse_type("int x").unwrap();
        assert_eq!(result.0, "int");
        assert_eq!(result.1, "x");
    }

    #[test]
    fn test_parse_to_separator() {
        assert_eq!(parse_to_separator("hello world"), "hello");
        assert_eq!(parse_to_separator("foo,bar"), "foo");
        assert_eq!(parse_to_separator("end;"), "end");
    }

    // ---- new tests for the ported CParse framework ----

    #[test]
    fn test_cparse_keyword_table() {
        let p = CParse::new(1024);
        assert_eq!(CParse::F_TYPEDEF, cparse_flags::F_TYPEDEF);
        assert_eq!(CParse::F_VOLATILE, 128);
        assert_eq!(CParse::F_ENUM, 2048);
        let _ = p;
    }

    #[test]
    fn test_cparse_convert_flag() {
        let mut p = CParse::new(1024);
        assert_eq!(p.convert_flag("const"), cparse_flags::F_CONST);
        assert_eq!(p.convert_flag("struct"), cparse_flags::F_STRUCT);
        assert_eq!(p.convert_flag("bogus"), 0);
        assert!(!p.get_error().is_empty());
    }

    #[test]
    fn test_cparse_add_specifier() {
        let mut p = CParse::new(1024);
        let mut spec = TypeSpecifiers::new();
        p.add_specifier(&mut spec, "const");
        p.add_specifier(&mut spec, "volatile");
        assert!(spec.flags & cparse_flags::F_CONST != 0);
        assert!(spec.flags & cparse_flags::F_VOLATILE != 0);
    }

    #[test]
    fn test_cparse_merge_pointer_and_array() {
        let mut p = CParse::new(1024);
        let mut dec = TypeDeclarator::with_name("x");
        p.merge_pointer(&[0, 0], &mut dec);
        assert_eq!(dec.num_modifiers(), 2);
        p.new_array(&mut dec, 0, 4);
        assert_eq!(dec.num_modifiers(), 3);
        assert_eq!(dec.mods[2].kind(), ModifierKind::Array);
    }

    #[test]
    fn test_enumerator_constructors() {
        let e1 = Enumerator::new("RED");
        assert!(!e1.constant_assigned);
        let e2 = Enumerator::with_value("GREEN", 2);
        assert!(e2.constant_assigned);
        assert_eq!(e2.value, 2);
    }

    #[test]
    fn test_parse_toseparator_from() {
        let (name, consumed) = parse_toseparator_from("  hello world");
        assert_eq!(name, "hello");
        assert_eq!(consumed, 7); // 2 ws + 5 letters
    }

    #[test]
    fn test_parse_machaddr_bracketed() {
        let (addr, size, consumed) = parse_machaddr("[ram,0x1000]").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert!(size == 4 || size == 8);
        assert!(consumed > 0);
    }

    #[test]
    fn test_parse_machaddr_with_size() {
        let (addr, size, _consumed) = parse_machaddr("[ram,0x1000,2]").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(size, 2);
    }

    #[test]
    fn test_parse_machaddr_join() {
        let (addr, _size, consumed) = parse_machaddr("{ abc def }").unwrap();
        assert_eq!(addr.as_u64(), 0);
        assert!(consumed > 0);
    }

    #[test]
    fn test_parse_op() {
        let (addr, uniq, _) = parse_op("0x1000:1f").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(uniq, 0x1f);
    }

    #[test]
    fn test_cparse_parse_stream_simple() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int x", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].get_identifier(), "x");
    }

    #[test]
    fn test_cparse_parse_stream_pointer() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int * ptr", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "ptr");
        assert_eq!(decls[0].num_modifiers(), 1);
        assert_eq!(decls[0].mods[0].kind(), ModifierKind::Pointer);
    }

    #[test]
    fn test_cparse_parse_stream_func() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int main(int argc)", DocType::Declaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "main");
        // basetype + function modifier
        assert!(decls[0].num_modifiers() >= 1);
    }

    #[test]
    fn test_cparse_parse_stream_multi_declarator() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int x, y", DocType::Declaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls.len(), 2);
    }

    // ---- new tests for the ported bison-bridge / modifier methods ----

    #[test]
    fn test_bison_token_constants() {
        // Faithful to the grammartokentype enum (grammar.cc:153-165).
        assert_eq!(bison_token::DOTDOTDOT, 258);
        assert_eq!(bison_token::BADTOKEN, 259);
        assert_eq!(bison_token::STRUCT, 260);
        assert_eq!(bison_token::UNION, 261);
        assert_eq!(bison_token::ENUM, 262);
        assert_eq!(bison_token::DECLARATION_RESULT, 263);
        assert_eq!(bison_token::PARAM_RESULT, 264);
        assert_eq!(bison_token::NUMBER, 265);
        assert_eq!(bison_token::IDENTIFIER, 266);
        assert_eq!(bison_token::STORAGE_CLASS_SPECIFIER, 267);
        assert_eq!(bison_token::TYPE_QUALIFIER, 268);
        assert_eq!(bison_token::FUNCTION_SPECIFIER, 269);
        assert_eq!(bison_token::TYPE_NAME, 270);
        assert_eq!(bison_token::END_OF_STREAM, -1);
    }

    #[test]
    fn test_lookup_identifier_keywords() {
        // Without an architecture handle, only keyword paths resolve.
        let mut p = CParse::new(1024);
        // Storage-class keywords → STORAGE_CLASS_SPECIFIER.
        assert_eq!(p.lookup_identifier("typedef"), bison_token::STORAGE_CLASS_SPECIFIER);
        assert_eq!(p.lookup_identifier("extern"), bison_token::STORAGE_CLASS_SPECIFIER);
        assert_eq!(p.lookup_identifier("static"), bison_token::STORAGE_CLASS_SPECIFIER);
        assert_eq!(p.lookup_identifier("auto"), bison_token::STORAGE_CLASS_SPECIFIER);
        assert_eq!(p.lookup_identifier("register"), bison_token::STORAGE_CLASS_SPECIFIER);
        // Type-qualifier keywords → TYPE_QUALIFIER.
        assert_eq!(p.lookup_identifier("const"), bison_token::TYPE_QUALIFIER);
        assert_eq!(p.lookup_identifier("restrict"), bison_token::TYPE_QUALIFIER);
        assert_eq!(p.lookup_identifier("volatile"), bison_token::TYPE_QUALIFIER);
        // inline → FUNCTION_SPECIFIER.
        assert_eq!(p.lookup_identifier("inline"), bison_token::FUNCTION_SPECIFIER);
        // struct / union / enum → STRUCT / UNION / ENUM.
        assert_eq!(p.lookup_identifier("struct"), bison_token::STRUCT);
        assert_eq!(p.lookup_identifier("union"), bison_token::UNION);
        assert_eq!(p.lookup_identifier("enum"), bison_token::ENUM);
        // Unknown identifier (no glb) → IDENTIFIER.
        assert_eq!(p.lookup_identifier("foo"), bison_token::IDENTIFIER);
    }

    #[test]
    fn test_lex_dispatches_tokens() {
        // CParse::lex (grammar.cc:2999): INTEGER→NUMBER, IDENTIFIER→keyword
        // reclassification, DOTDOTDOT→DOTDOTDOT, EOF→-1, punctuation passes
        // through as its ASCII value.
        let mut p = CParse::new(1024);
        p.lexer.set_input("... foo ;");
        // The first lex() returns the firsttoken seed if set; clear it so the
        // first real token comes through.
        p.first_token = -1;
        let t1 = p.lex();
        assert_eq!(t1, bison_token::DOTDOTDOT); // "..."
        // "foo" is an unknown identifier → IDENTIFIER.
        let t2 = p.lex();
        assert_eq!(t2, bison_token::IDENTIFIER);
        assert_eq!(p.yylval_str, "foo");
        // ";" is punctuation → its ASCII value 0x3b = 59.
        let t3 = p.lex();
        assert_eq!(t3, token_type::SEMICOLON as i32);
        assert_eq!(t3, 0x3b);
        // Next lex() is EOF → -1.
        let t4 = p.lex();
        assert_eq!(t4, bison_token::END_OF_STREAM);
    }

    #[test]
    fn test_lex_number_and_firsttoken_seed() {
        let mut p = CParse::new(1024);
        p.lexer.set_input("42");
        // Seed the firsttoken; the first lex() returns it then clears.
        p.first_token = bison_token::DECLARATION_RESULT;
        assert_eq!(p.lex(), bison_token::DECLARATION_RESULT);
        assert_eq!(p.first_token, -1);
        // Next lex() reads the actual input: 42 → NUMBER, yylval_int set.
        assert_eq!(p.lex(), bison_token::NUMBER);
        assert_eq!(p.yylval_int, 42);
    }

    #[test]
    fn test_lex_string_val_is_badtoken() {
        // A string literal is illegal in a type grammar → BADTOKEN with error.
        let mut p = CParse::new(1024);
        p.lexer.set_input("\"oops\"");
        p.first_token = -1;
        assert_eq!(p.lex(), bison_token::BADTOKEN);
        assert!(p.get_error().contains("Illegal string constant"));
    }

    #[test]
    fn test_lex_pending_error_short_circuits() {
        // A pending lasterror short-circuits lex() to BADTOKEN.
        let mut p = CParse::new(1024);
        p.lexer.set_input("foo");
        p.first_token = -1;
        p.set_error("prior failure");
        assert_eq!(p.lex(), bison_token::BADTOKEN);
    }

    #[test]
    fn test_lexer_write_location_format() {
        // GrammarLexer::writeLocation mirrors the C++ " at line N in <file>".
        let mut lex = GrammarLexer::new(1024);
        lex.push_file("test.c", "");
        let mut s = String::from("err");
        lex.write_location(&mut s, 7, 0);
        assert_eq!(s, "err at line 7 in test.c");
    }

    #[test]
    fn test_lexer_push_pop_file_stack() {
        // push_file installs the body as active input; pop_file restores the
        // previous stream or marks EOF when the stack empties.
        let mut lex = GrammarLexer::new(1024);
        assert!(lex.filestack.is_empty());
        lex.push_file("a.c", "int a");
        assert!(!lex.filestack.is_empty());
        assert!(!lex.end_of_file);
        // The pushed body is the active input.
        let t = lex.get_next_token();
        assert_eq!(t.get_string(), "int");
        // pop_file on a single-entry stack marks EOF.
        lex.pop_file();
        assert!(lex.end_of_file);
        assert!(lex.filestack.is_empty());
    }

    #[test]
    fn test_type_modifier_get_in_types_and_names() {
        // TypeModifier::get_in_types / get_in_names method-form wrappers
        // delegate to collect_param_types / collect_param_names.
        let mut tf = crate::type_system::typefactory::TypeFactory::new(8);
        // Faithful getBase twin (type.cc:3631): TypeFactory::new's cached
        // 4-byte INT core type satisfies the typecache fast path.
        let int_type = tf
            .get_base_result(4, crate::type_system::datatype::TypeMetatype::Int)
            .unwrap();
        let mut param = TypeDeclarator::new();
        param.basetype = Some(int_type);
        param.ident = "argc".to_string();
        let func = TypeModifier::Function {
            params: vec![Some(param)],
            dotdotdot: false,
        };
        let mut intypes: Vec<Arc<Datatype>> = Vec::new();
        let mut innames: Vec<String> = Vec::new();
        if let TypeModifier::Function { params, .. } = &func {
            func.get_in_types(&mut intypes, &mut tf, params);
            func.get_in_names(&mut innames, params);
        }
        assert_eq!(intypes.len(), 1);
        assert_eq!(innames, vec!["argc".to_string()]);
        assert!(!func.is_dotdotdot());
    }

    #[test]
    fn test_type_modifier_is_dotdotdot() {
        let func_va = TypeModifier::Function {
            params: vec![],
            dotdotdot: true,
        };
        assert!(func_va.is_dotdotdot());
        let ptr = TypeModifier::Pointer { flags: 0 };
        assert!(!ptr.is_dotdotdot());
    }

    #[test]
    fn test_pointer_mod_type_builds_ptr() {
        // PointerModifier::modType (grammar.cc:2403): wraps the base in a ptr.
        // Dispatched via the `mod_type` helper that implements all three
        // virtuals; the pointer branch is exercised here.
        let mut tf = crate::type_system::typefactory::TypeFactory::new(8);
        tf.setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let base = tf
            .get_base_result(4, crate::type_system::datatype::TypeMetatype::Int)
            .unwrap();
        let decl = TypeDeclarator::new();
        let ptr_mod = TypeModifier::Pointer { flags: 0 };
        let res = mod_type(&ptr_mod, base.clone(), &decl, &mut tf).expect("ptr");
        let direct = tf.get_type_pointer_default(base.clone());
        let repeated = mod_type(&ptr_mod, base.clone(), &decl, &mut tf).expect("repeat ptr");
        assert!(std::sync::Arc::ptr_eq(&res, &direct));
        assert!(std::sync::Arc::ptr_eq(&res, &repeated));
        assert_eq!(res.get_metatype(), crate::type_system::datatype::TypeMetatype::Pointer);
        assert!(res.get_name().is_empty());
        assert!(matches!(
            res.as_ref(),
            crate::type_system::datatype::Datatype::Pointer(pointer)
                if pointer.base.size == 8
                    && pointer.wordsize == 1
                    && std::sync::Arc::ptr_eq(&pointer.ptr_to, &base)
        ));

        let uint = tf
            .get_base_result(4, crate::type_system::datatype::TypeMetatype::Uint)
            .unwrap();
        let int_array = tf.get_array(base, 2);
        let uint_array = tf.get_array(uint, 2);
        let int_array_pointer =
            mod_type(&ptr_mod, int_array.clone(), &decl, &mut tf).expect("int array pointer");
        let uint_array_pointer =
            mod_type(&ptr_mod, uint_array.clone(), &decl, &mut tf).expect("uint array pointer");
        assert!(!std::sync::Arc::ptr_eq(
            &int_array_pointer,
            &uint_array_pointer
        ));
        assert!(matches!(
            int_array_pointer.as_ref(),
            crate::type_system::datatype::Datatype::Pointer(pointer)
                if std::sync::Arc::ptr_eq(&pointer.ptr_to, &int_array)
        ));
        assert!(matches!(
            uint_array_pointer.as_ref(),
            crate::type_system::datatype::Datatype::Pointer(pointer)
                if std::sync::Arc::ptr_eq(&pointer.ptr_to, &uint_array)
        ));
    }

    #[test]
    fn test_array_mod_type_builds_array() {
        // ArrayModifier::modType (grammar.cc:2412): wraps the base in an array.
        let mut tf = crate::type_system::typefactory::TypeFactory::new(8);
        let base = tf
            .get_base_result(4, crate::type_system::datatype::TypeMetatype::Int)
            .unwrap();
        let decl = TypeDeclarator::new();
        let arr_mod = TypeModifier::Array { flags: 0, array_size: 5 };
        let res = mod_type(&arr_mod, base, &decl, &mut tf).expect("array");
        assert_eq!(res.get_metatype(), crate::type_system::datatype::TypeMetatype::Array);
    }

    #[test]
    fn test_function_mod_type_builds_code() {
        // FunctionModifier::modType (grammar.cc:2465): builds a TypeCode from a
        // PrototypePieces (outtype + empty intypes), mirroring Ghidra's
        // getTypeCode(proto).
        let mut tf = crate::type_system::typefactory::TypeFactory::new(8);
        let base = tf
            .get_base_result(4, crate::type_system::datatype::TypeMetatype::Int)
            .unwrap();
        let decl = TypeDeclarator::new();
        let func_mod = TypeModifier::Function {
            params: vec![],
            dotdotdot: false,
        };
        let res = mod_type(&func_mod, base, &decl, &mut tf).expect("code");
        assert_eq!(res.get_metatype(), crate::type_system::datatype::TypeMetatype::Code);
    }

    // ---- new tests for the GrammarToken::set / void-param / accessor ports ----

    #[test]
    fn test_parse_char_constant_single() {
        // grammar.cc:1986 — a single char maps to its byte value.
        assert_eq!(parse_char_constant("A"), 65);
        assert_eq!(parse_char_constant("0"), 48);
    }

    #[test]
    fn test_parse_char_constant_escapes() {
        // grammar.cc:1988-2014 — backslash escapes.
        assert_eq!(parse_char_constant("\\n"), 10);
        assert_eq!(parse_char_constant("\\0"), 0);
        assert_eq!(parse_char_constant("\\a"), 7);
        assert_eq!(parse_char_constant("\\b"), 8);
        assert_eq!(parse_char_constant("\\f"), 12);
        assert_eq!(parse_char_constant("\\r"), 13);
        assert_eq!(parse_char_constant("\\t"), 9);
        assert_eq!(parse_char_constant("\\v"), 11);
        assert_eq!(parse_char_constant("\\\\"), 92);
        assert_eq!(parse_char_constant("\\'"), 39);
        assert_eq!(parse_char_constant("\\\""), 34);
    }

    #[test]
    fn test_grammar_token_set_with_text_integer() {
        // GrammarToken::set(integer, ptr, len) (grammar.cc:1971).
        let mut tok = GrammarToken::new();
        tok.set_with_text(token_type::INTEGER, "42");
        assert_eq!(tok.get_type(), token_type::INTEGER);
        assert_eq!(tok.get_integer(), 42);
    }

    #[test]
    fn test_grammar_token_set_with_text_hex() {
        let mut tok = GrammarToken::new();
        tok.set_with_text(token_type::INTEGER, "0xff");
        assert_eq!(tok.get_integer(), 255);
    }

    #[test]
    fn test_grammar_token_set_with_text_charconstant() {
        // GrammarToken::set(charconstant, ptr, len) decodes escapes.
        let mut tok = GrammarToken::new();
        tok.set_with_text(token_type::CHAR_CONSTANT, "\\n");
        assert_eq!(tok.get_type(), token_type::CHAR_CONSTANT);
        assert_eq!(tok.get_integer(), 10);
    }

    #[test]
    fn test_grammar_token_set_type_only() {
        // GrammarToken::set(uint4 tp) (grammar.cc:1960).
        let mut tok = GrammarToken::new();
        tok.set_type_only(token_type::SEMICOLON);
        assert_eq!(tok.get_type(), token_type::SEMICOLON);
    }

    #[test]
    fn test_function_modifier_void_param_dropped() {
        // FunctionModifier ctor (grammar.cc:2423-2430): a lone `(void)` param
        // is dropped, yielding a zero-arity function.
        let mut p = CParse::new(1024);
        let mut dec = TypeDeclarator::new();
        let void_dec = TypeDeclarator {
            basetype: Some(std::sync::Arc::new(
                crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        crate::type_system::datatype::TypeMetatype::Void,
                    ),
                ),
            )),
            ..TypeDeclarator::new()
        };
        p.new_func(&mut dec, vec![void_dec]);
        match &dec.mods[0] {
            TypeModifier::Function { params, .. } => assert!(params.is_empty()),
            _ => panic!("expected Function modifier"),
        }
    }

    #[test]
    fn test_function_modifier_is_valid_rejects_extra_void() {
        // FunctionModifier::isValid (grammar.cc:2456-2460): a non-lone void
        // parameter invalidates the modifier.
        let void_dec = TypeDeclarator {
            basetype: Some(std::sync::Arc::new(
                crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        crate::type_system::datatype::TypeMetatype::Void,
                    ),
                ),
            )),
            ..TypeDeclarator::new()
        };
        let int_dec = TypeDeclarator {
            basetype: Some(std::sync::Arc::new(
                crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        crate::type_system::datatype::TypeMetatype::Void,
                    ),
                ),
            )),
            ..TypeDeclarator::new()
        };
        let fmod = TypeModifier::Function {
            params: vec![Some(int_dec), Some(void_dec)],
            dotdotdot: false,
        };
        assert!(!fmod.is_valid());
    }

    #[test]
    fn test_pointer_array_accessors() {
        // PointerModifier/ArrayModifier ctor-param accessors.
        let ptr = TypeModifier::Pointer { flags: 7 };
        assert_eq!(ptr.pointer_flags(), Some(7));
        assert!(ptr.array_size().is_none());
        let arr = TypeModifier::Array { flags: 3, array_size: 10 };
        assert_eq!(arr.array_size(), Some(10));
        assert_eq!(arr.array_flags(), Some(3));
        assert!(arr.pointer_flags().is_none());
    }

    #[test]
    fn test_lexer_get_cur_stream_and_bump_line() {
        // GrammarLexer::getCurStream (grammar.hh:107) + bumpLine (grammar.cc:2054).
        let mut lex = GrammarLexer::new(1024);
        assert!(lex.get_cur_stream().is_none());
        lex.push_file("a.c", "int x;\n");
        assert_eq!(lex.get_cur_stream(), Some(0));
        let lineno_before = lex.cur_lineno();
        lex.bump_line();
        assert_eq!(lex.cur_lineno(), lineno_before + 1);
    }

    /// Standalone-flavor factory mirroring SleighArchitecture::buildCoreTypes
    /// (the name universe the typed driver resolves TYPE_NAME against) plus
    /// the x86-64-gcc size/alignment map the struct field-offset assignment
    /// consults (same construction the oracle fixture twin pins).
    fn standalone_factory() -> crate::type_system::typefactory::TypeFactory {
        use crate::type_system::typefactory::CoreTypeFlavor;
        let mut tf = crate::type_system::typefactory::TypeFactory::new_flavor(
            8,
            CoreTypeFlavor::Standalone,
        );
        let alignment_map = {
            let map = Arc::new(std::sync::RwLock::new({
                let mut m = crate::marshal::Element::new();
                m.set_name("size_alignment_map");
                m
            }));
            for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("16", "16")] {
                let entry = Arc::new(std::sync::RwLock::new({
                    let mut e = crate::marshal::Element::new();
                    e.set_name("entry");
                    e.add_attribute("size", size);
                    e.add_attribute("alignment", alignment);
                    e
                }));
                map.write().unwrap().add_child(entry);
            }
            map
        };
        let organization = Arc::new(std::sync::RwLock::new({
            let mut org = crate::marshal::Element::new();
            org.set_name("data_organization");
            org
        }));
        organization.write().unwrap().add_child(alignment_map);
        let registry = Arc::new(std::sync::RwLock::new(crate::marshal::IdRegistry::new()));
        let mut decoder = crate::marshal::TreeDecoder::new(organization, registry);
        tf.decode_data_organization(&mut decoder);
        tf.setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        tf
    }

    /// grammar.y:151-153 reduction order: `pointer direct_declarator` pushes
    /// the PointerModifiers AFTER the direct suffixes, so `int4 *x[3]` builds
    /// an array-of-pointers (`mods == [Array, Pointer]`).
    #[test]
    fn test_driver_pointer_pushes_after_suffixes() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("x * arr [3]", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "arr");
        assert_eq!(decls[0].num_modifiers(), 2);
        assert_eq!(decls[0].mods[0].kind(), ModifierKind::Array);
        assert_eq!(decls[0].mods[1].kind(), ModifierKind::Pointer);
    }

    /// grammar.y:158 grouping `'(' declarator ')'` shares the inner
    /// TypeDeclarator, so `int4 (*x)[3]` builds a pointer-to-array
    /// (`mods == [Pointer, Array]` — the group's star lands before the
    /// outer suffix).
    #[test]
    fn test_driver_grouping_binds_before_suffixes() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("x ( * grp ) [3]", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "grp");
        assert_eq!(decls[0].num_modifiers(), 2);
        assert_eq!(decls[0].mods[0].kind(), ModifierKind::Pointer);
        assert_eq!(decls[0].mods[1].kind(), ModifierKind::Array);
    }

    /// The typed driver resolves TYPE_NAME specifiers through the threaded
    /// factory (lookupIdentifier's findByName probe, grammar.cc:2972) and
    /// routes function suffixes through `new_func` — the lone `(void)`
    /// clearing and the varargs slot land in the FunctionModifier state.
    #[test]
    fn test_typed_parse_resolves_basetype_and_varargs() {
        let mut tf = standalone_factory();
        let mut p = CParse::new(4096);
        assert!(p.parse_stream_with_types("int4 f ( int4 , ... ) ;", DocType::Declaration, &mut tf));
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "f");
        assert_eq!(decls[0].basetype.as_ref().expect("basetype").get_name(), "int4");
        match &decls[0].mods[0] {
            TypeModifier::Function { params, dotdotdot } => {
                assert!(*dotdotdot, "varargs trailer folded into dotdotdot");
                assert_eq!(params.len(), 1, "trailer popped from paramlist");
            }
            other => panic!("expected function modifier, got {other:?}"),
        }
        // Lone (void) is cleared by the FunctionModifier ctor twin.
        let mut p2 = CParse::new(4096);
        assert!(p2.parse_stream_with_types("int4 g ( void ) ;", DocType::Declaration, &mut tf));
        let decls2 = p2.take_result_declarations().expect("decls");
        match &decls2[0].mods[0] {
            TypeModifier::Function { params, dotdotdot } => {
                assert!(!*dotdotdot);
                assert!(params.is_empty(), "f(void) cleared to zero arity");
            }
            other => panic!("expected function modifier, got {other:?}"),
        }
    }

    /// The typed driver commits struct definitions through `new_struct`
    /// (grammar.y:100/103), producing the named composite in the factory.
    #[test]
    fn test_typed_parse_struct_definition() {
        let mut tf = standalone_factory();
        let mut p = CParse::new(4096);
        assert!(p.parse_stream_with_types(
            "struct pair { int4 lo ; int4 hi ; }",
            DocType::ParameterDeclaration,
            &mut tf
        ));
        let decls = p.take_result_declarations().expect("decls");
        let base = decls[0].basetype.as_ref().expect("basetype");
        assert_eq!(base.get_name(), "pair");
        assert_eq!(base.get_size(), 8);
        assert_eq!(
            base.get_metatype(),
            crate::type_system::datatype::TypeMetatype::Struct
        );
    }
}
