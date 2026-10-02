# comment.rs — Comment database API

Faithful port of Ghidra's `comment.hh` / `comment.cc` (406 lines).

**Status:** L2. The in-memory ordering/database projection, the observed
comment codec state, and the CommentSorter shared-iterator walking machinery
(setupBlockList/setupOpList/setupHeader + hasNext/getNext interleaving) match
the locked 12.0.4 oracle byte-for-byte (`COMMENT-SORTER-ITERATORS-0001`,
38-line projection MATCH). Full codec L3 remains blocked on restoring the
decoded `AddrSpace` handle through `Decoder`/`AddrSpaceManager`
(`ADDRESS-0001`, `MARSHAL-PACKED-0001`); the sorter keeps two registered
representation residuals (block-cover projection, cloned-Comment ownership)
under `COMMENT-SORTER-ITERATORS-0001` — the printc.rs glue-snapshot residual
was resolved 2026-08-23 when the consumers moved to the direct protocol.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment.{hh,cc}`.

## Module `comment_type`
Comment property flags (comment.hh:53):
- `USER1 = 1`, `USER2 = 2`, `USER3 = 4`, `HEADER = 8`, `WARNING = 16`,
  `WARNINGHEADER = 32`.

## Module `header_type`
CommentSorter header types (comment.hh:197):
- `HEADER_BASIC = 0`, `HEADER_UNPLACED = 1`.

## Structs

### `Comment`
A comment attached to a specific function and code address (comment.hh:43).
- `new(tp, fad, ad, uq, txt)`, `new_empty()`.
- `get_type()`, `get_func_addr()`, `get_addr()`, `get_uniq()`, `get_text()`,
  `set_emitted(val)`, `is_emitted()`.
- `emitted` is an `AtomicBool` mirroring Ghidra's `mutable bool emitted`
  (comment.hh:50): `set_emitted` mutates through a shared reference exactly
  like the const `setEmitted` (comment.hh:63), so
  `PrintLanguage::emitLineComment`'s `comm->setEmitted(true)`
  (printlanguage.cc:648) ports to a call-site mark during the sorter's const
  walk. `Cell<bool>` was rejected because `Funcdata` reaches a `Sync` bound
  via `ffi.rs`'s `Mutex<Option<Funcdata>>` global; `Relaxed` orderings keep
  plain-bool semantics. `Clone` is field-wise (re-loads the current flag),
  matching C++'s implicit copy.
- `encode(encoder) -> Result<()>` (comment.cc:37),
  `decode(decoder) -> Result<()>` (comment.cc:57).
  Address children use distinct `space` and `offset` attributes through the
  `AddrSpace::encodeAttributes` wire shape; text uses the special
  `XMLcontent` attribute ID corresponding to Ghidra's `ATTRIB_CONTENT`.

### Free functions
- `encode_comment_type(name) -> Result<u32>` (comment.cc:77).
- `decode_comment_type(val) -> Result<String>` (comment.cc:97).

Both return an error for unknown values, mirroring Ghidra's `LowlevelError`
instead of silently mapping them to zero or an empty string.

### `CommentDatabaseInternal`
In-memory CommentDatabase (comment.hh:161).
- `new()`, `clear()`, `clear_type(fad, tp)` (comment.cc:158).
- `add_comment(tp, fad, ad, txt)` (comment.cc:178).
- `add_comment_no_duplicate(tp, fad, ad, txt) -> bool` (comment.cc:196).
- `num_comments()`, `comments_for_function(fad)`, `all_comments()`.
- `encode(encoder) -> Result<()>` (comment.cc:242),
  `decode(decoder) -> Result<()>` (comment.cc:253).

### `Subsort`
Sorting key for placing a Comment within a basic block (comment.hh:203).
- `index` is the signed basic-block index, `-1` for a function header (Ghidra's
  `int4`), so header keys order before every block key.
- `set_header(header_type)`, `set_block(i, ord)` mutate index/order in place
  and leave `pos` untouched (the caller-owned uniqueness counter,
  comment.hh:224/233).
- Derives `Ord` over `(index, order, pos)` — Ghidra's `Subsort::operator<`.

### `CommentSorter`
Sorts comments into and within basic blocks (comment.hh:195) and acts as the
state for walking comments within one basic block or the header.
- `new()` — `displayUnplacedComments = false` (comment.hh:245).
- `setup_function_list(tp, fd, db, display_unplaced) -> Result<()>`
  (comment.cc:334) — walks every comment of the function (no type filtering;
  consumers apply the mask), places each via `find_position`, resets
  `emitted`, and advances the shared `pos` counter only on placement. Dead
  ops surface the oracle's `Dead op reaching CommentSorter` LowlevelError
  text (comment.cc:289/303).
- `setup_block_bounds(bl_index)` (comment.cc:379) — `start =
  lower_bound((bl,0,0))`, `stop = upper_bound((bl,0xffffffff,0xffffffff))`.
- `setup_op_stop(op: Option<&PcodeOpRef>)` (comment.cc:362) — `NULL` sets
  `opstop = stop`; otherwise `opstop = upper_bound((bl, op order,
  0xffffffff))`. `start` persists across calls, so successive landmarks emit
  only the comments between them (the printc.cc:3234 protocol).
- `setup_header(header_type)` (comment.cc:394) — `start =
  lower_bound((-1,headerType,0))`, `opstop =
  upper_bound((-1,headerType,0xffffffff))`.
- `has_next()` / `get_next()` (comment.hh:250-251) — `hasNext` compares the
  `start`/`opstop` iterator ranks; `getNext` returns the current comment and
  advances `start`.
- The legacy Vec snapshot adapters (`setup_block_list`, `setup_op_list`,
  `has_header_comments`, `header_comments`) were removed 2026-08-23:
  printc.rs now drives this state machine directly (see docs/api/printc.md,
  `emit_comment_group`/`emit_comment_func_header`/`emit_comment_block_tree`).

The `map<Subsort, Comment *>` is modeled as a sorted vector of
`(Subsort, comment index)` pairs; the `start`/`stop`/`opstop` members are
ranks into that order (`len` == `end()`), stored in `Cell`s because Ghidra's
`start` is `mutable` inside const `hasNext`/`getNext` (comment.hh:239-241).
`lower_bound`/`upper_bound` are partition-point rank projections of the
`std::map` bounds. `find_position` (comment.cc:270) implements the full
eight-way placement ladder (header-at-entry, PcodeOpTree lower-bound
containment, previous-op `0xffffffff` tail, migrated backupOp, op-less
`(0,0)`, `displayUnplaced` salvage, excised drop, dead-op error);
`BlockBasic::contains` is projected from `[start_addr,
initial_range stop]` (`set_initial_range`, block.cc:2625) because Rudra has
no block cover RangeList (block.hh:476 residual). Since 0d2252d removed the
last-op fallback in `get_stop_addr`, manually constructed blocks must
install the cover explicitly — the same legal state the C++ fixture builds
via `Funcdata::setBasicBlockRange` (funcdata.hh:556); Ghidra has no last-op
fallback anywhere in `getStop` (block.cc:2328-2335 returns an invalid
`Address()` on an empty cover, residual BLOCKBASIC-COVER-0001).

## Codec evidence and residual

`COMMENT-WARNING-CODEC-0001` runs paired Ghidra/Rudra fixtures against oracle
commit `e40ed13014025f82488b1f8f7bca566894ac376b`. The byte-compared projection
covers:

- WARNING at `ram:0x2000` round-tripping type, function/address offsets, text,
  `uniq`, and deterministic comment order;
- `addCommentNoDuplicate` comparing address plus text independent of type;
- `clearType` filtering only the selected function and bit-mask types;
- unknown decoded type-name, unknown encoded property, and missing address
  offset errors, including partial object/encoder state.

Projection status is `MATCH`. Overall status remains `MISMATCH`: Ghidra's
`Address::decode` obtains the architecture-owned space through the decoder's
`AddrSpaceManager`; Rudra's current `Decoder` trait exposes no equivalent.
The Rust decoder therefore validates and consumes the encoded space name but
can only return the legacy offset-only `Address`. Unknown space-name rejection
and exact address-space identity remain with `ADDRESS-0001` and
`MARSHAL-PACKED-0001`; this module must not be promoted to L3 before they land.

## 2026-08-23：CommentSorter 共享迭代器状态机移植记录（COMMENT-SORTER-ITERATORS-0001）

- **Subsort.index 改为 `i32`、`-1` 表头注释**：对齐 Ghidra 的 `int4 index`
  （comment.hh:204），头部键排在一切块键之前；`set_header`/`set_block` 改为
  原地修改且不再触碰 `pos`（comment.hh:224/233——`pos` 是 setupFunctionList
  的调用方计数器）。
- **find_position 重写为 comment.cc:270-325 的八臂判定梯**：type==0 丢弃 →
  header/warningheader@fad → header_basic；PcodeOpTree lower_bound
  （(addr,time) 序，op.cc:1146）命中且所在块 contains → 该 op 的 order；
  前一 op 块 contains → 块尾 0xffffffff；精确地址 backupOp（op 迁移出原块）；
  无任何 op → (0,0)；displayUnplaced → header_unplaced；否则块被切除丢弃。
  死 op（optree 内无 parent）抛出与 oracle 逐字节相同的
  `Dead op reaching CommentSorter`（comment.cc:289/303，anyhow 通道）。
  旧实现的"块起始地址兜底"是自创算法，已删除。
- **setup_function_list 去掉自创 type 预过滤**：Ghidra 在 setup 阶段不按 tp
  过滤（消费端才做，printc.cc:3238/3280）；`pos` 计数器只在放置成功时递增
  且跨迭代持续（comment.cc:344/351）；放置后 `set_emitted(false)`。
- **start/stop/opstop 迭代器状态机**：`commmap` 建模为排序
  `Vec<(Subsort, usize)>`，三个迭代器建模为秩（`len` == `end()`），存于
  `Cell<usize>`（Ghidra 的 `mutable start` 在 const hasNext/getNext 中推进，
  comment.hh:239-251）。`setup_block_bounds`/`setup_op_stop`/`setup_header`
  分别复现 comment.cc:379/362/394 的 lower_bound/upper_bound 边界；
  `setup_op_stop(None)` 取 `opstop = stop`。连续 landmark 之间 `start` 不回退，
  只收窄 `opstop`——即 printc emitCommentGroup 的交错消费协议。
- **Vec 胶水适配器已删除**（原 `setup_block_list`/`setup_op_list`/
  `has_header_comments`/`header_comments`）：2026-08-23 printc.rs 消费端
  （`emit_comment_group`/`emit_comment_func_header`/`emit_comment_block_tree`）
  迁移到 `setup_block_bounds`/`setup_op_stop`/`setup_header`/
  `has_next`/`get_next` 直接协议，原残差 3 关闭；`Comment.emitted` 改为
  `AtomicBool` 内部可变（对齐 `mutable bool emitted`，comment.hh:50），
  使 `emit_line_comment` 后的 `set_emitted(true)`（printlanguage.cc:648）
  可经共享引用在排序器行走中落地。
- **Oracle 证据**：`tools/run_comment_sorter_iterators_oracle.sh`
  （pin-base 8d59b77 + src/comment.rs、src/block.rs overlay，schema-2
  metadata；2026-08-25 BLOCK-STOPADDR-FIXTURE-REGRESSION-0001 重钉后双侧
  在本机重跑通过：锁定 Ghidra 12.0.4 (e40ed130) 归档重建 + 宿主工具链）——
  锁定 Ghidra 12.0.4 (e40ed130) 与 Rudra 的 38 行交错消费投影
  **byte-identical**：header basic/unplaced 两轮、三个块的
  setupBlockList→setupOpList(op…)→setupOpList(NULL) 交错行走、
  0xffffffff 块尾放置、迁移 backupOp、空块 0 排空、tp 掩码外的 USER1
  注释照常放置（证明 setup 不过滤）、displayUnplaced=false 切除、
  死 op 错误文本、无 op 函数 (0,0) 放置。
- **残差（绑定 `COMMENT-SORTER-ITERATORS-0001`）**：
  1. `BlockBasic::contains` 用 `[start_addr, set_initial_range 端点]` 投影
     Ghidra 的 cover RangeList（Rudra 无块 cover 系统，block.hh:476）；
     fixture 两侧把块范围钉到相同边界（C++ `setBasicBlockRange` /
     Rudra `set_initial_range`），管线中块 cover 终值 == 末指令地址，故
     等价，但形式化等价未证；无 range 存量块的 `start_addr` 回退与
     Ghidra invalid-`Address()` 语义的差异归 `BLOCKBASIC-COVER-0001`。
  2. CommentSorter 持有 Comment 克隆而非数据库指针：setupFunctionList 的
     `setEmitted(false)` 与消费端发射后的 `set_emitted(true)` 都只改
     排序器副本，不回写 CommentDatabaseInternal（Ghidra 经
     `mutable emitted` 直改库内对象）。
  （原残差 3「printc.rs 胶水快照消费端」已于 2026-08-23 关闭。）
  模块整体仍为 L2/MISMATCH：codec 的 `ADDRESS-0001`/`MARSHAL-PACKED-0001`
  残差不变。
<!-- annotation-pass: 2026-08-23 -->

<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
