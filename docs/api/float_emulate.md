# `float_emulate.rs` API Reference

**源代码路径**: `src/float_emulate.rs`
**Ghidra 对应**: `float.hh` / `float.cc` (673行)
**状态**: ✅ **L3（结构级 1:1，2026-08-23 FLOAT-FMT-STRUCT-0001；FLOAT-OPTRUNC-OOB-0001 关闭
opTrunc 越界残差）**——全部 FloatFormat 方法覆盖；
host 转换走 oracle 位阶梯（createFloat/extractExpSig + 64 位顶对齐 fractional code 约定），
结构级 oracle 证明见 `tests/oracle/float_fmt_struct_1204`（153 case 含 opTrunc 三档越界）。21 单元测试。
**2026-08-23 结构重构（FLOAT-FMT-STRUCT-0001）**:
- `get_host_float`（float.cc:228-268）由 `(significand as f64) * 2f64.powi(...)` 乘积改为 oracle 位阶梯：
  顶对齐 `extract_fractional_code`（float.cc:113-119）→ `exp -= bias` → jbit room
  （`frac >>= 1; frac |= 1<<63`，float.cc:261-266）→ 静态 `create_float` ldexp 阶梯（float.cc:67-80）。
  **修复了 denormalized 分支的值缺陷**：原 `frac * 2^(1-bias)` 按右对齐 frac 计算，denormal 值偏大
  2^frac_size 倍（f32 0x00000001 原返回 2^-126，oracle 为 2^-149）。
- `get_encoding`（float.cc:293-346）由 `(host as f32).to_bits()`/`host.to_bits()` 位转换改为
  extractExpSig（float.cc:89-109，frexp→ldexp(·,63)→`(uintb)`→`<<1` 顶对齐中间态）+
  roundToNearestEven 位阶梯 + 顶对齐 setFractionalCode/setExponentCode/setSign 打包。
  **NaN 输入语义变化**：oracle 丢弃 NaN payload（getNaNEncoding 只留 quiet bit + 符号，
  float.cc:205-215），原实现的 to_bits 透传 payload 与 oracle 分歧；RNE 值行为对非 NaN 输入不变。
- `extract_fractional_code`/`set_fractional_code` 语义改为 **oracle 顶对齐约定**
  （float.cc:113-119/144-153）：extract 输出 bit63=frac MSB；set 输入顶对齐 code、
  `>>= 64-frac_size` 后 OR 入（不 mask x，调用方契约 float.cc:141 假定 frac 位已清零）。
  原右对齐+mask 语义与 oracle 语义不同；crate 内无外部调用者依赖旧语义。
- `set_sign`（float.cc:158-166）`sign=false` 时为恒等（oracle 从不清位）；`set_exponent_code`
  （float.cc:171-177）改为无 mask 的 OR。
- `get_zero/infinity/nan_encoding`（float.cc:181/193/205）改为 oracle 三 setter 结构；
  NaN quiet bit 以顶对齐 `1<<63` mask 经 setFractionalCode 落到 frac MSB。
- 新增静态 `create_float`/`extract_exp_sig`（float.cc:67/89，pub 以供 oracle fixture 直接驱动）
  与 libm `ldexp`/`frexp` FFI 绑定（oracle float.cc:25-26 `using std::ldexp/frexp`；
  `x * 2f64.powi(e)` 在指数本身上/下溢时不可复现 ldexp 的渐进下溢，
  如最小 f64 denormal 需 `ldexp(2^11, -1085) == 2^-1074`）。
- `round_to_nearest_even` 由 pub(crate) 改 pub（oracle fixture 驱动）。
- 新增 6 个结构回归测试（顶对齐约定/extractExpSig/denormal 阶梯/getEncoding 阶梯/
  createFloat ldexp 饱和/roundToNearestEven 直驱含回绕进位）；
  结构级 oracle 证明 `tests/oracle/float_fmt_struct_1204`（runner
  `tools/run_float_fmt_struct_oracle.sh`，锁 e40ed130）。
- `op_trunc`（float.cc:631-640）的 `(intb)val` 越界/NaN 语义与 `calc_mask(sizeout)` 缺失已由
  **FLOAT-OPTRUNC-OOB-0001** 修复（见下），经 19 个三档 oracle case 证明 MATCH。
**2026-08-23 修复（FLOAT-OPTRUNC-OOB-0001）**:
- `op_trunc(a, size_out)` 对齐 float.cc:631-640 全语义：`(intb)val` 在 x86-64 oracle host 上
  编译为 cvttsd2si——NaN/±Inf/|val|≥2^63 一律转为整数不定值 INT64_MIN(0x8000000000000000)，
  随后 `res &= calc_mask(sizeout)`（address.hh:499，uintbmasks 表 address.cc:631-634）。
  Rust 饱和 `as`（NaN→0、正溢出→i64::MAX）与 oracle 分歧，且原实现完全忽略 size_out 无 mask。
  修复后按显式范围测试 ±2^63 之外/NaN 走 INT64_MIN，界内截断向零；-2^63 恰好落入不定值分支
  且其真实转换值即 i64::MIN，两侧一致。calc_mask(8) 原样保留 0x8000000000000000，
  sizeout<8 时低字节为 0（oracle 实测 tr4_max_sz4=0、tr8_1e300_sz2=0）。
  oracle 证明：`tests/oracle/float_fmt_struct_1204` 扩展 19 个 trunc case
  （正常值 mask 档 / 大值越界档 / NaN-Inf 档），153/153 双侧字节一致，
  runner `tools/run_float_fmt_struct_oracle.sh` EXIT=0；新增单元测试
  `test_float_trunc_oob_and_mask`。
**2026-07-02 修复（R101）**: `max_exponent` 由硬编码 254/2046 改为 255/2047，对齐 Ghidra `float.cc:59 maxexponent = (1<<exp_size)-1`。原 off-by-one 使 `get_host_float` 的 `exp_code == max_exponent` 检查错过全 1 指数 → infinity/NaN 被误读为 normalized 值。
**2026-08-23 修复（FLOAT-OPINT2FLOAT-SIGN-0001）**:
- `op_int2float(a, size_in)` 改为 oracle 符号语义：`sign_extend(a, 8*sizein-1)`（address.hh:543）丢弃
  sizein 符号位以上的比特并符号扩展后再 `(double)` 转换（float.cc:611-617）。原实现按无符号 `a as f64`
  解释输入且忽略 `size_in`，负整数输入与 oracle 分歧。
- `op_float2_float` 由 host-double 中转改为 1:1 位级 `convert_encoding` 端口（float.cc:352-419），含
  静态 `round_to_nearest_even`（float.cc:276-288，uintb 进位回绕语义）。oracle
  `extractFractionalCode`/`setFractionalCode` 的 **64 位字顶对齐**约定（float.cc:113-119/144-153）
  自 FLOAT-FMT-STRUCT-0001 起由公共 helper 本身承载（此前 convert_encoding 用局部顶对齐操作）。
- `get_host_float` 的 NaN 分支补上编码符号（float.cc:253-254 `return sgn ? -nan : +nan;`）。
- 注释行号修正：`op_int2float`→float.cc:611、`get_nan_encoding`→float.cc:205、`get_size`→float.hh:66。
- 新增 2 个符号语义回归测试；oracle 证明见 `tests/oracle/float_int2float_sign_1204`
  （runner `tools/run_float_int2float_sign_oracle.sh`，锁 e40ed130；
  该 runner pin-base 冻结于 base 1fc8af3 + 2d85fa8 的 float_emulate.rs sha，
  本重构后其 sha 门禁会拒绝复跑——36 case 值等价由 float_fmt_struct_1204 全量重覆盖）。

## 模块说明

浮点格式编解码与运算模拟。对应 Ghidra 的 `float.hh`。

## 导出的公共 API

### `pub enum FloatClass`
浮点编码分类（Normalized/Infinity/Zero/Nan/Denormalized）。

### `pub struct FloatFormat`
IEEE754 浮点格式描述。对应 Ghidra `FloatFormat`。
- `new(size)` — 构造单/双精度格式
- `get_host_float(encoding, &mut class)` — 编码→f64，oracle 位阶梯（float.cc:228-268：
  顶对齐 frac + jbit room + createFloat ldexp；denormalized 分支含值修复）
- `get_encoding(host)` — f64→编码，oracle 位阶梯（float.cc:293-346：extractExpSig +
  roundToNearestEven + 顶对齐打包；NaN payload 被规范化为 quiet bit）
- `create_float(sign, signif, exp)` — 静态组合原语（float.cc:67-80，顶对齐 signif，ldexp 饱和）
- `extract_exp_sig(x, &mut sgn, &mut signif, &mut exp)` — 静态分解原语（float.cc:89-109，
  frexp/ldexp 顶对齐中间态；zero/inf/NaN 早退不写出参）
- `round_to_nearest_even(&mut signif, lowbitpos)` — RNE 原语（float.cc:276-288，uintb 回绕进位）
- `extract_fractional_code/sign/exponent_code` — 位域提取（frac **顶对齐**：bit63=frac MSB，
  float.cc:113-119）
- `set_fractional_code/set_sign/set_exponent_code` — 位域打包（顶对齐 code、OR 语义、
  set_sign(false) 恒等；float.cc:144-177）
- `get_zero/infinity/nan_encoding(sgn)` — 特殊值编码（float.cc:181/193/205，三 setter 结构）
- `convert_encoding(encoding, &formin)` — 位级格式互转（float.cc:352-419，顶对齐约定贯穿）
- `op_int2float(a, size_in)` — 有符号整数→浮点（sign_extend 自 size_in 字节，float.cc:611-617）
- `op_float2_float(a, &outformat)` — 精度转换（= outformat.convert_encoding(a, self)，float.cc:622-626）
- `op_trunc(a, size_out)` — 浮点→整数（x86-64 cvttsd2si 语义：NaN/±Inf/|val|≥2^63 →
  INT64_MIN 整数不定值，界内向零截断；再 `& calc_mask(size_out)`，float.cc:631-640）
- 15 个 op 操作：`op_equal/op_less/op_add/op_sub/op_mult/op_div/op_neg/op_abs/op_sqrt/op_floor/op_ceil/op_nan/op_int2float`

测试：float_emulate::tests 21 个（含 INT2FLOAT 符号扩展、convertEncoding 位级、
顶对齐约定、extractExpSig/createFloat/denormal 阶梯、roundToNearestEven 直驱回归，
以及 opTrunc 三档越界 + mask 回归）。

## 已知残差（登记于本文件，供后续 TODO 认领）

（无——opTrunc 越界残差已由 FLOAT-OPTRUNC-OOB-0001 关闭。）

## 2026-06-26（续）：float_emulate.rs 完善实现

新增完整浮点操作（覆盖 float.hh 全部 op 方法）：
- op_not_equal (!=) / op_less_equal (<=) / op_trunc (float→int) / op_round / op_float2_float (精度转换)
- 新增 op_div 测试 + 5 个新操作测试

现在覆盖 Ghidra FloatFormat 的全部 17 个 op 方法。
<!-- annotation-pass: 2026-08-23 -->

## 2026-09-26：printDecimal + calcPrecision（PRINTC-UNMAP-SINGLETON-0001，push_float 依赖）

- `calc_precision()`（`// Ghidra: float.cc:217 FloatFormat::calcPrecision`）——
  `decimalMinPrecision = floor(frac_size * 0.30103)`（log10(2) 截断）、
  `decimalMaxPrecision = ceil((frac_size + 1) * 0.30103) + 1`（IEEE 754
  二进制→十进制→二进制往返保真界）；两字段入 `FloatFormat` 结构
  （float.hh:51-52），`new` 尾调用（float.cc:66 ctor 同位）。
- `print_decimal(host, forcesci)`（`// Ghidra: float.cc:427
  FloatFormat::printDecimal`）——最小数字唯一表示环：`prec` 自
  decimalMinPrecision 起，`%.*g`（默认 floatfield）/`%.*e`（scientific，
  precision=prec-1 不计首位）渲染后按目标格式往返解析（size<=4 走 f32
  宽化，float.cc:451-457），相等即返；prec==decimalMaxPrecision 无条件返
  当前串（float.cc:442-443）。Rust 无 %g——`printf_g` 复刻 printf 算法
  （%e 读指数 → exp<-4||exp>=p 保 %e 否则 %f(p-1-exp) → 尾零剥离），指数尾
  规范化为 C 的 `e±NN` 形（Rust LowerExp 原生 `e<N>`）。
- 消费方：printc.rs `push_float_text`（printc.cc:1380-1424 全量移植的
  print 侧）；双侧 fixture `printc_singleton_emission_1204` 21 float case
  字节恒等（含 subnormal `1.4013e-45`、scinote `3.1415927e+00`、
  `1.00000000000000e-01` 往返精度形态）。
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
