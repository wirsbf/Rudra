# CARRY 泄漏根因档案(register0x00000200 vs oracle CARRY1 宏)

任务:`GLOBWORD-C3-CARRY-INJECT-0001`(writer w-x86carry, 2026-08-30)
worktree:`/home/wirs/.cache/rudra-w2-x86c`(master=66ae28b8)
oracle:Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`(decompile cpp)
SLEIGH spec:`sleigh_specs/x86-64.sla`(编译自同一 oracle 的 x86-64 语言)

## 0. 结论(一句话)

**curl 全语料 5 处 `register0x00000200` 泄漏不在 x86 提升,也不在 ruleaction 折叠规则:
SLEIGH 提升产出的 INT_CARRY 完整存活到最终 IR(输出 implied),但 Rudra printc 的
`emit_inline_expr` 没有 INT_CARRY/INT_SCARRY/INT_SBORROW 分支,implied 下降落入
`_ =>` fallback,把 CF(:register:200)按未命名位置打成 `register0x00000200`。**
Ghidra 侧对应物是 `PrintC::opIntCarry`(printc.hh:293)→ `opFunc`(printc.cc:424-448)
→ `TypeOpIntCarry::getOperatorName`(typeop.cc:1340-1346)= `"CARRY" + dec(in(0)->size())`
→ 打印 `CARRY1(a,b)`。**无任何 Ghidra 折叠规则参与**(RuleSborrow/RuleScarry 是
SBORROW 化简 signed 比较、RuleCarryElim 是常量 carry,均不在本形态上发射)。

## 1. 泄漏清单(基线 = master 66ae28b8,E2E 3104/0/0)

| Rudra 输出行 | 函数 | oracle golden 对应 |
|---|---|---|
| :1206 声明 `long register0x00000200;` | my_get_line(0x3840, 共享 file2string 尾) | — |
| :1231 `0 - (int *)(bool)(long)register0x00000200` | 同上 | :1331 `-(ulong)CARRY1((byte)uVar7,(byte)uVar7)` |
| :1233 同形态第二处 | 同上 | :1332 `(-5 - (ulong)CARRY1((byte)uVar6,(byte)uVar6))` |
| :1324 声明 | file2string.part.0(0x3a90) | — |
| :1343 同形态 | 同上 | :1478 `(-3 - (ulong)CARRY1((byte)uVar5,(byte)uVar5))` |

源指令(curl binary, file2string.part.0 strlen 尾):

```asm
3b5a: mov %eax,%ecx
3b5c: add %al,%cl        ; CF = carry(al+cl), al==cl → CARRY1(x,x)
3b5e: sbb $0x3,%rbx      ; rbx = (rbx-3) - zext(CF)
3b62: sub %r13,%rbx
```

## 2. 双侧证据

### 2.1 SLEIGH 提升侧(probe = `examples/x86carry_probe.rs`,提交在本仓库)

`sleigh_specs/x86-64.sla` 对 0x3b5c/0x3b5e 的 pcode(与 Ghidra 引擎逐 op 一致,经
sleigh_shim 直通):
```
@0x3b5c: INT_CARRY  out=register:0x200:1 = (register:0x8:1, register:0x0:1)   ← CF 定义
@0x3b5e: INT_ZEXT   out=uniq:0x57700:8 = (register:0x200:1)                   ← CF 读取
         ...
         INT_SUB    out=register:0x18:8 = (rbx-3, zext(CF))
```
寄存器布局(oracle sla getAllRegisters 全量 dump,RIP 相关):
`RAX=0x0 … R15=0xB8;CF=0x200 … ID=0x214(各 1 字节);rflags=0x280:8/eflags=0x280:4;RIP=0x288:8/EIP=0x288:4`。
即 **0x200 = CF(1-bit flag),不存在 8 字节寄存器**;泄漏名 `register0x00000200`
是 1 字节 CF 高变量走了未命名位置回退(worker Architecture 已装全量 register xref,
CF 有名,但 print 回退路径不查 xref)。

### 2.2 Rudra 最终 IR(E2E RUDRA_DUMP_FUNC=file2string.part.0)

```
op @0x3b5c CPUI_INT_CARRY outimpl=true vn#561(h=:register:200, t=Bool/bool)
    = (vn#563(h=:register:0, Uint/uint1), vn#563(同))
op @0x3b5e CPUI_INT_ZEXT  outimpl=true vn#3655(long) = (vn#561)
op @0x3b5e CPUI_CAST      outimpl=true vn#587(Bool/bool) = (vn#3655)     ← 多余 cast①
op @0x3b5e CPUI_CAST      outimpl=true vn#3657(Int/int8) = (vn#587)      ← 多余 cast②
op @0x3b5e CPUI_INT_SUB   = (const:0, vn#3657)
```
IR 链完整、INT_CARRY 存活、输出 implied → 泄漏纯为打印层。

### 2.3 oracle 实机(console decomp_opt,SLEIGHHOME=sleigh_specs)

```
iVar4 = (int8)puVar9 + ((-3 - (uint8)CARRY1((uint1)uVar3,(uint1)uVar3)) - (int8)auStack_148);
```
零 register0x00000200;CARRY1 宏形态与 golden(:1331/:1332/:1478)一致。

## 3. 修复规格(移交 printc/typeop owner;均不在本任务 write-set)

1. **printc.rs `emit_inline_expr`(≈:6373)**:新增
   `CPUI_INT_CARRY | CPUI_INT_SCARRY | CPUI_INT_SBORROW` 分支 → 调 op_func 形态
   (Ghidra printc.hh:293-295 opIntCarry/opIntScarry/opIntSborrow 全部 → opFunc)。
2. **operator 名**(typeop.cc:1340/1356/1372 getOperatorName):
   `format!("{}{}", NAME, op.get_in(0).size())`,NAME = `CARRY`/`SCARRY`/`SBORROW`
   (大写,非 pcode 名;非 Rudra 现有 "carry" 小写,无 size 后缀)。
   Rudra printc.rs:10827 `op_func` 现用 `op.opcode.name()`("INT_CARRY"),需改走
   typeop get_operator_name 端口。typeop.rs functional_binary_op! 宏(:610)的
   `push` 也应走 op_func(Ghidra typeop.hh:460-468 push → lng->opIntCarry)。
3. **残留预告(修复①②后仍存在,须另行登记)**:
   - CARRY 参数:Rudra IR 输入是裸 `register:0:1`(h=:register:0 无符号),oracle 是
     `(byte)uVar7` = SUBPIECE 化的 eax 读 → heritage 子寄存器 piece-split 域
     (heritage.rs,禁止本任务动)。不修则泄漏变形为 `CARRY1(register0x00000000, …)`。
   - 多余 CAST(bool) 链(§2.2 cast①②):oracle 只有一层 (uint8);coreaction
     ActionSetCasts/typeop cast 域。
4. **预期判据**:curl 全语料 `register0x00000200` 5→0;`CARRY1(`/`SCARRY`/`SBORROW`
   出现;3104/0/0 不劣化(cast 链残差会留少量 skeleton 行,需在 Differential 块解释)。

## 4. 本任务在 write-set 内的实修

- `src/disasm/x86_lift.rs`(iced 路径寄存器表):`"rip"|"eip"` 偏移 0x200 → **0x288**
  (oracle sla 布局;旧值与 CF..F5 flag 区 0x200..0x205 别名,rip 相对内存操作数的
  地址基会落在 flags 区)。curl E2E 实测输出字节不变(3104/0/0,leak 5 不变)。
- iced 路径(`httpd_decompile`/`rudra_decompile_func`)已知更大缺口,另行登记:
  `add/sub/and/or/xor/shl/shr/sar` 不产任何 flag pcode(Ghidra x86 sinc 语义全量
  CF/OF/SF/ZF/AF/PF);`sbb/adc/cmovcc/setcc` 完全未实现(0 op)。httpd golden 有
  `CARRY1`(:39307)与 `CARRY8`(:35777)形态;修复须按 ia.sinc 逐语义补,禁止简化版。

## 5. 证据产物

- probe:`examples/x86carry_probe.rs`(寄存器布局 + strlen 尾 pcode dump)。
- 基线/修复后 E2E:`/tmp/w-x86c-base.stdout`、`/tmp/w-x86c-fix.stdout`(字节一致)。
- IR dump:`/tmp/w-x86c-dump.stderr`(RUDRA_DUMP_FUNC=file2string.part.0)。
- oracle 运行:`/tmp/w-x86c-ore-f2s.stdout`(decomp_opt, /tmp/w-carry-ore)。
- 全量寄存器表 dump:probe 输出(1440 条,GPR/flags/rflags/RIP 摘录见 §2.1)。
