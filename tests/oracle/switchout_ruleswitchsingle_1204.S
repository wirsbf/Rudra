/* switchout_single.S — constructed RuleSwitchSingle trigger (hand-written
 * so the dispatch table entries are statically identical, which gcc folds
 * away in any pure-C form).
 *
 * single_target_switch: entry block (mask) -> dispatch block (table load +
 * BRANCHIND via jmp *%rcx) -> body block. The 8-entry table .rodata:jtab
 * all points at .Lbody, so recovered jumptable = 8 labelled entries with
 * one destination: dispatch block sizeOut==1 -> RuleSwitchSingle
 * (oracle ruleaction.cc:5412) converts BRANCHIND->BRANCH, warns
 * "Switch with 1 destination removed at ... : 8 cases all go to same
 * destination", and removeJumpTable (funcdata_block.cc:64-78) clears
 * f_switch_out from the dispatch block at cc:76.
 */
	.section .rodata
	.align 8
	.globl jtab
jtab:
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody
	.quad .Lbody

	.text
	.globl single_target_switch
	.type single_target_switch, @function
single_target_switch:
	endbr64
	movl	%edi, %eax          /* keep original arg            */
	andl	$7, %ecx            /* bound index -> table size 8  */
	leaq	jtab(%rip), %rdx    /* table base                   */
	movq	(%rdx,%rcx,8), %rcx /* load target (volatile load)  */
	jmp	*%rcx               /* BRANCHIND                    */
.Lbody:
	addl	$1, %eax            /* body work: r = x + 1         */
	ret
	.size single_target_switch, .-.Lbody
