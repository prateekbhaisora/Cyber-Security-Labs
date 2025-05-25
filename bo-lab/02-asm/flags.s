	.file	"flags.c"
	.text
	.globl	foo
	.type	foo, @function
foo:
	movl	%esi, %eax
	leal	(%rdi,%rsi), %edx
	testb	$1, %dl
	cmove	%edi, %eax
	ret
	.size	foo, .-foo
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
