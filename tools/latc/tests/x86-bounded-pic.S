.text
.global _start
.type _start,@function
_start:
    xor %r12d, %r12d
    jmp bounded_guard
.size _start, .-_start

/* Neither the dispatch nor its cases have STT_FUNC ownership. */
.global bounded_guard
bounded_guard:
    cmp $2, %r12d
    ja .Ldefault
    mov %r12d, %eax
    mov $7, %ebx
    lea .Ltable(%rip), %rcx
    movslq (%rcx,%rax,4), %rdx
    add %rcx, %rdx
    jmp *%rdx
.Ldefault:
    mov $1, %edi
    jmp .Lexit

/* Case labels deliberately have no STT_FUNC owner. */
.global bounded_case0, bounded_case1, bounded_case2
bounded_case0:
    xor %edi, %edi
    jmp .Lexit
bounded_case1:
    mov $1, %edi
    jmp .Lexit
bounded_case2:
    mov $2, %edi
.Lexit:
    mov $60, %eax
    syscall
.section .rodata
.Ltable:
    .long bounded_case0 - .Ltable
    .long bounded_case1 - .Ltable
    .long bounded_case2 - .Ltable
.section .note.GNU-stack,"",@progbits
