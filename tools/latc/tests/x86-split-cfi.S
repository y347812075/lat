.text
.global _start
.type _start,@function
_start:
    lea split_table+8(%rip), %rax
    mov $3, %ecx
    movzbl %cl, %r15d
.global split_complement
split_complement:
    mov $64, %cl
    sub %r15b, %cl
    movzbl %cl, %r12d
    call split_preserve
.global split_proof
split_proof:
    mov %rax, %rdx
    lea split_table(%rip), %rcx
    sub %rcx, %rdx
    mov %rdx, %rsi
    mov %r15d, %ecx
    shr %cl, %rsi
    mov %r12d, %ecx
    shl %cl, %rdx
    or %rsi, %rdx
    cmp $1, %rdx
    ja .Lfail
    call *(%rax)
    cmp $42, %eax
    jne .Lfail
    xor %edi, %edi
    mov $60, %eax
    syscall
.Lfail:
    mov $1, %edi
    mov $60, %eax
    syscall
.size _start, .-_start
.global split_case0, split_case1
.hidden split_case0, split_case1
split_case0:
    mov $41, %eax
    ret
split_case1:
    mov $42, %eax
    ret
.global split_preserve
split_preserve:
    push %r15
    mov $19, %r15d
    sub $32, %rsp
    lea 8(%rsp), %rdi
    call split_write_local
    add $32, %rsp
.global split_preserve_restore
split_preserve_restore:
    pop %r15
    ret
.global split_write_local
split_write_local:
    push %rbp
    mov %rsp, %rbp
    mov 8(%rbp), %rdx
    mov %rax, (%rdi)
    mov %rdx, 8(%rdi)
    setl %sil
.global split_setcc_store
split_setcc_store:
    seto 16(%rdi)
    pop %rbp
    ret
.section .data.rel.ro,"aw"
.p2align 3
.global split_table
split_table:
    .quad split_case0, split_case1
.global split_spare_reloc
split_spare_reloc:
    .quad split_preserve
.section .note.GNU-stack,"",@progbits
