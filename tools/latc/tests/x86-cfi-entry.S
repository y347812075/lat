.text
.global _start
.type _start,@function
_start:
    lea cfi_table+64(%rip), %rax
.global cfi_guard
cfi_guard:
    lea cfi_table(%rip), %rcx
    mov %rax, %rdx
    sub %rcx, %rdx
    ror $6, %rdx
    cmp $1, %rdx
    ja .Lfail
    mov $19, %esi
    call *(%rax)
    cmp $42, %eax
    jne .Lfail
    lea cfi_sparse_table+128(%rip), %rax
.global cfi_sparse_guard
cfi_sparse_guard:
    lea cfi_sparse_table(%rip), %rcx
    mov %rax, %rdx
    sub %rcx, %rdx
    ror $6, %rdx
    cmp $2, %rdx
    ja .Lfail
    movabs $5, %r15
    bt %rdx, %r15
    jae .Lfail
    call *(%rax)
    cmp $44, %eax
    jne .Lfail
    call .Lregister_dispatch
    cmp $46, %eax
    jne .Lfail
    lea cfi_narrow_table+128(%rip), %rax
.global cfi_narrow_guard
cfi_narrow_guard:
    lea cfi_narrow_table(%rip), %rcx
    mov %rax, %rdx
    sub %rcx, %rdx
    ror $6, %rdx
    cmp $2, %rdx
    ja .Lfail
.global cfi_narrow_mask
cfi_narrow_mask:
    mov $5, %r15d
    bt %edx, %r15d
    jae .Lfail
.global cfi_narrow_load
cfi_narrow_load:
    movzbl (%rsp), %esi
    call *(%rax)
    cmp $48, %eax
    jne .Lfail
    lea cfi_byte_table+3848(%rip), %rax
.global cfi_byte_guard
cfi_byte_guard:
    lea cfi_byte_table(%rip), %rcx
    mov %rax, %rdx
    sub %rcx, %rdx
    ror $3, %rdx
    cmp $481, %rdx
    ja .Lfail
.global cfi_byte_filter
cfi_byte_filter:
    lea cfi_byte_predicate(%rip), %rcx
    testb $128, (%rcx,%rdx)
    je .Lfail
    call *(%rax)
    cmp $50, %eax
    jne .Lfail
    xor %edi, %edi
    mov $60, %eax
    syscall
.Lfail:
    mov $1, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.Lregister_dispatch:
    push %rbx
    lea cfi_register_table+256(%rip), %rax
.global cfi_register_guard
cfi_register_guard:
    lea cfi_register_table(%rip), %rcx
    mov %rax, %rdx
    sub %rcx, %rdx
    ror $8, %rdx
    cmp $1, %rdx
    ja .Lregister_fail
.global cfi_register_load
cfi_register_load:
    mov 16(%rax), %rax
    mov %rbx, %rdi
    xor %esi, %esi
    pop %rbx
    jmp *%rax
.Lregister_fail:
    mov $1, %edi
    mov $60, %eax
    syscall

/* No STT_FUNC or FDE identifies either indirect target. */
.global cfi_case0, cfi_case1
.hidden cfi_case0, cfi_case1
cfi_case0:
    mov $41, %eax
    ret
cfi_case1:
    mov $42, %eax
    ret
.global cfi_sparse_case0, cfi_sparse_case1
.hidden cfi_sparse_case0, cfi_sparse_case1
cfi_sparse_case0:
    mov $43, %eax
    ret
cfi_sparse_case1:
    mov $44, %eax
    ret
.global cfi_register_case0, cfi_register_case1
.hidden cfi_register_case0, cfi_register_case1
cfi_register_case0:
    mov $45, %eax
    ret
cfi_register_case1:
    mov $46, %eax
    ret
.global cfi_narrow_case0, cfi_narrow_case1
.hidden cfi_narrow_case0, cfi_narrow_case1
cfi_narrow_case0:
    mov $47, %eax
    ret
cfi_narrow_case1:
    mov $48, %eax
    ret
.global cfi_byte_case0, cfi_byte_case1
.hidden cfi_byte_case0, cfi_byte_case1
cfi_byte_case0:
    mov $49, %eax
    ret
cfi_byte_case1:
    mov $50, %eax
    ret

.section .rodata,"a",@progbits
.global cfi_byte_predicate
.hidden cfi_byte_predicate
cfi_byte_predicate:
    .byte 128
    .zero 480
    .byte 128

.section .data.rel.ro,"aw",@progbits
.balign 64
.global cfi_table
.hidden cfi_table
cfi_table:
    .quad cfi_case0
    .zero 56
    .quad cfi_case1
.balign 64
.global cfi_sparse_table
.hidden cfi_sparse_table
cfi_sparse_table:
    .quad cfi_sparse_case0
    .zero 120
    .quad cfi_sparse_case1
.balign 256
.global cfi_register_table
.hidden cfi_register_table
cfi_register_table:
    .zero 16
    .quad cfi_register_case0
    .zero 248
    .quad cfi_register_case1
.balign 64
.global cfi_narrow_table
.hidden cfi_narrow_table
cfi_narrow_table:
    .quad cfi_narrow_case0
    .zero 120
    .quad cfi_narrow_case1
.balign 8
.global cfi_byte_table
.hidden cfi_byte_table
cfi_byte_table:
    .quad cfi_byte_case0
    .quad cfi_byte_case0 /* Unselected slot supplies an independent RELA probe. */
    .zero 3832
    .quad cfi_byte_case1
.section .note.GNU-stack,"",@progbits
