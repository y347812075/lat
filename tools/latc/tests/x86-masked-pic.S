.text
.global _start
.type _start,@function
_start:
    xor %r12d, %r12d
.Louter:
    xor %r13d, %r13d
.Linner:
    mov %r12d, %edi
    mov %r13d, %esi
    call masked_dispatch
    mov %r12d, %ebx
    sub %r13d, %ebx
    jns .Labs
    neg %ebx
.Labs:
    mov $43, %ecx
    sub %ebx, %ecx
    cmp %ecx, %eax
    jne .Lfail
    inc %r13d
    cmp $3, %r13d
    jbe .Linner
    inc %r12d
    cmp $3, %r12d
    jbe .Louter
    xor %edi, %edi
    mov $60, %eax
    syscall
.Lfail:
    mov $1, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

/* Dispatch and cases deliberately have no STT_FUNC ownership. */
.global masked_dispatch
masked_dispatch:
    mov %edi, %eax
    mov %esi, %ecx
    and $3, %eax
    and $3, %ecx
    cmp %eax, %ecx
    je .Lequal
    ja .Lordered
    xchg %eax, %ecx
.Lordered:
    lea 3(%rax), %rdx
    sub %rcx, %rdx
    lea .Ltable(%rip), %r11
    movslq (%r11,%rdx,4), %rcx
    lea (%r11,%rcx), %rcx
    jmp *%rcx
.Lequal:
    mov $43, %eax
    ret

.global masked_case0, masked_case1, masked_case2
masked_case0:
    mov $40, %eax
    ret
masked_case1:
    mov $41, %eax
    ret
masked_case2:
    mov $42, %eax
    ret
.section .rodata
.Ltable:
    .long masked_case0 - .Ltable
    .long masked_case1 - .Ltable
    .long masked_case2 - .Ltable
.section .note.GNU-stack,"",@progbits
