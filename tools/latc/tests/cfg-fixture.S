.text
.global _start
.type _start,@function
_start:
    call callee
    test %rax, %rax
    jz 1f
    call *%rax
1:
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.type callee,@function
callee:
    xor %eax, %eax
    ret
.size callee, .-callee

.type jump_source,@function
jump_source:
    jmp jump_target_mid
.size jump_source, .-jump_source

.type jump_container,@function
jump_container:
    nop
    nop
jump_target_mid:
    ret
.size jump_container, .-jump_container

.type jump_plt_source,@function
jump_plt_source:
    jmp synthetic_plt_second
.size jump_plt_source, .-jump_plt_source

.type fallthrough_check,@function
fallthrough_check:
    test %edi, %edi
    jne callee
.size fallthrough_check, .-fallthrough_check
.p2align 3

.type fallthrough_next,@function
fallthrough_next:
    ret
.size fallthrough_next, .-fallthrough_next

.type zero_sized,@function
zero_sized:
    ret

.type zero_sized_next,@function
zero_sized_next:
    ret
.size zero_sized_next, .-zero_sized_next

/* Deliberately omit STT_FUNC symbols, as in a static glibc .plt section. */
.section .plt,"ax",@progbits
synthetic_plt_first:
    jmp *synthetic_plt_target(%rip)
    xchg %ax, %ax
synthetic_plt_second:
    jmp *synthetic_plt_target(%rip)
    xchg %ax, %ax

.data
.align 8
synthetic_plt_target:
    .quad callee

.section .note.GNU-stack,"",@progbits
