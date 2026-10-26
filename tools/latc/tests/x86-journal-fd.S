.global _start, delivery_target
.section .text
_start:
    mov $1, %eax
    mov $1, %edi
    lea ready(%rip), %rsi
    mov $1, %edx
    syscall
    xor %eax, %eax
    xor %edi, %edi
    lea descriptor(%rip), %rsi
    mov $4, %edx
    syscall
    cmp $4, %eax
    jne failed
    mov descriptor(%rip), %edi
#if ATTACK == 5
    mov $292, %eax
    mov $1, %edi
    mov descriptor(%rip), %esi
    mov $02000000, %edx
    syscall
    test %rax, %rax
    js operation_done
    mov %eax, %edi
    mov $72, %eax
    mov $3, %esi
    syscall
    jmp operation_done
#elif ATTACK == 1
    mov $77, %eax
    xor %esi, %esi
#elif ATTACK == 2
    mov $72, %eax
    mov $4, %esi
    mov $02000, %edx
#elif ATTACK == 3
    mov $18, %eax
    lea zeros(%rip), %rsi
    mov $32, %edx
    mov $192, %r10d
#elif ATTACK == 4
    mov $32, %eax
#else
    mov $72, %eax
    mov $3, %esi
#endif
#if ATTACK != 5
    syscall
#endif
operation_done:
    mov %rax, result(%rip)
    mov $1, %eax
    mov $1, %edi
    lea result(%rip), %rsi
    mov $8, %edx
    syscall
    xor %eax, %eax
    xor %edi, %edi
    lea descriptor(%rip), %rsi
    mov $1, %edx
    syscall
    jmp delivery_target
.balign 64
delivery_target:
    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $1, %edx
    syscall
wait_again:
    xor %eax, %eax
    xor %edi, %edi
    lea descriptor(%rip), %rsi
    mov $1, %edx
    syscall
    jmp wait_again
failed:
    mov $60, %eax
    mov $91, %edi
    syscall
.section .rodata
ready: .ascii "R"
marker: .ascii "T"
zeros: .zero 32
.section .bss
.balign 8
result: .skip 8
descriptor: .skip 4
.section .note.GNU-stack,"",@progbits
