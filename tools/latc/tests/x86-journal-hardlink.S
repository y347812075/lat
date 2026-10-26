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
    lea paths(%rip), %rsi
    mov $1024, %edx
    syscall
    test %rax, %rax
    jle failed
    lea paths(%rip), %rsi
    mov %rsi, %r12
scan_alias:
    cmpb $0, (%r12)
    je alias_found
    inc %r12
    jmp scan_alias
alias_found:
    inc %r12
    mov $265, %eax
    mov $-100, %edi
    mov %rsi, %rsi
    mov $-100, %edx
    mov %r12, %r10
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js operation_done
    mov $257, %eax
    mov $-100, %edi
    mov %r12, %rsi
    mov $2, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js operation_done
    mov %eax, %edi
    mov $18, %eax
    lea zeros(%rip), %rsi
    mov $32, %edx
    mov $192, %r10d
    syscall
operation_done:
    mov %rax, result(%rip)
    mov $1, %eax
    mov $1, %edi
    lea result(%rip), %rsi
    mov $8, %edx
    syscall
    xor %eax, %eax
    xor %edi, %edi
    lea release(%rip), %rsi
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
    lea release(%rip), %rsi
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
release: .skip 1
paths: .skip 1024
.section .note.GNU-stack,"",@progbits
