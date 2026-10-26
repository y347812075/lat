.global _start, delivery_target
.section .text
_start:
    mov $1, %eax
    mov $1, %edi
    lea ready(%rip), %rsi
    mov $1, %edx
    syscall
    mov $47, %eax
    xor %edi, %edi
    lea message(%rip), %rsi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js operation_done
    mov control+16(%rip), %edi
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
.section .rodata
ready: .ascii "R"
marker: .ascii "T"
zeros: .zero 32
.section .data
.balign 8
payload: .ascii "x"
.balign 8
iov:
    .quad payload
    .quad 1
message:
    .quad 0
    .long 0
    .long 0
    .quad iov
    .quad 1
    .quad control
    .quad 64
    .long 0
    .long 0
.section .bss
.balign 8
result: .skip 8
release: .skip 1
control: .skip 64
.section .note.GNU-stack,"",@progbits
