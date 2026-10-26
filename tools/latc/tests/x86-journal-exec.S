.global _start, first_phase, second_phase
.section .text
_start:
    mov (%rsp), %eax
    cmp $1, %eax
    jne second_phase
first_phase:
    mov $1, %eax
    mov $1, %edi
    lea first_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    xor %eax, %eax
    xor %edi, %edi
    lea release_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    mov $59, %eax
    lea self_path(%rip), %rdi
    lea exec_argv(%rip), %rsi
    mov (%rsp), %rcx
    lea 16(%rsp,%rcx,8), %rdx
    syscall
    jmp failed

.balign 64
second_phase:
    mov $1, %eax
    mov $1, %edi
    lea second_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    xor %eax, %eax
    xor %edi, %edi
    lea release_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    lea second_delivery(%rip), %rax
    jmp *%rax

.balign 64
second_delivery:
    mov $1, %eax
    mov $1, %edi
    lea delivery_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    xor %eax, %eax
    xor %edi, %edi
    lea release_delivery(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    mov $60, %eax
    mov $42, %edi
    syscall
failed:
    mov $1, %eax
    mov $1, %edi
    lea failed_byte(%rip), %rsi
    mov $1, %edx
    syscall
    mov $60, %eax
    mov $125, %edi
    syscall

.section .rodata
self_path: .asciz "/proc/self/exe"
second_arg: .asciz "journal-exec-second"
first_byte: .ascii "A"
second_byte: .ascii "B"
delivery_byte: .ascii "C"
failed_byte: .ascii "F"

.section .data
.balign 8
exec_argv:
    .quad self_path
    .quad second_arg
    .quad 0

.section .bss
.balign 4
release_byte: .skip 1
release_delivery: .skip 1

.section .note.GNU-stack,"",@progbits
