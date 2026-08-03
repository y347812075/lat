.equ __NR_clone, 56
.equ __NR_exit, 60
.equ __NR_getpid, 39
.equ __NR_wait4, 61
.equ CLONE_PARENT_SETTID, 0x00100000
.equ CLONE_CHILD_SETTID, 0x01000000
.equ SIGCHLD, 17

.section .bss
.align 4
parent_tid:
    .long 0
child_tid:
    .long 0
status:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_clone, %eax
    mov $(CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | SIGCHLD), %edi
    xor %esi, %esi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js clone_failed
    jz child

    mov %eax, %r12d
    cmp parent_tid(%rip), %eax
    jne parent_tid_failed

    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r12, %rax
    jne wait_failed

    mov status(%rip), %eax
    test $0x7f, %eax
    jnz child_failed
    shr $8, %eax
    and $0xff, %eax
    test %eax, %eax
    jnz child_failed

    xor %edi, %edi
    jmp exit

child:
    mov $__NR_getpid, %eax
    syscall
    cmp child_tid(%rip), %eax
    jne child_tid_failed
    xor %edi, %edi
    jmp exit

clone_failed:
    mov $10, %edi
    jmp exit

parent_tid_failed:
    mov $11, %edi
    jmp reap_child

wait_failed:
    mov $12, %edi
    jmp exit

child_failed:
    mov $13, %edi
    jmp exit

child_tid_failed:
    mov $14, %edi
    jmp exit

reap_child:
    mov %edi, %r13d
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    mov %r13d, %edi

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
