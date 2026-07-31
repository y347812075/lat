.equ __NR_getpid, 39
.equ __NR_setpgid, 109
.equ __NR_getpgid, 121
.equ __NR_exit, 60
.equ SCAN_LIMIT, 128

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_setpgid, %eax
    xor %edi, %edi
    xor %esi, %esi
    syscall
    test %rax, %rax
    js setup_failed

    mov $__NR_getpid, %eax
    syscall
    mov %eax, %r12d

    mov $__NR_getpgid, %eax
    xor %edi, %edi
    syscall
    test %rax, %rax
    js setup_failed
    mov %eax, %r13d

    lea 1(%r12), %r14d
    lea SCAN_LIMIT(%r14), %r15d

scan_next:
    mov $__NR_getpgid, %eax
    mov %r14d, %edi
    syscall
    cmp %r13d, %eax
    je internal_thread_visible
    inc %r14d
    cmp %r15d, %r14d
    jl scan_next

    xor %edi, %edi
    jmp exit

setup_failed:
    mov $11, %edi
    jmp exit

internal_thread_visible:
    mov $10, %edi

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
