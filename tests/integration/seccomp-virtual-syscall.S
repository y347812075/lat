.equ __NR_prctl, 157
.equ __NR_exit_group, 231
.equ __NR_seccomp, 317
.equ __NR_tunnel_virtual, 600

.equ PR_SET_NO_NEW_PRIVS, 38
.equ SECCOMP_SET_MODE_FILTER, 1
.equ SECCOMP_RET_ERRNO_6, 0x00050006
.equ SECCOMP_RET_ALLOW, 0x7fff0000
.equ ENOSYS, 38

.section .data
.align 8
filter_program:
    .short 4
    .zero 6
    .quad filter

.align 8
filter:
    .short 0x20
    .byte 0, 0
    .long 0
    .short 0x15
    .byte 0, 1
    .long __NR_tunnel_virtual
    .short 0x06
    .byte 0, 0
    .long SECCOMP_RET_ERRNO_6
    .short 0x06
    .byte 0, 0
    .long SECCOMP_RET_ALLOW

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_tunnel_virtual, %eax
    mov $0x87, %edi
    mov $0x87, %esi
    mov $0x87, %edx
    syscall
    cmp $-ENOSYS, %rax
    jne unfiltered_failed

    mov $__NR_prctl, %eax
    mov $PR_SET_NO_NEW_PRIVS, %edi
    mov $1, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne set_nnp_failed

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea filter_program(%rip), %rdx
    syscall
    test %rax, %rax
    jne install_failed

    mov $__NR_tunnel_virtual, %eax
    mov $0x87, %edi
    mov $0x87, %esi
    mov $0x87, %edx
    syscall
    cmp $-6, %rax
    jne filtered_failed

    xor %edi, %edi
    jmp exit

unfiltered_failed:
    mov $10, %edi
    jmp exit
set_nnp_failed:
    mov $11, %edi
    jmp exit
install_failed:
    mov $12, %edi
    jmp exit
filtered_failed:
    mov $13, %edi

exit:
    mov $__NR_exit_group, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
