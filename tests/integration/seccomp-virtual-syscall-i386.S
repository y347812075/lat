.equ __NR_prctl, 172
.equ __NR_exit_group, 252
.equ __NR_seccomp, 354
.equ __NR_tunnel_virtual, 600

.equ PR_SET_NO_NEW_PRIVS, 38
.equ SECCOMP_SET_MODE_FILTER, 1
.equ SECCOMP_RET_ERRNO_6, 0x00050006
.equ SECCOMP_RET_ALLOW, 0x7fff0000
.equ ENOSYS, 38

.section .rodata
unknown_method:
    .asciz "guest-forged-tunnel-method"

.section .data
.align 4
filter_program:
    .short 4
    .zero 2
    .long filter

.align 4
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
    mov $0x87, %ebx
    mov $0x87, %ecx
    mov $0x87, %edx
    int $0x80
    cmp $-ENOSYS, %eax
    jne unfiltered_failed

    mov $__NR_prctl, %eax
    mov $PR_SET_NO_NEW_PRIVS, %ebx
    mov $1, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
    int $0x80
    test %eax, %eax
    jne set_nnp_failed

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %ebx
    xor %ecx, %ecx
    mov $filter_program, %edx
    int $0x80
    test %eax, %eax
    jne install_failed

    mov $__NR_tunnel_virtual, %eax
    mov $0x87, %ebx
    mov $0x87, %ecx
    mov $0x87, %edx
    int $0x80
    cmp $-6, %eax
    jne filtered_failed

    mov $__NR_tunnel_virtual, %eax
    mov $unknown_method, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    int $0x80
    cmp $-6, %eax
    jne readable_string_failed

    push $0
    push $0
    push $unknown_method
    push $__NR_tunnel_virtual
    call forged_loader_syscall
    add $16, %esp
    cmp $-6, %eax
    jne copied_marker_failed

    xor %ebx, %ebx
    jmp exit

forged_loader_syscall:
    push %ebp
    push %edi
    push %esi
    push %ebx
    mov 44(%esp), %ebp
    mov 40(%esp), %edi
    mov 36(%esp), %esi
    mov 32(%esp), %edx
    mov 28(%esp), %ecx
    mov 24(%esp), %ebx
    mov 20(%esp), %eax
    int $0x80
    pop %ebx
    pop %esi
    pop %edi
    pop %ebp
    ret

unfiltered_failed:
    mov $10, %ebx
    jmp exit
set_nnp_failed:
    mov $11, %ebx
    jmp exit
install_failed:
    mov $12, %ebx
    jmp exit
filtered_failed:
    mov $13, %ebx
    jmp exit
readable_string_failed:
    mov $14, %ebx
    jmp exit
copied_marker_failed:
    mov $15, %ebx

exit:
    mov $__NR_exit_group, %eax
    int $0x80
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
