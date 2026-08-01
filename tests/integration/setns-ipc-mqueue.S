.equ __NR_close, 3
.equ __NR_mount, 165
.equ __NR_exit_group, 231
.equ __NR_setns, 308

#ifndef SETNS_FD
#define SETNS_FD 9
#endif

#ifndef EXPECT_SETNS_ERRNO
#define EXPECT_SETNS_ERRNO 0
#endif

#ifndef SETNS_ONLY
#define SETNS_ONLY 0
#endif

.section .rodata
mq_source:
    .asciz "mqueue"
mq_target:
    .asciz "mqueue"
mq_type:
    .asciz "mqueue"

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_setns, %eax
    mov $SETNS_FD, %edi
    mov $SETNS_FLAGS, %esi
    syscall
#if EXPECT_SETNS_ERRNO
    cmp $-EXPECT_SETNS_ERRNO, %rax
    jne setns_error_mismatch
    xor %edi, %edi
    jmp exit
#else
    test %rax, %rax
    js setns_failed

    mov $__NR_close, %eax
    mov $SETNS_FD, %edi
    syscall

#if SETNS_ONLY
    xor %edi, %edi
    jmp exit
#endif

    mov $__NR_mount, %eax
    lea mq_source(%rip), %rdi
    lea mq_target(%rip), %rsi
    lea mq_type(%rip), %rdx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js mount_failed

    xor %edi, %edi
    jmp exit
#endif

setns_failed:
    mov $10, %edi
    jmp exit

setns_error_mismatch:
    mov $11, %edi
    jmp exit

mount_failed:
    mov $20, %edi

exit:
    mov $__NR_exit_group, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
