.equ __NR_prctl, 157
.equ __NR_seccomp, 317
.equ __NR_exit_group, 231

.equ PR_GET_SECCOMP, 21
.equ PR_SET_SECCOMP, 22
.equ PR_SET_NO_NEW_PRIVS, 38
.equ PR_GET_NO_NEW_PRIVS, 39

.equ SECCOMP_MODE_FILTER, 2
.equ SECCOMP_SET_MODE_FILTER, 1
.equ SECCOMP_FILTER_FLAG_TSYNC, 1
.equ SECCOMP_RET_ALLOW, 0x7fff0000

.equ EACCES, 13
.equ EFAULT, 14
.equ EINVAL, 22

.section .data
.align 8
zero_length_program:
    .short 0
    .zero 6
    .quad allow_filter
null_filter_program:
    .short 1
    .zero 6
    .quad 0
bad_filter_pointer_program:
    .short 1
    .zero 6
    .quad 1
invalid_filter_program:
    .short 1
    .zero 6
    .quad invalid_filter
allow_filter_program:
    .short 1
    .zero 6
    .quad allow_filter

.align 8
invalid_filter:
    .short 0xffff
    .byte 0, 0
    .long 0
allow_filter:
    .short 0x06
    .byte 0, 0
    .long SECCOMP_RET_ALLOW

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_prctl, %eax
    mov $PR_GET_NO_NEW_PRIVS, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne skip

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    mov $0x80000000, %esi
    xor %edx, %edx
    syscall
    cmp $-EINVAL, %rax
    jne fail_invalid_flags

    mov $__NR_prctl, %eax
    mov $PR_SET_SECCOMP, %edi
    mov $SECCOMP_MODE_FILTER, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    cmp $-EFAULT, %rax
    jne fail_prctl_null_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    cmp $-EFAULT, %rax
    jne fail_seccomp_null_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    mov $SECCOMP_FILTER_FLAG_TSYNC, %esi
    xor %edx, %edx
    syscall
    cmp $-EFAULT, %rax
    jne fail_tsync_null_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea zero_length_program(%rip), %rdx
    syscall
    cmp $-EINVAL, %rax
    jne fail_zero_length_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea null_filter_program(%rip), %rdx
    syscall
    cmp $-EACCES, %rax
    jne fail_null_filter_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea bad_filter_pointer_program(%rip), %rdx
    syscall
    cmp $-EACCES, %rax
    jne fail_bad_filter_pointer_before_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea invalid_filter_program(%rip), %rdx
    syscall
    cmp $-EACCES, %rax
    jne fail_invalid_filter_before_nnp

    mov $__NR_prctl, %eax
    mov $PR_SET_NO_NEW_PRIVS, %edi
    mov $1, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne fail_set_nnp

    mov $__NR_prctl, %eax
    mov $PR_SET_SECCOMP, %edi
    mov $SECCOMP_MODE_FILTER, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    cmp $-EFAULT, %rax
    jne fail_prctl_null_after_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    cmp $-EFAULT, %rax
    jne fail_seccomp_null_after_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea null_filter_program(%rip), %rdx
    syscall
    cmp $-EINVAL, %rax
    jne fail_null_filter_after_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea bad_filter_pointer_program(%rip), %rdx
    syscall
    cmp $-EFAULT, %rax
    jne fail_bad_filter_pointer_after_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea invalid_filter_program(%rip), %rdx
    syscall
    cmp $-EINVAL, %rax
    jne fail_invalid_filter_after_nnp

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    mov $SECCOMP_FILTER_FLAG_TSYNC, %esi
    lea allow_filter_program(%rip), %rdx
    syscall
    test %rax, %rax
    jne fail_tsync_install

    mov $__NR_prctl, %eax
    mov $PR_GET_SECCOMP, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    cmp $SECCOMP_MODE_FILTER, %rax
    jne fail_get_seccomp

    mov $__NR_prctl, %eax
    mov $PR_SET_SECCOMP, %edi
    mov $SECCOMP_MODE_FILTER, %esi
    lea allow_filter_program(%rip), %rdx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne fail_prctl_install

    xor %edi, %edi
    jmp exit

skip:
    mov $77, %edi
    jmp exit
fail_invalid_flags:
    mov $10, %edi
    jmp exit
fail_prctl_null_before_nnp:
    mov $11, %edi
    jmp exit
fail_seccomp_null_before_nnp:
    mov $12, %edi
    jmp exit
fail_tsync_null_before_nnp:
    mov $13, %edi
    jmp exit
fail_zero_length_before_nnp:
    mov $14, %edi
    jmp exit
fail_null_filter_before_nnp:
    mov $15, %edi
    jmp exit
fail_invalid_filter_before_nnp:
    mov $16, %edi
    jmp exit
fail_set_nnp:
    mov $17, %edi
    jmp exit
fail_prctl_null_after_nnp:
    mov $18, %edi
    jmp exit
fail_seccomp_null_after_nnp:
    mov $19, %edi
    jmp exit
fail_null_filter_after_nnp:
    mov $20, %edi
    jmp exit
fail_invalid_filter_after_nnp:
    mov $21, %edi
    jmp exit
fail_tsync_install:
    mov $22, %edi
    jmp exit
fail_get_seccomp:
    mov $23, %edi
    jmp exit
fail_prctl_install:
    mov $24, %edi
    jmp exit
fail_bad_filter_pointer_before_nnp:
    mov $25, %edi
    jmp exit
fail_bad_filter_pointer_after_nnp:
    mov $26, %edi

exit:
    mov $__NR_exit_group, %eax
    syscall
    hlt
