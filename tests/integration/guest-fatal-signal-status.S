.equ __NR_clone, 56
.equ __NR_exit, 60
.equ __NR_getpid, 39
.equ __NR_kill, 62
.equ __NR_rt_sigaction, 13
.equ __NR_rt_sigreturn, 15
.equ __NR_gettid, 186
.equ __NR_rt_tgsigqueueinfo, 297
.equ __NR_wait4, 61
.equ SIGABRT, 6
.equ SIGSEGV, 11
.equ SIGSYS, 31
.equ SIGCHLD, 17
.equ SA_SIGINFO, 0x00000004
.equ SA_RESTORER, 0x04000000
.equ SA_RESETHAND, 0x80000000

.section .data
.align 8
segv_action:
    .quad reraise_handler
    .quad (SA_SIGINFO | SA_RESTORER | SA_RESETHAND)
    .quad signal_restorer
    .quad 0

.section .bss
.align 4
status:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    mov $SIGSEGV, %edi
    mov $2, %esi
    call run_case
    test %eax, %eax
    jnz reraised_segv_failed

    mov $SIGSEGV, %edi
    mov $1, %esi
    call run_case
    test %eax, %eax
    jnz segv_failed

    mov $SIGSYS, %edi
    xor %esi, %esi
    call run_case
    test %eax, %eax
    jnz sigsys_failed

    mov $SIGABRT, %edi
    xor %esi, %esi
    call run_case
    test %eax, %eax
    jnz sigabrt_failed

    xor %edi, %edi
    jmp exit

segv_failed:
    add $10, %eax
    mov %eax, %edi
    jmp exit

sigsys_failed:
    add $20, %eax
    mov %eax, %edi
    jmp exit

reraised_segv_failed:
    add $40, %eax
    mov %eax, %edi
    jmp exit

sigabrt_failed:
    add $30, %eax
    mov %eax, %edi
    jmp exit

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.type run_case, @function
run_case:
    mov %edi, %r12d
    mov %esi, %r13d

    mov $__NR_clone, %eax
    mov $SIGCHLD, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js .Lclone_failed
    jz .Lchild
    mov %eax, %r14d

    mov %r14d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r14, %rax
    jne .Lwait_failed

    mov status(%rip), %eax
    and $0x7f, %eax
    cmp %r12d, %eax
    jne .Lstatus_failed
    xor %eax, %eax
    ret

.Lchild:
    cmp $2, %r13d
    je .Linstall_handler
    test %r13d, %r13d
    jz .Lsend_signal
.Ltrigger_fault:
    xor %eax, %eax
    movb $1, (%rax)
    jmp .Lchild_survived

.Linstall_handler:
    mov $__NR_rt_sigaction, %eax
    mov $SIGSEGV, %edi
    lea segv_action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    js .Lchild_survived
    jmp .Ltrigger_fault

.Lsend_signal:
    mov $__NR_getpid, %eax
    syscall
    mov %eax, %edi
    mov %r12d, %esi
    mov $__NR_kill, %eax
    syscall

.Lchild_survived:
    mov $40, %edi
    mov $__NR_exit, %eax
    syscall

.Lclone_failed:
    mov $1, %eax
    ret

.Lwait_failed:
    mov $2, %eax
    ret

.Lstatus_failed:
    mov $3, %eax
    ret
.size run_case, .-run_case

.type reraise_handler, @function
reraise_handler:
    mov %rsi, %r15
    mov $__NR_getpid, %eax
    syscall
    mov %eax, %r12d
    mov $__NR_gettid, %eax
    syscall
    mov %eax, %r13d
    mov $__NR_rt_tgsigqueueinfo, %eax
    mov %r12d, %edi
    mov %r13d, %esi
    mov $SIGSEGV, %edx
    mov %r15, %r10
    syscall
    ret
.size reraise_handler, .-reraise_handler

.type signal_restorer, @function
signal_restorer:
    mov $__NR_rt_sigreturn, %eax
    syscall
.size signal_restorer, .-signal_restorer

.section .note.GNU-stack,"",@progbits
