.equ __NR_getpid, 39
.equ __NR_clone, 56
.equ __NR_exit, 60
.equ __NR_wait4, 61
.equ __NR_kill, 62
.equ __NR_ptrace, 101
.equ __NR_prctl, 157
.equ __NR_seccomp, 317

.equ SIGCHLD, 17
.equ SIGSTOP, 19
.equ SIGTRAP, 5
.equ PTRACE_TRACEME, 0
.equ PTRACE_CONT, 7
.equ PTRACE_GETREGS, 12
.equ PTRACE_SETREGS, 13
.equ PTRACE_SETOPTIONS, 0x4200
.equ PTRACE_GETEVENTMSG, 0x4201
.equ PTRACE_O_TRACESECCOMP, 0x80
.equ PTRACE_EVENT_SECCOMP, 7
.equ PR_SET_NO_NEW_PRIVS, 38
.equ SECCOMP_SET_MODE_FILTER, 1
.equ SECCOMP_RET_TRACE, 0x7ff000cc
.equ SECCOMP_RET_ALLOW, 0x7fff0000

.equ REGS_RAX, 80
.equ REGS_ORIG_RAX, 120
.equ REGS_SIZE, 168

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
    .long __NR_getpid
    .short 0x06
    .byte 0, 0
    .long SECCOMP_RET_TRACE
    .short 0x06
    .byte 0, 0
    .long SECCOMP_RET_ALLOW

.section .bss
.align 8
status:
    .long 0
event_data:
    .quad 0
regs:
    .skip REGS_SIZE

.section .text
.global _start
.type _start, @function
_start:
    mov $SIGCHLD, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $__NR_clone, %eax
    syscall
    test %rax, %rax
    js clone_failed
    jz child

    mov %eax, %r12d
    mov %r12d, %edi
    lea status(%rip), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r12, %rax
    jne initial_wait_failed
    mov status(%rip), %eax
    shr $8, %eax
    and $0xff, %eax
    cmp $SIGSTOP, %eax
    jne initial_stop_failed

    mov $PTRACE_SETOPTIONS, %edi
    mov %r12d, %esi
    xor %edx, %edx
    mov $PTRACE_O_TRACESECCOMP, %r10d
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne setoptions_failed

    mov $PTRACE_CONT, %edi
    mov %r12d, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne continue_failed

    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r12, %rax
    jne trace_wait_failed
    mov status(%rip), %eax
    mov %eax, %ecx
    shr $8, %eax
    and $0xff, %eax
    cmp $SIGTRAP, %eax
    jne trace_status_failed
    shr $16, %ecx
    cmp $PTRACE_EVENT_SECCOMP, %ecx
    jne trace_status_failed

    mov $PTRACE_GETEVENTMSG, %edi
    mov %r12d, %esi
    xor %edx, %edx
    lea event_data(%rip), %r10
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne eventmsg_failed
    cmpq $0xcc, event_data(%rip)
    jne eventmsg_failed

    mov $PTRACE_GETREGS, %edi
    mov %r12d, %esi
    xor %edx, %edx
    lea regs(%rip), %r10
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne getregs_failed
    cmpq $__NR_getpid, regs+REGS_ORIG_RAX(%rip)
    jne getregs_failed

    movq $-1, regs+REGS_ORIG_RAX(%rip)
    movq $42, regs+REGS_RAX(%rip)
    mov $PTRACE_SETREGS, %edi
    mov %r12d, %esi
    xor %edx, %edx
    lea regs(%rip), %r10
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne setregs_failed

    mov $PTRACE_CONT, %edi
    mov %r12d, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne continue_failed

    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r12, %rax
    jne final_wait_failed
    mov status(%rip), %eax
    test %eax, %eax
    jne child_failed
    xor %edi, %edi
    jmp exit

child:
    mov $PTRACE_TRACEME, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_ptrace, %eax
    syscall
    test %rax, %rax
    jne child_ptrace_failed

    mov $__NR_getpid, %eax
    syscall
    mov %eax, %edi
    mov $SIGSTOP, %esi
    mov $__NR_kill, %eax
    syscall

    mov $__NR_prctl, %eax
    mov $PR_SET_NO_NEW_PRIVS, %edi
    mov $1, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne child_nnp_failed

    mov $__NR_seccomp, %eax
    mov $SECCOMP_SET_MODE_FILTER, %edi
    xor %esi, %esi
    lea filter_program(%rip), %rdx
    syscall
    test %rax, %rax
    jne child_filter_failed

    mov $__NR_getpid, %eax
    syscall
    cmp $42, %rax
    jne child_result_failed
    xor %edi, %edi
    jmp exit

clone_failed:
    mov $10, %edi
    jmp exit
initial_wait_failed:
    mov $11, %edi
    jmp exit
initial_stop_failed:
    mov $12, %edi
    jmp exit
setoptions_failed:
    mov $13, %edi
    jmp exit
continue_failed:
    mov $14, %edi
    jmp exit
trace_wait_failed:
    mov $15, %edi
    jmp exit
trace_status_failed:
    mov $16, %edi
    jmp exit
eventmsg_failed:
    mov $17, %edi
    jmp exit
getregs_failed:
    mov $18, %edi
    jmp exit
setregs_failed:
    mov $19, %edi
    jmp exit
final_wait_failed:
    mov $20, %edi
    jmp exit
child_failed:
    mov $21, %edi
    jmp exit
child_ptrace_failed:
    mov $30, %edi
    jmp exit
child_nnp_failed:
    mov $31, %edi
    jmp exit
child_filter_failed:
    mov $32, %edi
    jmp exit
child_result_failed:
    mov $33, %edi

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
