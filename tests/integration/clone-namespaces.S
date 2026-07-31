.equ __NR_newfstatat, 262
.equ __NR_clone, 56
.equ __NR_wait4, 61
.equ __NR_exit, 60
.equ AT_FDCWD, -100
.equ CLONE_NEWNS, 0x00020000
.equ CLONE_NEWUTS, 0x04000000
.equ CLONE_NEWIPC, 0x08000000
.equ CLONE_NEWUSER, 0x10000000
.equ CLONE_NEWNS_IPC_UTS, (CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS)
.equ CLONE_NAMESPACE_FLAGS, (CLONE_NEWUSER | CLONE_NEWNS_IPC_UTS)
.equ SIGCHLD, 17

.section .rodata
mnt_ns:
    .asciz "/proc/self/ns/mnt"
ipc_ns:
    .asciz "/proc/self/ns/ipc"
uts_ns:
    .asciz "/proc/self/ns/uts"

.section .bss
.align 8
parent_mnt_stat:
    .space 144
parent_ipc_stat:
    .space 144
parent_uts_stat:
    .space 144
child_stat:
    .space 144
status:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    lea mnt_ns(%rip), %rsi
    lea parent_mnt_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js parent_stat_failed

    lea ipc_ns(%rip), %rsi
    lea parent_ipc_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js parent_stat_failed

    lea uts_ns(%rip), %rsi
    lea parent_uts_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js parent_stat_failed

    mov $__NR_clone, %eax
    mov $(CLONE_NAMESPACE_FLAGS | SIGCHLD), %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js clone_failed
    jz child

    mov %rax, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    test %rax, %rax
    js wait_failed

    mov status(%rip), %edi
    test $0x7f, %edi
    jnz child_signaled
    shr $8, %edi
    and $0xff, %edi
    jmp exit

child:
    lea mnt_ns(%rip), %rsi
    lea child_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js child_stat_failed
    mov parent_mnt_stat+8(%rip), %rax
    cmp child_stat+8(%rip), %rax
    je mnt_unchanged

    lea ipc_ns(%rip), %rsi
    lea child_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js child_stat_failed
    mov parent_ipc_stat+8(%rip), %rax
    cmp child_stat+8(%rip), %rax
    je ipc_unchanged

    lea uts_ns(%rip), %rsi
    lea child_stat(%rip), %rdx
    call stat_namespace
    test %rax, %rax
    js child_stat_failed
    mov parent_uts_stat+8(%rip), %rax
    cmp child_stat+8(%rip), %rax
    je uts_unchanged

    xor %edi, %edi
    jmp exit

stat_namespace:
    mov $__NR_newfstatat, %eax
    mov $AT_FDCWD, %edi
    xor %r10d, %r10d
    syscall
    ret

parent_stat_failed:
    mov $10, %edi
    jmp exit

clone_failed:
    mov $20, %edi
    jmp exit

child_stat_failed:
    mov $30, %edi
    jmp exit

mnt_unchanged:
    mov $31, %edi
    jmp exit

ipc_unchanged:
    mov $32, %edi
    jmp exit

uts_unchanged:
    mov $33, %edi
    jmp exit

wait_failed:
    mov $40, %edi
    jmp exit

child_signaled:
    mov $41, %edi

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
