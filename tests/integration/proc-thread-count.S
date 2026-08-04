.equ __NR_read, 0
.equ __NR_stat, 4
.equ __NR_close, 3
.equ __NR_clone, 56
.equ __NR_exit, 60
.equ __NR_futex, 202
.equ __NR_openat, 257
.equ __NR_newfstatat, 262
.equ AT_FDCWD, -100
.equ O_RDONLY, 0
.equ O_DIRECTORY, 0x10000
.equ CLONE_VM, 0x00000100
.equ CLONE_FS, 0x00000200
.equ CLONE_FILES, 0x00000400
.equ CLONE_SIGHAND, 0x00000800
.equ CLONE_THREAD, 0x00010000
.equ CLONE_SYSVSEM, 0x00040000
.equ CLONE_CHILD_CLEARTID, 0x00200000
.equ CLONE_CHILD_SETTID, 0x01000000
.equ CLONE_FLAGS, (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND)
.equ CLONE_FLAGS_2, (CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID)
.equ CLONE_FLAGS_3, (CLONE_CHILD_SETTID)
.equ FUTEX_WAIT, 0
.equ FUTEX_WAKE, 1

.section .rodata
proc_stat:
    .asciz "/proc/self/stat"
proc_task:
    .asciz "/proc/self/task/"
proc_root:
    .asciz "/proc"
relative_task:
    .asciz "self/task"

.section .bss
.align 8
statbuf:
    .space 2048
task_statbuf:
    .space 144
.align 16
thread_stack:
    .space 65536
.align 4
child_tid:
    .long 0
thread_release:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    mov $__NR_clone, %eax
    mov $(CLONE_FLAGS | CLONE_FLAGS_2 | CLONE_FLAGS_3), %edi
    lea thread_stack+65536(%rip), %rsi
    xor %edx, %edx
    lea child_tid(%rip), %r10
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js clone_failed
    jz guest_thread
    mov %eax, %r12d

.Lwait_started:
    mov child_tid(%rip), %eax
    test %eax, %eax
    jz .Lwait_started

    call read_proc_thread_count
    cmp $2, %eax
    jne live_count_failed

    movl $1, thread_release(%rip)
    mov $__NR_futex, %eax
    lea thread_release(%rip), %rdi
    mov $FUTEX_WAKE, %esi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    syscall

.Lwait_stopped:
    mov child_tid(%rip), %edx
    test %edx, %edx
    jz .Lstopped
    mov $__NR_futex, %eax
    lea child_tid(%rip), %rdi
    mov $FUTEX_WAIT, %esi
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    syscall
    jmp .Lwait_stopped

.Lstopped:
    call read_proc_thread_count
    cmp $1, %eax
    jne stopped_count_failed

    mov $__NR_stat, %eax
    lea proc_task(%rip), %rdi
    lea task_statbuf(%rip), %rsi
    syscall
    test %rax, %rax
    js task_stat_failed
    cmpq $3, task_statbuf+16(%rip)
    jne task_stat_failed

    mov $__NR_newfstatat, %eax
    mov $AT_FDCWD, %edi
    lea proc_task(%rip), %rsi
    lea task_statbuf(%rip), %rdx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js task_stat_failed
    cmpq $3, task_statbuf+16(%rip)
    jne task_fstatat_failed

    mov $__NR_openat, %eax
    mov $AT_FDCWD, %edi
    lea proc_root(%rip), %rsi
    mov $(O_RDONLY | O_DIRECTORY), %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js task_dirfd_failed
    mov %eax, %r15d

    mov $__NR_newfstatat, %eax
    mov %r15d, %edi
    lea relative_task(%rip), %rsi
    lea task_statbuf(%rip), %rdx
    xor %r10d, %r10d
    syscall
    mov %rax, %r14
    mov $__NR_close, %eax
    mov %r15d, %edi
    syscall
    test %r14, %r14
    js task_dirfd_failed
    cmpq $3, task_statbuf+16(%rip)
    jne task_dirfd_failed

    mov $__NR_stat, %eax
    lea relative_task(%rip), %rdi
    lea task_statbuf(%rip), %rsi
    syscall
    test %rax, %rax
    js relative_task_stat_failed
    cmpq $2, task_statbuf+16(%rip)
    jne relative_task_stat_failed

    mov $__NR_newfstatat, %eax
    mov $AT_FDCWD, %edi
    lea relative_task(%rip), %rsi
    lea task_statbuf(%rip), %rdx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js relative_task_fstatat_failed
    cmpq $2, task_statbuf+16(%rip)
    jne relative_task_fstatat_failed

    xor %edi, %edi
    jmp exit

guest_thread:
    mov $__NR_futex, %eax
    lea thread_release(%rip), %rdi
    mov $FUTEX_WAIT, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    syscall
    xor %edi, %edi
    mov $__NR_exit, %eax
    syscall

clone_failed:
    mov $10, %edi
    jmp exit

live_count_failed:
    mov $11, %edi
    jmp release_thread

stopped_count_failed:
    mov $12, %edi
    jmp exit

task_stat_failed:
    mov $13, %edi
    jmp exit

task_fstatat_failed:
    mov $14, %edi
    jmp exit

task_dirfd_failed:
    mov $15, %edi
    jmp exit

relative_task_stat_failed:
    mov $16, %edi
    jmp exit

relative_task_fstatat_failed:
    mov $17, %edi
    jmp exit

release_thread:
    mov %edi, %r12d
    movl $1, thread_release(%rip)
    mov $__NR_futex, %eax
    lea thread_release(%rip), %rdi
    mov $FUTEX_WAKE, %esi
    mov $1, %edx
    syscall
    mov %r12d, %edi

exit:
    mov $__NR_exit, %eax
    syscall
.size _start, .-_start

.type read_proc_thread_count, @function
read_proc_thread_count:
    mov $__NR_openat, %eax
    mov $AT_FDCWD, %edi
    lea proc_stat(%rip), %rsi
    mov $O_RDONLY, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .Lread_failed
    mov %eax, %r13d

    mov $__NR_read, %eax
    mov %r13d, %edi
    lea statbuf(%rip), %rsi
    mov $2047, %edx
    syscall
    mov %rax, %r14

    mov $__NR_close, %eax
    mov %r13d, %edi
    syscall

    test %r14, %r14
    jle .Lread_failed
    lea statbuf(%rip), %rsi
    mov %r14, %rcx

.Lfind_comm_end:
    cmpb $')', (%rsi)
    je .Lafter_comm
    inc %rsi
    loop .Lfind_comm_end
    jmp .Lread_failed

.Lafter_comm:
    inc %rsi
    mov $3, %ecx

.Lnext_field:
    cmp $20, %ecx
    je .Lparse_count
.Lskip_spaces:
    cmpb $' ', (%rsi)
    jne .Lskip_field
    inc %rsi
    jmp .Lskip_spaces
.Lskip_field:
    cmpb $' ', (%rsi)
    je .Lfield_done
    cmpb $0, (%rsi)
    je .Lread_failed
    inc %rsi
    jmp .Lskip_field
.Lfield_done:
    inc %ecx
    jmp .Lnext_field

.Lparse_count:
.Lparse_spaces:
    cmpb $' ', (%rsi)
    jne .Lparse_digits
    inc %rsi
    jmp .Lparse_spaces
.Lparse_digits:
    xor %eax, %eax
.Lparse_digit:
    movzbl (%rsi), %edx
    sub $'0', %edx
    cmp $9, %edx
    ja .Lparse_done
    imul $10, %eax, %eax
    add %edx, %eax
    inc %rsi
    jmp .Lparse_digit
.Lparse_done:
    ret

.Lread_failed:
    mov $-1, %eax
    ret
.size read_proc_thread_count, .-read_proc_thread_count

.section .note.GNU-stack,"",@progbits
