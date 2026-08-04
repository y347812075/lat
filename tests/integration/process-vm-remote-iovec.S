.equ __NR_read, 0
.equ __NR_write, 1
.equ __NR_close, 3
.equ __NR_mmap, 9
.equ __NR_mprotect, 10
.equ __NR_pipe, 22
.equ __NR_clone, 56
.equ __NR_exit, 60
.equ __NR_wait4, 61
.equ __NR_process_vm_readv, 310
.equ __NR_process_vm_writev, 311
.equ PROT_READ_WRITE, 3
.equ MAP_PRIVATE_ANONYMOUS, 0x22
.equ SIGCHLD, 17

.section .rodata
child_data:
    .ascii "hello"
parent_data:
    .ascii "world"

.section .bss
.align 8
address_pipe:
    .skip 8
sync_pipe:
    .skip 8
remote_address:
    .quad 0
remote_cross_address:
    .quad 0
protected_address:
    .quad 0
divergent_address:
    .quad 0
local_buffer:
    .skip 8
local_iov:
    .quad 0, 0
remote_iov:
    .quad 0, 0
status:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    lea address_pipe(%rip), %rdi
    mov $__NR_pipe, %eax
    syscall
    test %rax, %rax
    js pipe_failed

    xor %edi, %edi
    mov $8192, %esi
    mov $PROT_READ_WRITE, %edx
    mov $MAP_PRIVATE_ANONYMOUS, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $__NR_mmap, %eax
    syscall
    test %rax, %rax
    js protected_mmap_failed
    mov %rax, protected_address(%rip)
    lea 4096(%rax), %rdi
    mov $4096, %esi
    xor %edx, %edx
    mov $__NR_mprotect, %eax
    syscall
    test %rax, %rax
    js protected_mprotect_failed

    xor %edi, %edi
    mov $4096, %esi
    xor %edx, %edx
    mov $MAP_PRIVATE_ANONYMOUS, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $__NR_mmap, %eax
    syscall
    test %rax, %rax
    js divergent_mmap_failed
    mov %rax, divergent_address(%rip)

    lea sync_pipe(%rip), %rdi
    mov $__NR_pipe, %eax
    syscall
    test %rax, %rax
    js pipe_failed

    mov $(SIGCHLD), %edi
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
    mov address_pipe(%rip), %edi
    lea remote_address(%rip), %rsi
    mov $16, %edx
    mov $__NR_read, %eax
    syscall
    cmp $16, %rax
    jne parent_read_address_failed

    lea local_buffer(%rip), %rax
    mov %rax, local_iov(%rip)
    movq $5, local_iov+8(%rip)
    mov remote_address(%rip), %rax
    mov %rax, remote_iov(%rip)
    movq $5, remote_iov+8(%rip)

    mov $__NR_process_vm_readv, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $5, %rax
    jne process_read_failed

    mov local_buffer(%rip), %eax
    cmp child_data(%rip), %eax
    jne process_read_failed
    movzbl local_buffer+4(%rip), %eax
    cmpb child_data+4(%rip), %al
    jne process_read_failed

    lea parent_data(%rip), %rax
    mov %rax, local_iov(%rip)
    mov $__NR_process_vm_writev, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $5, %rax
    jne process_write_failed

    lea local_buffer(%rip), %rax
    mov %rax, local_iov(%rip)
    movq $5, local_iov+8(%rip)
    mov divergent_address(%rip), %rax
    mov %rax, remote_iov(%rip)
    movq $5, remote_iov+8(%rip)
    mov $__NR_process_vm_readv, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $5, %rax
    jne process_divergent_read_failed

    mov local_buffer(%rip), %eax
    cmp child_data(%rip), %eax
    jne process_divergent_read_failed
    movzbl local_buffer+4(%rip), %eax
    cmpb child_data+4(%rip), %al
    jne process_divergent_read_failed

    mov protected_address(%rip), %rax
    mov %rax, local_iov(%rip)
    movq $4096, local_iov+8(%rip)
    mov remote_cross_address(%rip), %rax
    add $2048, %rax
    mov %rax, remote_iov(%rip)
    movq $4096, remote_iov+8(%rip)
    mov $__NR_process_vm_writev, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $2048, %rax
    jne process_remote_partial_write_failed

    addq $2048, local_iov(%rip)
    movq $2048, local_iov+8(%rip)
    addq $2048, remote_iov(%rip)
    movq $2048, remote_iov+8(%rip)
    mov $__NR_process_vm_writev, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $-14, %rax
    jne process_remote_protected_write_failed

    mov protected_address(%rip), %rax
    mov %rax, local_iov(%rip)
    movq $4096, local_iov+8(%rip)
    mov protected_address(%rip), %rax
    add $2048, %rax
    mov %rax, remote_iov(%rip)
    movq $4096, remote_iov+8(%rip)
    mov $__NR_process_vm_writev, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $2048, %rax
    jne process_partial_write_failed

    addq $2048, local_iov(%rip)
    movq $2048, local_iov+8(%rip)
    addq $2048, remote_iov(%rip)
    movq $2048, remote_iov+8(%rip)
    mov $__NR_process_vm_writev, %eax
    mov %r12d, %edi
    lea local_iov(%rip), %rsi
    mov $1, %edx
    lea remote_iov(%rip), %r10
    mov $1, %r8d
    xor %r9d, %r9d
    syscall
    cmp $-14, %rax
    jne process_protected_write_failed

    mov sync_pipe+4(%rip), %edi
    lea status(%rip), %rsi
    mov $1, %edx
    mov $__NR_write, %eax
    syscall
    cmp $1, %rax
    jne sync_failed

    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $__NR_wait4, %eax
    syscall
    cmp %r12, %rax
    jne wait_failed
    mov status(%rip), %eax
    test %eax, %eax
    jne child_failed
    xor %edi, %edi
    jmp exit

child:
    mov divergent_address(%rip), %rdi
    mov $4096, %esi
    mov $PROT_READ_WRITE, %edx
    mov $__NR_mprotect, %eax
    syscall
    test %rax, %rax
    js child_divergent_mprotect_failed
    mov divergent_address(%rip), %rax
    mov child_data(%rip), %rcx
    mov %rcx, (%rax)

    xor %edi, %edi
    mov $4096, %esi
    mov $PROT_READ_WRITE, %edx
    mov $MAP_PRIVATE_ANONYMOUS, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $__NR_mmap, %eax
    syscall
    test %rax, %rax
    js child_mmap_failed
    mov %rax, %r12

    mov child_data(%rip), %rcx
    mov %rcx, (%r12)
    mov %r12, remote_address(%rip)

    xor %edi, %edi
    mov $8192, %esi
    mov $PROT_READ_WRITE, %edx
    mov $MAP_PRIVATE_ANONYMOUS, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $__NR_mmap, %eax
    syscall
    test %rax, %rax
    js child_cross_mmap_failed
    mov %rax, remote_cross_address(%rip)
    lea 4096(%rax), %rdi
    mov $4096, %esi
    xor %edx, %edx
    mov $__NR_mprotect, %eax
    syscall
    test %rax, %rax
    js child_cross_mprotect_failed

    mov address_pipe+4(%rip), %edi
    lea remote_address(%rip), %rsi
    mov $16, %edx
    mov $__NR_write, %eax
    syscall
    cmp $16, %rax
    jne child_pipe_failed

    mov sync_pipe(%rip), %edi
    lea status(%rip), %rsi
    mov $1, %edx
    mov $__NR_read, %eax
    syscall
    cmp $1, %rax
    jne child_sync_failed

    mov (%r12), %eax
    cmp parent_data(%rip), %eax
    jne child_data_failed
    movzbl 4(%r12), %eax
    cmpb parent_data+4(%rip), %al
    jne child_data_failed
    xor %edi, %edi
    jmp exit

pipe_failed:
    mov $10, %edi
    jmp exit
clone_failed:
    mov $11, %edi
    jmp exit
parent_read_address_failed:
    mov $12, %edi
    jmp reap_child
process_read_failed:
    mov $13, %edi
    jmp reap_child
process_write_failed:
    mov $14, %edi
    jmp reap_child
sync_failed:
    mov $15, %edi
    jmp reap_child
wait_failed:
    mov $16, %edi
    jmp exit
child_failed:
    mov $17, %edi
    jmp exit
protected_mmap_failed:
    mov $18, %edi
    jmp exit
protected_mprotect_failed:
    mov $19, %edi
    jmp exit
child_mmap_failed:
    mov $20, %edi
    jmp exit
child_pipe_failed:
    mov $21, %edi
    jmp exit
child_sync_failed:
    mov $22, %edi
    jmp exit
child_data_failed:
    mov $23, %edi
    jmp exit
process_partial_write_failed:
    mov $24, %edi
    jmp reap_child
process_protected_write_failed:
    mov $25, %edi
    jmp reap_child
process_divergent_read_failed:
    mov $26, %edi
    jmp reap_child
process_remote_partial_write_failed:
    mov $27, %edi
    jmp reap_child
process_remote_protected_write_failed:
    mov $28, %edi
    jmp reap_child
divergent_mmap_failed:
    mov $29, %edi
    jmp exit
child_divergent_mprotect_failed:
    mov $30, %edi
    jmp exit
child_cross_mmap_failed:
    mov $31, %edi
    jmp exit
child_cross_mprotect_failed:
    mov $32, %edi
    jmp exit

reap_child:
    mov %edi, %r13d
    mov sync_pipe+4(%rip), %edi
    lea status(%rip), %rsi
    mov $1, %edx
    mov $__NR_write, %eax
    syscall
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
