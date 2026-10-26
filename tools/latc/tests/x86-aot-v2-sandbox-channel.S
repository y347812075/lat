.section .rodata
message:
    .ascii "SANDBOX_CHANNEL_OK\n"
.equ message_size, .-message

.section .bss
.align 8
child_status:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    cmpq $3, (%rsp)
    jne failed
    mov 16(%rsp), %r12
    mov 24(%rsp), %rax
    movzbl (%rax), %r13d
    cmp $'s', %r13d
    je fork_child
    # A mapped user namespace is supplied by the test harness.
    mov $272, %eax
    mov $0x60000000, %edi
    syscall
    test %rax, %rax
    js failed
fork_child:
    # Share the filesystem state with the parent, as sandbox launchers do.
    mov $56, %eax
    mov $0x211, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js failed
    jz child
    mov %eax, %edi
    mov $61, %eax
    lea child_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js failed
    cmpl $0, child_status(%rip)
    jne failed
    xor %edi, %edi
    jmp finish
child:
    cmp $'s', %r13d
    je change_root
    mov $39, %eax
    syscall
    cmp $1, %eax
    jne failed
change_root:
    mov $161, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js failed
    # These TBs must be learned after both pathname and network isolation.
.global sandbox_channel_after_chroot
sandbox_channel_after_chroot:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_size, %edx
    syscall
    cmp $message_size, %rax
    jne failed
    xor %edi, %edi
    jmp finish
failed:
    mov $81, %edi
finish:
    mov $60, %eax
    syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
