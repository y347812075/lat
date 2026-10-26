.global _start
.type _start, @function
.ifndef REPLACE_SYSCALL
.set REPLACE_SYSCALL, 33
.endif
.section .text
_start:
    /* Replacing an internal target must not close its module lifetime pin. */
    mov $3, %r12d
.Ldup_loop:
    mov $REPLACE_SYSCALL, %eax
    mov $1, %edi
    mov %r12d, %esi
    mov $0x80000, %edx
    syscall
    inc %r12d
    cmp $1000, %r12d
    jne .Ldup_loop

    /* A normal guest target must still support both replacement operations. */
    mov $33, %eax
    mov $1, %edi
    mov $1000, %esi
    syscall
    cmp $1000, %rax
    jne .Lfail
    mov $292, %eax
    mov $1, %edi
    mov $1000, %esi
    xor %edx, %edx
    syscall
    cmp $1000, %rax
    jne .Lfail
    mov $3, %eax
    mov $1000, %edi
    syscall

    mov $3, %r12d
.Lunlock_loop:
    mov $73, %eax
    mov %r12d, %edi
    mov $8, %esi
    syscall
    inc %r12d
    cmp $1024, %r12d
    jne .Lunlock_loop

    /* Ordinary guest descriptors must retain working flock semantics. */
    mov $73, %eax
    mov $1, %edi
    mov $6, %esi
    syscall
    test %rax, %rax
    jne .Lfail
    mov $73, %eax
    mov $1, %edi
    mov $8, %esi
    syscall
    test %rax, %rax
    jne .Lfail

    mov $3, %edi
.Lclose_loop:
    mov $3, %eax
    syscall
    inc %edi
    cmp $1024, %edi
    jne .Lclose_loop

    mov $1, %eax
    mov $1, %edi
    lea closed_message(%rip), %rsi
    mov $7, %edx
    syscall

    mov $35, %eax
    lea sleep_time(%rip), %rdi
    xor %esi, %esi
    syscall

    mov $60, %eax
    xor %edi, %edi
    syscall
    ud2
.Lfail:
    mov $60, %eax
    mov $1, %edi
    syscall
    ud2
.size _start, .-_start

.section .rodata
closed_message:
    .ascii "CLOSED\n"

.section .data
.align 8
sleep_time:
    .quad 30
    .quad 0
