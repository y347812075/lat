    .text
    .globl _start, provenance_entry, provenance_skip, provenance_wait, provenance_exit
    .type _start,@function
_start:
provenance_entry:
    fninit
    xor %eax, %eax
    test %eax, %eax
    jz provenance_wait
provenance_skip:
    jmp provenance_exit
    .size _start, .-_start
    .type provenance_wait,@function
provenance_wait:
    fwait
    jmp provenance_exit
    .size provenance_wait, .-provenance_wait
    .type provenance_exit,@function
provenance_exit:
    mov $60, %eax
    xor %edi, %edi
    syscall
    .size provenance_exit, .-provenance_exit
    .section .note.GNU-stack,"",@progbits
