.text
.global _start
.type _start,@function
_start:
    call callee
    test %rax, %rax
    jz 1f
    call *%rax
1:
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.type callee,@function
callee:
    xor %eax, %eax
    ret
.size callee, .-callee

.section .note.GNU-stack,"",@progbits
