.text
.global _start
.type _start,@function
_start:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    aesenc %xmm1, %xmm0
    pcmpeqb expected(%rip), %xmm0
    pmovmskb %xmm0, %eax
    cmp $65535, %eax
    jne fail
    call constant_second
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start,.-_start
.p2align 4
.global constant_second
.type constant_second,@function
constant_second:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    aesenclast %xmm1, %xmm0
    pcmpeqb expected(%rip), %xmm0
    pmovmskb %xmm0, %eax
    cmp $65535, %eax
    jne fail
    ret
.size constant_second,.-constant_second
fail:
    mov $1, %edi
    mov $60, %eax
    syscall
.section .rodata
.p2align 4
expected:
.fill 16,1,0x63
.section .note.GNU-stack,"",@progbits
