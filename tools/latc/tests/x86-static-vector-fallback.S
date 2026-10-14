.text
.global _start
.type _start,@function
_start:
    call supported_value
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.type supported_value,@function
supported_value:
    mov $42, %eax
    ret
.size supported_value, .-supported_value

/* Static discovery must not export these unused CPU-specific variants. */
.type unsupported_zmm,@function
unsupported_zmm:
    vmovdqa64 %zmm0, %zmm1
    ret
.size unsupported_zmm, .-unsupported_zmm

.type unsupported_opmask,@function
unsupported_opmask:
    kmovw %eax, %k1
    ret
.size unsupported_opmask, .-unsupported_opmask

.type unsupported_extended,@function
unsupported_extended:
    vmovdqa64 %xmm16, %xmm17
    ret
.size unsupported_extended, .-unsupported_extended

.type unsupported_caller,@function
unsupported_caller:
    jmp unsupported_zmm
.size unsupported_caller, .-unsupported_caller

/* Cross the compiler's multi-worker threshold with ordinary static entries. */
.macro padding_function
.p2align 4
.type padding_\@,@function
padding_\@:
    ret
.size padding_\@, .-padding_\@
.endm
.rept 4200
padding_function
.endr

.section .note.GNU-stack,"",@progbits
