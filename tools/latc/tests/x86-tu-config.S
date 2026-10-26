.text
.global _start
.type _start, @function
_start:
    cvttss2si %xmm0, %eax
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.altmacro
.macro unit number
.p2align 4
.type unit_\number, @function
unit_\number:
.if (\number / 2 * 2 != \number)
    cvttss2si %xmm0, %eax
.else
    mov $7, %eax
.endif
    ret
.size unit_\number, .-unit_\number
.endm
.set number, 0
.rept 4096
unit %number
.set number, number + 1
.endr
.section .note.GNU-stack,"",@progbits
