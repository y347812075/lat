.text
.global _start
.type _start,@function
_start:
    fninit
    call wait_site
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start,.-_start
.p2align 4
.global wait_site
.type wait_site,@function
wait_site:
    fwait
    ret
.size wait_site,.-wait_site
.section .note.GNU-stack,"",@progbits
