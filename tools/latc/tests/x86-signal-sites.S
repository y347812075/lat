.text

.global signal_boundary_site
.global signal_boundary_fault
.global signal_boundary_resume
.type signal_boundary_site,@function
signal_boundary_site:
    movabs $0x1122334455667788, %r8
    mov $42, %eax
    xor %edx, %edx
    xor %ecx, %ecx
    jmp signal_boundary_fault
.p2align 4
signal_boundary_fault:
    div %ecx
signal_boundary_resume:
    xor %eax, %eax
    ret
.size signal_boundary_site, .-signal_boundary_site

.global signal_internal_site
.global signal_internal_fault
.global signal_internal_resume
.type signal_internal_site,@function
signal_internal_site:
    movabs $0x2233445566778899, %r8
    mov $35, %eax
    add $7, %eax
    xor %edx, %edx
    xor %ecx, %ecx
signal_internal_fault:
    div %ecx
signal_internal_resume:
    xor %eax, %eax
    ret
.size signal_internal_site, .-signal_internal_site

.global signal_helper_site
.global signal_helper_fault
.global signal_helper_resume
.type signal_helper_site,@function
signal_helper_site:
    movabs $0x33445566778899aa, %r8
signal_helper_fault:
    ud2
signal_helper_resume:
    xor %eax, %eax
    ret
.size signal_helper_site, .-signal_helper_site

.section .note.GNU-stack,"",@progbits
