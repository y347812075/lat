.global _start
.type _start, @function
.section .text
_start:
    mov $60, %eax
    mov $42, %edi
    syscall
    ud2
.size _start, .-_start

.global extra_entry
.type extra_entry, @function
extra_entry:
    mov $60, %eax
    mov $43, %edi
    syscall
    ud2
.size extra_entry, .-extra_entry

.global extra_entry2
.type extra_entry2, @function
extra_entry2:
    mov $60, %eax
    mov $44, %edi
    syscall
    ud2
.size extra_entry2, .-extra_entry2
