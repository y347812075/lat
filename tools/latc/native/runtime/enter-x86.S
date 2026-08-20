.text
.align 2
.global lat_native_enter_x86_exit_smoke
.type lat_native_enter_x86_exit_smoke, @function
lat_native_enter_x86_exit_smoke:
    move $s8, $a1
    move $s4, $a2
    move $fp, $a3
    jr $a0
.size lat_native_enter_x86_exit_smoke, .-lat_native_enter_x86_exit_smoke
