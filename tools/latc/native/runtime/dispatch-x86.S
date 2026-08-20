.text
.align 2
.global lat_native_x86_dispatch_jirl
.type lat_native_x86_dispatch_jirl, @function
lat_native_x86_dispatch_jirl:
    addi.d $sp, $sp, -96
    st.d $ra, $sp, 0
    st.d $a2, $sp, 8
    st.d $a3, $sp, 16
    st.d $a4, $sp, 24
    st.d $a5, $sp, 32
    st.d $a6, $sp, 40
    st.d $t5, $sp, 48
    st.d $t6, $sp, 56
    st.d $t7, $sp, 64
    st.d $t8, $sp, 72
    st.d $r21, $sp, 80
    move $a0, $r21
    bl lat_native_x86_dispatch_lookup
    ld.d $r21, $sp, 80
    ld.d $t8, $sp, 72
    ld.d $t7, $sp, 64
    ld.d $t6, $sp, 56
    ld.d $t5, $sp, 48
    ld.d $a6, $sp, 40
    ld.d $a5, $sp, 32
    ld.d $a4, $sp, 24
    ld.d $a3, $sp, 16
    ld.d $a2, $sp, 8
    ld.d $ra, $sp, 0
    addi.d $sp, $sp, 96
    jr $a0
.size lat_native_x86_dispatch_jirl, .-lat_native_x86_dispatch_jirl
