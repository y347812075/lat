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

.align 2
.global lat_native_x86_syscall
.type lat_native_x86_syscall, @function
lat_native_x86_syscall:
    bl lat_native_x86_syscall_impl
    ld.d $a0, $s8, 320
    bl lat_native_x86_dispatch_lookup

    ld.d $s0, $s8, 344
    ld.d $s1, $s8, 352
    ld.d $s2, $s8, 360
    ld.d $s3, $s8, 368
    ld.d $s4, $s8, 376
    ld.d $s5, $s8, 384
    ld.d $s6, $s8, 392
    ld.d $s7, $s8, 400
    ld.d $a2, $s8, 408
    ld.d $a3, $s8, 416
    ld.d $a4, $s8, 424
    ld.d $a5, $s8, 432
    ld.d $t5, $s8, 440
    ld.d $t6, $s8, 448
    ld.d $t7, $s8, 456
    ld.d $t8, $s8, 464
    ld.d $a6, $s8, 480

    fld.d $f0, $s8, 928
    fld.d $f1, $s8, 944
    fld.d $f2, $s8, 960
    fld.d $f3, $s8, 976
    fld.d $f4, $s8, 992
    fld.d $f5, $s8, 1008
    fld.d $f6, $s8, 1024
    fld.d $f7, $s8, 1040

    addi.d $t0, $s8, 2032
    xvld $xr16, $t0, -856
    xvld $xr17, $t0, -792
    xvld $xr18, $t0, -728
    xvld $xr19, $t0, -664
    xvld $xr20, $t0, -600
    xvld $xr21, $t0, -536
    xvld $xr22, $t0, -472
    xvld $xr23, $t0, -408
    xvld $xr24, $t0, -344
    xvld $xr25, $t0, -280
    xvld $xr26, $t0, -216
    xvld $xr27, $t0, -152
    xvld $xr28, $t0, -88
    xvld $xr29, $t0, -24
    xvld $xr30, $t0, 40
    xvld $xr31, $t0, 104

    ld.d $r21, $s8, 320
    jr $a0
.size lat_native_x86_syscall, .-lat_native_x86_syscall
