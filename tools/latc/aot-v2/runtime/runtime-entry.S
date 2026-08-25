.text
.align 2

.macro LAT_AOT_RUNTIME_ENTRY name, slot
    .global \name
    .type \name, @function
\name:
    la.local $t0, lat_aot_runtime_target_slots_v2
    ld.d $t0, $t0, (\slot * 8)
    beqz $t0, 1f
    jr $t0
1:
    break 0
    .size \name, .-\name
.endm

LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_epilogue_ret_id_1, 0
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_epilogue_ret_id_0, 1
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_jirl_epilogue_ret_id_1, 2
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_jirl_epilogue_ret_id_0, 3
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_epilogue_ret_0, 4
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_update_mxcsr_status, 5
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_fxsave, 6
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_fxrstor, 7
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_fpregs_x80_to_64, 8
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_fpregs_64_to_x80, 9
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_update_fp_status, 10
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_cpuid, 11
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_raise_illop, 12
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_raise_gpf, 13
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_pcmpistri_xmm, 14
LAT_AOT_RUNTIME_ENTRY lat_aot_runtime_pcmpistrm_xmm, 15

.section .note.GNU-stack,"",@progbits
