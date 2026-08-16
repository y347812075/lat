/* LSX implementations for AVX scalar conversion instructions. */
/*
 * SPDX-FileCopyrightText: 2021-2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "common.h"
#include "reg-alloc.h"
#include "lsenv.h"
#include "latx-options.h"
#include "translate.h"

#ifdef CONFIG_LATX_AVX_OPT

bool translate_vcvtss2sd_lsx(IR1_INST *pir1)
{
    IR1_OPND *dest_opnd = ir1_get_opnd(pir1, 0);
    IR1_OPND *src1_opnd = ir1_get_opnd(pir1, 1);
    IR2_OPND src1 = ra_alloc_ftemp();
    IR2_OPND src2 = load_freg128_from_ir1(ir1_get_opnd(pir1, 2));
    IR2_OPND converted = ra_alloc_ftemp();
    IR2_OPND bits = ra_alloc_itemp();

    lsassert(ir1_opnd_is_xmm(dest_opnd) && ir1_opnd_is_xmm(src1_opnd));
    la_vori_b(src1, ra_alloc_xmm(ir1_opnd_base_reg_num(src1_opnd)), 0);
    la_fcvt_d_s(converted, src2);
    la_vpickve2gr_du(bits, converted, 0);
    la_vinsgr2vr_d(src1, bits, 0);
    la_vori_b(ra_alloc_xmm(ir1_opnd_base_reg_num(dest_opnd)), src1, 0);
    clear_ymm_high128_shadow(ir1_opnd_base_reg_num(dest_opnd));
    ra_free_temp(bits);
    ra_free_temp(converted);
    ra_free_temp(src1);
    return true;
}

bool translate_vcvtsi2ss_lsx(IR1_INST *pir1)
{
    IR1_OPND *dest_opnd = ir1_get_opnd(pir1, 0);
    IR1_OPND *src1_opnd = ir1_get_opnd(pir1, 1);
    IR1_OPND *src2_opnd = ir1_get_opnd(pir1, 2);
    IR2_OPND fcsr = set_fpu_fcsr_rounding_field_by_x86();
    IR2_OPND dest = ra_alloc_ftemp();
    IR2_OPND src2 = load_ireg_from_ir1(src2_opnd, UNKNOWN_EXTENSION, false);
    IR2_OPND converted = ra_alloc_ftemp();

    lsassert(ir1_opnd_is_xmm(dest_opnd) && ir1_opnd_is_xmm(src1_opnd));
    la_vori_b(dest, ra_alloc_xmm(ir1_opnd_base_reg_num(src1_opnd)), 0);
    la_movgr2fr_d(converted, src2);
    if (ir1_opnd_size(src2_opnd) == 64) {
        la_ffint_s_l(converted, converted);
    } else {
        la_ffint_s_w(converted, converted);
    }
    la_vextrins_w(dest, converted, VEXTRINS_IMM_4_0(0, 0));
    la_vori_b(ra_alloc_xmm(ir1_opnd_base_reg_num(dest_opnd)), dest, 0);
    clear_ymm_high128_shadow(ir1_opnd_base_reg_num(dest_opnd));
    set_fpu_rounding_mode(fcsr);
    ra_free_temp_auto(fcsr);
    ra_free_temp(converted);
    ra_free_temp_auto(src2);
    ra_free_temp(dest);
    return true;
}

#endif
