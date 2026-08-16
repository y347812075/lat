/*
 * SPDX-FileCopyrightText: 2021-2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "common.h"
#include "reg-alloc.h"
#include "latx-options.h"
#include "translate.h"

#ifdef CONFIG_LATX_AVX_OPT

typedef IR2_INST *(*latx_avx_shift_imm_fn)(IR2_OPND, IR2_OPND, int);
typedef IR2_INST *(*latx_avx_shift_var_fn)(IR2_OPND, IR2_OPND, IR2_OPND);

static void load_avx_shift_operand_lsx(IR1_OPND *opnd, bool is_ymm,
                                       IR2_OPND *low, IR2_OPND *high)
{
    *high = (IR2_OPND){ 0 };
    if (ir1_opnd_is_mem(opnd)) {
        if (is_ymm) {
            load_v256_from_ir1_mem_exact(opnd, low, high);
        } else {
            *low = load_v128_from_ir1_mem_exact(opnd);
        }
        return;
    }

    lsassert(ir1_opnd_is_xmm(opnd) || ir1_opnd_is_ymm(opnd));
    *low = ra_alloc_ftemp();
    la_vori_b(*low, ra_alloc_xmm(ir1_opnd_base_reg_num(opnd)), 0);
    if (is_ymm) {
        *high = load_ymm_high128_shadow(ir1_opnd_base_reg_num(opnd));
    }
}

static void apply_avx_shift_imm_lsx(IR2_OPND dest, IR2_OPND src,
                                    latx_avx_shift_imm_fn shift, int imm,
                                    int max_count, bool arithmetic)
{
    if (arithmetic) {
        if (imm > max_count) {
            imm = max_count;
        }
        shift(dest, src, imm);
    } else if (imm > max_count) {
        la_vxor_v(dest, dest, dest);
    } else {
        shift(dest, src, imm);
    }
}

static void apply_avx_shift_var_lsx(
    IR2_OPND dest, IR2_OPND src, IR2_OPND count,
    latx_avx_shift_var_fn shift, latx_avx_shift_imm_fn valid,
    latx_avx_shift_imm_fn sign, int max_count, bool arithmetic)
{
    IR2_OPND mask = ra_alloc_ftemp();

    if (max_count == 63) {
        IR2_OPND limit = ra_alloc_ftemp();
        IR2_OPND limit_value = ra_alloc_itemp();

        /* vslei.du cannot encode the unsigned bound 63. */
        li_d(limit_value, 63);
        la_vreplgr2vr_d(limit, limit_value);
        la_vsle_du(mask, count, limit);
        ra_free_temp(limit_value);
        ra_free_temp(limit);
    } else {
        valid(mask, count, max_count);
    }
    shift(dest, src, count);
    if (arithmetic) {
        IR2_OPND sign_fill = ra_alloc_ftemp();

        sign(sign_fill, src, max_count);
        la_vbitsel_v(dest, sign_fill, dest, mask);
        ra_free_temp(sign_fill);
    } else {
        la_vand_v(dest, dest, mask);
    }
    ra_free_temp(mask);
}

/* VPSLL{W,D,Q}/VPSRL{W,D,Q}/VPSRA{W,D} use the low 64-bit count as one
 * scalar.  The LSX variable shift reads an element-sized count, so make a
 * width-matched shift vector while checking the original complete count. */
static void apply_avx_shift_scalar_lsx(
    IR2_OPND dest, IR2_OPND src, IR2_OPND count,
    latx_avx_shift_var_fn shift, latx_avx_shift_imm_fn replicate,
    latx_avx_shift_imm_fn sign, int max_count, bool arithmetic)
{
    IR2_OPND shift_count = ra_alloc_ftemp();
    IR2_OPND scalar_count = ra_alloc_ftemp();
    IR2_OPND mask = ra_alloc_ftemp();

    replicate(shift_count, count, 0);
    la_vreplvei_d(scalar_count, count, 0);
    if (max_count == 63) {
        IR2_OPND limit = ra_alloc_ftemp();
        IR2_OPND limit_value = ra_alloc_itemp();

        li_d(limit_value, 63);
        la_vreplgr2vr_d(limit, limit_value);
        la_vsle_du(mask, scalar_count, limit);
        ra_free_temp(limit_value);
        ra_free_temp(limit);
    } else {
        la_vslei_du(mask, scalar_count, max_count);
    }
    shift(dest, src, shift_count);
    if (arithmetic) {
        IR2_OPND sign_fill = ra_alloc_ftemp();
        sign(sign_fill, src, max_count);
        la_vbitsel_v(dest, sign_fill, dest, mask);
        ra_free_temp(sign_fill);
    } else {
        la_vand_v(dest, dest, mask);
    }
    ra_free_temp(mask);
    ra_free_temp(scalar_count);
    ra_free_temp(shift_count);
}

static bool translate_avx_integer_shift_lsx(IR1_INST *pir1)
{
    IR1_OPND *opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND *opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND *opnd2 = ir1_get_opnd(pir1, 2);
    int dest_index = ir1_opnd_base_reg_num(opnd0);
    bool is_ymm = ir1_opnd_is_ymm(opnd0);
    bool arithmetic = false;
    bool scalar_count = false;
    int max_count = 0;
    latx_avx_shift_imm_fn shift_imm = NULL;
    latx_avx_shift_var_fn shift_var = NULL;
    latx_avx_shift_imm_fn replicate_count = NULL;
    latx_avx_shift_imm_fn valid = NULL;
    latx_avx_shift_imm_fn sign = NULL;

    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
             (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));

    switch (ir1_opcode(pir1)) {
    case dt_X86_INS_VPSLLW:
        shift_imm = la_vslli_h;
        shift_var = la_vsll_h;
        valid = la_vslei_hu;
        max_count = 15;
        scalar_count = true;
        replicate_count = la_vreplvei_h;
        break;
    case dt_X86_INS_VPSLLD:
        shift_imm = la_vslli_w;
        shift_var = la_vsll_w;
        valid = la_vslei_wu;
        max_count = 31;
        scalar_count = true;
        replicate_count = la_vreplvei_w;
        break;
    case dt_X86_INS_VPSLLQ:
        shift_imm = la_vslli_d;
        shift_var = la_vsll_d;
        valid = la_vslei_du;
        max_count = 63;
        scalar_count = true;
        replicate_count = la_vreplvei_d;
        break;
    case dt_X86_INS_VPSRLW:
        shift_imm = la_vsrli_h;
        shift_var = la_vsrl_h;
        valid = la_vslei_hu;
        max_count = 15;
        scalar_count = true;
        replicate_count = la_vreplvei_h;
        break;
    case dt_X86_INS_VPSRLD:
        shift_imm = la_vsrli_w;
        shift_var = la_vsrl_w;
        valid = la_vslei_wu;
        max_count = 31;
        scalar_count = true;
        replicate_count = la_vreplvei_w;
        break;
    case dt_X86_INS_VPSRLQ:
        shift_imm = la_vsrli_d;
        shift_var = la_vsrl_d;
        valid = la_vslei_du;
        max_count = 63;
        scalar_count = true;
        replicate_count = la_vreplvei_d;
        break;
    case dt_X86_INS_VPSRAW:
        shift_imm = la_vsrai_h;
        shift_var = la_vsra_h;
        valid = la_vslei_hu;
        sign = la_vsrai_h;
        max_count = 15;
        scalar_count = true;
        replicate_count = la_vreplvei_h;
        arithmetic = true;
        break;
    case dt_X86_INS_VPSRAD:
        shift_imm = la_vsrai_w;
        shift_var = la_vsra_w;
        valid = la_vslei_wu;
        sign = la_vsrai_w;
        max_count = 31;
        scalar_count = true;
        replicate_count = la_vreplvei_w;
        arithmetic = true;
        break;
    case dt_X86_INS_VPSLLVD:
        shift_var = la_vsll_w;
        valid = la_vslei_wu;
        max_count = 31;
        break;
    case dt_X86_INS_VPSLLVQ:
        shift_var = la_vsll_d;
        valid = la_vslei_du;
        max_count = 63;
        break;
    case dt_X86_INS_VPSRLVD:
        shift_var = la_vsrl_w;
        valid = la_vslei_wu;
        max_count = 31;
        break;
    case dt_X86_INS_VPSRLVQ:
        shift_var = la_vsrl_d;
        valid = la_vslei_du;
        max_count = 63;
        break;
    case dt_X86_INS_VPSRAVD:
        shift_var = la_vsra_w;
        valid = la_vslei_wu;
        sign = la_vsrai_w;
        max_count = 31;
        arithmetic = true;
        break;
    case dt_X86_INS_VPSLLDQ:
        lsassert(ir1_opnd_is_imm(opnd2));
        shift_imm = la_vbsll_v;
        max_count = 15;
        break;
    case dt_X86_INS_VPSRLDQ:
        lsassert(ir1_opnd_is_imm(opnd2));
        shift_imm = la_vbsrl_v;
        max_count = 15;
        break;
    default:
        lsassert(0);
        return false;
    }

    IR2_OPND src_low;
    IR2_OPND src_high;

    load_avx_shift_operand_lsx(opnd1, is_ymm, &src_low, &src_high);

    if (ir1_opnd_is_imm(opnd2)) {
        int imm = ir1_opnd_uimm(opnd2);

        apply_avx_shift_imm_lsx(src_low, src_low, shift_imm, imm,
                                max_count, arithmetic);
        if (is_ymm) {
            apply_avx_shift_imm_lsx(src_high, src_high, shift_imm, imm,
                                    max_count, arithmetic);
        }
    } else {
        IR2_OPND count_low;
        IR2_OPND count_high;
        bool count_is_ymm = is_ymm && !scalar_count;

        lsassert(shift_var != NULL);
        load_avx_shift_operand_lsx(opnd2, count_is_ymm,
                                   &count_low, &count_high);
        if (scalar_count) {
            /* x86 uses the complete low 64-bit count for packed shifts. */
            apply_avx_shift_scalar_lsx(src_low, src_low, count_low, shift_var,
                                        replicate_count, sign, max_count,
                                        arithmetic);
            if (is_ymm) {
                apply_avx_shift_scalar_lsx(src_high, src_high, count_low,
                                           shift_var, replicate_count, sign,
                                           max_count, arithmetic);
            }
        } else {
            apply_avx_shift_var_lsx(src_low, src_low, count_low, shift_var,
                                    valid, sign, max_count, arithmetic);
            if (is_ymm) {
                apply_avx_shift_var_lsx(src_high, src_high, count_high,
                                        shift_var, valid, sign, max_count,
                                        arithmetic);
            }
        }
        ra_free_temp(count_low);
        if (count_is_ymm) {
            ra_free_temp(count_high);
        }
    }

    la_vori_b(ra_alloc_xmm(dest_index), src_low, 0);
    if (is_ymm) {
        store_ymm_high128_shadow(src_high, dest_index);
    } else {
        clear_ymm_high128_shadow(dest_index);
    }
    ra_free_temp(src_low);
    if (is_ymm) {
        ra_free_temp(src_high);
    }
    return true;
}

static bool translate_avx_byte_shift_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsllx_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsrlx_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsrax_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsllvd_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsllvq_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsrlvd_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsrlvq_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpsravd_lsx(IR1_INST *pir1)
{
    return translate_avx_integer_shift_lsx(pir1);
}

bool translate_vpslldq_lsx(IR1_INST *pir1)
{
    return translate_avx_byte_shift_lsx(pir1);
}

bool translate_vpsrldq_lsx(IR1_INST *pir1)
{
    return translate_avx_byte_shift_lsx(pir1);
}

#endif
