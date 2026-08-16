/*
 * SPDX-FileCopyrightText: 2021-2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "common.h"
#include "cpu.h"
#include "reg-alloc.h"
#include "fpu/softfloat.h"
#include "latx-options.h"
#include "translate.h"

#ifdef CONFIG_LATX_AVX_OPT

typedef IR2_INST *(*latx_lsx_fma_op)(IR2_OPND, IR2_OPND, IR2_OPND,
                                     IR2_OPND);

typedef struct LatxLsxFmaValue {
    IR2_OPND low;
    IR2_OPND high;
    bool wide;
} LatxLsxFmaValue;

static IR2_OPND load_lsx_fma_scalar(IR1_OPND *opnd)
{
    IR2_OPND value = ra_alloc_ftemp();

    la_vxor_v(value, value, value);
    if (ir1_opnd_is_mem(opnd)) {
        IR2_OPND integer;

        if (ir1_opnd_size(opnd) == 32) {
            integer = load_u32_from_ir1_mem_exact(opnd);
            la_vinsgr2vr_w(value, integer, 0);
        } else {
            integer = load_u64_from_ir1_mem_exact(opnd);
            la_vinsgr2vr_d(value, integer, 0);
        }
        ra_free_temp(integer);
    } else {
        la_vori_b(value, ra_alloc_xmm(ir1_opnd_base_reg_num(opnd)), 0);
    }
    return value;
}

static IR2_OPND load_lsx_fma_half(IR1_OPND *opnd, bool high)
{
    bool wide = ir1_opnd_is_ymm(opnd) ||
                (ir1_opnd_is_mem(opnd) && ir1_opnd_size(opnd) == 256);

    if (ir1_opnd_is_mem(opnd)) {
        if (wide) {
            if (high) {
                return load_v256_high_from_ir1_mem_exact(opnd);
            }
            IR2_OPND low;
            IR2_OPND high_value;

            load_v256_from_ir1_mem_exact(opnd, &low, &high_value);
            ra_free_temp(high_value);
            return low;
        }
        if (!high) {
            return load_v128_from_ir1_mem_exact(opnd);
        }
        IR2_OPND value = ra_alloc_ftemp();

        la_vxor_v(value, value, value);
        return value;
    }
    if (high) {
        if (wide) {
            return load_ymm_high128_shadow(
                ir1_opnd_base_reg_num(opnd));
        }
        IR2_OPND value = ra_alloc_ftemp();

        la_vxor_v(value, value, value);
        return value;
    }
    return ra_alloc_xmm(ir1_opnd_base_reg_num(opnd));
}

static void select_fma_operands(IR1_INST *pir1, LatxLsxFmaValue *a,
                                LatxLsxFmaValue *b, LatxLsxFmaValue *c,
                                LatxLsxFmaValue **x, LatxLsxFmaValue **y,
                                LatxLsxFmaValue **z)
{
    switch (ir1_opcode(pir1)) {
    case dt_X86_INS_VFMADD132PD:
    case dt_X86_INS_VFMADD132PS:
    case dt_X86_INS_VFMADD132SD:
    case dt_X86_INS_VFMADD132SS:
    case dt_X86_INS_VFMSUB132PD:
    case dt_X86_INS_VFMSUB132PS:
    case dt_X86_INS_VFMSUB132SD:
    case dt_X86_INS_VFMSUB132SS:
    case dt_X86_INS_VFNMADD132PD:
    case dt_X86_INS_VFNMADD132PS:
    case dt_X86_INS_VFNMADD132SD:
    case dt_X86_INS_VFNMADD132SS:
    case dt_X86_INS_VFNMSUB132PD:
    case dt_X86_INS_VFNMSUB132PS:
    case dt_X86_INS_VFNMSUB132SD:
    case dt_X86_INS_VFNMSUB132SS:
    case dt_X86_INS_VFMADDSUB132PD:
    case dt_X86_INS_VFMADDSUB132PS:
    case dt_X86_INS_VFMSUBADD132PD:
    case dt_X86_INS_VFMSUBADD132PS:
        *x = a; *y = c; *z = b;
        break;
    case dt_X86_INS_VFMADD213PD:
    case dt_X86_INS_VFMADD213PS:
    case dt_X86_INS_VFMADD213SD:
    case dt_X86_INS_VFMADD213SS:
    case dt_X86_INS_VFMSUB213PD:
    case dt_X86_INS_VFMSUB213PS:
    case dt_X86_INS_VFMSUB213SD:
    case dt_X86_INS_VFMSUB213SS:
    case dt_X86_INS_VFNMADD213PD:
    case dt_X86_INS_VFNMADD213PS:
    case dt_X86_INS_VFNMADD213SD:
    case dt_X86_INS_VFNMADD213SS:
    case dt_X86_INS_VFNMSUB213PD:
    case dt_X86_INS_VFNMSUB213PS:
    case dt_X86_INS_VFNMSUB213SD:
    case dt_X86_INS_VFNMSUB213SS:
    case dt_X86_INS_VFMADDSUB213PD:
    case dt_X86_INS_VFMADDSUB213PS:
    case dt_X86_INS_VFMSUBADD213PD:
    case dt_X86_INS_VFMSUBADD213PS:
        *x = b; *y = a; *z = c;
        break;
    case dt_X86_INS_VFMADD231PD:
    case dt_X86_INS_VFMADD231PS:
    case dt_X86_INS_VFMADD231SD:
    case dt_X86_INS_VFMADD231SS:
    case dt_X86_INS_VFMSUB231PD:
    case dt_X86_INS_VFMSUB231PS:
    case dt_X86_INS_VFMSUB231SD:
    case dt_X86_INS_VFMSUB231SS:
    case dt_X86_INS_VFNMADD231PD:
    case dt_X86_INS_VFNMADD231PS:
    case dt_X86_INS_VFNMADD231SD:
    case dt_X86_INS_VFNMADD231SS:
    case dt_X86_INS_VFNMSUB231PD:
    case dt_X86_INS_VFNMSUB231PS:
    case dt_X86_INS_VFNMSUB231SD:
    case dt_X86_INS_VFNMSUB231SS:
    case dt_X86_INS_VFMADDSUB231PD:
    case dt_X86_INS_VFMADDSUB231PS:
    case dt_X86_INS_VFMSUBADD231PD:
    case dt_X86_INS_VFMSUBADD231PS:
        *x = b; *y = c; *z = a;
        break;
    default:
        lsassert(0);
    }
}

static IR2_OPND fma_sign_mask(bool double_precision)
{
    IR2_OPND mask = ra_alloc_ftemp();
    IR2_OPND bits = ra_alloc_itemp();

    if (double_precision) {
        la_lu52i_d(bits, zero_ir2_opnd, 0x800);
        la_vreplgr2vr_d(mask, bits);
    } else {
        la_lu12i_w(bits, 0x80000);
        la_vreplgr2vr_w(mask, bits);
    }
    ra_free_temp(bits);
    return mask;
}

static IR2_OPND fma_lane_mask(bool add_even, bool double_precision)
{
    IR2_OPND mask = ra_alloc_ftemp();
    IR2_OPND bits = ra_alloc_itemp();

    if (double_precision) {
        la_vxor_v(mask, mask, mask);
        li_d(bits, UINT64_MAX);
        la_vreplgr2vr_d(mask, bits);
        if (add_even) {
            la_vinsgr2vr_d(mask, zero_ir2_opnd, 1);
        } else {
            la_vinsgr2vr_d(mask, zero_ir2_opnd, 0);
        }
    } else {
        li_wu(bits, UINT32_MAX);
        la_vxor_v(mask, mask, mask);
        if (add_even) {
            la_vinsgr2vr_w(mask, bits, 0);
            la_vinsgr2vr_w(mask, bits, 2);
        } else {
            la_vinsgr2vr_w(mask, bits, 1);
            la_vinsgr2vr_w(mask, bits, 3);
        }
    }
    ra_free_temp(bits);
    return mask;
}

static void free_lsx_fma_value(LatxLsxFmaValue *value)
{
    ra_free_temp_auto(value->high);
    ra_free_temp_auto(value->low);
}

static void correct_lsx_fma_nan_lane(IR2_OPND result, IR2_OPND x,
                                     IR2_OPND y, IR2_OPND z,
                                     bool double_precision, int lane)
{
    IR2_OPND bits = ra_alloc_itemp();
    IR2_OPND field = ra_alloc_itemp();
    IR2_OPND x_not_nan = ra_alloc_label();
    IR2_OPND y_not_nan = ra_alloc_label();
    IR2_OPND z_not_nan = ra_alloc_label();
    IR2_OPND write_result = ra_alloc_label();
    IR2_OPND done = ra_alloc_label();

    (void)result;

    if (double_precision) {
        la_vpickve2gr_du(bits, x, lane);
    } else {
        la_vpickve2gr_w(bits, x, lane);
        la_bstrpick_d(bits, bits, 31, 0);
    }
    la_bstrpick_d(field, bits, double_precision ? 62 : 30,
                  double_precision ? 52 : 23);
    la_xori(field, field, double_precision ? 0x7ff : 0xff);
    la_bne(field, zero_ir2_opnd, x_not_nan);
    la_bstrpick_d(field, bits, double_precision ? 51 : 22, 0);
    la_beq(field, zero_ir2_opnd, x_not_nan);
    li_d(field, double_precision ? UINT64_C(0x0008000000000000)
                                : UINT64_C(0x00400000));
    la_or(bits, bits, field);
    la_b(write_result);
    la_label(x_not_nan);
    if (double_precision) {
        la_vpickve2gr_du(bits, y, lane);
    } else {
        la_vpickve2gr_w(bits, y, lane);
        la_bstrpick_d(bits, bits, 31, 0);
    }
    la_bstrpick_d(field, bits, double_precision ? 62 : 30,
                  double_precision ? 52 : 23);
    la_xori(field, field, double_precision ? 0x7ff : 0xff);
    la_bne(field, zero_ir2_opnd, y_not_nan);
    la_bstrpick_d(field, bits, double_precision ? 51 : 22, 0);
    la_beq(field, zero_ir2_opnd, y_not_nan);
    li_d(field, double_precision ? UINT64_C(0x0008000000000000)
                                : UINT64_C(0x00400000));
    la_or(bits, bits, field);
    la_b(write_result);
    la_label(y_not_nan);
    if (double_precision) {
        la_vpickve2gr_du(bits, z, lane);
    } else {
        la_vpickve2gr_w(bits, z, lane);
        la_bstrpick_d(bits, bits, 31, 0);
    }
    la_bstrpick_d(field, bits, double_precision ? 62 : 30,
                  double_precision ? 52 : 23);
    la_xori(field, field, double_precision ? 0x7ff : 0xff);
    la_bne(field, zero_ir2_opnd, z_not_nan);
    la_bstrpick_d(field, bits, double_precision ? 51 : 22, 0);
    la_beq(field, zero_ir2_opnd, z_not_nan);
    li_d(field, double_precision ? UINT64_C(0x0008000000000000)
                                : UINT64_C(0x00400000));
    la_or(bits, bits, field);
    la_b(write_result);
    la_label(z_not_nan);
    if (double_precision) {
        la_vpickve2gr_du(bits, result, lane);
        la_bstrpick_d(field, bits, 62, 52);
        la_xori(field, field, 0x7ff);
        la_bne(field, zero_ir2_opnd, done);
        la_bstrpick_d(field, bits, 51, 0);
        la_beq(field, zero_ir2_opnd, done);
        li_d(bits, UINT64_C(0xfff8000000000000));
        la_vinsgr2vr_d(result, bits, lane);
    } else {
        la_vpickve2gr_w(bits, result, lane);
        la_bstrpick_d(bits, bits, 31, 0);
        la_bstrpick_d(field, bits, 30, 23);
        la_xori(field, field, 0xff);
        la_bne(field, zero_ir2_opnd, done);
        la_bstrpick_d(field, bits, 22, 0);
        la_beq(field, zero_ir2_opnd, done);
        li_d(bits, UINT64_C(0xffc00000));
        la_vinsgr2vr_w(result, bits, lane);
    }
    la_label(write_result);
    if (double_precision) {
        la_vinsgr2vr_d(result, bits, lane);
    } else {
        la_vinsgr2vr_w(result, bits, lane);
    }
    la_label(done);
    ra_free_temp(field);
    ra_free_temp(bits);
}

static void correct_lsx_fma_nan(IR2_OPND result, IR2_OPND x, IR2_OPND y,
                                IR2_OPND z, bool double_precision)
{
    int lanes = double_precision ? 2 : 4;

    for (int lane = 0; lane < lanes; ++lane) {
        correct_lsx_fma_nan_lane(result, x, y, z, double_precision, lane);
    }
}

static void translate_lsx_fma_vector(IR2_OPND dest, IR2_OPND x, IR2_OPND y,
                                     IR2_OPND z, bool double_precision,
                                     bool negate_product, bool subtract,
                                     bool alternating)
{
    IR2_OPND product_x = x;
    latx_lsx_fma_op op = double_precision ? la_vfmadd_d : la_vfmadd_s;

    if (negate_product) {
        IR2_OPND mask = fma_sign_mask(double_precision);

        product_x = ra_alloc_ftemp();
        la_vxor_v(product_x, x, mask);
        ra_free_temp(mask);
    }
    if (subtract) {
        op = double_precision ? la_vfmsub_d : la_vfmsub_s;
    }
    if (!alternating) {
        op(dest, product_x, y, z);
        correct_lsx_fma_nan(dest, x, y, z, double_precision);
    } else {
        IR2_OPND sub_result = ra_alloc_ftemp();
        IR2_OPND mask = fma_lane_mask(!subtract, double_precision);

        (double_precision ? la_vfmadd_d : la_vfmadd_s)(
            dest, product_x, y, z);
        correct_lsx_fma_nan(dest, x, y, z, double_precision);
        (double_precision ? la_vfmsub_d : la_vfmsub_s)(
            sub_result, product_x, y, z);
        correct_lsx_fma_nan(sub_result, x, y, z, double_precision);
        la_vbitsel_v(dest, dest, sub_result, mask);
        ra_free_temp(mask);
        ra_free_temp(sub_result);
    }
    if (negate_product) {
        ra_free_temp(product_x);
    }
}

static bool translate_lsx_fma(IR1_INST *pir1, bool double_precision,
                              bool scalar, bool negate_product, bool subtract,
                              bool alternating)
{
    IR1_OPND *opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND *opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND *opnd2 = ir1_get_opnd(pir1, 2);
    LatxLsxFmaValue a;
    LatxLsxFmaValue b;
    LatxLsxFmaValue c;
    LatxLsxFmaValue *x;
    LatxLsxFmaValue *y;
    LatxLsxFmaValue *z;
    IR2_OPND fcsr;

    fcsr = set_fpu_fcsr_rounding_field_by_x86();
    if (scalar) {
        a.low = load_lsx_fma_scalar(opnd0);
        b.low = load_lsx_fma_scalar(opnd1);
        c.low = load_lsx_fma_scalar(opnd2);
        a.high = zero_ir2_opnd;
        b.high = zero_ir2_opnd;
        c.high = zero_ir2_opnd;
        a.wide = b.wide = c.wide = false;
        x = &a;
        y = &b;
        z = &c;
        select_fma_operands(pir1, &a, &b, &c, &x, &y, &z);
        IR2_OPND low = ra_alloc_ftemp();
        IR2_OPND result = ra_alloc_ftemp();
        IR2_OPND result_word = ra_alloc_itemp();

        if (negate_product) {
            IR2_OPND neg = ra_alloc_ftemp();
            IR2_OPND sign = fma_sign_mask(double_precision);
            la_vxor_v(neg, x->low, sign);
            ra_free_temp(sign);
            if (subtract) {
                if (double_precision) {
                    la_fmsub_d(result, neg, y->low, z->low);
                } else {
                    la_fmsub_s(result, neg, y->low, z->low);
                }
            } else if (double_precision) {
                la_fmadd_d(result, neg, y->low, z->low);
            } else {
                la_fmadd_s(result, neg, y->low, z->low);
            }
            ra_free_temp(neg);
        } else if (subtract) {
            if (double_precision) {
                la_fmsub_d(result, x->low, y->low, z->low);
            } else {
                la_fmsub_s(result, x->low, y->low, z->low);
            }
        } else if (double_precision) {
            la_fmadd_d(result, x->low, y->low, z->low);
        } else {
            la_fmadd_s(result, x->low, y->low, z->low);
        }
        correct_lsx_fma_nan(result, x->low, y->low, z->low,
                            double_precision);
        la_vori_b(low, a.low, 0);
        if (double_precision) {
            la_vpickve2gr_du(result_word, result, 0);
            la_vinsgr2vr_d(low, result_word, 0);
        } else {
            la_vpickve2gr_w(result_word, result, 0);
            la_vinsgr2vr_w(low, result_word, 0);
        }
        la_vori_b(ra_alloc_xmm(ir1_opnd_base_reg_num(opnd0)), low, 0);
        clear_ymm_high128_shadow(ir1_opnd_base_reg_num(opnd0));
        ra_free_temp(result_word);
        ra_free_temp(result);
        ra_free_temp(low);
        free_lsx_fma_value(&c);
        free_lsx_fma_value(&b);
        free_lsx_fma_value(&a);
    } else {
        IR2_OPND low;
        IR2_OPND high;
        int dest_index = ir1_opnd_base_reg_num(opnd0);
        bool ymm = ir1_opnd_is_ymm(opnd0);

        a.wide = b.wide = c.wide = true;
        a.low = load_lsx_fma_half(opnd0, false);
        b.low = load_lsx_fma_half(opnd1, false);
        c.low = load_lsx_fma_half(opnd2, false);
        x = &a;
        y = &b;
        z = &c;
        select_fma_operands(pir1, &a, &b, &c, &x, &y, &z);
        low = ra_alloc_ftemp();
        translate_lsx_fma_vector(low, x->low, y->low, z->low,
                                 double_precision, negate_product, subtract,
                                 alternating);
        ra_free_temp_auto(a.low);
        ra_free_temp_auto(b.low);
        ra_free_temp_auto(c.low);

        if (!ymm) {
            /* A VEX.128 FMA writes only the low XMM value and clears its
             * YMM shadow.  Do not allocate an unused high-half work set. */
            la_vori_b(ra_alloc_xmm(dest_index), low, 0);
            clear_ymm_high128_shadow(dest_index);
            ra_free_temp(low);
            set_fpu_rounding_mode(fcsr);
            ra_free_temp_auto(fcsr);
            return true;
        }

        a.high = load_lsx_fma_half(opnd0, true);
        b.high = load_lsx_fma_half(opnd1, true);
        c.high = load_lsx_fma_half(opnd2, true);
        select_fma_operands(pir1, &a, &b, &c, &x, &y, &z);
        high = ra_alloc_ftemp();
        translate_lsx_fma_vector(high, x->high, y->high, z->high,
                                 double_precision, negate_product, subtract,
                                 alternating);
        la_vori_b(ra_alloc_xmm(dest_index), low, 0);
        store_ymm_high128_shadow(high, dest_index);
        ra_free_temp_auto(c.high);
        ra_free_temp_auto(b.high);
        ra_free_temp_auto(a.high);
        ra_free_temp(high);
        ra_free_temp(low);
    }
    set_fpu_rounding_mode(fcsr);
    ra_free_temp_auto(fcsr);
    return true;
}

#define LSX_FMA_WRAPPERS(name, precision, scalar, negate, subtract, alternate) \
bool translate_##name##_lsx(IR1_INST *pir1) \
{ \
    return translate_lsx_fma(pir1, precision, scalar, negate, subtract, alternate); \
}

LSX_FMA_WRAPPERS(vfmaddxxxpd, true, false, false, false, false)
LSX_FMA_WRAPPERS(vfmaddxxxps, false, false, false, false, false)
LSX_FMA_WRAPPERS(vfmaddxxxsd, true, true, false, false, false)
LSX_FMA_WRAPPERS(vfmaddxxxss, false, true, false, false, false)
LSX_FMA_WRAPPERS(vfmsubxxxpd, true, false, false, true, false)
LSX_FMA_WRAPPERS(vfmsubxxxps, false, false, false, true, false)
LSX_FMA_WRAPPERS(vfmsubxxxsd, true, true, false, true, false)
LSX_FMA_WRAPPERS(vfmsubxxxss, false, true, false, true, false)
LSX_FMA_WRAPPERS(vfnmaddxxxpd, true, false, true, false, false)
LSX_FMA_WRAPPERS(vfnmaddxxxps, false, false, true, false, false)
LSX_FMA_WRAPPERS(vfnmaddxxxsd, true, true, true, false, false)
LSX_FMA_WRAPPERS(vfnmaddxxxss, false, true, true, false, false)
LSX_FMA_WRAPPERS(vfnmsubxxxpd, true, false, true, true, false)
LSX_FMA_WRAPPERS(vfnmsubxxxps, false, false, true, true, false)
LSX_FMA_WRAPPERS(vfnmsubxxxsd, true, true, true, true, false)
LSX_FMA_WRAPPERS(vfnmsubxxxss, false, true, true, true, false)

LSX_FMA_WRAPPERS(vfmaddsubxxxpd, true, false, false, false, true)
LSX_FMA_WRAPPERS(vfmaddsubxxxps, false, false, false, false, true)
LSX_FMA_WRAPPERS(vfmsubaddxxxpd, true, false, false, true, true)
LSX_FMA_WRAPPERS(vfmsubaddxxxps, false, false, false, true, true)

#undef LSX_FMA_WRAPPERS
#endif
