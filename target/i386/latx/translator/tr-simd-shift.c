#include "common.h"
#include "reg-alloc.h"
#include "latx-options.h"
#include "translate.h"

bool translate_psllw(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 15);

            la_vreplvei_h(temp1, src, 0);
            la_vsll_h(dest, dest, temp1);
            la_vand_v(dest, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 15) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vslli_h(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 15)
                la_vxor_v(dest, dest, dest);
            else {
                la_vslli_h(dest, dest, imm);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vslei_du(temp1, src, 15);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vreplvei_h(temp2, src, 0);
            la_vsll_h(dest, dest, temp2);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_pslld(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 31);
            la_vreplvei_w(temp1, src, 0);
            la_vsll_w(dest, dest, temp1);
            la_vand_v(dest, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 31) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vslli_w(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 31)
                la_vxor_v(dest, dest, dest);
            else {
                la_vslli_w(dest, dest, imm);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vslei_du(temp1, src, 31);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vreplvei_w(temp2, src, 0);
            la_vsll_w(dest, dest, temp2);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_psllq(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vldi(temp2, VLDI_IMM_TYPE0(3, 63));
            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsle_du(temp3, temp1, temp2);
            la_vreplvei_d(temp1, src, 0);
            la_vsll_d(dest, dest, temp1);
            la_vand_v(dest, dest, temp3);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 63) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vslli_d(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 63)
                la_vxor_v(dest, dest, dest);
            else {
                la_vslli_d(dest, dest, imm);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vldi(temp1, VLDI_IMM_TYPE0(3, 63));
            la_vsle_du(temp1, src, temp1);
            la_vsll_d(dest, dest, src);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_psrlw(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 15);
            la_vreplvei_h(temp1, src, 0);
            la_vsrl_h(dest, dest, temp1);
            la_vand_v(dest, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 15) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vsrli_h(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 15)
                la_vxor_v(dest, dest, dest);
            else {
                la_vsrli_h(dest, dest, imm);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vslei_du(temp1, src, 15);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vreplvei_h(temp2, src, 0);
            la_vsrl_h(dest, dest, temp2);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_psrld(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 31);
            la_vreplvei_w(temp1, src, 0);
            la_vsrl_w(dest, dest, temp1);
            la_vand_v(dest, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 31) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vsrli_w(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 31)
                la_vxor_v(dest, dest, dest);
            else {
                la_vsrli_w(dest, dest, imm);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vslei_du(temp1, src, 31);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vreplvei_w(temp2, src, 0);
            la_vsrl_w(dest, dest, temp2);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_psrlq(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vldi(temp2, VLDI_IMM_TYPE0(3, 63));
            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsle_du(temp3, temp1, temp2);
            la_vsrl_d(dest, dest, temp1);
            la_vand_v(dest, dest, temp3);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 63) {
                la_vxor_v(dest, dest, dest);
            } else {
                la_vsrli_d(dest, dest, imm);
            }
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 63)
                la_movgr2fr_d(dest, zero_ir2_opnd);
            else {
                IR2_OPND itemp = ra_alloc_itemp();
                li_wu(itemp, imm);
                la_movfr2gr_d(itemp, dest);
                la_srli_d(itemp, itemp, imm);
                la_movgr2fr_d(dest, itemp);
                ra_free_temp(itemp);
            }
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vldi(temp1, VLDI_IMM_TYPE0(3, 63));
            la_vsle_du(temp1, src, temp1);
            la_vsrl_d(dest, dest, src);
            la_vand_v(dest, dest, temp1);
        }
    }
    return true;
}

bool translate_psraw(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 15);
            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsrai_h(temp3, dest, 15);
            la_vreplvei_h(temp1, src, 0);
            la_vsra_h(dest, dest, temp1);
            la_vbitsel_v(dest, temp3, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 15)
                imm = 15;
            la_vsrai_h(dest, dest, imm);
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 15)
                imm = 15;
            la_vsrai_h(dest, dest, imm);
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);

            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);

            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 15);
            la_vreplvei_h(temp1, src, 0);

            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsrai_h(temp3, dest, 15);
            la_vsra_h(dest, dest, temp1);
            la_vbitsel_v(dest, temp3, dest, temp2);
        }
    }
    return true;
}

bool translate_psrad(IR1_INST *pir1)
{
    if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0))) {
        IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
        if (ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
            ir1_opnd_is_mem(ir1_get_opnd(pir1, 1))) {
            IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 31);
            la_vreplvei_w(temp1, src, 0);
            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsrai_w(temp3, dest, 31);
            la_vsra_w(dest, dest, temp1);
            la_vbitsel_v(dest, temp3, dest, temp2);
        } else if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 1))) {
            uint8_t imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
            if (imm > 31)
                imm = 31;
            la_vsrai_w(dest, dest, imm);
        } else {
            lsassert(0);
        }
    } else { //mmx
        /* transfer to mmx mode */
        transfer_to_mmx_mode();

        if (ir1_opnd_is_imm(ir1_get_opnd(pir1, 0) + 1)) {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            uint8 imm = ir1_opnd_uimm(ir1_get_opnd(pir1, 0) + 1);
            if (imm > 31)
                imm = 31;
            la_vsrai_w(dest, dest, imm);
        } else {
            IR2_OPND dest = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0), false, IS_INTEGER);
            IR2_OPND src = load_freg_from_ir1_1(
                ir1_get_opnd(pir1, 0) + 1, false, IS_INTEGER);
            IR2_OPND temp1 = ra_alloc_ftemp();
            la_vreplvei_d(temp1, src, 0);
            IR2_OPND temp2 = ra_alloc_ftemp();
            la_vslei_du(temp2, temp1, 31);
            la_vreplvei_w(temp1, src, 0);
            IR2_OPND temp3 = ra_alloc_ftemp();
            la_vsrai_w(temp3, dest, 31);
            la_vsra_w(dest, dest, temp1);
            la_vbitsel_v(dest, temp3, dest, temp2);
        }
    }
    return true;
}

bool translate_pslldq(IR1_INST *pir1)
{
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0)));
    IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
    uint8_t imm8 = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
    if (imm8 > 15) {
        la_vxor_v(dest, dest, dest);
    } else if (imm8 == 0) {
        return true;
    } else {
        la_vbsll_v(dest, dest, imm8);
    }
    return true;
}

bool translate_psrldq(IR1_INST *pir1)
{
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0)));
    IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
    uint8_t imm8 = ir1_opnd_uimm(ir1_get_opnd(pir1, 1));
    if (imm8 > 15) {
        la_vxor_v(dest, dest, dest);
    } else if (imm8 == 0) {
        return true;
    } else {
        la_vbsrl_v(dest, dest, imm8);
    }
    return true;
}


bool translate_addsubpd(IR1_INST *pir1)
{
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0)));
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
             ir1_opnd_is_mem(ir1_get_opnd(pir1, 1)));

    IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
    IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
    IR2_OPND temp_dest_sub = ra_alloc_ftemp();
    IR2_OPND ftemp_src_add = ra_alloc_ftemp();
    IR2_OPND ftemp_src_sub = ra_alloc_ftemp();
    IR2_OPND ftemp_dest_add = ra_alloc_ftemp();
    IR2_OPND ftemp_dest_sub = ra_alloc_ftemp();

    la_vbsll_v(ftemp_src_add, src, 0);
    la_vbsll_v(ftemp_src_sub, src, 0);
    la_vbsll_v(ftemp_dest_add, dest, 0);
    la_vbsll_v(ftemp_dest_sub, dest, 0);

    la_vpermi_w(ftemp_src_add, src, 0xee);
    la_vpermi_w(ftemp_dest_add, dest, 0xee);
    la_vpermi_w(ftemp_src_sub, src, 0x44);
    la_vpermi_w(ftemp_dest_sub, dest, 0x44);

    la_vfsub_d(temp_dest_sub, ftemp_dest_sub, ftemp_src_sub);
    la_vfadd_d(dest, ftemp_dest_add, ftemp_src_add);
    if (option_enable_lasx) {
        la_xvinsve0_d(dest, temp_dest_sub, 0);
    } else {
        la_vextrins_d(dest, temp_dest_sub, 0);
    }

    ra_free_temp(temp_dest_sub);
    ra_free_temp(ftemp_src_add);
    ra_free_temp(ftemp_src_sub);
    ra_free_temp(ftemp_dest_add);
    ra_free_temp(ftemp_dest_sub);
    return true;
}

bool translate_addsubps(IR1_INST *pir1)
{
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 0)));
    lsassert(ir1_opnd_is_xmm(ir1_get_opnd(pir1, 1)) ||
             ir1_opnd_is_mem(ir1_get_opnd(pir1, 1)));

    IR2_OPND dest = load_freg128_from_ir1(ir1_get_opnd(pir1, 0));
    IR2_OPND src = load_freg128_from_ir1(ir1_get_opnd(pir1, 1));
    IR2_OPND temp_dest_sub = ra_alloc_ftemp();
    IR2_OPND ftemp_src_add = ra_alloc_ftemp();
    IR2_OPND ftemp_src_sub = ra_alloc_ftemp();
    IR2_OPND ftemp_dest_add = ra_alloc_ftemp();
    IR2_OPND ftemp_dest_sub = ra_alloc_ftemp();

    /**
     * The two should not interfere with each other When
     * calculating addition or subtraction, or unexpected FPE
     * would be triggered. See VPERMI in Volume 2 of LOONGARCH for
     * more informations.
     */
    la_vbsll_v(ftemp_src_add, src, 0);
    la_vbsll_v(ftemp_src_sub, src, 0);
    la_vbsll_v(ftemp_dest_add, dest, 0);
    la_vbsll_v(ftemp_dest_sub, dest, 0);

    la_vpermi_w(ftemp_src_add, src, 0xf5);
    la_vpermi_w(ftemp_dest_add, dest, 0xf5);
    la_vpermi_w(ftemp_src_sub, src, 0xa0);
    la_vpermi_w(ftemp_dest_sub, dest, 0xa0);

    la_vfsub_s(temp_dest_sub, ftemp_dest_sub, ftemp_src_sub);
    la_vfadd_s(dest, ftemp_dest_add, ftemp_src_add);

   /*
    * Pick temp_sub data to [0:31] [64:95]
    */
    if (option_enable_lasx) {
        la_xvinsve0_w(dest, temp_dest_sub, 0);
    } else {
        la_vextrins_w(dest, temp_dest_sub, 0);
    }
    la_vbsrl_v(temp_dest_sub, temp_dest_sub, 8);
    if (option_enable_lasx) {
        la_xvinsve0_w(dest, temp_dest_sub, 2);
    } else {
        la_vextrins_w(dest, temp_dest_sub, 0x2 << 4);
    }

    ra_free_temp(temp_dest_sub);
    ra_free_temp(ftemp_src_add);
    ra_free_temp(ftemp_src_sub);
    ra_free_temp(ftemp_dest_add);
    ra_free_temp(ftemp_dest_sub);

    return true;
}

#ifdef CONFIG_LATX_AVX_OPT
bool translate_vpslldq(IR1_INST * pir1) {
    IR1_OPND * opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND * opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND * opnd2 = ir1_get_opnd(pir1, 2);
    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
        (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));
    lsassert(ir1_opnd_is_imm(opnd2));
    IR2_OPND dest = load_freg256_from_ir1(opnd0);
    IR2_OPND src = load_freg256_from_ir1(opnd1);
    uint8_t imm = ir1_opnd_uimm(opnd2);
    if (imm > 15) {
        la_xvandi_b(dest, src, 0);
        return true;
    }
    la_xvbsll_v(dest, src, imm);
    if (ir1_opnd_is_xmm(opnd0)) {
        set_high128_xreg_to_zero(dest);
    }
    return true;
}

bool translate_vpsllx(IR1_INST * pir1) {
    IR1_OPND * opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND * opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND * opnd2 = ir1_get_opnd(pir1, 2);
    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
        (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));
    IR2_OPND dest = load_freg256_from_ir1(opnd0);
    IR2_OPND src = load_freg256_from_ir1(opnd1);
    IR2_INST * ( * rep_inst)(IR2_OPND, IR2_OPND);
    IR2_INST * ( * tr_inst_i)(IR2_OPND, IR2_OPND, int);
    IR2_INST * ( * tr_inst_r)(IR2_OPND, IR2_OPND, IR2_OPND);
    int max_count;
    switch (ir1_opcode(pir1)) {
        case dt_X86_INS_VPSLLW:
            rep_inst = la_xvreplve0_h;
            tr_inst_i = la_xvslli_h;
            tr_inst_r = la_xvsll_h;
            max_count = 15;
            break;
        case dt_X86_INS_VPSLLD:
            rep_inst = la_xvreplve0_w;
            tr_inst_i = la_xvslli_w;
            tr_inst_r = la_xvsll_w;
            max_count = 31;
            break;
        case dt_X86_INS_VPSLLQ:
            rep_inst = la_xvreplve0_d;
            tr_inst_i = la_xvslli_d;
            tr_inst_r = la_xvsll_d;
            max_count = 63;
            break;
        default:
            rep_inst = NULL;
            tr_inst_i = NULL;
            tr_inst_r = NULL;
            max_count = 0;
            lsassert(0);
            break;
    }
    if (ir1_opnd_is_imm(opnd2)) {
        uint8_t imm = ir1_opnd_uimm(opnd2);
        if (imm > max_count) {
            la_xvxor_v(dest, dest, dest);
        } else {
            tr_inst_i(dest, src, imm);
        }
    } else {
        IR2_OPND src2 = load_freg256_from_ir1(opnd2);
        IR2_OPND mask = ra_alloc_ftemp();
        IR2_OPND temp = ra_alloc_ftemp();
        if (max_count == 63) {
            la_xvreplve0_d(mask, src2);
            la_xvldi(temp, VLDI_IMM_TYPE0(3, 63));
            la_xvsle_du(mask, mask, temp);
        } else {
            la_xvreplve0_d(mask, src2);
            la_xvslei_du(mask, mask, max_count);
        }
        rep_inst(temp, src2);
        tr_inst_r(dest, src, temp);
        la_xvand_v(dest, dest, mask);
    }
    if (ir1_opnd_is_xmm(opnd0)) {
        set_high128_xreg_to_zero(dest);
    }
    return true;
}

bool translate_vpsrldq(IR1_INST * pir1) {
    IR1_OPND * opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND * opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND * opnd2 = ir1_get_opnd(pir1, 2);
    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
        (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));
    lsassert(ir1_opnd_is_imm(opnd2));
    IR2_OPND dest = load_freg256_from_ir1(opnd0);
    IR2_OPND src = load_freg256_from_ir1(opnd1);
    uint8_t imm = ir1_opnd_uimm(opnd2);
    if (imm > 15) {
        la_xvxor_v(dest, dest, dest);
        return true;
    }
    la_xvbsrl_v(dest, src, imm);
    if (ir1_opnd_is_xmm(opnd0)) {
        set_high128_xreg_to_zero(dest);
    }
    return true;
}

bool translate_vpsrlx(IR1_INST * pir1) {
    IR1_OPND * opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND * opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND * opnd2 = ir1_get_opnd(pir1, 2);
    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
        (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));
    IR2_OPND dest = load_freg256_from_ir1(opnd0);
    IR2_OPND src = load_freg256_from_ir1(opnd1);
    IR2_INST * ( * rep_inst)(IR2_OPND, IR2_OPND);
    IR2_INST * ( * tr_inst_i)(IR2_OPND, IR2_OPND, int);
    IR2_INST * ( * tr_inst_r)(IR2_OPND, IR2_OPND, IR2_OPND);
    IR2_OPND label_exit = ra_alloc_label();
    IR2_OPND label_shift = ra_alloc_label();
    int max_count;
    switch (ir1_opcode(pir1)) {
        case dt_X86_INS_VPSRLW:
            rep_inst = la_xvreplve0_h;
            tr_inst_i = la_xvsrli_h;
            tr_inst_r = la_xvsrl_h;
            max_count = 15;
            break;
        case dt_X86_INS_VPSRLD:
            rep_inst = la_xvreplve0_w;
            tr_inst_i = la_xvsrli_w;
            tr_inst_r = la_xvsrl_w;
            max_count = 31;
            break;
        case dt_X86_INS_VPSRLQ:
            rep_inst = la_xvreplve0_d;
            tr_inst_i = la_xvsrli_d;
            tr_inst_r = la_xvsrl_d;
            max_count = 63;
            break;
        default:
            rep_inst = NULL;
            tr_inst_i = NULL;
            tr_inst_r = NULL;
            max_count = 0;
            lsassert(0);
            break;
    }
    if (ir1_opnd_is_imm(opnd2)) {
        uint8_t imm = ir1_opnd_uimm(opnd2);
        if (imm > max_count) {
            la_xvxor_v(dest, dest, dest);
        } else {
            tr_inst_i(dest, src, imm);
        }
    } else {
        IR2_OPND src2 = load_freg256_from_ir1(opnd2);
        IR2_OPND mask = ra_alloc_ftemp();
        IR2_OPND temp = ra_alloc_ftemp();

        IR2_OPND count = ra_alloc_itemp();
        IR2_OPND max = ra_alloc_itemp();
        la_addi_d(max, zero_ir2_opnd, max_count);
        la_vpickve2gr_d(count, src2, 0);
        la_blt(count, max, label_shift);
        la_xvxor_v(dest, dest, dest);
        la_b(label_exit);

        la_label(label_shift);
        if (max_count == 63) {
            la_xvreplve0_d(mask, src2);
            la_xvldi(temp, VLDI_IMM_TYPE0(3, 63));
            la_xvsle_du(mask, mask, temp);
        } else {
            la_xvreplve0_d(mask, src2);
            la_xvslei_du(mask, mask, max_count);
        }
        rep_inst(temp, src2);
        tr_inst_r(dest, src, temp);
        la_xvand_v(dest, dest, mask);
    }
    if (ir1_opnd_is_xmm(opnd0)) {
        set_high128_xreg_to_zero(dest);
    }
    la_label(label_exit);
    return true;
}

bool translate_vpsrax(IR1_INST * pir1) {
    IR1_OPND * opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND * opnd1 = ir1_get_opnd(pir1, 1);
    IR1_OPND * opnd2 = ir1_get_opnd(pir1, 2);
    lsassert((ir1_opnd_is_xmm(opnd0) && ir1_opnd_is_xmm(opnd1)) ||
        (ir1_opnd_is_ymm(opnd0) && ir1_opnd_is_ymm(opnd1)));
    IR2_OPND dest = load_freg256_from_ir1(opnd0);
    IR2_OPND src = load_freg256_from_ir1(opnd1);
    IR2_INST * ( * rep_inst)(IR2_OPND, IR2_OPND);
    IR2_INST * ( * tr_inst_i)(IR2_OPND, IR2_OPND, int);
    IR2_INST * ( * tr_inst_r)(IR2_OPND, IR2_OPND, IR2_OPND);
    int max_count;
    switch (ir1_opcode(pir1)) {
        case dt_X86_INS_VPSRAW:
            rep_inst = la_xvreplve0_h;
            tr_inst_i = la_xvsrai_h;
            tr_inst_r = la_xvsra_h;
            max_count = 15;
            break;
        case dt_X86_INS_VPSRAD:
            rep_inst = la_xvreplve0_w;
            tr_inst_i = la_xvsrai_w;
            tr_inst_r = la_xvsra_w;
            max_count = 31;
            break;
        default:
            rep_inst = NULL;
            tr_inst_i = NULL;
            tr_inst_r = NULL;
            max_count = 0;
            lsassert(0);
            break;
    }
    if (ir1_opnd_is_imm(opnd2)) {
        uint8_t imm = ir1_opnd_uimm(opnd2);
        if (imm > max_count)
            imm = max_count;
        tr_inst_i(dest, src, imm);
    } else {
        IR2_OPND src2 = load_freg256_from_ir1(opnd2);
        IR2_OPND mask = ra_alloc_ftemp();
        IR2_OPND temp = ra_alloc_ftemp();
        IR2_OPND temp_sign = ra_alloc_ftemp();
        if (max_count == 63) {
            la_xvreplve0_d(mask, src2);
            la_vldi(temp, VLDI_IMM_TYPE0(3, 63));
            la_xvsle_du(mask, mask, temp);
        } else {
            la_xvreplve0_d(mask, src2);
            la_xvslei_du(mask, mask, max_count);
        }
        tr_inst_i(temp_sign, src, max_count);
        rep_inst(temp, src2);
        tr_inst_r(temp, src, temp);
        la_xvbitsel_v(dest, temp_sign, temp, mask);
    }
    if (ir1_opnd_is_xmm(opnd0)) {
        set_high128_xreg_to_zero(dest);
    }
    return true;
}
#endif
