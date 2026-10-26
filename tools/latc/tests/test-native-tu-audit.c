#include "native-tu-audit.h"
#include "native-image.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t fixture(uint8_t *data)
{
    memset(data, 0, 4096);
    LatNativeImageHeaderV2 *h = (void *)data;
    memcpy(h->magic, LAT_NATIVE_IMAGE_MAGIC, 8);
    h->version = LAT_NATIVE_IMAGE_VERSION;
    h->header_size = sizeof(*h);
    h->flags = LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP;
    strcpy(h->lat_build_id, "audit-fixture");
    h->guest_image_offset = sizeof(*h);
    h->guest_image_size = 8;
    h->code_offset = sizeof(*h) + 8;
    h->code_size = 160;
    h->tb_table_offset = h->code_offset + 160;
    h->tb_count = 2;
    h->relocation_offset = h->tb_table_offset + 2 * sizeof(LatNativeTbV1);
    h->relocation_count = 1;
    h->pc_map_offset = h->relocation_offset + sizeof(LatNativeRelocationV1);
    h->tu_table_offset = h->pc_map_offset;
    h->tu_count = 2;
    LatNativeTbV1 *tbs = (void *)(data + h->tb_table_offset);
    LatNativeTuV1 *tus = (void *)(data + h->tu_table_offset);
    for (unsigned i = 0; i < 2; i++) {
        tbs[i] = (LatNativeTbV1){.guest_pc = i + 1, .code_offset = i * 96,
            .code_size = 16, .flags = 3, .tu_index = i};
        tus[i] = (LatNativeTuV1){.code_offset = i * 96, .code_size = 64,
            .search_offset = i * 96 + 48};
    }
    uint32_t *code = (void *)(data + h->code_offset);
    for (unsigned i = 0; i < 40; i++) code[i] = 0x03400000u;
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    *rel = (LatNativeRelocationV1){.code_offset = 0, .slots = 2,
        .kind = LAT_NATIVE_RELOC_RUNTIME_SYMBOL,
        .target = LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0};
    code[0] = 0x50000000u;
    return h->tu_table_offset + 2 * sizeof(*tus);
}

static void test_execution(void)
{
    uint8_t data[4096];
    size_t size = fixture(data);
    LatNativeImageHeaderV2 *h = (void *)data;
    uint32_t *code = (void *)(data + h->code_offset);
    LatNativeTbV1 *tbs = (void *)(data + h->tb_table_offset);
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    LatNativeTuExecutionAudit audit;
    char error[256] = {0};
    code[24] = 0x50000000u; /* independent second entry loops locally */
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(audit.entries == 2 && audit.reachable_words == 3);
    /* A recorded conditional exit retains its untaken path. */
    rel->slots = 1;
    code[0] = 0x58000000u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "crosses executable boundary"));
    code[11] = 0x50000000u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    /* Unconditional branches cannot make unreachable padding executable. */
    code[1] = 0x50000000u;
    code[11] = 0x03400000u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    /* A second TB entry is checked even when the first cannot reach it. */
    tbs[1].code_offset = 100;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "crosses executable boundary"));
    tbs[1].code_offset = 96;
    rel->slots = 2;
    code[0] = 0x50000000u;
    code[1] = 0x03400000u;
    tbs[0].code_offset = 4;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "window interior"));
    tbs[0].code_offset = 0;
    /* A branch into an existing patch interior is rejected. */
    code[24] = 0x50000000u | ((uint32_t)-23 & 0xffff) << 10 | 0x3ff;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "nonlocal TU branch")); /* cross-TU already fails reference audit */
    code[24] = 0x50000000u;
    code[0] = 0x54000000u; /* BL to a returning helper requires its continuation */
    rel->slots = 1;
    rel->target = LAT_NATIVE_SYMBOL_CPUID;
    code[1] = 0x03400000u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "crosses executable boundary"));
    code[0] = 0x58000000u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unlinked returning TU helper"));
    rel->slots = 3;
    code[0] = 0x1400000cu;
    code[1] = 0x0380018cu;
    code[2] = 0x1600000cu;
    code[3] = 0x00150004u; /* OR a0, zero, zero */
    code[4] = 0x4c000181u; /* JIRL ra, t0, 0 */
    code[5] = 0x50000000u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(audit.helper_calls == 1);
    rel->addend = 4;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "runtime entry addend"));
    rel->addend = 0;
    code[4] = 0x4c000180u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unlinked returning TU helper"));
    code[4] = 0x4c000181u;
    /* Clobbering the target before JIRL invalidates that helper proof. */
    code[3] = 0x0015000cu;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unresolved TU indirect transfer"));
    code[3] = 0x00150004u;
    tbs[0].code_offset = 16;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "window interior"));
    tbs[0].code_offset = 0;
    code[5] = 0x50000000u | ((uint32_t)-1 & 0xffff) << 10 | 0x3ff;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "window interior"));
    code[5] = 0x50000000u;
    rel->target = LAT_NATIVE_SYMBOL_RAISE_GPF;
    code[5] = 0x03400000u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    code[4] = 0x4c000180u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(lat_native_tu_audit_execution(data, sizeof(*h) - 1, &audit, error, sizeof(error)));
    assert(lat_native_tu_audit_execution(data, size, NULL, error, sizeof(error)));
    /* A local far call visits its target and checks its return continuation. */
    size = fixture(data);
    rel->slots = 1;
    code[0] = 0x58000000u;
    code[1] = 0x1e00000cu;
    code[2] = 0x4c001181u; /* JIRL ra, t0, 4 => target20 */
    code[3] = code[5] = code[24] = 0x50000000u;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    code[3] = 0x03400000u;
    code[4] = 0x50000000u | ((uint32_t)-2 & 0xffff) << 10 | 0x3ff;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "window interior"));

    size = fixture(data);
    code[24] = 0x50000000u;
    code[0] = 0x1e00000cu;
    code[1] = 0x4c000184u;
    rel->target = LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0;
    assert(!lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    code[1] = 0x4c000183u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unknown TU transfer return convention"));
    rel->target = LAT_NATIVE_SYMBOL_CPUID;
    code[1] = 0x4c000180u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unlinked returning TU helper"));

    static const uint32_t dispatch[] = {
        0x004542ab, 0x0015aeab, 0x00cf016b, 0x002dd96b,
        0x28c0016c, 0x5c000d95, 0x28c0216b, 0x4c000160,
        0x28c543ed, 0x580049a0, 0x004542ae, 0x0015baae,
        0x00cf01ce, 0x004119ce, 0x0010b5ce, 0x28c001cc,
        0x5c002d95, 0x28c061cc, 0x58002580, 0x28c0018b,
        0x28c081cc, 0x5c00198b, 0x28c041cc, 0x28c563eb,
        0x5c000d8b, 0x28c021cb, 0x4c000160,
    };
    size = fixture(data);
    h->tb_count = h->tu_count = 1;
    size = h->tu_table_offset + sizeof(LatNativeTuV1);
    LatNativeTuV1 *tu = (void *)(data + h->tu_table_offset);
    tu[0].code_size = 160;
    tu[0].search_offset = 144;
    tbs[0].code_size = 144;
    tbs[0].indirect_exit_offset = 1;
    rel->code_offset = 108;
    rel->slots = 1;
    memcpy(code, dispatch, sizeof(dispatch));
    for (unsigned j = 27; j < 40; j++) code[j] = 0x03400000u;
    code[27] = 0x50000000u;
    int result = lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error));
    if (result) fprintf(stderr, "dispatch fixture: %s\n", error);
    assert(!result);
    assert(audit.dispatch_windows == 1);
    code[27] = 0x58000000u;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "crosses executable boundary"));
    code[28] = 0x50000000u | ((uint32_t)-26 & 0xffff) << 10 | 0x3ff;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "window interior"));
    code[27] = 0x50000000u;
    /* A near-match cannot suppress the unknown indirect control transfer. */
    code[0] ^= 1;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    memcpy(code, dispatch, sizeof(dispatch));
    tbs[0].indirect_exit_offset = 0;
    assert(lat_native_tu_audit_execution(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "unresolved TU indirect transfer"));
}

int main(void)
{
    uint8_t data[4096];
    size_t size = fixture(data);
    LatNativeImageHeaderV2 *h = (void *)data;
    uint32_t *code = (void *)(data + h->code_offset);
    LatNativeRelocationV1 *rel = (void *)(data + h->relocation_offset);
    LatNativeTuReferenceAudit audit;
    char error[256] = {0};
    assert(!lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    assert(audit.patch_windows == 1 && audit.instructions == 22);
    /* A moved unlink stub is beyond its ordinary TB, but inside its TU. */
    code[8] = 0x18000000u | ((uint32_t)-8 & 0xfffff) << 5 | 4;
    assert(!lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    assert(audit.local_addresses == 1);
    code[9] = 0x50000000u | ((uint32_t)-1 & 0xffff) << 10 | 0x3ff;
    assert(!lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    assert(audit.local_branches == 1);
    for (unsigned i = 0; i < 11; i++) {
        size = fixture(data);
        switch (i) {
        case 0: code[8] = 0x50004000u; break; /* target96 in other TU */
        case 1: code[8] = 0x50001000u; break; /* target48 in search suffix */
        case 2: code[8] = 0x1a000004u; break; /* page-rounded address */
        case 3: code[8] = 0x1c000004u; break; /* unaudited PCADDU12 consumer */
        case 4: code[8] = 0x1e00000cu; code[9] = 0x4c0001a0u; break; /* wrong base */
        case 5: code[1] = 0x00100000u; break; /* fake tail-window padding */
        case 6: rel->code_offset = 44; break; /* crosses executable prefix */
        case 7: rel->code_offset = 48; break; /* patch in search data */
        case 8: code[8] = 0x18000204u; break; /* PCADDI target96 */
        case 9: code[8] = 0x48004200u; break; /* LBT JISCR0 */
        case 10: code[8] = 0x48004300u; break; /* LBT JISCR1 */
        }
        assert(!lat_native_image_validate(data, size, error, sizeof(error)));
        assert(lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    }
    size = fixture(data);
    /* Decode the complete PCADDU/JIRL expression, including its negative low. */
    code[8] = 0x1e00000cu;
    code[9] = 0x4c000180u | ((uint32_t)-8 & 0xffff) << 10;
    assert(!lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    assert(audit.local_addresses == 1);
    /* Explicit page-rounded JRRA window is allowed only with full template. */
    rel->kind = LAT_NATIVE_RELOC_JRRA_TARGET;
    rel->slots = 4;
    code[0] = 0x1a00000cu;
    code[1] = 0x0380018cu;
    code[2] = 0x981u;
    code[3] = 0x9a0u;
    assert(!lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    code[2] ^= 1;
    assert(lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    size = fixture(data);
    /* Independently valid overlapping patch records cannot both own words. */
    memmove(data + h->tu_table_offset + sizeof(*rel), data + h->tu_table_offset,
            2 * sizeof(LatNativeTuV1));
    h->tu_table_offset += sizeof(*rel);
    h->pc_map_offset += sizeof(*rel);
    h->relocation_count = 2;
    size += sizeof(*rel);
    rel[1] = rel[0];
    rel[1].code_offset = 0;
    assert(!lat_native_image_validate(data, size, error, sizeof(error)));
    assert(lat_native_tu_audit_references(data, size, &audit, error, sizeof(error)));
    assert(strstr(error, "overlapping or unowned TU patch"));
    /* Boundary and truncated headers must fail without reading instruction data. */
    assert(lat_native_tu_audit_references(data, sizeof(*h) - 1, &audit, error, sizeof(error)));
    assert(lat_native_tu_audit_references(data, size, NULL, error, sizeof(error)));
    test_execution();
    puts("test-native-tu-audit: PASS local/stub/branch/far/JRRA/templates/execution/negative");
    return 0;
}
