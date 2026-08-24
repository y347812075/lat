#include "registry.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    static const unsigned char text[32];
    static const LatAotTbV2 tbs[] = {
        { .guest_rva = 0x1000, .host_offset = 4, .host_size = 4,
          .flags = LAT_AOT_TB_CODE64 },
        { .guest_rva = 0x1000, .host_offset = 8, .host_size = 4,
          .flags = LAT_AOT_TB_CODE64 | LAT_AOT_TB_PARALLEL },
    };
    static const LatAotModuleV2 descriptor = {
        .text_begin = text,
        .text_end = text + sizeof(text),
        .tb_begin = tbs,
        .tb_end = tbs + 2,
    };
    static const LatAotLoadedModuleV2 module = {
        .descriptor = &descriptor,
    };
    LatAotModuleInstanceV2 first = {
        .module = &module,
        .guest_load_bias = 0x400000,
        .guest_begin = 0x400000,
        .guest_end = 0x500000,
    };
    LatAotModuleInstanceV2 second = {
        .module = &module,
        .guest_load_bias = 0x700000,
        .guest_begin = 0x700000,
        .guest_end = 0x800000,
    };
    LatAotModuleInstanceV2 overlap = {
        .module = &module,
        .guest_begin = 0x480000,
        .guest_end = 0x580000,
    };
    LatAotRegistryV2 registry;
    if (lat_aot_v2_registry_init(&registry) ||
        lat_aot_v2_registry_register(&registry, &first) ||
        lat_aot_v2_registry_register(&registry, &second)) {
        perror("registry setup");
        return 1;
    }
    LatAotTargetV2 target;
    if (lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64, &target) ||
        target.host_address != text + 4 || target.instance != &first ||
        lat_aot_v2_registry_lookup(&registry, 0x701000,
                                   LAT_AOT_TB_CODE64 |
                                   LAT_AOT_TB_PARALLEL, &target) ||
        target.host_address != text + 8 || target.instance != &second) {
        fprintf(stderr, "registry lookup failed\n");
        return 1;
    }
    errno = 0;
    if (lat_aot_v2_registry_register(&registry, &overlap) == 0 ||
        errno != EEXIST) {
        fprintf(stderr, "overlapping instance was accepted\n");
        return 1;
    }
    uint64_t generation = atomic_load(&first.generation);
    if (lat_aot_v2_registry_deactivate(&registry, &first) ||
        atomic_load(&first.generation) != generation + 1 ||
        lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64, &target) == 0) {
        fprintf(stderr, "registry deactivation failed\n");
        return 1;
    }
    lat_aot_v2_registry_destroy(&registry);
    puts("test-aot-v2-registry: PASS");
    return 0;
}
