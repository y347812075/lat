#include "registry.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct LookupThread {
    LatAotRegistryV2 *registry;
    _Atomic int *stop;
    _Atomic int *failed;
} LookupThread;

static void *lookup_unchanged_instance(void *opaque)
{
    LookupThread *thread = opaque;
    while (!atomic_load_explicit(thread->stop, memory_order_acquire)) {
        LatAotTargetV2 target;
        if (lat_aot_v2_registry_lookup(thread->registry, 0x701000,
                                       LAT_AOT_TB_CODE64, &target) ||
            target.host_address == NULL || target.instance == NULL) {
            atomic_store_explicit(thread->failed, 1, memory_order_release);
            break;
        }
        lat_aot_v2_registry_target_release(&target);
    }
    return NULL;
}

int main(void)
{
    static const unsigned char text[32];
    static const LatAotTbV2 tbs[] = {
        { .guest_rva = 0x1000, .host_offset = 4, .host_size = 4,
          .flags = LAT_AOT_TB_CODE64 },
        { .guest_rva = 0x1000, .host_offset = 8, .host_size = 4,
          .flags = LAT_AOT_TB_CODE64 | LAT_AOT_TB_PARALLEL },
    };
    static const LatAotGuestSlotV2 guest_slots[] = {
        { .guest_rva = 0x1234, .fp_offset = -8 },
        { .guest_rva = 0x5678, .fp_offset = -16 },
    };
    static const LatAotModuleV2 descriptor = {
        .text_begin = text,
        .text_end = text + sizeof(text),
        .tb_begin = tbs,
        .tb_end = tbs + 2,
        .guest_slot_begin = guest_slots,
        .guest_slot_end = guest_slots + 2,
    };
    static const LatAotLoadedModuleV2 module = {
        .descriptor = &descriptor,
    };
    LatAotModuleInstanceV2 first = {
        .module = &module,
        .guest_load_bias = 0x400000,
        .guest_begin = 0x400000,
        .guest_end = 0x500000,
        .exec_range_count = 1,
        .exec_ranges = { { .begin = 0x401000, .end = 0x410000 } },
    };
    LatAotModuleInstanceV2 second = {
        .module = &module,
        .guest_load_bias = 0x700000,
        .guest_begin = 0x700000,
        .guest_end = 0x800000,
        .exec_range_count = 1,
        .exec_ranges = { { .begin = 0x701000, .end = 0x710000 } },
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
        target.host_address != text + 4 || target.instance != &first) {
        fprintf(stderr, "registry lookup failed\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);
    if (lat_aot_v2_registry_lookup(&registry, 0x701000,
                                   LAT_AOT_TB_CODE64 |
                                   LAT_AOT_TB_PARALLEL, &target) ||
        target.host_address != text + 8 || target.instance != &second) {
        fprintf(stderr, "registry parallel lookup failed\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);
    uint64_t context_words[4] = {0};
    void *jump_cache = &context_words[2];
    if (lat_aot_v2_context_apply_guest_slots(&descriptor, 0x400000,
                                             jump_cache) ||
        context_words[1] != 0x401234 || context_words[0] != 0x405678) {
        fprintf(stderr, "guest context slots were not populated\n");
        return 1;
    }
    errno = 0;
    if (lat_aot_v2_registry_register(&registry, &overlap) == 0 ||
        errno != EEXIST) {
        fprintf(stderr, "overlapping instance was accepted\n");
        return 1;
    }
    uint64_t generation = atomic_load(&first.generation);
    size_t deactivated = 99;
    if (lat_aot_v2_registry_deactivate_range(&registry, 0x480000, 0x481000,
                                             &deactivated) || deactivated ||
        lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64, &target)) {
        fprintf(stderr, "registry no-op range deactivation failed\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);
    if (lat_aot_v2_registry_deactivate_range(&registry, 0x401800, 0x401900,
                                             &deactivated) ||
        deactivated != 1 ||
        atomic_load(&first.generation) != generation + 1 ||
        lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64, &target) == 0 ||
        lat_aot_v2_registry_lookup(&registry, 0x701000,
                                   LAT_AOT_TB_CODE64, &target)) {
        fprintf(stderr, "registry range deactivation failed\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);

    enum { LOOKUP_THREADS = 4, INVALIDATION_ROUNDS = 2000 };
    pthread_t lookup_threads[LOOKUP_THREADS];
    _Atomic int stop = 0;
    _Atomic int failed = 0;
    LookupThread thread = {
        .registry = &registry,
        .stop = &stop,
        .failed = &failed,
    };
    LatAotModuleInstanceV2 *transients = calloc(
        INVALIDATION_ROUNDS, sizeof(*transients));
    if (!transients) {
        perror("calloc transient instances");
        return 1;
    }
    for (size_t i = 0; i < LOOKUP_THREADS; i++) {
        if (pthread_create(&lookup_threads[i], NULL,
                           lookup_unchanged_instance, &thread)) {
            perror("pthread_create");
            return 1;
        }
    }
    for (uint64_t i = 0; i < INVALIDATION_ROUNDS; i++) {
        uint64_t base = 0x900000 + i * 0x200000;
        LatAotModuleInstanceV2 *transient = &transients[i];
        *transient = (LatAotModuleInstanceV2) {
            .module = &module,
            .guest_load_bias = base,
            .guest_begin = base,
            .guest_end = base + 0x100000,
            .exec_range_count = 1,
            .exec_ranges = { { .begin = base + 0x1000,
                               .end = base + 0x10000 } },
        };
        int register_result = lat_aot_v2_registry_register(&registry,
                                                            transient);
        int register_errno = errno;
        int deactivate_result = register_result ? -1 :
            lat_aot_v2_registry_deactivate_range(
                &registry, base + 0x1800, base + 0x1900, &deactivated);
        if (register_result || deactivate_result || deactivated != 1 ||
            atomic_load(&transient->active) ||
            atomic_load(&transient->generation) != 2 ||
            atomic_load_explicit(&failed, memory_order_acquire)) {
            fprintf(stderr,
                    "concurrent registry invalidation failed round=%llu "
                    "register=%d errno=%d deactivate=%d removed=%zu "
                    "active=%d generation=%llu lookup_failed=%d\n",
                    (unsigned long long)i, register_result, register_errno,
                    deactivate_result, deactivated,
                    atomic_load(&transient->active),
                    (unsigned long long)atomic_load(&transient->generation),
                    atomic_load_explicit(&failed, memory_order_acquire));
            atomic_store_explicit(&failed, 1, memory_order_release);
            break;
        }
    }
    atomic_store_explicit(&stop, 1, memory_order_release);
    for (size_t i = 0; i < LOOKUP_THREADS; i++) {
        pthread_join(lookup_threads[i], NULL);
    }
    if (atomic_load_explicit(&failed, memory_order_acquire)) {
        free(transients);
        return 1;
    }
    lat_aot_v2_registry_drain(&registry);
    LatAotRegistryCountsV2 counts;
    lat_aot_v2_registry_counts(&registry, &counts);
    if (counts.current_snapshots != 1 || counts.retired_snapshots ||
        counts.readers || atomic_load_explicit(&second.readers,
                                                memory_order_acquire)) {
        fprintf(stderr,
                "registry reclamation failed current=%zu retired=%zu "
                "readers=%zu instance_readers=%u\n",
                counts.current_snapshots, counts.retired_snapshots,
                counts.readers, atomic_load_explicit(&second.readers,
                                                     memory_order_acquire));
        free(transients);
        return 1;
    }
    lat_aot_v2_registry_destroy(&registry);
    free(transients);
    puts("test-aot-v2-registry: PASS");
    return 0;
}
