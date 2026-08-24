#ifndef LAT_AOT_V2_REGISTRY_H
#define LAT_AOT_V2_REGISTRY_H

#include "lat-aot-v2.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct LatAotLoadedModuleV2 {
    void *dl_handle;
    const LatAotModuleV2 *descriptor;
    LatAotNoteV2 note;
} LatAotLoadedModuleV2;

typedef struct LatAotModuleInstanceV2 {
    const LatAotLoadedModuleV2 *module;
    uint64_t guest_load_bias;
    uint64_t guest_begin;
    uint64_t guest_end;
    _Atomic uint64_t generation;
    _Atomic int active;
} LatAotModuleInstanceV2;

typedef struct LatAotRegistrySnapshotV2 LatAotRegistrySnapshotV2;

typedef struct LatAotRegistryV2 {
    pthread_mutex_t write_lock;
    _Atomic(LatAotRegistrySnapshotV2 *) current;
    LatAotRegistrySnapshotV2 *retired;
} LatAotRegistryV2;

typedef struct LatAotTargetV2 {
    const void *host_address;
    LatAotModuleInstanceV2 *instance;
    uint64_t generation;
} LatAotTargetV2;

int lat_aot_v2_registry_init(LatAotRegistryV2 *registry);
void lat_aot_v2_registry_destroy(LatAotRegistryV2 *registry);
int lat_aot_v2_registry_register(LatAotRegistryV2 *registry,
                                 LatAotModuleInstanceV2 *instance);
int lat_aot_v2_registry_deactivate(LatAotRegistryV2 *registry,
                                   LatAotModuleInstanceV2 *instance);
int lat_aot_v2_registry_lookup(const LatAotRegistryV2 *registry,
                               uint64_t guest_pc, uint32_t flags,
                               LatAotTargetV2 *target);

#endif
