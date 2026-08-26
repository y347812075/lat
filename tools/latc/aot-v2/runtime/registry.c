#include "registry.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct LatAotRegistrySnapshotV2 {
    size_t count;
    LatAotModuleInstanceV2 **instances;
    LatAotRegistrySnapshotV2 *retired_next;
};

static int compare_instance(const void *left, const void *right)
{
    const LatAotModuleInstanceV2 *a =
        *(LatAotModuleInstanceV2 *const *)left;
    const LatAotModuleInstanceV2 *b =
        *(LatAotModuleInstanceV2 *const *)right;
    if (a->guest_begin != b->guest_begin) {
        return a->guest_begin < b->guest_begin ? -1 : 1;
    }
    return a->guest_end < b->guest_end ? -1 : a->guest_end > b->guest_end;
}

static LatAotRegistrySnapshotV2 *snapshot_new(size_t count)
{
    LatAotRegistrySnapshotV2 *snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) {
        return NULL;
    }
    if (count) {
        snapshot->instances = calloc(count, sizeof(*snapshot->instances));
        if (!snapshot->instances) {
            free(snapshot);
            return NULL;
        }
    }
    snapshot->count = count;
    return snapshot;
}

static void snapshot_free(LatAotRegistrySnapshotV2 *snapshot)
{
    if (!snapshot) {
        return;
    }
    free(snapshot->instances);
    free(snapshot);
}

int lat_aot_v2_registry_init(LatAotRegistryV2 *registry)
{
    if (!registry) {
        errno = EINVAL;
        return -1;
    }
    memset(registry, 0, sizeof(*registry));
    if (pthread_mutex_init(&registry->write_lock, NULL)) {
        errno = EBUSY;
        return -1;
    }
    LatAotRegistrySnapshotV2 *empty = snapshot_new(0);
    if (!empty) {
        pthread_mutex_destroy(&registry->write_lock);
        return -1;
    }
    atomic_store_explicit(&registry->current, empty, memory_order_release);
    return 0;
}

void lat_aot_v2_registry_destroy(LatAotRegistryV2 *registry)
{
    if (!registry) {
        return;
    }
    snapshot_free(atomic_load_explicit(&registry->current,
                                      memory_order_acquire));
    LatAotRegistrySnapshotV2 *snapshot = registry->retired;
    while (snapshot) {
        LatAotRegistrySnapshotV2 *next = snapshot->retired_next;
        snapshot_free(snapshot);
        snapshot = next;
    }
    pthread_mutex_destroy(&registry->write_lock);
    memset(registry, 0, sizeof(*registry));
}

static int publish_snapshot(LatAotRegistryV2 *registry,
                            LatAotRegistrySnapshotV2 *replacement)
{
    LatAotRegistrySnapshotV2 *old = atomic_exchange_explicit(
        &registry->current, replacement, memory_order_acq_rel);
    old->retired_next = registry->retired;
    registry->retired = old;
    return 0;
}

int lat_aot_v2_registry_register(LatAotRegistryV2 *registry,
                                 LatAotModuleInstanceV2 *instance)
{
    if (!registry || !instance || !instance->module ||
        !instance->module->descriptor ||
        instance->guest_begin >= instance->guest_end) {
        errno = EINVAL;
        return -1;
    }
    if (instance->exec_range_count > LAT_AOT_V2_MAX_EXEC_RANGES) {
        errno = EINVAL;
        return -1;
    }
    for (uint32_t i = 0; i < instance->exec_range_count; i++) {
        const LatAotGuestRangeV2 *range = &instance->exec_ranges[i];
        if (range->begin < instance->guest_begin ||
            range->end > instance->guest_end || range->begin >= range->end ||
            (i && instance->exec_ranges[i - 1].end > range->begin)) {
            errno = EINVAL;
            return -1;
        }
    }
    pthread_mutex_lock(&registry->write_lock);
    LatAotRegistrySnapshotV2 *old = atomic_load_explicit(
        &registry->current, memory_order_acquire);
    LatAotRegistrySnapshotV2 *replacement = snapshot_new(old->count + 1);
    if (!replacement) {
        pthread_mutex_unlock(&registry->write_lock);
        return -1;
    }
    memcpy(replacement->instances, old->instances,
           old->count * sizeof(*old->instances));
    replacement->instances[old->count] = instance;
    qsort(replacement->instances, replacement->count,
          sizeof(*replacement->instances), compare_instance);
    for (size_t i = 1; i < replacement->count; i++) {
        if (replacement->instances[i - 1]->guest_end >
            replacement->instances[i]->guest_begin) {
            snapshot_free(replacement);
            pthread_mutex_unlock(&registry->write_lock);
            errno = EEXIST;
            return -1;
        }
    }
    atomic_store_explicit(&instance->active, 1, memory_order_release);
    if (!atomic_load_explicit(&instance->generation, memory_order_relaxed)) {
        atomic_store_explicit(&instance->generation, 1, memory_order_relaxed);
    }
    publish_snapshot(registry, replacement);
    pthread_mutex_unlock(&registry->write_lock);
    return 0;
}

int lat_aot_v2_registry_deactivate(LatAotRegistryV2 *registry,
                                   LatAotModuleInstanceV2 *instance)
{
    if (!registry || !instance) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&registry->write_lock);
    atomic_store_explicit(&instance->active, 0, memory_order_release);
    atomic_fetch_add_explicit(&instance->generation, 1, memory_order_acq_rel);
    LatAotRegistrySnapshotV2 *old = atomic_load_explicit(
        &registry->current, memory_order_acquire);
    size_t retained = 0;
    for (size_t i = 0; i < old->count; i++) {
        retained += old->instances[i] != instance;
    }
    if (retained == old->count) {
        pthread_mutex_unlock(&registry->write_lock);
        errno = ENOENT;
        return -1;
    }
    LatAotRegistrySnapshotV2 *replacement = snapshot_new(retained);
    if (!replacement) {
        pthread_mutex_unlock(&registry->write_lock);
        return -1;
    }
    for (size_t i = 0, output = 0; i < old->count; i++) {
        if (old->instances[i] != instance) {
            replacement->instances[output++] = old->instances[i];
        }
    }
    publish_snapshot(registry, replacement);
    pthread_mutex_unlock(&registry->write_lock);
    return 0;
}

static int instance_exec_range_overlaps(const LatAotModuleInstanceV2 *instance,
                                        uint64_t guest_begin,
                                        uint64_t guest_end)
{
    if (!instance->exec_range_count) {
        return guest_begin < instance->guest_end &&
               guest_end > instance->guest_begin;
    }
    for (uint32_t i = 0; i < instance->exec_range_count; i++) {
        if (guest_begin < instance->exec_ranges[i].end &&
            guest_end > instance->exec_ranges[i].begin) {
            return 1;
        }
    }
    return 0;
}

int lat_aot_v2_registry_deactivate_range(LatAotRegistryV2 *registry,
                                         uint64_t guest_begin,
                                         uint64_t guest_end,
                                         size_t *deactivated)
{
    if (!registry || guest_begin >= guest_end) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&registry->write_lock);
    LatAotRegistrySnapshotV2 *old = atomic_load_explicit(
        &registry->current, memory_order_acquire);
    size_t removed = 0;
    for (size_t i = 0; i < old->count; i++) {
        removed += instance_exec_range_overlaps(old->instances[i],
                                                guest_begin, guest_end);
    }
    if (!removed) {
        if (deactivated) {
            *deactivated = 0;
        }
        pthread_mutex_unlock(&registry->write_lock);
        return 0;
    }
    LatAotRegistrySnapshotV2 *replacement = snapshot_new(old->count - removed);
    if (!replacement) {
        pthread_mutex_unlock(&registry->write_lock);
        return -1;
    }
    for (size_t i = 0, output = 0; i < old->count; i++) {
        LatAotModuleInstanceV2 *instance = old->instances[i];
        if (instance_exec_range_overlaps(instance, guest_begin, guest_end)) {
            atomic_store_explicit(&instance->active, 0, memory_order_release);
            atomic_fetch_add_explicit(&instance->generation, 1,
                                      memory_order_acq_rel);
        } else {
            replacement->instances[output++] = instance;
        }
    }
    publish_snapshot(registry, replacement);
    if (deactivated) {
        *deactivated = removed;
    }
    pthread_mutex_unlock(&registry->write_lock);
    return 0;
}

static const LatAotTbV2 *find_tb(const LatAotModuleV2 *module,
                                 uint64_t guest_rva, uint32_t flags)
{
    size_t count = (size_t)(module->tb_end - module->tb_begin);
    size_t left = 0;
    size_t right = count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        const LatAotTbV2 *tb = &module->tb_begin[middle];
        if (tb->guest_rva < guest_rva ||
            (tb->guest_rva == guest_rva && tb->flags < flags)) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < count && module->tb_begin[left].guest_rva == guest_rva &&
        module->tb_begin[left].flags == flags) {
        return &module->tb_begin[left];
    }
    return NULL;
}

int lat_aot_v2_registry_lookup(const LatAotRegistryV2 *registry,
                               uint64_t guest_pc, uint32_t flags,
                               LatAotTargetV2 *target)
{
    if (!registry || !target) {
        errno = EINVAL;
        return -1;
    }
    LatAotRegistrySnapshotV2 *snapshot = atomic_load_explicit(
        &registry->current, memory_order_acquire);
    size_t left = 0;
    size_t right = snapshot->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (snapshot->instances[middle]->guest_begin <= guest_pc) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (!left) {
        errno = ENOENT;
        return -1;
    }
    LatAotModuleInstanceV2 *instance = snapshot->instances[left - 1];
    if (guest_pc >= instance->guest_end ||
        !atomic_load_explicit(&instance->active, memory_order_acquire)) {
        errno = ENOENT;
        return -1;
    }
    const LatAotModuleV2 *module = instance->module->descriptor;
    const LatAotTbV2 *tb = find_tb(module,
        guest_pc - instance->guest_load_bias, flags);
    if (!tb) {
        errno = ENOENT;
        return -1;
    }
    target->host_address = module->text_begin + tb->host_offset;
    target->instance = instance;
    target->generation = atomic_load_explicit(&instance->generation,
                                               memory_order_acquire);
    return 0;
}

int lat_aot_v2_context_apply_guest_slots(const LatAotModuleV2 *module,
                                         uint64_t guest_load_bias,
                                         void *jump_cache)
{
    if (!module || !jump_cache) {
        errno = EINVAL;
        return -1;
    }
    uintptr_t begin = (uintptr_t)module->guest_slot_begin;
    uintptr_t end = (uintptr_t)module->guest_slot_end;
    if ((!begin != !end) || end < begin ||
        (end - begin) % sizeof(LatAotGuestSlotV2)) {
        errno = EINVAL;
        return -1;
    }
    size_t count = (end - begin) / sizeof(LatAotGuestSlotV2);
    if (count > LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT) {
        errno = E2BIG;
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        const LatAotGuestSlotV2 *slot = &module->guest_slot_begin[i];
        if (slot->reserved || slot->fp_offset != -(int32_t)((i + 1) * 8) ||
            guest_load_bias > UINT64_MAX - slot->guest_rva) {
            errno = ENOEXEC;
            return -1;
        }
        *(uint64_t *)((unsigned char *)jump_cache + slot->fp_offset) =
            guest_load_bias + slot->guest_rva;
    }
    return 0;
}
