#include "native-tu-plan.h"
#include "native-image.h"
#include "native-tu-audit.h"
#include "lat-aot-v2.h"
#include "lat-translation-config.h"

#include <glib.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list args;
        va_start(args, format);
        vsnprintf(error, size, format, args);
        va_end(args);
    }
    return -1;
}

static uint32_t root(uint32_t *parents, uint32_t node)
{
    while (parents[node] != node) {
        parents[node] = parents[parents[node]];
        node = parents[node];
    }
    return node;
}

static int patch_owner(const LatNativeTuV1 *tus, uint64_t count,
                        const LatNativeRelocationV1 *patch)
{
    uint64_t left = 0, right = count;
    while (left < right) {
        uint64_t middle = left + (right - left) / 2;
        if (tus[middle].code_offset <= patch->code_offset) left = middle + 1;
        else right = middle;
    }
    if (!left) return -1;
    const LatNativeTuV1 *tu = &tus[left - 1];
    uint64_t offset = patch->code_offset - tu->code_offset;
    if (offset >= tu->code_size || patch->slots * 4 > tu->code_size - offset) {
        return -1;
    }
    return (int)(left - 1);
}

static int plan_tus(const void *data, size_t size, const LatTbKeySet *seeds,
    uint64_t changed, LatTbKeySet *result, char *error, size_t error_size)
{
    if (!result) return fail(error, error_size, "missing TU plan output");
    memset(result, 0, sizeof(*result));
    if (!seeds || (seeds->count && !seeds->keys) ||
        lat_native_image_validate(data, size, error, error_size)) return -1;
    const LatNativeImageHeaderV2 *h = data;
    if (!h->tu_count || h->tu_count > INT_MAX || h->tb_count > UINT32_MAX ||
        memcmp(h->guest_sha256, seeds->source_sha256, 32)) {
        return fail(error, error_size, "native TU plan source or TU metadata mismatch");
    }
    const uint8_t *bytes = data;
    const LatNativeTbV1 *tbs = (const void *)(bytes + h->tb_table_offset);
    const LatNativeTuV1 *tus = (const void *)(bytes + h->tu_table_offset);
    const LatNativeRelocationV1 *rel = (const void *)(bytes + h->relocation_offset);
    g_autofree uint32_t *parents = g_new(uint32_t, h->tu_count);
    g_autofree bool *selected = g_new0(bool, h->tu_count);
    g_autoptr(GPtrArray) incoming = g_ptr_array_new_with_free_func(
        (GDestroyNotify)g_array_unref);
    g_autoptr(GArray) queue = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    for (uint32_t i = 0; i < h->tu_count; i++) {
        parents[i] = i;
        g_ptr_array_add(incoming, g_array_new(FALSE, FALSE, sizeof(uint32_t)));
    }
    for (uint64_t i = 0; i < h->tb_count; i++) {
        if (tbs[i].flags != 3 || tbs[i].guest_pc < h->preferred_guest_base) {
            return fail(error, error_size, "native TU plan requires RVA-compatible parallel keys");
        }
        if (i && tbs[i].guest_pc == tbs[i - 1].guest_pc &&
            tbs[i].flags == tbs[i - 1].flags) {
            uint32_t a = root(parents, tbs[i - 1].tu_index);
            uint32_t b = root(parents, tbs[i].tu_index);
            parents[b] = a;
        }
    }
    for (uint64_t i = 0; i < h->relocation_count; i++) {
        int owner = patch_owner(tus, h->tu_count, &rel[i]);
        if (owner < 0) {
            return fail(error, error_size, "native TU plan relocation has no complete TU owner");
        }
        if (rel[i].physical_target_plus_one) {
            uint32_t target = root(parents,
                tbs[rel[i].physical_target_plus_one - 1].tu_index);
            uint32_t source = root(parents, owner);
            GArray *edges = g_ptr_array_index(incoming, target);
            g_array_append_val(edges, source);
        }
    }
    for (size_t i = 0; i < seeds->count; i++) {
        const LatTbKey *key = &seeds->keys[i];
        if (key->flags != 3 || key->reserved ||
            key->guest_rva > UINT64_MAX - h->preferred_guest_base) {
            return fail(error, error_size, "invalid TU plan seed key");
        }
        uint64_t pc = key->guest_rva + h->preferred_guest_base;
        uint64_t left = 0, right = h->tb_count;
        while (left < right) {
            uint64_t middle = left + (right - left) / 2;
            if (tbs[middle].guest_pc < pc) left = middle + 1;
            else right = middle;
        }
        if (left == h->tb_count || tbs[left].guest_pc != pc) {
            return fail(error, error_size, "TU plan seed is absent from native image");
        }
        uint32_t node = root(parents, tbs[left].tu_index);
        if (!selected[node]) {
            selected[node] = true;
            g_array_append_val(queue, node);
        }
    }
    for (uint32_t i = 0; changed && i < h->tu_count; i++) {
        if (!tus[i].config_dependency_version ||
            (tus[i].config_dependencies & changed)) {
            uint32_t node = root(parents, i);
            if (!selected[node]) {
                selected[node] = true;
                g_array_append_val(queue, node);
            }
        }
    }
    for (guint i = 0; i < queue->len; i++) {
        GArray *edges = g_ptr_array_index(incoming,
                                          g_array_index(queue, uint32_t, i));
        for (guint j = 0; j < edges->len; j++) {
            uint32_t node = g_array_index(edges, uint32_t, j);
            if (!selected[node]) {
                selected[node] = true;
                g_array_append_val(queue, node);
            }
        }
    }
    g_autoptr(GArray) keys = g_array_new(FALSE, FALSE, sizeof(LatTbKey));
    for (uint64_t i = 0; i < h->tb_count; i++) {
        if (selected[root(parents, tbs[i].tu_index)]) {
            LatTbKey key = {.guest_rva = tbs[i].guest_pc - h->preferred_guest_base,
                            .flags = tbs[i].flags};
            if (keys->len) {
                const LatTbKey *previous = &g_array_index(keys, LatTbKey,
                                                          keys->len - 1);
                if (previous->guest_rva == key.guest_rva &&
                    previous->flags == key.flags) continue;
            }
            if (keys->len == LAT_AOT_V2_TBSET_RECORD_LIMIT) {
                return fail(error, error_size, "TU plan exceeds TB set record limit");
            }
            g_array_append_val(keys, key);
        }
    }
    memcpy(result->source_sha256, seeds->source_sha256, 32);
    result->sequence = seeds->sequence;
    result->count = keys->len;
    result->keys = (LatTbKey *)g_array_free(g_steal_pointer(&keys), FALSE);
    if (lat_tb_key_set_sort_unique(result, error, error_size)) {
        lat_tb_key_set_destroy(result);
        return -1;
    }
    return 0;
}

int lat_native_tu_plan(const void *data, size_t size, const LatTbKeySet *seeds,
                       LatTbKeySet *result, char *error, size_t error_size)
{
    return plan_tus(data, size, seeds, 0, result, error, error_size);
}

int lat_native_tu_config_plan(const void *data, size_t size,
    const void *target, size_t target_size, LatTbKeySet *result,
    uint64_t *changed, char *error, size_t error_size)
{
    if (!result || !changed) {
        return fail(error, error_size, "missing configuration TU plan output");
    }
    memset(result, 0, sizeof(*result));
    *changed = LAT_CONFIG_ALL_BITS;
    if (lat_native_image_validate(data, size, error, error_size)) return -1;
    const LatNativeImageHeaderV2 *h = data;
    if (!(h->flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED)) {
        return fail(error, error_size, "native TU plan requires a configuration snapshot");
    }
    LatTranslationConfig old_config, target_config;
    if (lat_translation_config_decode((const uint8_t *)data + size -
            h->translation_config_size, h->translation_config_size, NULL,
            &old_config, error, error_size) ||
        lat_translation_config_decode(target, target_size, old_config.build_id,
            &target_config, error, error_size) ||
        lat_translation_config_diff(&old_config, &target_config, changed,
            error, error_size)) return -1;
    LatTbKeySet seeds = {0};
    memcpy(seeds.source_sha256, h->guest_sha256, 32);
    return plan_tus(data, size, &seeds, *changed, result, error, error_size);
}

static int native_key_set(const LatNativeImageHeaderV2 *header,
                          const LatNativeTbV1 *tbs, LatTbKeySet *set,
                          char *error, size_t error_size)
{
    if (header->tb_count > LAT_AOT_V2_TBSET_RECORD_LIMIT) {
        return fail(error, error_size, "native key set exceeds record limit");
    }
    memset(set, 0, sizeof(*set));
    memcpy(set->source_sha256, header->guest_sha256, 32);
    set->keys = header->tb_count ?
        malloc(header->tb_count * sizeof(LatTbKey)) : NULL;
    if (header->tb_count && !set->keys) {
        return fail(error, error_size, "out of memory building native key set");
    }
    for (uint64_t i = 0; i < header->tb_count; i++) {
        set->keys[set->count++] = (LatTbKey) {
            .guest_rva = tbs[i].guest_pc - header->preferred_guest_base,
            .flags = tbs[i].flags,
        };
    }
    if (lat_tb_key_set_sort_unique(set, error, error_size)) {
        lat_tb_key_set_destroy(set);
        return -1;
    }
    return 0;
}

static int normalized_key_set(const LatTbKeySet *input,
                              const uint8_t source_sha256[32],
                              LatTbKeySet *result,
                              char *error, size_t error_size)
{
    LatTbKeySet empty = {0};
    if (input && (input->count > LAT_AOT_V2_TBSET_RECORD_LIMIT ||
                  (input->count && !input->keys))) {
        return fail(error, error_size, "invalid migration plan key set");
    }
    for (size_t i = 0; input && i < input->count; i++) {
        if (input->keys[i].flags != 3 || input->keys[i].reserved) {
            return fail(error, error_size,
                        "migration plan requires RVA-compatible parallel keys");
        }
    }
    memcpy(empty.source_sha256, source_sha256, 32);
    return lat_tb_key_set_union(input ? input : &empty, &empty, result,
                                error, error_size);
}

void lat_native_tu_migration_plan_destroy(LatNativeTuMigrationPlan *plan)
{
    if (!plan) return;
    lat_tb_key_set_destroy(&plan->affected_keys);
    lat_tb_key_set_destroy(&plan->retained_keys);
    lat_tb_key_set_destroy(&plan->compile_required_keys);
    lat_tb_key_set_destroy(&plan->deferred_static_keys);
    memset(plan, 0, sizeof(*plan));
}

int lat_native_tu_migration_plan(const void *data, size_t size,
    const void *target, size_t target_size,
    const LatTbKeySet *runtime_required,
    const LatTbKeySet *static_candidates,
    LatNativeTuMigrationPlan *plan, char *error, size_t error_size)
{
    if (!plan || !data) {
        return fail(error, error_size, "missing migration plan input");
    }
    lat_native_tu_migration_plan_destroy(plan);

    int result = -1;
    uint64_t changed = 0;
    LatTbKeySet native = {0}, required = {0}, static_keys = {0};
    LatTbKeySet missing_required = {0}, retained_or_required = {0};
    if (lat_native_tu_config_plan(data, size, target, target_size,
            &plan->affected_keys, &changed, error, error_size)) {
        goto out;
    }
    const LatNativeImageHeaderV2 *header = data;
    const LatNativeTbV1 *tbs = (const void *)((const uint8_t *)data +
                                               header->tb_table_offset);
    LatTranslationConfig old_config, target_config;
    const uint8_t *old_bytes = (const uint8_t *)data + size -
                               header->translation_config_size;
    if (lat_translation_config_decode(old_bytes,
            header->translation_config_size, NULL, &old_config,
            error, error_size) ||
        lat_translation_config_decode(target, target_size,
            old_config.build_id, &target_config, error, error_size) ||
        lat_translation_config_digest(&old_config, plan->old_config_sha256,
            error, error_size) ||
        lat_translation_config_digest(&target_config,
            plan->target_config_sha256, error, error_size) ||
        native_key_set(header, tbs, &native, error, error_size) ||
        lat_tb_key_set_difference(&native, &plan->affected_keys,
            &plan->retained_keys, error, error_size) ||
        normalized_key_set(runtime_required, header->guest_sha256, &required,
            error, error_size) ||
        normalized_key_set(static_candidates, header->guest_sha256,
            &static_keys, error, error_size) ||
        lat_tb_key_set_difference(&required, &plan->retained_keys,
            &missing_required, error, error_size) ||
        lat_tb_key_set_union(&plan->affected_keys, &missing_required,
            &plan->compile_required_keys, error, error_size) ||
        lat_tb_key_set_union(&plan->retained_keys,
            &plan->compile_required_keys, &retained_or_required,
            error, error_size) ||
        lat_tb_key_set_difference(&static_keys, &retained_or_required,
            &plan->deferred_static_keys, error, error_size)) {
        goto out;
    }
    plan->changed_fields = changed;
    plan->configuration_contract_complete =
        old_config.compatibility_complete && target_config.compatibility_complete;
    plan->reuse_authorized = false;
    plan->movement_certified = false;
    if (!plan->affected_keys.count && !plan->compile_required_keys.count) {
        plan->kind = LAT_NATIVE_TU_MIGRATION_NOOP;
    } else if (plan->affected_keys.count == native.count) {
        plan->kind = LAT_NATIVE_TU_MIGRATION_FULL;
    } else {
        plan->kind = LAT_NATIVE_TU_MIGRATION_PARTIAL;
    }
    result = 0;
out:
    lat_tb_key_set_destroy(&native);
    lat_tb_key_set_destroy(&required);
    lat_tb_key_set_destroy(&static_keys);
    lat_tb_key_set_destroy(&missing_required);
    lat_tb_key_set_destroy(&retained_or_required);
    if (result) lat_native_tu_migration_plan_destroy(plan);
    return result;
}

typedef struct ExtractRange {
    uint64_t old_offset, size, new_offset;
} ExtractRange;

static int range_owner(const LatNativeTuV1 *tus, uint64_t count,
                        uint64_t begin, uint64_t length)
{
    uint64_t left = 0, right = count;
    while (left < right) {
        uint64_t mid = left + (right - left) / 2;
        if (tus[mid].code_offset <= begin) left = mid + 1;
        else right = mid;
    }
    if (!left || !length) return -1;
    const LatNativeTuV1 *tu = &tus[left - 1];
    uint64_t offset = begin - tu->code_offset;
    return offset < tu->code_size && length <= tu->code_size - offset ?
        (int)(left - 1) : -1;
}

static int append_range(GByteArray *code, const uint8_t *old,
    uint64_t offset, uint64_t length, uint32_t alignment, uint64_t *destination)
{
    uint64_t start = ((uint64_t)code->len + alignment - 1) &
                     ~((uint64_t)alignment - 1);
    if (start > G_MAXUINT || length > G_MAXUINT - start) return -1;
    guint previous = code->len;
    g_byte_array_set_size(code, start + length);
    memset(code->data + previous, 0, start - previous);
    memcpy(code->data + start, old + offset, length);
    *destination = start;
    return 0;
}

int lat_native_tu_extract(const void *data, size_t size,
    const LatTbKeySet *remove, void **output, size_t *output_size,
    char *error, size_t error_size)
{
    if (!output || !output_size) {
        return fail(error, error_size, "missing TU extraction output");
    }
    *output = NULL;
    *output_size = 0;
    LatTbKeySet closed = {0};
    if (lat_native_tu_plan(data, size, remove, &closed, error, error_size)) return -1;
    const LatNativeImageHeaderV2 *h = data;
    if (!(h->flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED)) {
        lat_tb_key_set_destroy(&closed);
        return fail(error, error_size, "TU extraction requires quarantined configuration replay");
    }
    LatNativeTuExecutionAudit execution;
    if (lat_native_tu_audit_execution(data, size, &execution, error, error_size)) {
        lat_tb_key_set_destroy(&closed);
        return -1;
    }
    const uint8_t *bytes = data, *old_code = bytes + h->code_offset;
    const LatNativeTuV1 *tus = (const void *)(bytes + h->tu_table_offset);
    const LatNativeTbV1 *tbs = (const void *)(bytes + h->tb_table_offset);
    const LatNativeRelocationV1 *rels = (const void *)(bytes + h->relocation_offset);
    const LatNativePcMapV2 *maps = (const void *)(bytes + h->pc_map_offset);
    g_autofree bool *discard = g_new0(bool, h->tu_count);
    g_autofree uint32_t *tu_indices = g_new(uint32_t, h->tu_count);
    g_autofree uint32_t *tb_indices = g_new0(uint32_t, h->tb_count);
    g_autofree uint64_t *offsets = g_new0(uint64_t, h->tu_count);
    g_autoptr(GByteArray) code = g_byte_array_new();
    g_autoptr(GArray) new_tus = g_array_new(FALSE, FALSE, sizeof(LatNativeTuV1));
    g_autoptr(GArray) new_tbs = g_array_new(FALSE, FALSE, sizeof(LatNativeTbV1));
    g_autoptr(GArray) new_rels = g_array_new(FALSE, FALSE, sizeof(LatNativeRelocationV1));
    g_autoptr(GArray) new_maps = g_array_new(FALSE, FALSE, sizeof(LatNativePcMapV2));
    g_autoptr(GArray) objects = g_array_new(FALSE, FALSE, sizeof(ExtractRange));
    g_autofree uint8_t *buffer = NULL;
    size_t key = 0;
    for (uint64_t i = 0; i < h->tb_count; i++) {
        uint64_t rva = tbs[i].guest_pc - h->preferred_guest_base;
        while (key < closed.count && closed.keys[key].guest_rva < rva) key++;
        if (key < closed.count && closed.keys[key].guest_rva == rva) {
            discard[tbs[i].tu_index] = true;
        }
    }
    lat_tb_key_set_destroy(&closed);
    for (uint64_t i = 0; i < h->tu_count; i++) {
        tu_indices[i] = UINT32_MAX;
        if (discard[i]) continue;
        LatNativeTuV1 tu = tus[i];
        if (append_range(code, old_code, tu.code_offset, tu.code_size, 32,
                         &offsets[i])) goto too_large;
        tu_indices[i] = new_tus->len;
        tu.search_offset = offsets[i] + tu.search_offset - tu.code_offset;
        tu.code_offset = offsets[i];
        g_array_append_val(new_tus, tu);
    }
    for (uint64_t i = 0; i < h->tb_count; i++) {
        if (discard[tbs[i].tu_index]) continue;
        LatNativeTbV1 tb = tbs[i];
        tb.code_offset = offsets[tb.tu_index] + tb.code_offset -
                         tus[tb.tu_index].code_offset;
        tb.tu_index = tu_indices[tb.tu_index];
        g_array_append_val(new_tbs, tb);
        tb_indices[i] = new_tbs->len;
    }
    if (!new_tbs->len) {
        return fail(error, error_size, "empty TU complement has no native image representation");
    }
    for (uint64_t i = 0; i < h->relocation_count; i++) {
        LatNativeRelocationV1 rel = rels[i];
        int owner = range_owner(tus, h->tu_count, rel.code_offset, rel.slots * 4);
        if (owner < 0) return fail(error, error_size, "extracted patch has no complete TU owner");
        if (discard[owner]) continue;
        rel.code_offset = offsets[owner] + rel.code_offset - tus[owner].code_offset;
        if (rel.physical_target_plus_one) {
            rel.physical_target_plus_one = tb_indices[rel.physical_target_plus_one - 1];
            if (!rel.physical_target_plus_one) {
                return fail(error, error_size, "extracted patch targets removed physical TB");
            }
        }
        if (rel.kind == LAT_NATIVE_RELOC_IMAGE_DATA) {
            uint64_t destination = UINT64_MAX;
            for (guint j = 0; j < objects->len; j++) {
                const ExtractRange *object = &g_array_index(objects, ExtractRange, j);
                if (object->old_offset == rel.data_object_offset) {
                    destination = object->new_offset;
                    break;
                }
            }
            if (destination == UINT64_MAX) {
                if (append_range(code, old_code, rel.data_object_offset,
                        rel.data_object_size, rel.data_object_alignment,
                        &destination)) goto too_large;
                ExtractRange object = {rel.data_object_offset,
                    rel.data_object_size, destination};
                g_array_append_val(objects, object);
            }
            rel.addend = destination + (uint64_t)rel.addend - rel.data_object_offset;
            rel.data_object_offset = destination;
        }
        g_array_append_val(new_rels, rel);
    }
    for (uint64_t i = 0; i < h->pc_map_count; i++) {
        LatNativePcMapV2 map = maps[i];
        int owner = range_owner(tus, h->tu_count, map.host_offset_begin,
                                map.host_offset_end - map.host_offset_begin);
        if (owner < 0) return fail(error, error_size, "extracted PC map has no complete TU owner");
        if (discard[owner]) continue;
        map.host_offset_begin = offsets[owner] + map.host_offset_begin - tus[owner].code_offset;
        map.host_offset_end = offsets[owner] + map.host_offset_end - tus[owner].code_offset;
        g_array_append_val(new_maps, map);
    }
    LatNativeImageHeaderV2 result = *h;
    result.guest_image_offset = sizeof(result);
    result.code_offset = (sizeof(result) + h->guest_image_size + 7) & ~UINT64_C(7);
    result.code_size = code->len;
    result.tb_table_offset = (result.code_offset + code->len + 7) & ~UINT64_C(7);
    result.tb_count = new_tbs->len;
    result.relocation_offset = result.tb_table_offset + (uint64_t)new_tbs->len * sizeof(LatNativeTbV1);
    result.relocation_count = new_rels->len;
    result.pc_map_offset = result.relocation_offset + (uint64_t)new_rels->len * sizeof(LatNativeRelocationV1);
    result.pc_map_count = new_maps->len;
    result.tu_table_offset = result.pc_map_offset + (uint64_t)new_maps->len * sizeof(LatNativePcMapV2);
    result.tu_count = new_tus->len;
    uint64_t length = result.tu_table_offset + (uint64_t)new_tus->len * sizeof(LatNativeTuV1) + h->translation_config_size;
    if (length > SIZE_MAX || length < result.tu_table_offset) goto too_large;
    buffer = g_malloc0(length);
    memcpy(buffer, &result, sizeof(result));
    memcpy(buffer + result.guest_image_offset, bytes + h->guest_image_offset, h->guest_image_size);
    memcpy(buffer + result.code_offset, code->data, code->len);
    memcpy(buffer + result.tb_table_offset, new_tbs->data, new_tbs->len * sizeof(LatNativeTbV1));
    if (new_rels->len) memcpy(buffer + result.relocation_offset, new_rels->data, new_rels->len * sizeof(LatNativeRelocationV1));
    if (new_maps->len) memcpy(buffer + result.pc_map_offset, new_maps->data, new_maps->len * sizeof(LatNativePcMapV2));
    memcpy(buffer + result.tu_table_offset, new_tus->data, new_tus->len * sizeof(LatNativeTuV1));
    memcpy(buffer + length - h->translation_config_size,
           bytes + size - h->translation_config_size, h->translation_config_size);
    if (lat_native_tu_audit_execution(buffer, length, &execution, error, error_size)) return -1;
    *output = g_steal_pointer(&buffer);
    *output_size = length;
    return 0;
too_large:
    return fail(error, error_size, "extracted native image is too large");
}
