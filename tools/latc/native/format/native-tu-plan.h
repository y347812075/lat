#ifndef LATC_NATIVE_TU_PLAN_H
#define LATC_NATIVE_TU_PLAN_H

#include <stdbool.h>
#include "lat-tb-key-set.h"

/* Metadata closure only, not a configuration compatibility decision. Includes
 * entire TUs, same-key physical aliases, and incoming physical dependencies.
 * Raw code/data extraction must additionally prove all unrecorded code edges. */
int lat_native_tu_plan(const void *data, size_t size, const LatTbKeySet *seeds,
                       LatTbKeySet *result, char *error, size_t error_size);

/* Compare an embedded configuration with a target snapshot, then close affected
 * TUs. An incomplete snapshot permits planning only, never reuse authorization. */
int lat_native_tu_config_plan(const void *data, size_t size,
    const void *target, size_t target_size, LatTbKeySet *result,
    uint64_t *changed, char *error, size_t error_size);

typedef enum LatNativeTuMigrationKind {
    LAT_NATIVE_TU_MIGRATION_NOOP = 0,
    LAT_NATIVE_TU_MIGRATION_PARTIAL = 1,
    LAT_NATIVE_TU_MIGRATION_FULL = 2,
} LatNativeTuMigrationKind;

/* Planning-only view of a possible v11 configuration migration. It separates
 * old native coverage into affected/retained TUs and classifies mandatory
 * runtime keys ahead of optional static candidates. It grants neither reuse
 * nor movement authority and must not feed normal merge or publication. */
/* Initialize the plan to zero before its first build. */
typedef struct LatNativeTuMigrationPlan {
    LatNativeTuMigrationKind kind;
    uint64_t changed_fields;
    uint8_t old_config_sha256[32];
    uint8_t target_config_sha256[32];
    LatTbKeySet affected_keys;
    LatTbKeySet retained_keys;
    LatTbKeySet compile_required_keys;
    LatTbKeySet deferred_static_keys;
    bool configuration_contract_complete;
    bool reuse_authorized;
    bool movement_certified;
} LatNativeTuMigrationPlan;

/* runtime_required contains new mandatory keys not already promised by the old
 * native; old native keys are included automatically. static_candidates may be
 * NULL and are deferred when already retained or mandatory. */
int lat_native_tu_migration_plan(const void *data, size_t size,
    const void *target, size_t target_size,
    const LatTbKeySet *runtime_required,
    const LatTbKeySet *static_candidates,
    LatNativeTuMigrationPlan *plan, char *error, size_t error_size);
void lat_native_tu_migration_plan_destroy(LatNativeTuMigrationPlan *plan);

typedef enum LatNativeTuMigrationBindStatus {
    LAT_NATIVE_TU_MIGRATION_BIND_REJECT = 0,
    LAT_NATIVE_TU_MIGRATION_BIND_READY = 1,
    LAT_NATIVE_TU_MIGRATION_BIND_EXPAND_AND_RECOMPILE = 2,
} LatNativeTuMigrationBindStatus;

/* Bind a quarantined target-native delta to an existing plan. Structural or
 * identity mismatches fail the call; overlapping actual keys request an
 * expanded plan. READY only means the delta can enter the later coverage and
 * movement verification stage; it is not a publication or execution grant. */
/* Initialize the binding to zero before its first use. */
typedef struct LatNativeTuMigrationBinding {
    LatNativeTuMigrationBindStatus status;
    LatTbKeySet delta_keys;
    LatTbKeySet collision_keys;
    LatTbKeySet missing_required_keys;
    bool covers_required_keys;
} LatNativeTuMigrationBinding;

int lat_native_tu_migration_bind_delta(const void *old_data, size_t old_size,
    const void *delta_data, size_t delta_size,
    const LatNativeTuMigrationPlan *plan,
    LatNativeTuMigrationBinding *binding, char *error, size_t error_size);
void lat_native_tu_migration_binding_destroy(
    LatNativeTuMigrationBinding *binding);

/* Compact the complement of the closed removal plan. Experimental replay images
 * only: the unchanged CONFIG_UNVERIFIED flag prohibits execution/publication.
 * This remaps recorded references, not a certificate of machine-code mobility.
 * Caller releases *output with g_free. Empty complements are rejected. */
int lat_native_tu_extract(const void *data, size_t size,
    const LatTbKeySet *remove, void **output, size_t *output_size,
    char *error, size_t error_size);

#endif
