#ifndef LATCD_MANAGED_CONFIG_H
#define LATCD_MANAGED_CONFIG_H
#include <sys/types.h>

typedef struct LatcdManagedConfig {
    uid_t service_uid, client_uid;
    char *cache, *admin, *broker, *compiler, *runner, *runtime;
} LatcdManagedConfig;

int latcd_managed_config_load(const char *path, LatcdManagedConfig *config);
/* Validate before any cache access, tool execution, or runtime loading. */
int latcd_managed_config_validate(const LatcdManagedConfig *config);
/* The trusted launcher must also prevent pre-main dynamic loader injection. */
int latcd_managed_environment_validate(char *const environment[]);
void latcd_managed_config_clear(LatcdManagedConfig *config);
#endif
