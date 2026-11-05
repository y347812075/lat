#ifndef LAT_AOT_AUTO_CONFIG_H
#define LAT_AOT_AUTO_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

struct LatcdClientFdProtection;
bool lat_aot_config_option(const char *key, const char *value);
void lat_aot_config_system_defaults(void);
#ifdef LAT_AOT_TEST_CONFIG
void lat_aot_test_system_defaults(const char *directory);
#endif
void lat_aot_config_environment(void);
int lat_aot_config_select(int *legacy, bool explicit_legacy, bool *selected,
                         char *error, size_t error_size);
int lat_aot_config_init(int *legacy, bool explicit_legacy, const char *bindir,
                        const char *libdir, char *error, size_t error_size);
const char *lat_aot_cache_path(void);
const char *lat_aot_socket_path(void);
const char *lat_aot_module_path(void);
bool lat_aot_broker_enabled(void);
bool lat_aot_ensure_daemon(void);
int lat_aot_open_channel(char *error, size_t error_size);
/* Connect only to an existing daemon; never starts one. */
int lat_aot_open_existing_channel(char *error, size_t error_size);
int lat_aot_open_existing_channel_protected(
    const struct LatcdClientFdProtection *protection,
    char *error, size_t error_size);

#endif
