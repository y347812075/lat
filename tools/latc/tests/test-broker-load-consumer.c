#define _GNU_SOURCE
#include "latcd-client.h"
#include "lat-translation-config.h"
#include "module-loader.h"
#include "internal-fd-registry.h"
#include "cache-lifecycle.h"
#include "latc-build-id.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void close_internal(int fd)
{
    lat_aot_v2_cache_close_fd(fd, true, NULL, 0);
}

static int snapshot(const char *path, uint8_t digest[32], size_t *length)
{
    gchar *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &data, &size, NULL)) return -1;
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, (guchar *)data, size);
    gsize n = 32;
    g_checksum_get_digest(sum, digest, &n);
    g_checksum_free(sum);
    int fd = memfd_create("broker-load-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || write(fd, data, size) != (ssize_t)size ||
        fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
    g_free(data);
    *length = size;
    return fd;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) return 2;
    uint8_t source_hash[32], ignored[32], config_hash[32];
    size_t source_size, config_size;
    int source = snapshot(argv[2], source_hash, &source_size);
    int config_fd = snapshot(argv[3], ignored, &config_size);
    if (source < 0 || config_fd < 0 || config_size > 4096) return 1;
    uint8_t config_data[4096];
    LatTranslationConfig decoded;
    char error[256] = {0};
    if (pread(config_fd, config_data, config_size, 0) != (ssize_t)config_size ||
        lat_translation_config_decode(config_data, config_size, NULL, &decoded, error, sizeof(error)) ||
        lat_translation_config_digest(&decoded, config_hash, error, sizeof(error))) return 1;
    LatcdClientFdProtection protection = {lat_aot_v2_internal_fd_allocation_lock,
        lat_aot_v2_internal_fd_unlock, lat_aot_v2_internal_fd_register_locked, close_internal};
    int fd = latcd_client_broker_load(argv[1], geteuid(), source, config_fd, source_size,
        source_hash, config_hash, 1, &protection, error, sizeof(error));
    close(source); close(config_fd);
    if (argc == 6) {
        if (fd >= 0) close_internal(fd);
        return fd < 0 ? 0 : 1;
    }
    if (fd < 0) { fprintf(stderr, "%s\n", error); return 1; }
    LatAotExpectedV2 expected = {.available_features = UINT64_MAX};
    memcpy(expected.source_sha256, source_hash, 32);
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, (const guchar *)LATC_BUILD_ID, strlen(LATC_BUILD_ID));
    gsize n = 32; g_checksum_get_digest(sum, expected.codegen_id, &n); g_checksum_free(sum);
    LatAotConfigIdentityV2 identity = {.revision = LAT_AOT_CONFIG_NOTE_REVISION,
        .schema = LAT_AOT_CONFIG_SCHEMA_V1, .domain = LAT_AOT_CONFIG_DOMAIN_TRANSLATION_V1};
    memcpy(identity.digest, config_hash, 32);
    LatAotLoadedModuleV2 module;
    if (lat_aot_v2_module_load_config_fd(fd, &expected, &identity, &module, error, sizeof(error))) {
        fprintf(stderr, "%s\n", error); return 1;
    }
    if (unlink(argv[4])) return 1;
    uint64_t (*entry)(void) = (void *)module.descriptor->text_begin;
    uint64_t result = entry();
    dlclose(module.dl_handle);
    close_internal(module.backing_fd);
    if (result != 42) return 1;
    puts("test-broker-load-consumer: PASS");
    return 0;
}
