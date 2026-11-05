#define _GNU_SOURCE
#include "../latcd/cache-export.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool cancelled(void *opaque) { return *(bool *)opaque; }

int main(int argc, char **argv)
{
    int source = memfd_create("export-source", MFD_CLOEXEC);
    assert(source >= 0 && write(source, "abc", 3) == 3 && !fchmod(source, 0400));
    char *digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, "abc", 3);
    bool stop = true;
    assert(latcd_cache_export_copy_bounded(source, digest, 3, 0, cancelled, &stop) < 0 &&
           errno == ECANCELED);
    assert(latcd_cache_export_copy_bounded(source, digest, 3, g_get_monotonic_time() - 1,
                                           NULL, NULL) < 0 && errno == ECANCELED);
    stop = false;
    int bounded = latcd_cache_export_copy_bounded(source, digest, 3,
        g_get_monotonic_time() + G_TIME_SPAN_SECOND, cancelled, &stop);
    assert(bounded >= 0);
    close(bounded);
    assert(latcd_cache_export_copy(source, digest, 2) < 0);
    int copy = latcd_cache_export_copy(source, digest, 3);
    assert(copy >= 0 && (fcntl(copy, F_GET_SEALS) &
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) ==
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
    struct stat copy_stat;
    assert(!fstat(copy, &copy_stat) && (copy_stat.st_mode & 0777) == 0555);
    LatAotExpectedV2 expected = {0};
    LatAotConfigIdentityV2 config = {0};
    char error[256];
    assert(latcd_cache_export_config_bounded(source, digest, 3, &expected, &config,
                                             0, NULL, NULL, error, sizeof(error)) < 0);
    char data[3];
    assert(pread(copy, data, sizeof(data), 0) == 3 && !memcmp(data, "abc", 3));
    assert(pwrite(copy, "x", 1, 0) < 0 && errno == EPERM);
    assert(pwrite(source, "x", 1, 0) == 1);
    assert(pread(copy, data, sizeof(data), 0) == 3 && !memcmp(data, "abc", 3));
    digest[0] = digest[0] == '0' ? '1' : '0';
    assert(latcd_cache_export_copy(source, digest, 3) < 0);
    g_free(digest); close(copy); close(source);
    if (argc == 2) {
        gchar *bytes = NULL;
        gsize size = 0;
        assert(g_file_get_contents(argv[1], &bytes, &size, NULL));
        digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar *)bytes, size);
        source = memfd_create("config-export-source", MFD_CLOEXEC);
        assert(source >= 0 && write(source, bytes, size) == (ssize_t)size &&
               !fchmod(source, 0500));
        g_free(bytes);
        expected.available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES;
        memset(expected.source_sha256, 0x11, 32);
        memset(expected.codegen_id, 0x22, 32);
        config.revision = LAT_AOT_CONFIG_NOTE_REVISION;
        config.schema = LAT_AOT_CONFIG_SCHEMA_V1;
        config.domain = LAT_AOT_CONFIG_DOMAIN_TRANSLATION_V1;
        memset(config.digest, 0x44, 32);
        copy = latcd_cache_export_config_bounded(source, digest, size, &expected,
                                                  &config, 0, NULL, NULL, error, sizeof(error));
        assert(copy >= 0);
        assert(!fstat(copy, &copy_stat) && (copy_stat.st_mode & 0777) == 0555);
        assert((fcntl(copy, F_GET_SEALS) & (F_SEAL_WRITE | F_SEAL_GROW |
                F_SEAL_SHRINK | F_SEAL_SEAL)) == (F_SEAL_WRITE | F_SEAL_GROW |
                F_SEAL_SHRINK | F_SEAL_SEAL));
        close(copy);
        config.digest[0] ^= 1;
        assert(latcd_cache_export_config_bounded(source, digest, size, &expected,
                    &config, 0, NULL, NULL, error, sizeof(error)) < 0);
        close(source);
        g_free(digest);
    } else assert(argc == 1);
    return 0;
}
