#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "replay-validate.h"
#include "native-image.h"
#include "lat-tb-key-set.h"

#include <glib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int replay_native_keys(int image_fd, int config_fd,
                              const uint8_t expected_source[32], LatTbKeySet *keys,
                              char *error, size_t error_size)
{
    struct stat image_stat, config_stat;
    LatTbKeySet available = {0};
    char *image = NULL;
    char config[4096];
    int result = -1;

    if (fstat(image_fd, &image_stat) || !S_ISREG(image_stat.st_mode) ||
        image_stat.st_size <= 0 || (uintmax_t)image_stat.st_size > SIZE_MAX ||
        fstat(config_fd, &config_stat) || !S_ISREG(config_stat.st_mode) ||
        config_stat.st_size <= 0 || config_stat.st_size > (off_t)sizeof(config) ||
        pread(config_fd, config, config_stat.st_size, 0) != config_stat.st_size)
        goto out;
    size_t image_size = (size_t)image_stat.st_size;
    image = g_try_malloc(image_size);
    if (!image) goto out;
    for (size_t offset = 0; offset < image_size;) {
        size_t wanted = MIN(image_size - offset, (size_t)SSIZE_MAX);
        ssize_t n = pread(image_fd, image + offset, wanted, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto out;
        offset += n;
    }
    if (lat_native_image_validate(image, image_size, error, error_size))
        goto out;
    const LatNativeImageHeaderV2 *header = (const void *)image;
    size_t config_size = (size_t)config_stat.st_size;
    if (!(header->flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED) ||
        header->translation_config_size != config_size || config_size > image_size ||
        memcmp((const char *)image + image_size - config_size, config, config_size) ||
        (expected_source && memcmp(header->guest_sha256, expected_source, 32)))
        goto out;
    const LatNativeTbV1 *tbs = (const void *)((const char *)image + header->tb_table_offset);
    memcpy(available.source_sha256, header->guest_sha256, 32);
    available.keys = g_new0(LatTbKey, header->tb_count);
    available.count = header->tb_count;
    for (size_t i = 0; i < available.count; i++) {
        if (tbs[i].guest_pc < header->preferred_guest_base) goto out;
        available.keys[i].guest_rva = tbs[i].guest_pc - header->preferred_guest_base;
        available.keys[i].flags = tbs[i].flags;
    }
    if (lat_tb_key_set_sort_unique(&available, error, error_size)) goto out;
    *keys = available;
    memset(&available, 0, sizeof(available));
    result = 0;
out:
    g_free(image);
    lat_tb_key_set_destroy(&available);
    return result;
}

int lat_replay_native_missing_fd(int image_fd, int config_fd, int tbset_fd,
                                  const uint8_t expected_source[32], LatTbKeySet *delta,
                                  char *error, size_t error_size)
{
    LatTbKeySet requested = {0}, available = {0};
    int result = replay_native_keys(image_fd, config_fd, expected_source, &available,
                                    error, error_size);
    if (!result) result = lat_tb_key_set_read_fd(tbset_fd, available.source_sha256,
                                                  &requested, error, error_size);
    if (!result) result = lat_tb_key_set_difference(&requested, &available, delta,
                                                    error, error_size);
    lat_tb_key_set_destroy(&requested);
    lat_tb_key_set_destroy(&available);
    return result;
}

int lat_replay_native_validate_fd(int image_fd, int config_fd, int tbset_fd,
                                  const uint8_t expected_source[32],
                                  char *error, size_t error_size)
{
    LatTbKeySet missing = {0};
    int result = lat_replay_native_missing_fd(image_fd, config_fd, tbset_fd,
                                               expected_source, &missing,
                                               error, error_size);
    if (!result && missing.count) {
        if (error && error_size)
            snprintf(error, error_size, "missing requested TB rva=0x%" PRIx64 " flags=0x%x",
                     missing.keys[0].guest_rva, missing.keys[0].flags);
        result = -1;
    }
    lat_tb_key_set_destroy(&missing);
    return result;
}

int lat_replay_native_validate_incremental_fd(int image_fd, int config_fd,
    int tbset_fd, int base_fd, const uint8_t expected_source[32],
    char *error, size_t error_size)
{
    LatTbKeySet candidate = {0}, base = {0}, missing = {0};
    int result = lat_replay_native_validate_fd(image_fd, config_fd, tbset_fd,
                                                expected_source, error, error_size);
    if (result || base_fd < 0) return result;
    result = replay_native_keys(image_fd, config_fd, expected_source, &candidate,
                                error, error_size);
    if (!result) result = replay_native_keys(base_fd, config_fd, candidate.source_sha256,
                                              &base, error, error_size);
    if (!result) result = lat_tb_key_set_difference(&base, &candidate, &missing,
                                                     error, error_size);
    if (!result && missing.count) {
        if (error && error_size)
            snprintf(error, error_size, "missing baseline TB rva=0x%" PRIx64 " flags=0x%x",
                     missing.keys[0].guest_rva, missing.keys[0].flags);
        result = -1;
    }
    lat_tb_key_set_destroy(&candidate);
    lat_tb_key_set_destroy(&base);
    lat_tb_key_set_destroy(&missing);
    return result;
}

int lat_replay_native_authorize_incremental_fd(int image_fd, int config_fd,
    int tbset_fd, int base_fd, const uint8_t expected_source[32],
    char *error, size_t error_size)
{
    if (lat_replay_native_validate_incremental_fd(image_fd, config_fd, tbset_fd,
                                                   base_fd, expected_source,
                                                   error, error_size))
        return -1;
    LatNativeImageHeaderV2 header;
    if (pread(image_fd, &header, sizeof(header), 0) != sizeof(header) ||
        !(header.flags & LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED)) {
        if (error && error_size) snprintf(error, error_size, "invalid replay header");
        return -1;
    }
    struct stat image_stat;
    if (fstat(image_fd, &image_stat) || !S_ISREG(image_stat.st_mode) ||
        header.translation_config_size == 0 ||
        header.translation_config_size > (uint64_t)image_stat.st_size) {
        if (error && error_size) snprintf(error, error_size, "invalid replay image size");
        return -1;
    }
    off_t config_size = (off_t)header.translation_config_size;
    header.flags &= ~LAT_NATIVE_IMAGE_CONFIG_UNVERIFIED;
    header.translation_config_size = 0;
    header.translation_config_projection = 0;
    memset(header.translation_config_sha256, 0, sizeof(header.translation_config_sha256));
    if (ftruncate(image_fd, image_stat.st_size - config_size) ||
        pwrite(image_fd, &header, sizeof(header), 0) != sizeof(header) || fsync(image_fd)) {
        if (error && error_size)
            snprintf(error, error_size, "cannot authorize replay image: %s", strerror(errno));
        return -1;
    }
    return 0;
}
