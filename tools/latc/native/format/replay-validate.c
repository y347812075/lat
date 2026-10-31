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

int lat_replay_native_validate_fd(int image_fd, int config_fd, int tbset_fd,
                                  const uint8_t expected_source[32],
                                  char *error, size_t error_size)
{
    struct stat image_stat, config_stat;
    LatTbKeySet requested = {0}, available = {0}, missing = {0};
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
    if (lat_tb_key_set_sort_unique(&available, error, error_size) ||
        lat_tb_key_set_read_fd(tbset_fd, header->guest_sha256, &requested, error, error_size) ||
        lat_tb_key_set_difference(&requested, &available, &missing, error, error_size))
        goto out;
    if (missing.count) {
        if (error && error_size)
            snprintf(error, error_size, "missing requested TB rva=0x%" PRIx64 " flags=0x%x",
                     missing.keys[0].guest_rva, missing.keys[0].flags);
        goto out;
    }
    result = 0;
out:
    g_free(image);
    lat_tb_key_set_destroy(&requested);
    lat_tb_key_set_destroy(&available);
    lat_tb_key_set_destroy(&missing);
    return result;
}
