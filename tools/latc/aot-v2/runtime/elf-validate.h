#ifndef LAT_AOT_V2_ELF_VALIDATE_H
#define LAT_AOT_V2_ELF_VALIDATE_H

#include "lat-aot-v2.h"

#include <stddef.h>

int lat_aot_v2_elf_validate_memory(const void *data, size_t size,
                                   const LatAotExpectedV2 *expected,
                                   LatAotNoteV2 *note, char *error,
                                   size_t error_size);

/* Structural identity matching only; the caller must authenticate expected. */
int lat_aot_v2_elf_validate_config_memory(const void *data, size_t size,
    const LatAotExpectedV2 *expected, const LatAotConfigIdentityV2 *config,
    LatAotConfigNoteV2 *note, char *error, size_t error_size);

int lat_aot_v2_elf_validate_fd(int fd, const LatAotExpectedV2 *expected,
                               LatAotNoteV2 *note, char *error,
                               size_t error_size);

#endif
