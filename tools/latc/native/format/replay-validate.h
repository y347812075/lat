#ifndef LAT_REPLAY_VALIDATE_H
#define LAT_REPLAY_VALIDATE_H

#include <stddef.h>
#include <stdint.h>
#include "lat-tb-key-set.h"

/* Validate a quarantined image against the frozen request; never authorizes
 * execution or publication. The caller retains ownership of all descriptors. */
int lat_replay_native_validate_fd(int image_fd, int config_fd, int tbset_fd,
                                  const uint8_t expected_source[32],
                                  char *error, size_t error_size);
int lat_replay_native_missing_fd(int image_fd, int config_fd, int tbset_fd,
                                 const uint8_t expected_source[32],
                                 LatTbKeySet *missing,
                                 char *error, size_t error_size);

#endif
