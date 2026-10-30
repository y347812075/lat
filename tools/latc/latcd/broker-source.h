#ifndef LATCD_BROKER_SOURCE_H
#define LATCD_BROKER_SOURCE_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
typedef bool (*LatcdBrokerCancelled)(void *opaque);
/* Validates a sealed source snapshot and writes its verified SHA-256. */
int latcd_broker_source_validate(int fd, uint64_t size, uint64_t limit,
                                 const uint8_t claimed[32], uint8_t verified[32],
                                 char *error, size_t error_size);
int latcd_broker_source_validate_bounded(int fd, uint64_t size, uint64_t limit,
                                 const uint8_t claimed[32], uint8_t verified[32],
                                 char *error, size_t error_size, int64_t deadline_us,
                                 LatcdBrokerCancelled cancelled, void *opaque);
#endif
