#ifndef LATCD_BROKER_SOURCE_H
#define LATCD_BROKER_SOURCE_H
#include <stddef.h>
#include <stdint.h>
/* Validates a sealed source snapshot and writes its verified SHA-256. */
int latcd_broker_source_validate(int fd, uint64_t size, uint64_t limit,
                                 const uint8_t claimed[32], uint8_t verified[32],
                                 char *error, size_t error_size);
#endif
