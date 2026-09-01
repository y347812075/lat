#ifndef LATCD_CLIENT_H
#define LATCD_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int latcd_client_submit_tbset_fd(const char *socket_path, int source_fd,
                                 int tbset_fd, uint32_t priority,
                                 uint64_t request_id,
                                 char *error, size_t error_size);

#endif
