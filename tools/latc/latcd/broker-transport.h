#ifndef LATCD_BROKER_TRANSPORT_H
#define LATCD_BROKER_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define LATCD_BROKER_EXPORT_VERSION 1u
typedef struct LatcdBrokerExportRequest {
    uint32_t version;
    uint32_t reserved;
    uint64_t source_size;
    uint8_t source_sha256[32];
} LatcdBrokerExportRequest;

typedef struct LatcdBrokerExportResponse {
    uint32_t version;
    uint32_t status;
} LatcdBrokerExportResponse;

/* Set SO_PASSCRED before receiving. expected_uid comes from trusted policy. */
int latcd_broker_peer(int socket_fd, uid_t expected_uid, uid_t *uid, gid_t *gid);
/* Fixed-size packet; accepts exactly one credential and at most one fd. */
int latcd_broker_receive(int socket_fd, uid_t uid, gid_t gid,
                         void *packet, size_t size, int *received_fd);
int latcd_broker_send(int socket_fd, const void *packet, size_t size, int fd);
#endif
