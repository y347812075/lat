#ifndef LATCD_BROKER_TRANSPORT_H
#define LATCD_BROKER_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define LATCD_BROKER_EXPORT_VERSION 2u
#define LATCD_BROKER_PURPOSE_OFFLINE_SNAPSHOT 1u
typedef struct LatcdBrokerExportRequest {
    uint32_t version;
    uint32_t reserved;
    uint64_t source_size;
    uint8_t source_sha256[32];
} LatcdBrokerExportRequest;

typedef struct LatcdBrokerExportResponse {
    uint32_t version;
    uint32_t status;
    uint32_t purpose;
    uint32_t execution_authorized;
    uint64_t module_size;
    uint8_t source_sha256[32];
    uint8_t module_sha256[32];
} LatcdBrokerExportResponse;

/* Call before bind/listen so credentials are attached to early packets. */
int latcd_broker_listener_socket(void);
typedef struct LatcdBrokerListener {
    int fd;
    int directory;
    int ownership;
    char name[80];
    char anchor[96];
    dev_t device;
    ino_t inode;
} LatcdBrokerListener;
/* Directory must be held by the service and not writable by other users. */
int latcd_broker_listener_open(LatcdBrokerListener *listener, int directory,
                               const char *name);
/* Returns -1 if the pathname no longer names this listener. */
int latcd_broker_listener_close(LatcdBrokerListener *listener);

/* Set SO_PASSCRED before receiving. expected_uid comes from trusted policy. */
int latcd_broker_peer(int socket_fd, uid_t expected_uid, uid_t *uid, gid_t *gid);
/* Single nonblocking syscall: EAGAIN/EINTR return to the event loop.
 * Fixed-size packet; accepts exactly one credential and at most one fd. */
int latcd_broker_receive(int socket_fd, uid_t uid, gid_t gid,
                         void *packet, size_t size, int *received_fd);
int latcd_broker_send(int socket_fd, const void *packet, size_t size, int fd);
/* Exactly two descriptors are required; both are closed on invalid packets. */
int latcd_broker_receive_pair(int socket_fd, uid_t uid, gid_t gid,
                              void *packet, size_t size, int received_fds[2]);
int latcd_broker_send_pair(int socket_fd, const void *packet, size_t size,
                           const int fds[2]);
#endif
