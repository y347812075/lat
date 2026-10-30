#ifndef LATCD_BROKER_TRANSPORT_H
#define LATCD_BROKER_TRANSPORT_H
#include <stddef.h>
#include <sys/types.h>

/* Set SO_PASSCRED before receiving. expected_uid comes from trusted policy. */
int latcd_broker_peer(int socket_fd, uid_t expected_uid, uid_t *uid, gid_t *gid);
/* Fixed-size packet; accepts exactly one credential and at most one fd. */
int latcd_broker_receive(int socket_fd, uid_t uid, gid_t gid,
                         void *packet, size_t size, int *received_fd);
int latcd_broker_send(int socket_fd, const void *packet, size_t size, int fd);
#endif
