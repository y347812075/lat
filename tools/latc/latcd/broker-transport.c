#define _GNU_SOURCE
#include "broker-transport.h"
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int latcd_broker_peer(int fd, uid_t expected_uid, uid_t *uid, gid_t *gid)
{
    int type, enabled = 1;
    socklen_t length = sizeof(type);
    struct ucred peer;
    if (!uid || !gid || getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) ||
        length != sizeof(type) || type != SOCK_SEQPACKET ||
        setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) goto fail;
    length = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
        length != sizeof(peer) || peer.uid != expected_uid) goto fail;
    *uid = peer.uid; *gid = peer.gid;
    return 0;
fail:
    errno = EACCES;
    return -1;
}

int latcd_broker_send(int fd, const void *packet, size_t size, int passed)
{
    if (!packet || !size) { errno = EINVAL; return -1; }
    struct iovec iov = {.iov_base = (void *)packet, .iov_len = size};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    if (passed >= 0) {
        msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &passed, sizeof(passed));
    }
    ssize_t result;
    do { result = sendmsg(fd, &msg, MSG_NOSIGNAL); } while (result < 0 && errno == EINTR);
    if (result == (ssize_t)size) return 0;
    if (result >= 0) errno = EIO;
    return -1;
}

int latcd_broker_receive(int fd, uid_t uid, gid_t gid, void *packet, size_t size, int *received_fd)
{
    if (!packet || !size || !received_fd) { errno = EINVAL; return -1; }
    *received_fd = -1;
    struct iovec iov = {.iov_base = packet, .iov_len = size};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8)]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
                         .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    ssize_t count;
    do { count = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC); } while (count < 0 && errno == EINTR);
    if (count < 0) return -1;
    bool valid = count == (ssize_t)size && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    bool credentials = false; unsigned fds = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_len < CMSG_LEN(0)) { valid = false; continue; }
        size_t payload = c->cmsg_len - CMSG_LEN(0);
        if (c->cmsg_type == SCM_CREDENTIALS && payload == sizeof(struct ucred) && !credentials) {
            struct ucred peer; memcpy(&peer, CMSG_DATA(c), sizeof(peer));
            credentials = true; valid &= peer.uid == uid && peer.gid == gid;
        } else if (c->cmsg_type == SCM_RIGHTS && payload % sizeof(int) == 0) {
            for (size_t i = 0; i < payload / sizeof(int); i++) {
                int received; memcpy(&received, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(received));
                if (++fds == 1) *received_fd = received; else close(received);
            }
        } else valid = false;
    }
    if (valid && credentials && fds <= 1) return 0;
    if (*received_fd >= 0) close(*received_fd);
    *received_fd = -1; errno = EPROTO; return -1;
}
