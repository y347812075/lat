#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "broker-transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/un.h>
#include <unistd.h>

int latcd_broker_listener_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int latcd_broker_listener_open(LatcdBrokerListener *listener, int directory,
                               const char *name)
{
    struct stat parent, path;
    if (!listener || !name || !*name || strlen(name) >= sizeof(listener->name) ||
        strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..") ||
        fstat(directory, &parent) || !S_ISDIR(parent.st_mode) ||
        parent.st_uid != geteuid() || (parent.st_mode & 0022)) {
        errno = EINVAL; return -1;
    }
    *listener = (LatcdBrokerListener) {.fd = -1, .directory = -1, .ownership = -1};
    char anchor[96];
    if (snprintf(anchor, sizeof(anchor), ".%s.anchor", name) >= (int)sizeof(anchor)) {
        errno = ENAMETOOLONG; return -1;
    }
    int ownership = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (ownership < 0 || flock(ownership, LOCK_EX | LOCK_NB)) {
        int saved = errno; if (ownership >= 0) close(ownership); errno = saved; return -1;
    }
    struct stat marker, public;
    bool have_marker = !fstatat(directory, anchor, &marker, AT_SYMLINK_NOFOLLOW);
    if (!have_marker && errno != ENOENT) goto fail_ownership;
    bool have_public = !fstatat(directory, name, &public, AT_SYMLINK_NOFOLLOW);
    if (!have_public && errno != ENOENT) goto fail_ownership;
    if (have_marker && (!S_ISSOCK(marker.st_mode) || marker.st_uid != geteuid() ||
        (have_public && (public.st_dev != marker.st_dev || public.st_ino != marker.st_ino)))) {
        errno = ESTALE; goto fail_ownership;
    }
    if (have_public && !have_marker) { errno = EEXIST; goto fail_ownership; }
    if ((have_public && (unlinkat(directory, name, 0) || fsync(directory))) ||
        (have_marker && (unlinkat(directory, anchor, 0) || fsync(directory))))
        goto fail_ownership;
    int held = fcntl(directory, F_DUPFD_CLOEXEC, 3);
    if (held < 0) goto fail_ownership;
    int fd = latcd_broker_listener_socket();
    if (fd < 0) { close(held); goto fail_ownership; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int length = snprintf(address.sun_path, sizeof(address.sun_path),
                          "/proc/self/fd/%d/%s", held, anchor);
    if (length < 0 || (size_t)length >= sizeof(address.sun_path)) {
        close(fd); close(held); errno = ENAMETOOLONG; goto fail_ownership;
    }
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) {
        int saved = errno; close(fd); close(held); errno = saved; goto fail_ownership;
    }
    if (fstatat(held, anchor, &path, AT_SYMLINK_NOFOLLOW) || !S_ISSOCK(path.st_mode) ||
        path.st_uid != geteuid()) {
        close(fd); close(held); errno = ESTALE; goto fail_ownership;
    }
    listener->fd = fd; listener->directory = held; listener->ownership = ownership;
    listener->device = path.st_dev; listener->inode = path.st_ino;
    strcpy(listener->name, name);
    strcpy(listener->anchor, anchor);
    if (fchmodat(held, anchor, 0666, 0) || listen(fd, 16) || fsync(held) ||
        linkat(held, anchor, held, name, 0) || fsync(held)) {
        int saved = errno; latcd_broker_listener_close(listener); errno = saved; return -1;
    }
    return 0;
fail_ownership:
    { int saved = errno; close(ownership); errno = saved; return -1; }
}

int latcd_broker_listener_close(LatcdBrokerListener *listener)
{
    if (!listener || listener->fd < 0 || listener->directory < 0) {
        errno = EINVAL; return -1;
    }
    close(listener->fd);
    struct stat path;
    int result = -1;
    if (!fstatat(listener->directory, listener->name, &path, AT_SYMLINK_NOFOLLOW) &&
        S_ISSOCK(path.st_mode) && path.st_dev == listener->device && path.st_ino == listener->inode)
        result = unlinkat(listener->directory, listener->name, 0);
    else errno = ESTALE;
    if (!result && fsync(listener->directory)) result = -1;
    if (!result) {
        if (fstatat(listener->directory, listener->anchor, &path, AT_SYMLINK_NOFOLLOW) ||
            !S_ISSOCK(path.st_mode) || path.st_dev != listener->device || path.st_ino != listener->inode) {
            errno = ESTALE; result = -1;
        } else if (unlinkat(listener->directory, listener->anchor, 0) || fsync(listener->directory)) {
            result = -1;
        }
    }
    int saved = errno;
    close(listener->directory);
    close(listener->ownership);
    listener->fd = listener->directory = listener->ownership = -1;
    errno = saved;
    return result;
}

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
    ssize_t result = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
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
    ssize_t count = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
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
