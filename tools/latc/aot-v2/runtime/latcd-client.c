#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "latcd-client.h"
#include "latcd-protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

static int submit(const char *socket_path, int source_fd, int profile_fd,
                  uint32_t priority, uint64_t request_id,
                  char *error, size_t error_size)
{
    if (!socket_path || !*socket_path || source_fd < 0 ||
        strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd submission arguments");
    }
    int socket_fd = socket(AF_UNIX,
                           SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return fail(error, error_size, "cannot create latcd socket: %s",
                    strerror(errno));
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(socket_fd, (const void *)&address, sizeof(address))) {
        int saved = errno;
        close(socket_fd);
        errno = saved;
        return fail(error, error_size, "cannot connect to latcd: %s",
                    strerror(saved));
    }
    LatcdRequestV1 request = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request),
        .priority = priority,
        .flags = profile_fd >= 0 ? LATCD_REQUEST_HAS_PROFILE : 0,
        .request_id = request_id,
    };
    struct iovec iov = {
        .iov_base = &request,
        .iov_len = sizeof(request),
    };
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 2)];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    int descriptors[2] = { source_fd, profile_fd };
    size_t descriptor_count = profile_fd >= 0 ? 2 : 1;
    header->cmsg_len = CMSG_LEN(sizeof(int) * descriptor_count);
    memcpy(CMSG_DATA(header), descriptors,
           sizeof(int) * descriptor_count);
    message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptor_count);
    ssize_t sent = sendmsg(socket_fd, &message,
                           MSG_DONTWAIT | MSG_NOSIGNAL);
    int saved = errno;
    close(socket_fd);
    if (sent != sizeof(request)) {
        errno = sent < 0 ? saved : EIO;
        return fail(error, error_size, "cannot submit ELF to latcd: %s",
                    sent < 0 ? strerror(saved) : "short packet");
    }
    return 0;
}

int latcd_client_submit_fd(const char *socket_path, int source_fd,
                           uint32_t priority, uint64_t request_id,
                           char *error, size_t error_size)
{
    return submit(socket_path, source_fd, -1, priority, request_id,
                  error, error_size);
}

int latcd_client_submit_profile_fd(const char *socket_path, int source_fd,
                                   int profile_fd, uint32_t priority,
                                   uint64_t request_id,
                                   char *error, size_t error_size)
{
    if (profile_fd < 0) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd profile descriptor");
    }
    return submit(socket_path, source_fd, profile_fd, priority, request_id,
                  error, error_size);
}
