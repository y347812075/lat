#define _GNU_SOURCE

#include "latcd-protocol.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

static int request_header_valid(const LatcdRequestV1 *request)
{
    return request->magic == LATCD_REQUEST_MAGIC &&
           request->version == LATCD_PROTOCOL_VERSION &&
           request->size == sizeof(*request) &&
           !(request->flags & ~LATCD_REQUEST_HAS_PROFILE);
}

int latcd_send_request(int socket_fd, int source_fd, int profile_fd,
                       const LatcdRequestV1 *request,
                       char *error, size_t error_size)
{
    int has_profile = !!(request &&
                         (request->flags & LATCD_REQUEST_HAS_PROFILE));
    if (socket_fd < 0 || source_fd < 0 || !request ||
        (has_profile != (profile_fd >= 0)) ||
        !request_header_valid(request)) {
        return fail(error, error_size, "invalid latcd request arguments");
    }
    struct iovec iov = {
        .iov_base = (void *)request,
        .iov_len = sizeof(*request),
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
    size_t descriptor_count = has_profile ? 2 : 1;
    header->cmsg_len = CMSG_LEN(sizeof(int) * descriptor_count);
    memcpy(CMSG_DATA(header), descriptors,
           sizeof(int) * descriptor_count);
    message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptor_count);
    ssize_t sent;
    do {
        sent = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != sizeof(*request)) {
        return fail(error, error_size, "cannot send latcd request: %s",
                    sent < 0 ? strerror(errno) : "short packet");
    }
    return 0;
}

int latcd_receive_request(int socket_fd, LatcdRequestV1 *request,
                          int *source_fd, int *profile_fd,
                          char *error, size_t error_size)
{
    if (socket_fd < 0 || !request || !source_fd || !profile_fd) {
        return fail(error, error_size, "invalid latcd receive arguments");
    }
    *source_fd = -1;
    *profile_fd = -1;
    struct iovec iov = { .iov_base = request, .iov_len = sizeof(*request) };
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 4)];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    ssize_t received;
    do {
        received = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    int descriptors[4];
    size_t descriptor_count = 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(sizeof(int))) {
            continue;
        }
        size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int *fds = (const void *)CMSG_DATA(header);
        for (size_t i = 0; i < count && descriptor_count < 4; i++) {
            descriptors[descriptor_count++] = fds[i];
        }
    }
    if (received != sizeof(*request) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        for (size_t i = 0; i < descriptor_count; i++) {
            close(descriptors[i]);
        }
        return fail(error, error_size, "invalid latcd request packet");
    }
    size_t expected_count = (request->flags & LATCD_REQUEST_HAS_PROFILE) ?
                            2 : 1;
    if (!request_header_valid(request) ||
        descriptor_count != expected_count) {
        for (size_t i = 0; i < descriptor_count; i++) {
            close(descriptors[i]);
        }
        return fail(error, error_size,
                    "latcd request header or descriptor count is invalid");
    }
    *source_fd = descriptors[0];
    if (expected_count == 2) {
        *profile_fd = descriptors[1];
    }
    return 0;
}

int latcd_send_response(int socket_fd, const LatcdResponseV1 *response,
                        char *error, size_t error_size)
{
    ssize_t sent;
    do {
        sent = send(socket_fd, response, sizeof(*response), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != sizeof(*response)) {
        return fail(error, error_size, "cannot send latcd response: %s",
                    sent < 0 ? strerror(errno) : "short packet");
    }
    return 0;
}

int latcd_receive_response(int socket_fd, LatcdResponseV1 *response,
                           char *error, size_t error_size)
{
    ssize_t received;
    do {
        received = recv(socket_fd, response, sizeof(*response), 0);
    } while (received < 0 && errno == EINTR);
    if (received != sizeof(*response) ||
        response->magic != LATCD_RESPONSE_MAGIC ||
        response->version != LATCD_PROTOCOL_VERSION ||
        response->size != sizeof(*response)) {
        return fail(error, error_size, "invalid latcd response packet");
    }
    response->message[sizeof(response->message) - 1] = '\0';
    return 0;
}
