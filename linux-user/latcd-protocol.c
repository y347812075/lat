#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "latcd-protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
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

int latcd_socket_address(const char *path, struct sockaddr_un *address,
                         int *directory_fd, char *error, size_t error_size)
{
    *directory_fd = -1;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    if (!path || !*path) {
        errno = EINVAL;
        return fail(error, error_size, "empty socket path");
    }
    if (strlen(path) < sizeof(address->sun_path)) {
        strcpy(address->sun_path, path);
        return 0;
    }
    const char *slash = strrchr(path, '/');
    if (!slash || !slash[1]) {
        errno = ENAMETOOLONG;
        return fail(error, error_size, "invalid long socket path");
    }
    char *parent = strndup(path, slash - path);
    if (!parent) return fail(error, error_size, "cannot allocate socket parent");
    int fd = open(parent, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    free(parent);
    if (fd < 0) return fail(error, error_size, "cannot open socket parent: %s", strerror(errno));
    int length = snprintf(address->sun_path, sizeof(address->sun_path),
                          "/proc/self/fd/%d/%s", fd, slash + 1);
    if (length < 0 || (size_t)length >= sizeof(address->sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return fail(error, error_size, "socket basename is too long");
    }
    *directory_fd = fd;
    return 0;
}

static int expected_descriptors(const LatcdRequestV2 *request)
{
    if (request->operation == LATCD_OP_SUBMIT_KEYS) return 2;
    if (request->operation == LATCD_OP_SUBMIT_STATIC_KEYS) return 2;
    if (request->operation == LATCD_OP_FLUSH_SOURCE) return 1;
    if (request->operation == LATCD_OP_FLUSH_ALL) return 0;
    if (request->operation == LATCD_OP_PRECOMPILE_SOURCE) return 1;
    if (request->operation == LATCD_OP_HELLO) return 0;
    if (request->operation == LATCD_OP_OPEN_CHANNEL) return 0;
    if (request->operation == LATCD_OP_REGISTER_JOURNAL) return 2;
    if (request->operation == LATCD_OP_COLLECT_JOURNALS) return 0;
    if (request->operation == LATCD_OP_REGISTER_JOURNAL_CAPABILITY) return 2;
    return -1;
}

static int request_header_valid(const LatcdRequestV2 *request)
{
    return request->magic == LATCD_REQUEST_MAGIC &&
           request->version == LATCD_PROTOCOL_VERSION &&
           request->size == sizeof(*request) &&
           expected_descriptors(request) >= 0;
}

static int send_request(int socket_fd, int source_fd, int keys_fd,
                         int reply_fd, const LatcdRequestV2 *request,
                         char *error, size_t error_size)
{
    int count = request ? expected_descriptors(request) : -1;
    if (socket_fd < 0 || !request || !request_header_valid(request) ||
        (count >= 1 && source_fd < 0) || (count == 2 && keys_fd < 0)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd request arguments");
    }
    struct iovec iov = { .iov_base = (void *)request,
                         .iov_len = sizeof(*request) };
    LatcdRequestV2 packet = *request;
    if (reply_fd >= 0) {
        packet.magic = LATCD_CHANNEL_REQUEST_MAGIC;
    }
    iov.iov_base = &packet;
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 3)];
    } control = {0};
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };
    int descriptors[3] = { source_fd, keys_fd };
    if (reply_fd >= 0) {
        descriptors[count++] = reply_fd;
    }
    if (count) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * count);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * count);
        memcpy(CMSG_DATA(header), descriptors, sizeof(int) * count);
    }
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

int latcd_send_request(int socket_fd, int source_fd, int keys_fd,
                       const LatcdRequestV2 *request,
                       char *error, size_t error_size)
{
    return send_request(socket_fd, source_fd, keys_fd, -1, request,
                         error, error_size);
}

int latcd_send_channel_request(int socket_fd, int source_fd, int keys_fd,
                               int reply_fd, const LatcdRequestV2 *request,
                               char *error, size_t error_size)
{
    if (reply_fd < 0) {
        errno = EINVAL;
        return fail(error, error_size, "missing channel reply descriptor");
    }
    return send_request(socket_fd, source_fd, keys_fd, reply_fd, request,
                         error, error_size);
}

static int receive_request(int socket_fd, LatcdRequestV2 *request,
                            int *source_fd, int *keys_fd, int *reply_fd,
                            char *error, size_t error_size)
{
    if (socket_fd < 0 || !request || !source_fd || !keys_fd) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd receive arguments");
    }
    *source_fd = -1;
    *keys_fd = -1;
    if (reply_fd) {
        *reply_fd = -1;
    }
    memset(request, 0, sizeof(*request));
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
            header->cmsg_len < CMSG_LEN(sizeof(int))) continue;
        size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int *fds = (const void *)CMSG_DATA(header);
        for (size_t i = 0; i < count && descriptor_count < 4; i++) {
            descriptors[descriptor_count++] = fds[i];
        }
    }
    bool channel = reply_fd != NULL;
    bool magic_valid = request->magic == (channel ?
        LATCD_CHANNEL_REQUEST_MAGIC : LATCD_REQUEST_MAGIC);
    LatcdRequestV2 normalized = *request;
    normalized.magic = LATCD_REQUEST_MAGIC;
    int expected = magic_valid && request_header_valid(&normalized) ?
                   expected_descriptors(&normalized) : -1;
    if (received != sizeof(*request) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        expected < 0 || descriptor_count != (size_t)expected + channel) {
        for (size_t i = 0; i < descriptor_count; i++) close(descriptors[i]);
        errno = EPROTO;
        return fail(error, error_size,
                    "latcd request header or descriptor count is invalid");
    }
    if (channel) {
        int reply = descriptors[expected];
        int type = 0;
        socklen_t size = sizeof(type);
        struct sockaddr_un address;
        socklen_t address_size = sizeof(address);
        if (getsockopt(reply, SOL_SOCKET, SO_TYPE, &type, &size) ||
            size != sizeof(type) || type != SOCK_SEQPACKET ||
            getpeername(reply, (void *)&address, &address_size) ||
            address.sun_family != AF_UNIX) {
            for (size_t i = 0; i < descriptor_count; i++) {
                close(descriptors[i]);
            }
            errno = EPROTO;
            return fail(error, error_size, "invalid channel reply socket");
        }
        *reply_fd = reply;
    }
    *request = normalized;
    if (expected >= 1) *source_fd = descriptors[0];
    if (expected == 2) *keys_fd = descriptors[1];
    return 0;
}

int latcd_receive_request(int socket_fd, LatcdRequestV2 *request,
                          int *source_fd, int *keys_fd,
                          char *error, size_t error_size)
{
    return receive_request(socket_fd, request, source_fd, keys_fd, NULL,
                            error, error_size);
}

int latcd_receive_channel_request(int socket_fd, LatcdRequestV2 *request,
                                  int *source_fd, int *keys_fd, int *reply_fd,
                                  char *error, size_t error_size)
{
    if (!reply_fd) {
        errno = EINVAL;
        return fail(error, error_size, "missing channel reply output");
    }
    return receive_request(socket_fd, request, source_fd, keys_fd, reply_fd,
                            error, error_size);
}

static int send_response(int socket_fd, const LatcdResponseV2 *response,
                           int fd, int flags, char *error, size_t error_size)
{
    if (socket_fd < 0 || !response ||
        (fd >= 0 && response->status != LATCD_STATUS_OK)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd response arguments");
    }
    struct iovec iov = {.iov_base = (void *)response, .iov_len = sizeof(*response)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd >= 0) {
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(fd));
        memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    }
    ssize_t sent;
    do {
        sent = sendmsg(socket_fd, &message, flags | MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != sizeof(*response)) {
        return fail(error, error_size, "cannot send latcd response: %s",
                    sent < 0 ? strerror(errno) : "short packet");
    }
    return 0;
}

int latcd_send_response(int socket_fd, const LatcdResponseV2 *response,
                        char *error, size_t error_size)
{
    return send_response(socket_fd, response, -1, 0, error, error_size);
}

int latcd_send_response_fd(int socket_fd, const LatcdResponseV2 *response,
                           int fd, char *error, size_t error_size)
{
    return send_response(socket_fd, response, fd, MSG_DONTWAIT, error, error_size);
}

int latcd_receive_response(int socket_fd, LatcdResponseV2 *response,
                           char *error, size_t error_size)
{
    return latcd_receive_response_fd(socket_fd, response, NULL, error, error_size);
}

int latcd_receive_response_fd(int socket_fd, LatcdResponseV2 *response,
                              int *fd, char *error, size_t error_size)
{
    if (fd) *fd = -1;
    if (socket_fd < 0 || !response) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd response receive arguments");
    }
    memset(response, 0, sizeof(*response));
    struct iovec iov = {.iov_base = response, .iov_len = sizeof(*response)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 4)];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    ssize_t received;
    do {
        received = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    int descriptors[4];
    size_t count = 0;
    bool ancillary_valid = true;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(sizeof(int))) {
            ancillary_valid = false;
            continue;
        }
        size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int)) ancillary_valid = false;
        const int *fds = (const void *)CMSG_DATA(header);
        for (size_t i = 0; i < bytes / sizeof(int); i++) {
            if (count < 4) descriptors[count++] = fds[i];
            else { close(fds[i]); ancillary_valid = false; }
        }
    }
    size_t expected = fd && response->status == LATCD_STATUS_OK ? 1 : 0;
    if (received != sizeof(*response) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || !ancillary_valid ||
        count != expected || response->reserved ||
        response->magic != LATCD_RESPONSE_MAGIC ||
        response->version != LATCD_PROTOCOL_VERSION ||
        response->size != sizeof(*response)) {
        for (size_t i = 0; i < count; i++) close(descriptors[i]);
        errno = EPROTO;
        return fail(error, error_size, "invalid latcd response packet");
    }
    if (count) *fd = descriptors[0];
    response->message[sizeof(response->message) - 1] = '\0';
    return 0;
}
