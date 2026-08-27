#define _GNU_SOURCE

#include "latcd-protocol.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *message)
{
    fprintf(stderr, "test-latcd-protocol: %s\n", message);
    return 1;
}

static int send_raw_request(int socket_fd, const LatcdRequestV1 *request,
                            const int *fds, size_t fd_count)
{
    struct iovec iov = {
        .iov_base = (void *)request,
        .iov_len = sizeof(*request),
    };
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 8)];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    if (fd_count) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
    }
    return sendmsg(socket_fd, &message, 0) == sizeof(*request) ? 0 : -1;
}

int main(void)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets)) {
        return fail("socketpair failed");
    }
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    LatcdRequestV1 sent = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(sent),
        .priority = LATCD_PRIORITY_STARTUP,
        .request_id = 42,
    };
    char error[128] = {0};
    if (source < 0 || latcd_send_request(sockets[0], source, -1, &sent,
                                         error, sizeof(error))) {
        return fail(error);
    }
    LatcdRequestV1 received;
    int received_fd = -1;
    int received_profile = -1;
    if (latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_profile,
                              error, sizeof(error)) ||
        received.request_id != sent.request_id || received_fd < 0 ||
        received_profile >= 0) {
        return fail(error[0] ? error : "valid request changed in transit");
    }
    close(received_fd);

    sent.flags = LATCD_REQUEST_HAS_PROFILE;
    if (latcd_send_request(sockets[0], source, source, &sent,
                           error, sizeof(error)) ||
        latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_profile, error, sizeof(error)) ||
        received_fd < 0 || received_profile < 0 ||
        !(received.flags & LATCD_REQUEST_HAS_PROFILE)) {
        return fail(error[0] ? error : "profile request changed in transit");
    }
    close(received_fd);
    close(received_profile);
    sent.flags = 0;

    if (send_raw_request(sockets[0], &sent, NULL, 0)) {
        return fail("cannot send request without descriptor");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_profile,
                               error, sizeof(error)) ||
        !strstr(error, "descriptor count")) {
        return fail("request without descriptor was accepted");
    }

    int two_fds[2] = { source, source };
    if (send_raw_request(sockets[0], &sent, two_fds, 2)) {
        return fail("cannot send request with two descriptors");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_profile,
                               error, sizeof(error)) ||
        !strstr(error, "descriptor count")) {
        return fail("request with two descriptors was accepted");
    }

    int many_fds[5] = { source, source, source, source, source };
    if (send_raw_request(sockets[0], &sent, many_fds, 5)) {
        return fail("cannot send request with truncated descriptor set");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_profile,
                               error, sizeof(error)) ||
        !strstr(error, "invalid latcd request packet")) {
        return fail("truncated descriptor set was accepted");
    }

    sent.magic ^= 1;
    if (send_raw_request(sockets[0], &sent, &source, 1)) {
        return fail("cannot send request with invalid header");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_profile,
                               error, sizeof(error)) ||
        !strstr(error, "header or descriptor")) {
        return fail("request with invalid header was accepted");
    }

    close(source);
    close(sockets[0]);
    close(sockets[1]);
    puts("latcd protocol tests: PASS");
    return 0;
}
