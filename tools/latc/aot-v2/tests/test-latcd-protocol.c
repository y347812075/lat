#define _GNU_SOURCE

#include "latcd-protocol.h"

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *message)
{
    fprintf(stderr, "test-latcd-protocol: %s\n", message);
    return 1;
}

static int send_raw_packet(int socket_fd, const void *packet, size_t size,
                           const int *fds, size_t fd_count)
{
    struct iovec iov = {
        .iov_base = (void *)packet,
        .iov_len = size,
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
    return sendmsg(socket_fd, &message, 0) == (ssize_t)size ? 0 : -1;
}

static int send_raw_request(int socket_fd, const LatcdRequestV2 *request,
                            const int *fds, size_t fd_count)
{
    return send_raw_packet(socket_fd, request, sizeof(*request), fds, fd_count);
}

static unsigned open_descriptor_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 0;
    unsigned count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
}

static int test_response_fds(int sender, int receiver, int source)
{
    char error[128];
    for (unsigned variant = 0; variant < 12; variant++) {
        LatcdResponseV2 sent = {
            .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(sent), .request_id = 9,
        }, response;
        int fds[8] = {source, source, source, source, source, source, source, source};
        size_t count = 1, size = sizeof(sent);
        if (variant == 1) count = 0;
        if (variant == 2) count = 2;
        if (variant == 3) count = 8;
        if (variant == 4) sent.magic ^= 1;
        if (variant == 5) size--;
        if (variant == 6) sent.reserved = 1;
        if (variant == 7 || variant == 8) sent.status = LATCD_STATUS_BAD_REQUEST;
        if (variant == 8) count = 0;
        if (variant == 9) sent.version++;
        if (variant == 10) sent.size--;
        unsigned before = open_descriptor_count();
        if (send_raw_packet(sender, &sent, size, fds, count)) return fail("send response fds");
        int output = 123;
        int result = latcd_receive_response_fd(receiver, &response,
            variant == 11 ? NULL : &output, error, sizeof(error));
        if (variant == 0) {
            if (result || output < 0 || !(fcntl(output, F_GETFD) & FD_CLOEXEC))
                return fail("valid response fd rejected");
            close(output);
        } else if (variant == 8) {
            if (result || output != -1 || response.status != LATCD_STATUS_BAD_REQUEST)
                return fail("fd-free rejection rejected");
        } else if (!result || errno != EPROTO || (variant != 11 && output != -1)) {
            return fail("invalid response ancillary/header accepted");
        }
        if (open_descriptor_count() != before) return fail("response fd leak");
    }
    LatcdResponseV2 sent = {
        .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(sent), .request_id = 10,
    }, received;
    int output;
    if (latcd_send_response_fd(sender, &sent, source, error, sizeof(error)) ||
        latcd_receive_response_fd(receiver, &received, &output, error, sizeof(error)))
        return fail(error);
    close(output);
    sent.status = LATCD_STATUS_BAD_REQUEST;
    if (!latcd_send_response_fd(sender, &sent, source, error, sizeof(error)) || errno != EINVAL)
        return fail("error response allowed fd transfer");
    return 0;
}

static int test_reply_backpressure(int source)
{
    int pair[2], ready[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) || pipe(ready))
        return fail("cannot create backpressure fixture");
    int buffer = 4096;
    if (setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer))) return fail("send buffer");
    LatcdResponseV2 response = {
        .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response),
    };
    char error[128];
    unsigned sent = 0;
    while (!latcd_send_response_fd(pair[0], &response, source, error, sizeof(error))) {
        if (++sent > 10000) return fail("unbounded reply queue");
    }
    if (!sent || (errno != EAGAIN && errno != EWOULDBLOCK)) return fail("missing reply backpressure");
    pid_t child = fork();
    if (child < 0) return fail("fork backpressure sender");
    if (!child) {
        close(ready[0]);
        close(pair[1]);
        if (write(ready[1], "s", 1) != 1) _exit(1);
        int result = latcd_send_response(pair[0], &response, error, sizeof(error));
        if (write(ready[1], result ? "f" : "d", 1) != 1) _exit(2);
        _exit(result != 0);
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1 || byte != 's') return fail("sender startup");
    struct pollfd event = {.fd = ready[0], .events = POLLIN};
    if (poll(&event, 1, 100) != 0) return fail("legacy reply stopped blocking");
    for (unsigned i = 0; i < sent; i++) {
        int received;
        if (latcd_receive_response_fd(pair[1], &response, &received, error, sizeof(error)))
            return fail(error);
        close(received);
    }
    if (poll(&event, 1, 2000) != 1 || read(ready[0], &byte, 1) != 1 || byte != 'd')
        return fail("legacy reply did not resume");
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        return fail("backpressure sender failed");
    if (latcd_receive_response(pair[1], &response, error, sizeof(error))) return fail(error);
    close(ready[0]); close(pair[0]); close(pair[1]);
    return 0;
}

static int test_channel(int sender, int receiver, int source)
{
    char error[256];
    for (unsigned operation = LATCD_OP_SUBMIT_KEYS;
         operation <= LATCD_OP_REGISTER_JOURNAL_CAPABILITY; operation++) {
        LatcdRequestV2 sent = {
            .magic = LATCD_REQUEST_MAGIC,
            .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(sent),
            .operation = operation,
            .request_id = operation,
        };
        int replies[2][2];
        for (unsigned i = 0; i < 2; i++) {
            if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                           0, replies[i])) {
                return fail("cannot create independent reply socket");
            }
            sent.request_id = 100 + i;
            if (latcd_send_channel_request(sender, source, source,
                    replies[i][1], &sent, error, sizeof(error))) {
                return fail(error);
            }
            close(replies[i][1]);
        }
        int received_replies[2];
        for (unsigned i = 0; i < 2; i++) {
            LatcdRequestV2 request;
            int received_source, received_keys;
            if (latcd_receive_channel_request(receiver, &request,
                    &received_source, &received_keys, &received_replies[i],
                    error, sizeof(error)) ||
                request.magic != LATCD_REQUEST_MAGIC ||
                request.operation != operation || request.request_id != 100 + i) {
                return fail("channel request changed in transit");
            }
            int expected = operation == LATCD_OP_SUBMIT_KEYS ||
                           operation == LATCD_OP_SUBMIT_STATIC_KEYS ||
                           operation == LATCD_OP_REGISTER_JOURNAL ||
                           operation == LATCD_OP_REGISTER_JOURNAL_CAPABILITY ? 2 :
                           operation == LATCD_OP_FLUSH_SOURCE ||
                           operation == LATCD_OP_PRECOMPILE_SOURCE ? 1 : 0;
            if ((received_source >= 0) != (expected >= 1) ||
                (received_keys >= 0) != (expected == 2) ||
                !(fcntl(received_replies[i], F_GETFD) & FD_CLOEXEC)) {
                return fail("channel descriptor ownership is invalid");
            }
            if (received_source >= 0) close(received_source);
            if (received_keys >= 0) close(received_keys);
        }
        /* Reversed responses must still reach the matching sender. */
        for (unsigned i = 2; i-- > 0;) {
            LatcdResponseV2 response = {
                .magic = LATCD_RESPONSE_MAGIC,
                .version = LATCD_PROTOCOL_VERSION,
                .size = sizeof(response),
                .request_id = 100 + i,
            };
            if (latcd_send_response(received_replies[i], &response,
                                    error, sizeof(error))) {
                return fail(error);
            }
            close(received_replies[i]);
        }
        for (unsigned i = 0; i < 2; i++) {
            LatcdResponseV2 response;
            if (latcd_receive_response(replies[i][0], &response,
                                       error, sizeof(error)) ||
                response.request_id != 100 + i) {
                return fail("channel responses crossed senders");
            }
            close(replies[i][0]);
        }
    }
    for (unsigned variant = 0; variant < 11; variant++) {
        int reply[2];
        int type = variant == 3 ? SOCK_STREAM : SOCK_SEQPACKET;
        if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, reply)) {
            return fail("cannot create malformed reply fixture");
        }
        if (variant == 10) {
            close(reply[1]);
            reply[1] = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
            if (reply[1] < 0) return fail("cannot create unconnected reply");
        }
        LatcdRequestV2 sent = {
            .magic = LATCD_CHANNEL_REQUEST_MAGIC,
            .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(sent),
            .operation = LATCD_OP_HELLO,
        };
        int fds[5] = { reply[1], source, source, source, source };
        size_t count = 1;
        if (variant == 0) count = 0;
        if (variant == 1) count = 2;
        if (variant == 2) fds[0] = source;
        if (variant == 4) sent.magic = LATCD_REQUEST_MAGIC;
        if (variant == 5) sent.operation = 99;
        if (variant == 6) count = 5;
        if (variant == 7) sent.size--;
        unsigned char packet[sizeof(sent) + 1] = {0};
        memcpy(packet, &sent, sizeof(sent));
        size_t packet_size = sizeof(sent);
        if (variant == 8) packet_size--;
        if (variant == 9) packet_size++;
        unsigned before = open_descriptor_count();
        if (!before || send_raw_packet(sender, packet, packet_size, fds, count)) {
            return fail("cannot send malformed channel request");
        }
        LatcdRequestV2 received;
        int received_source, received_keys, received_reply;
        errno = 0;
        if (!latcd_receive_channel_request(receiver, &received,
                &received_source, &received_keys, &received_reply,
                error, sizeof(error)) || errno != EPROTO ||
            received_source != -1 || received_keys != -1 || received_reply != -1) {
            return fail("malformed channel request was accepted or leaked outputs");
        }
        if (open_descriptor_count() != before) {
            return fail("malformed channel request leaked descriptors");
        }
        close(reply[0]);
        close(reply[1]);
    }
    LatcdRequestV2 sent = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(sent), .operation = LATCD_OP_HELLO,
    };
    if (!latcd_send_channel_request(sender, -1, -1, -1, &sent,
                                    error, sizeof(error)) || errno != EINVAL) {
        return fail("missing reply descriptor was accepted");
    }
    return 0;
}

int main(void)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets)) {
        return fail("socketpair failed");
    }
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0 || test_response_fds(sockets[0], sockets[1], source)) return 1;
    if (test_reply_backpressure(source)) return 1;
    LatcdRequestV2 sent = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(sent),
        .priority = LATCD_PRIORITY_STARTUP,
        .operation = LATCD_OP_SUBMIT_KEYS,
        .request_id = 42,
    };
    char error[128] = {0};
    if (source < 0 || latcd_send_request(sockets[0], source, source, &sent,
                                         error, sizeof(error))) {
        return fail(error);
    }
    LatcdRequestV2 received;
    int received_fd = -1;
    int received_tbset = -1;
    if (latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_tbset,
                              error, sizeof(error)) ||
        received.request_id != sent.request_id || received_fd < 0 ||
        received_tbset < 0 ||
        received.operation != LATCD_OP_SUBMIT_KEYS) {
        return fail(error[0] ? error : "valid request changed in transit");
    }
    close(received_fd);
    close(received_tbset);

    sent.operation = LATCD_OP_FLUSH_ALL;

    if (send_raw_request(sockets[0], &sent, NULL, 0)) {
        return fail("cannot send flush-all request");
    }
    error[0] = '\0';
    if (latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_tbset, error, sizeof(error)) ||
        received_fd >= 0 || received_tbset >= 0) {
        return fail("valid flush-all request was rejected");
    }

    int two_fds[2] = { source, source };
    sent.operation = LATCD_OP_FLUSH_SOURCE;
    if (send_raw_request(sockets[0], &sent, &source, 1)) {
        return fail("cannot send flush-source request");
    }
    if (latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_tbset, error, sizeof(error)) ||
        received_fd < 0 || received_tbset >= 0) {
        return fail("valid flush-source request was rejected");
    }
    close(received_fd);

    sent.operation = LATCD_OP_PRECOMPILE_SOURCE;
    if (send_raw_request(sockets[0], &sent, &source, 1)) {
        return fail("cannot send precompile request");
    }
    if (latcd_receive_request(sockets[1], &received, &received_fd,
                              &received_tbset, error, sizeof(error)) ||
        received_fd < 0 || received_tbset >= 0 ||
        received.operation != LATCD_OP_PRECOMPILE_SOURCE) {
        return fail("valid precompile request was rejected");
    }
    close(received_fd);

    if (send_raw_request(sockets[0], &sent, two_fds, 2)) {
        return fail("cannot send request with two descriptors");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_tbset,
                               error, sizeof(error)) ||
        !strstr(error, "descriptor count")) {
        return fail("one-FD request with two descriptors was accepted");
    }

    int many_fds[5] = { source, source, source, source, source };
    if (send_raw_request(sockets[0], &sent, many_fds, 5)) {
        return fail("cannot send request with truncated descriptor set");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_tbset,
                               error, sizeof(error)) ||
        !strstr(error, "header or descriptor")) {
        return fail("truncated descriptor set was accepted");
    }

    sent.operation = 99;
    sent.magic ^= 1;
    if (send_raw_request(sockets[0], &sent, &source, 1)) {
        return fail("cannot send request with invalid header");
    }
    error[0] = '\0';
    if (!latcd_receive_request(sockets[1], &received, &received_fd,
                               &received_tbset,
                               error, sizeof(error)) ||
        !strstr(error, "header or descriptor")) {
        return fail("request with invalid header was accepted");
    }

    if (test_channel(sockets[0], sockets[1], source)) {
        return 1;
    }
    close(source);
    close(sockets[0]);
    close(sockets[1]);
    puts("latcd protocol tests: PASS");
    return 0;
}
