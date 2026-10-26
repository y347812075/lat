#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "latcd-client.h"
#include "latcd-protocol.h"
#include "lat-key-journal.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static int latcd_client_operation_timeout(uint32_t operation)
{
    const char *name;
    int fallback;
    if (operation == LATCD_OP_SUBMIT_KEYS ||
        operation == LATCD_OP_SUBMIT_STATIC_KEYS) {
        name = "LATX_AOT_V2_SUBMIT_TIMEOUT_MS";
        fallback = 5000;
    } else if (operation == LATCD_OP_HELLO) {
        name = "LATX_AOT_V2_HELLO_TIMEOUT_MS";
        fallback = 3000;
    } else {
        return 120000;
    }
    const char *value = getenv(name);
    if (value && *value) {
        char *end = NULL;
        long parsed = strtol(value, &end, 10);
        if (end && !*end && parsed > 0 && parsed <= 600000) {
            return (int)parsed;
        }
    }
    return fallback;
}

static int connect_daemon(const char *socket_path,
                           char *error, size_t error_size)
{
    if (!socket_path || !*socket_path) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd client arguments");
    }
    int socket_fd = socket(AF_UNIX,
                           SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return fail(error, error_size, "cannot create latcd socket: %s",
                    strerror(errno));
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int directory_fd;
    if (latcd_socket_address(socket_path, &address, &directory_fd, error, error_size)) {
        close(socket_fd);
        return -1;
    }
    int connected = connect(socket_fd, (const void *)&address, sizeof(address));
    int connect_error = errno;
    if (directory_fd >= 0) close(directory_fd);
    if (connected) {
        int saved = connect_error;
        close(socket_fd);
        errno = saved;
        return fail(error, error_size, "cannot connect to latcd: %s",
                    strerror(saved));
    }
    struct ucred credentials;
    socklen_t credentials_size = sizeof(credentials);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_size) ||
        credentials_size != sizeof(credentials) ||
        credentials.uid != geteuid()) {
        close(socket_fd);
        errno = EPERM;
        return fail(error, error_size, "latcd peer is not the current user");
    }
    return socket_fd;
}

static int receive_response(int socket_fd, uint32_t operation,
                             uint64_t request_id, const char *build_id,
                             const uint8_t cache_identity[32],
                             LatcdResponseV2 *output, int *directory_fd,
                             char *error, size_t error_size)
{
    if (directory_fd) *directory_fd = -1;
    struct pollfd event = { .fd = socket_fd, .events = POLLIN };
    int timeout = latcd_client_operation_timeout(operation);
    int ready;
    do {
        ready = poll(&event, 1, timeout);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0 || !(event.revents & POLLIN)) {
        int saved = ready == 0 ? ETIMEDOUT :
                    (ready < 0 ? errno : ECONNRESET);
        errno = saved;
        return fail(error, error_size, "latcd did not finish request: %s",
                    strerror(saved));
    }
    LatcdResponseV2 response;
    int descriptor = -1;
    if (latcd_receive_response_fd(socket_fd, &response,
            directory_fd ? &descriptor : NULL, error, error_size)) {
        return -1;
    }
    if (response.request_id != request_id) {
        if (descriptor >= 0) close(descriptor);
        errno = EPROTO;
        return fail(error, error_size, "latcd response id does not match");
    }
    if (response.status != LATCD_STATUS_OK) {
        if (descriptor >= 0) close(descriptor);
        errno = EIO;
        return fail(error, error_size, "latcd rejected request: %s",
                    response.message[0] ? response.message : "unknown error");
    }
    if (build_id && (strcmp(response.message, build_id) ||
        (cache_identity && memcmp(response.source_sha256, cache_identity, 32)))) {
        if (descriptor >= 0) close(descriptor);
        errno = EPROTO;
        return fail(error, error_size, "latcd build or cache identity mismatch");
    }
    if (directory_fd) *directory_fd = descriptor;
    if (output) *output = response;
    return 0;
}

static int exchange(const char *socket_path, int source_fd, int keys_fd,
                    uint32_t operation, uint32_t priority,
                    uint64_t request_id, uint64_t sequence,
                    const char *build_id, const uint8_t cache_identity[32],
                    char *error, size_t error_size)
{
    int socket_fd = connect_daemon(socket_path, error, error_size);
    if (socket_fd < 0) {
        return -1;
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request),
        .operation = operation,
        .priority = priority,
        .request_id = request_id,
        .sequence = sequence,
    };
    if (latcd_send_request(socket_fd, source_fd, keys_fd, &request,
                           error, error_size)) {
        close(socket_fd);
        return -1;
    }
    int result = receive_response(socket_fd, operation, request_id, build_id,
                                    cache_identity, NULL, NULL, error, error_size);
    int saved = errno;
    close(socket_fd);
    errno = saved;
    return result;
}

int latcd_client_open_channel(const char *socket_path, const char *build_id,
                              const uint8_t cache_identity[32],
                              char *error, size_t error_size)
{
    if (!build_id || !*build_id) {
        errno = EINVAL;
        return fail(error, error_size, "missing channel build identity");
    }
    int channel = connect_daemon(socket_path, error, error_size);
    if (channel < 0) {
        return -1;
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request), .operation = LATCD_OP_OPEN_CHANNEL,
        .request_id = 1,
    };
    if (latcd_send_request(channel, -1, -1, &request, error, error_size) ||
        receive_response(channel, LATCD_OP_HELLO, request.request_id, build_id,
                          cache_identity, NULL, NULL, error, error_size)) {
        int saved = errno;
        close(channel);
        errno = saved;
        return -1;
    }
    return channel;
}

int latcd_client_channel_submit_keys_fd(int channel_fd, int source_fd,
                                        int keys_fd, uint32_t priority,
                                        uint64_t request_id, uint64_t sequence,
                                        char *error, size_t error_size)
{
    if (channel_fd < 0) {
        errno = EINVAL;
        return fail(error, error_size, "invalid channel descriptor");
    }
    int replies[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    0, replies)) {
        return fail(error, error_size, "cannot create channel reply: %s",
                    strerror(errno));
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request), .operation = LATCD_OP_SUBMIT_KEYS,
        .priority = priority, .request_id = request_id, .sequence = sequence,
    };
    int result = latcd_send_channel_request(channel_fd, source_fd, keys_fd,
        replies[1], &request, error, error_size);
    close(replies[1]);
    if (!result) {
        result = receive_response(replies[0], request.operation, request_id,
                                    NULL, NULL, NULL, NULL, error, error_size);
    }
    int saved = errno;
    close(replies[0]);
    errno = saved;
    return result;
}

static int register_journal(const char *path, int channel, int source, int config,
                              const uint8_t digest[32], uint64_t capacity,
                              uint64_t request_id, char epoch[33], int *directory_fd,
                              char *error, size_t error_size)
{
    if (epoch) epoch[0] = 0;
    if (directory_fd) *directory_fd = -1;
    if (!epoch || !digest || source < 0 || config < 0 || !capacity ||
        capacity > LAT_KEY_JOURNAL_MAX_SLOTS || (!path && channel < 0)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid journal registration arguments");
    }
    int socket_fd, replies[2] = {-1, -1};
    if (path) {
        socket_fd = connect_daemon(path, error, error_size);
        if (socket_fd < 0) return -1;
    } else {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         0, replies))
            return fail(error, error_size, "cannot create journal reply: %s", strerror(errno));
        socket_fd = replies[0];
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request), .operation = LATCD_OP_REGISTER_JOURNAL,
        .request_id = request_id, .sequence = capacity,
    };
    if (directory_fd) request.operation = LATCD_OP_REGISTER_JOURNAL_CAPABILITY;
    int result = path ? latcd_send_request(socket_fd, source, config, &request, error, error_size) :
        latcd_send_channel_request(channel, source, config, replies[1], &request, error, error_size);
    if (replies[1] >= 0) close(replies[1]);
    LatcdResponseV2 response;
    int descriptor = -1;
    if (!result) result = receive_response(socket_fd, request.operation, request_id,
        NULL, NULL, &response, directory_fd ? &descriptor : NULL, error, error_size);
    if (!result) {
        bool valid = !memcmp(response.source_sha256, digest, 32) &&
            !response.accepted_sequence && !response.published_sequence &&
            strlen(response.message) == 32;
        for (unsigned i = 0; valid && i < 32; i++) {
            char c = response.message[i];
            valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }
        if (valid && directory_fd) {
            struct stat st;
            valid = !fstat(descriptor, &st) && S_ISDIR(st.st_mode) &&
                st.st_uid == geteuid() && (st.st_mode & 0777) == 0700;
        }
        if (!valid) {
            errno = EPROTO;
            result = fail(error, error_size, "invalid journal registration identity or watermarks");
        } else {
            memcpy(epoch, response.message, 33);
            if (directory_fd) *directory_fd = descriptor;
        }
    }
    int saved = errno;
    if (result && descriptor >= 0) close(descriptor);
    close(socket_fd);
    errno = saved;
    return result;
}

int latcd_client_register_journal(const char *path, int source, int config,
                                   const uint8_t digest[32], uint64_t capacity,
                                   uint64_t request_id, char epoch[33],
                                   char *error, size_t error_size)
{
    return register_journal(path, -1, source, config, digest, capacity, request_id,
                             epoch, NULL, error, error_size);
}

int latcd_client_channel_register_journal(int channel, int source, int config,
                                           const uint8_t digest[32], uint64_t capacity,
                                           uint64_t request_id, char epoch[33],
                                           char *error, size_t error_size)
{
    return register_journal(NULL, channel, source, config, digest, capacity, request_id,
                             epoch, NULL, error, error_size);
}

int latcd_client_register_journal_capability(const char *path, int source, int config,
    const uint8_t digest[32], uint64_t capacity, uint64_t request_id, char epoch[33],
    int *directory_fd, char *error, size_t error_size)
{
    if (!directory_fd) {
        if (epoch) epoch[0] = 0;
        errno = EINVAL;
        return fail(error, error_size, "missing journal directory output");
    }
    return register_journal(path, -1, source, config, digest, capacity, request_id,
                             epoch, directory_fd, error, error_size);
}

int latcd_client_channel_register_journal_capability(int channel, int source, int config,
    const uint8_t digest[32], uint64_t capacity, uint64_t request_id, char epoch[33],
    int *directory_fd, char *error, size_t error_size)
{
    if (!directory_fd) {
        if (epoch) epoch[0] = 0;
        errno = EINVAL;
        return fail(error, error_size, "missing journal directory output");
    }
    return register_journal(NULL, channel, source, config, digest, capacity, request_id,
                             epoch, directory_fd, error, error_size);
}

int latcd_client_hello(const char *socket_path, const char *build_id,
                        const uint8_t cache_identity[32],
                        char *error, size_t error_size)
{
    return exchange(socket_path, -1, -1, LATCD_OP_HELLO,
                    0, 1, 0, build_id, cache_identity, error, error_size);
}

int latcd_client_submit_keys_fd(const char *socket_path, int source_fd,
                                int keys_fd, uint32_t priority,
                                uint64_t request_id, uint64_t sequence,
                                char *error, size_t error_size)
{
    return exchange(socket_path, source_fd, keys_fd, LATCD_OP_SUBMIT_KEYS,
                    priority, request_id, sequence, NULL, NULL, error, error_size);
}

int latcd_client_flush_source(const char *socket_path, int source_fd,
                              uint64_t request_id,
                              char *error, size_t error_size)
{
    return exchange(socket_path, source_fd, -1, LATCD_OP_FLUSH_SOURCE,
                    LATCD_PRIORITY_STARTUP, request_id, 0, NULL, NULL,
                    error, error_size);
}

int latcd_client_flush_all(const char *socket_path, uint64_t request_id,
                           char *error, size_t error_size)
{
    return exchange(socket_path, -1, -1, LATCD_OP_FLUSH_ALL,
                    LATCD_PRIORITY_STARTUP, request_id, 0, NULL, NULL,
                    error, error_size);
}

int latcd_client_precompile_source(const char *socket_path, int source_fd,
                                   uint64_t request_id,
                                   char *error, size_t error_size)
{
    return exchange(socket_path, source_fd, -1,
                    LATCD_OP_PRECOMPILE_SOURCE, LATCD_PRIORITY_STARTUP,
                    request_id, 0, NULL, NULL, error, error_size);
}
