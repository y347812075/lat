#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "latcd-client.h"
#include "latcd-protocol.h"
#include "lat-key-journal.h"

#include <errno.h>
#include <glib.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
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
    } else if (operation == LATCD_OP_APPEND_JOURNAL) {
        name = "LATX_AOT_V2_JOURNAL_TIMEOUT_MS";
        fallback = LATCD_BROKER_REQUEST_TIMEOUT_MS;
    } else if (operation == LATCD_OP_HELLO ||
               operation == LATCD_OP_PREPARE_SOURCE_LOCK) {
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

static int connect_daemon_protected(const char *socket_path,
                           uid_t expected_uid,
                           const LatcdClientFdProtection *protection,
                           char *error, size_t error_size)
{
    if (!socket_path || !*socket_path) {
        errno = EINVAL;
        return fail(error, error_size, "invalid latcd client arguments");
    }
    if (protection) protection->allocation_lock();
    int socket_fd = socket(AF_UNIX,
                           SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        int saved = errno; if (protection) protection->unlock(); errno = saved;
        return fail(error, error_size, "cannot create latcd socket: %s",
                    strerror(errno));
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int directory_fd;
    if (latcd_socket_address(socket_path, &address, &directory_fd, error, error_size)) {
        int saved = errno;
        close(socket_fd);
        if (protection) protection->unlock();
        errno = saved;
        return -1;
    }
    int connected = connect(socket_fd, (const void *)&address, sizeof(address));
    int connect_error = errno;
    if (directory_fd >= 0) close(directory_fd);
    if (connected) {
        int saved = connect_error;
        close(socket_fd);
        if (protection) protection->unlock();
        errno = saved;
        return fail(error, error_size, "cannot connect to latcd: %s",
                    strerror(saved));
    }
    if (protection && protection->register_locked(socket_fd)) {
        int saved = errno; close(socket_fd); protection->unlock(); errno = saved;
        return fail(error, error_size, "cannot protect latcd socket: %s", strerror(errno));
    }
    if (protection) protection->unlock();
    struct ucred credentials;
    socklen_t credentials_size = sizeof(credentials);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_size) ||
        credentials_size != sizeof(credentials) ||
        credentials.uid != expected_uid) {
        if (protection) protection->close_fd(socket_fd); else close(socket_fd);
        errno = EPERM;
        return fail(error, error_size, "latcd peer UID does not match");
    }
    return socket_fd;
}

static int connect_daemon(const char *socket_path, char *error, size_t error_size)
{
    return connect_daemon_protected(socket_path, geteuid(), NULL, error, error_size);
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
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return fail(error, error_size, "cannot read request clock: %s", strerror(errno));
    int64_t deadline = (int64_t)now.tv_sec * 1000000000 + now.tv_nsec +
                       (int64_t)timeout * 1000000;
    int ready;
    for (;;) {
        ready = poll(&event, 1, timeout);
        if (ready >= 0 || errno != EINTR) break;
        if (clock_gettime(CLOCK_MONOTONIC, &now))
            return fail(error, error_size, "cannot read request clock: %s", strerror(errno));
        int64_t remaining = deadline - ((int64_t)now.tv_sec * 1000000000 + now.tv_nsec);
        if (remaining <= 0) { ready = 0; break; }
        timeout = (int)((remaining + 999999) / 1000000);
    }
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

int latcd_client_open_channel_protected(const char *socket_path, const char *build_id,
    const uint8_t cache_identity[32], const LatcdClientFdProtection *protection,
    char *error, size_t error_size)
{
    if (!build_id || !*build_id || (protection &&
        (!protection->allocation_lock || !protection->unlock ||
         !protection->register_locked || !protection->close_fd))) {
        errno = EINVAL;
        return fail(error, error_size, "missing channel build identity");
    }
    int channel = connect_daemon_protected(socket_path, geteuid(), protection, error, error_size);
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
        if (protection) protection->close_fd(channel); else close(channel);
        errno = saved;
        return -1;
    }
    return channel;
}

int latcd_client_open_channel(const char *socket_path, const char *build_id,
                              const uint8_t cache_identity[32],
                              char *error, size_t error_size)
{
    return latcd_client_open_channel_protected(socket_path, build_id, cache_identity,
                                               NULL, error, error_size);
}

int latcd_client_channel_prepare_source_lock_protected(int channel_fd, int cache_fd,
    const uint8_t digest[32], uint64_t request_id, bool *sent,
    const LatcdClientFdProtection *protection, char *error, size_t error_size)
{
    if (sent) *sent = false;
    if (channel_fd < 0 || cache_fd < 0 || !digest || (protection &&
        (!protection->allocation_lock || !protection->unlock ||
         !protection->register_locked || !protection->close_fd))) {
        errno = EINVAL;
        return fail(error, error_size, "invalid source lock request");
    }
    if (protection) protection->allocation_lock();
    int data = memfd_create("latcd-source-digest", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (data >= 0 && protection && protection->register_locked(data)) {
        int saved = errno; close(data); data = -1; errno = saved;
    }
    int saved = errno;
    if (protection) protection->unlock();
    errno = saved;
    if (data < 0) return fail(error, error_size, "cannot create digest descriptor: %s", strerror(errno));
    ssize_t written;
    do { written = write(data, digest, 32); } while (written < 0 && errno == EINTR);
    if (written != 32 || fcntl(data, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) {
        int saved = written >= 0 && written != 32 ? EIO : errno;
        if (protection) protection->close_fd(data); else close(data);
        errno = saved;
        return fail(error, error_size, "cannot seal source digest: %s", strerror(errno));
    }
    int replies[2];
    if (protection) protection->allocation_lock();
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, replies)) {
        int saved = errno;
        if (protection) protection->unlock();
        if (protection) protection->close_fd(data); else close(data);
        errno = saved;
        return fail(error, error_size, "cannot create lock reply: %s", strerror(errno));
    }
    if (protection && protection->register_locked(replies[0])) {
        int saved = errno; close(replies[0]); close(replies[1]); protection->unlock();
        protection->close_fd(data); errno = saved;
        return fail(error, error_size, "cannot protect lock reply: %s", strerror(errno));
    }
    if (protection && protection->register_locked(replies[1])) {
        int saved = errno; close(replies[1]); protection->unlock();
        protection->close_fd(replies[0]); protection->close_fd(data); errno = saved;
        return fail(error, error_size, "cannot protect lock reply: %s", strerror(errno));
    }
    if (protection) protection->unlock();
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request), .operation = LATCD_OP_PREPARE_SOURCE_LOCK,
        .request_id = request_id,
    };
    int result = latcd_send_channel_request(channel_fd, cache_fd, data, replies[1],
                                             &request, error, error_size);
    if (!result && sent) *sent = true;
    if (protection) { protection->close_fd(data); protection->close_fd(replies[1]); }
    else { close(data); close(replies[1]); }
    LatcdResponseV2 response;
    if (!result) result = receive_response(replies[0], request.operation, request_id,
                                            NULL, NULL, &response, NULL, error, error_size);
    if (!result && memcmp(response.source_sha256, digest, 32)) {
        errno = EPROTO;
        result = fail(error, error_size, "source lock response digest mismatch");
    }
    saved = errno;
    if (protection) protection->close_fd(replies[0]); else close(replies[0]);
    errno = saved;
    return result;
}

int latcd_client_channel_prepare_source_lock_ex(int channel_fd, int cache_fd,
    const uint8_t digest[32], uint64_t request_id, bool *sent,
    char *error, size_t error_size)
{
    return latcd_client_channel_prepare_source_lock_protected(channel_fd, cache_fd,
        digest, request_id, sent, NULL, error, error_size);
}

int latcd_client_channel_prepare_source_lock(int channel_fd, int cache_fd,
    const uint8_t digest[32], uint64_t request_id, char *error, size_t error_size)
{
    return latcd_client_channel_prepare_source_lock_ex(channel_fd, cache_fd,
        digest, request_id, NULL, error, error_size);
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

int latcd_client_broker_journal(const char *path, uid_t uid, int source, int config,
    const uint8_t digest[32], uint32_t operation, uint64_t request_id,
    uint64_t sequence, uint8_t epoch[16], const LatcdClientFdProtection *protection,
    char *error, size_t error_size)
{
    const int seals_required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = source < 0 ? -1 : fcntl(source, F_GET_SEALS);
    if (!digest || !epoch || config < 0 || seals < 0 ||
        (seals & seals_required) != seals_required ||
        (operation != LATCD_OP_REGISTER_JOURNAL && operation != LATCD_OP_APPEND_JOURNAL) ||
        (operation == LATCD_OP_REGISTER_JOURNAL && (!sequence || sequence > LAT_KEY_JOURNAL_MAX_SLOTS))) {
        errno = EINVAL;
        return fail(error, error_size, "invalid broker journal arguments");
    }
    LatcdBrokerJournalRequest request = {.version = LATCD_BROKER_JOURNAL_VERSION,
        .operation = operation, .request_id = request_id, .sequence = sequence};
    if (operation == LATCD_OP_APPEND_JOURNAL) memcpy(request.epoch, epoch, 16);
    int fd = connect_daemon_protected(path, uid, protection, error, error_size);
    if (fd < 0) return -1;
    int fds[2] = {source, config};
    struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(fds))]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(c), fds, sizeof(fds));
    ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    int result = 0;
    if (sent != sizeof(request)) {
        if (sent >= 0) errno = EIO;
        result = fail(error, error_size, "cannot send broker journal: %s", strerror(errno));
    }
    LatcdResponseV2 response;
    if (!result) result = receive_response(fd, operation, request_id, NULL, NULL,
                                           &response, NULL, error, error_size);
    uint8_t parsed[16];
    if (!result && operation == LATCD_OP_REGISTER_JOURNAL) {
        bool valid = strlen(response.message) == 32;
        for (unsigned i = 0; valid && i < 16; i++) {
            unsigned value = 0;
            for (unsigned j = 0; j < 2; j++) {
                char ch = response.message[2 * i + j];
                if (ch >= '0' && ch <= '9') value = value * 16 + ch - '0';
                else if (ch >= 'a' && ch <= 'f') value = value * 16 + ch - 'a' + 10;
                else { valid = false; break; }
            }
            parsed[i] = value;
        }
        if (!valid) { errno = EPROTO; result = fail(error, error_size, "invalid broker epoch"); }
    }
    if (!result && (memcmp(response.source_sha256, digest, 32) ||
                    response.accepted_sequence || response.published_sequence)) {
        errno = EPROTO; result = fail(error, error_size, "invalid broker journal identity");
    }
    if (!result && operation == LATCD_OP_REGISTER_JOURNAL) memcpy(epoch, parsed, 16);
    int saved = errno;
    if (protection) protection->close_fd(fd); else close(fd);
    errno = saved;
    return result;
}

int latcd_client_broker_load(const char *path, uid_t uid, int source, int config,
    uint64_t source_size, const uint8_t source_hash[32], const uint8_t config_hash[32],
    uint64_t request_id, const LatcdClientFdProtection *protection,
    char *error, size_t error_size)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int source_seals = source < 0 ? -1 : fcntl(source, F_GET_SEALS);
    int config_seals = config < 0 ? -1 : fcntl(config, F_GET_SEALS);
    if (!source_hash || !config_hash || !source_size || source_seals < 0 ||
        config_seals < 0 || (source_seals & required) != required ||
        (config_seals & required) != required || !protection ||
        !protection->allocation_lock || !protection->unlock ||
        !protection->register_locked || !protection->close_fd) {
        errno = EINVAL; return fail(error, error_size, "invalid broker load arguments");
    }
    int socket_fd = connect_daemon_protected(path, uid, protection, error, error_size);
    if (socket_fd < 0) return -1;
    LatcdBrokerLoadRequest request = {.version = LATCD_BROKER_LOAD_VERSION,
        .request_id = request_id, .source_size = source_size};
    memcpy(request.source_sha256, source_hash, 32);
    memcpy(request.config_sha256, config_hash, 32);
    int passed[2] = {source, config};
    struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(passed))]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(passed));
    memcpy(CMSG_DATA(c), passed, sizeof(passed));
    int output = -1;
    if (sendmsg(socket_fd, &msg, MSG_NOSIGNAL) != sizeof(request)) goto failed;
    struct pollfd event = {.fd = socket_fd, .events = POLLIN};
    int ready;
    do { ready = poll(&event, 1, LATCD_BROKER_REQUEST_TIMEOUT_MS); } while (ready < 0 && errno == EINTR);
    if (ready <= 0 || !(event.revents & POLLIN)) { errno = ETIMEDOUT; goto failed; }
    LatcdBrokerLoadResponse response;
    struct iovec received = {.iov_base = &response, .iov_len = sizeof(response)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int) * 8)]; } ancillary = {0};
    struct msghdr reply = {.msg_iov = &received, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
    protection->allocation_lock();
    ssize_t count = recvmsg(socket_fd, &reply, MSG_CMSG_CLOEXEC);
    unsigned fds = 0;
    bool valid = count == sizeof(response) && !(reply.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (c = CMSG_FIRSTHDR(&reply); c; c = CMSG_NXTHDR(&reply, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len < CMSG_LEN(0) || (c->cmsg_len - CMSG_LEN(0)) % sizeof(int)) {
            valid = false; continue;
        }
        size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < n; i++) {
            int fd; memcpy(&fd, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(fd));
            if (!fds++) output = fd; else close(fd);
        }
    }
    valid = valid && fds == 1 && response.version == LATCD_BROKER_LOAD_VERSION &&
        !response.status && response.purpose == LATCD_BROKER_LOAD_PURPOSE &&
        !response.reserved && response.request_id == request_id &&
        !memcmp(response.source_sha256, source_hash, 32) &&
        !memcmp(response.config_sha256, config_hash, 32);
    if (valid && protection->register_locked(output)) valid = false;
    if (!valid && output >= 0) { close(output); output = -1; }
    protection->unlock();
    if (!valid) {
        snprintf(error, error_size,
                 "invalid broker load response status=%u purpose=%u request=%llu fds=%u",
                 response.status, response.purpose,
                 (unsigned long long)response.request_id, fds);
        errno = EPROTO;
        goto failed;
    }
    struct stat st;
    int seals = fcntl(output, F_GET_SEALS);
    if (seals < 0 || (seals & required) != required || fstat(output, &st) ||
        !S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0555 || st.st_size <= 0 ||
        (uint64_t)st.st_size != response.module_size || response.module_size > (UINT64_C(1) << 30)) {
        errno = EPROTO; goto failed;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    if (!sum) { errno = ENOMEM; goto failed; }
    unsigned char buffer[65536], digest[32];
    off_t offset = 0;
    while (offset < st.st_size) {
        size_t wanted = MIN(sizeof(buffer), (uint64_t)(st.st_size - offset));
        ssize_t n = pread(output, buffer, wanted, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        g_checksum_update(sum, buffer, n); offset += n;
    }
    gsize digest_size = sizeof(digest);
    g_checksum_get_digest(sum, digest, &digest_size);
    g_checksum_free(sum);
    if (offset != st.st_size || memcmp(digest, response.module_sha256, 32)) {
        errno = EPROTO; goto failed;
    }
    protection->close_fd(socket_fd);
    return output;
failed: {
    int saved = errno ? errno : EIO;
    if (output >= 0) protection->close_fd(output);
    protection->close_fd(socket_fd);
    errno = saved;
    return fail(error, error_size, "broker load failed: %s", strerror(saved));
}
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

static int append_journal(const char *path, int channel, int source, int config,
                          const uint8_t digest[32], uint64_t journal_id,
                          uint64_t key_rva, char *error, size_t error_size)
{
    if (!digest || source < 0 || config < 0 || (!path && channel < 0)) {
        errno = EINVAL;
        return fail(error, error_size, "invalid journal append arguments");
    }
    int socket_fd, replies[2] = {-1, -1};
    if (path) {
        socket_fd = connect_daemon(path, error, error_size);
        if (socket_fd < 0) return -1;
    } else {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                       0, replies)) {
            return fail(error, error_size, "cannot create journal reply: %s",
                        strerror(errno));
        }
        socket_fd = replies[0];
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request), .operation = LATCD_OP_APPEND_JOURNAL,
        .request_id = journal_id, .sequence = key_rva,
    };
    int result = path ? latcd_send_request(socket_fd, source, config, &request,
                                            error, error_size) :
        latcd_send_channel_request(channel, source, config, replies[1], &request,
                                   error, error_size);
    if (replies[1] >= 0) close(replies[1]);
    LatcdResponseV2 response;
    if (!result) {
        result = receive_response(socket_fd, request.operation, journal_id,
                                  NULL, NULL, &response, NULL, error, error_size);
    }
    if (!result && (memcmp(response.source_sha256, digest, 32) ||
                    response.accepted_sequence || response.published_sequence)) {
        errno = EPROTO;
        result = fail(error, error_size,
                      "invalid journal append identity or watermarks");
    }
    int saved = errno;
    close(socket_fd);
    errno = saved;
    return result;
}

int latcd_client_append_journal(const char *path, int source, int config,
    const uint8_t digest[32], uint64_t journal_id, uint64_t key_rva,
    char *error, size_t error_size)
{
    return append_journal(path, -1, source, config, digest, journal_id, key_rva,
                          error, error_size);
}

int latcd_client_channel_append_journal(int channel, int source, int config,
    const uint8_t digest[32], uint64_t journal_id, uint64_t key_rva,
    char *error, size_t error_size)
{
    return append_journal(NULL, channel, source, config, digest, journal_id,
                          key_rva, error, error_size);
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
