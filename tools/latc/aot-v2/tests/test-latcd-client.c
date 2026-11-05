#define _GNU_SOURCE

#include "latcd-client.h"
#include "latcd-protocol.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *message)
{
    fprintf(stderr, "test-latcd-client: %s\n", message);
    return 1;
}

static int fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    }
    closedir(directory);
    return count;
}

static void test_lock(void) { }
static int test_register(int fd) { return fd < 0 ? -1 : 0; }
static void test_close(int fd) { close(fd); }

static int test_broker_load(int server, const char *path)
{
    int input = memfd_create("load-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    int module = memfd_create("load-module", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (input < 0 || module < 0 || write(input, "x", 1) != 1 ||
        write(module, "module", 6) != 6 || fchmod(module, 0555) ||
        fcntl(input, F_ADD_SEALS, seals) || fcntl(module, F_ADD_SEALS, seals))
        return fail("load fixture");
    for (unsigned variant = 0; variant < 4; variant++) {
        pid_t child = fork();
        if (child < 0) return fail("fork load client");
        if (!child) {
            uint8_t source_hash[32] = {7}, config_hash[32] = {8};
            LatcdClientFdProtection protection = {test_lock, test_lock, test_register, test_close};
            char error[256];
            int before = fd_count();
            int fd = latcd_client_broker_load(path, geteuid(), input, input, 1,
                source_hash, config_hash, 71, &protection, error, sizeof(error));
            if (fd >= 0) close(fd);
            _exit(fd_count() != before || (variant == 0 ? fd < 0 : fd >= 0));
        }
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        LatcdBrokerLoadRequest request;
        union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control = {0};
        struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
        if (client < 0 || recvmsg(client, &msg, MSG_CMSG_CLOEXEC) != sizeof(request))
            return fail("load request");
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len != CMSG_LEN(2 * sizeof(int)) || request.request_id != 71)
            return fail("load request identity");
        int received[2]; memcpy(received, CMSG_DATA(c), sizeof(received));
        close(received[0]); close(received[1]);
        LatcdBrokerLoadResponse response = {.version = LATCD_BROKER_LOAD_VERSION,
            .purpose = LATCD_BROKER_LOAD_PURPOSE, .request_id = 71,
            .module_size = 6, .source_sha256 = {7}, .config_sha256 = {8}};
        GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(sum, (const guchar *)"module", 6);
        gsize size = 32; g_checksum_get_digest(sum, response.module_sha256, &size);
        g_checksum_free(sum);
        if (variant == 1) response.purpose = 0;
        if (variant == 2) response.module_sha256[0] ^= 1;
        if (variant == 3) response.config_sha256[0] ^= 1;
        iov = (struct iovec) {.iov_base = &response, .iov_len = sizeof(response)};
        memset(&control, 0, sizeof(control));
        msg = (struct msghdr) {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = CMSG_SPACE(sizeof(int))};
        c = CMSG_FIRSTHDR(&msg); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(c), &module, sizeof(module));
        if (sendmsg(client, &msg, MSG_NOSIGNAL) != sizeof(response)) return fail("load response");
        close(client);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
            return fail("load validation");
    }
    close(input); close(module);
    return 0;
}

static int test_broker_journal(int server, const char *path)
{
    int source = memfd_create("broker-client-test", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (source < 0 || write(source, "x", 1) != 1 || fcntl(source, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return fail("seal fixture");
    for (unsigned variant = 0; variant < 4; variant++) {
        pid_t child = fork();
        if (child < 0) return fail("fork broker client");
        if (!child) {
            uint8_t digest[32] = {7}, epoch[16] = {0};
            char error[256];
            int result = latcd_client_broker_journal(path, geteuid() + (variant == 3),
                source, source, digest, LATCD_OP_REGISTER_JOURNAL, 83, 8,
                epoch, NULL, error, sizeof(error));
            if (variant == 0) _exit(result || epoch[0] != 1 || epoch[15] != 0xef);
            _exit(result >= 0);
        }
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) return fail("accept broker client");
        if (variant != 3) {
            LatcdBrokerJournalRequest request;
            union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control = {0};
            struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
            struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
            if (recvmsg(client, &msg, MSG_CMSG_CLOEXEC) != sizeof(request)) return fail("broker request");
            struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
            if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
                c->cmsg_len != CMSG_LEN(2 * sizeof(int)) || request.request_id != 83 ||
                request.operation != LATCD_OP_REGISTER_JOURNAL || request.sequence != 8)
                return fail("broker request identity");
            int received[2]; memcpy(received, CMSG_DATA(c), sizeof(received));
            close(received[0]); close(received[1]);
            LatcdResponseV2 response = {.magic = LATCD_RESPONSE_MAGIC,
                .version = LATCD_PROTOCOL_VERSION, .size = sizeof(response),
                .request_id = 83, .source_sha256 = {7}};
            strcpy(response.message, "0123456789abcdef0123456789abcdef");
            if (variant == 1) response.source_sha256[0]++;
            if (variant == 2) response.message[31] = 'g';
            if (send(client, &response, sizeof(response), MSG_NOSIGNAL) != sizeof(response))
                return fail("broker response");
        }
        close(client);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
            return fail("broker client validation");
    }
    close(source);
    return 0;
}

static int test_registration(int server, const char *path, int source, const char *temporary)
{
    const char *epoch_text = "0123456789abcdef0123456789abcdef";
    char *directory_name;
    if (asprintf(&directory_name, "%s/journal-client-fd-XXXXXX", temporary) < 0)
        return fail("cannot allocate capability fixture path");
    if (!mkdtemp(directory_name)) return fail("cannot create capability fixture");
    int directory_fd = open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || rmdir(directory_name)) return fail("cannot open capability fixture");
    free(directory_name);
    char *file_name;
    if (asprintf(&file_name, "%s/journal-client-file-XXXXXX", temporary) < 0)
        return fail("cannot allocate regular fixture path");
    int regular_fd = mkstemp(file_name);
    if (regular_fd < 0 || fchmod(regular_fd, 0700) || unlink(file_name))
        return fail("cannot create non-directory capability fixture");
    free(file_name);
    for (unsigned capability = 0; capability < 2; capability++) {
    for (unsigned channel_mode = 0; channel_mode < 2; channel_mode++) {
        for (unsigned variant = 0; variant < (capability ? 14u : 11u); variant++) {
            pid_t child = fork();
            if (child < 0) return fail("cannot fork registration client");
            if (!child) {
                char error[256], epoch[33] = "unchanged";
                uint8_t digest[32] = {7};
                int channel = channel_mode ? latcd_client_open_channel(path,
                    "test-build", digest, error, sizeof(error)) : -1;
                if (channel_mode && channel < 0) _exit(2);
                int before = fd_count();
                int received_directory = -1;
                int result;
                if (capability) result = channel_mode ? latcd_client_channel_register_journal_capability(
                    channel, source, source, digest, 8, 83, epoch, &received_directory, error, sizeof(error)) :
                    latcd_client_register_journal_capability(path, source, source, digest,
                        8, 83, epoch, &received_directory, error, sizeof(error));
                else result = channel_mode ? latcd_client_channel_register_journal(
                    channel, source, source, digest, 8, 83, epoch, error, sizeof(error)) :
                    latcd_client_register_journal(path, source, source, digest,
                        8, 83, epoch, error, sizeof(error));
                int saved = errno;
                if (capability && !variant) {
                    if (received_directory < 0 || !(fcntl(received_directory, F_GETFD) & FD_CLOEXEC)) _exit(6);
                    close(received_directory);
                } else if (received_directory != -1) _exit(7);
                if (before < 0 || fd_count() != before) _exit(3);
                if ((variant == 9 || variant == 10) && channel_mode) {
                    if (result >= 0 || epoch[0]) _exit(4);
                    /* An abandoned dedicated reply must not consume the channel. */
                    if (latcd_client_channel_register_journal(channel, source, source,
                            digest, 8, 84, epoch, error, sizeof(error)) ||
                        strcmp(epoch, epoch_text) || fd_count() != before) _exit(5);
                }
                if (channel >= 0) close(channel);
                if (variant == 9 || variant == 10) _exit(!(result < 0 &&
                    (channel_mode || !epoch[0]) && saved == EPROTO));
                if (!variant) _exit(result || strcmp(epoch, epoch_text));
                _exit(!(result < 0 && !epoch[0] &&
                        saved == (variant == 7 ? EIO : EPROTO)));
            }
            int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
            LatcdRequestV2 request;
            int source_fd = -1, config_fd = -1, reply = -1;
            char error[256];
            if (client < 0) return fail("cannot accept registration client");
            if (channel_mode) {
                if (latcd_receive_request(client, &request, &source_fd, &config_fd,
                        error, sizeof(error)) || request.operation != LATCD_OP_OPEN_CHANNEL)
                    return fail("invalid registration channel bootstrap");
                LatcdResponseV2 hello = {
                    .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
                    .size = sizeof(hello), .request_id = request.request_id,
                    .source_sha256 = {7},
                };
                strcpy(hello.message, "test-build");
                if (latcd_send_response(client, &hello, error, sizeof(error))) return fail(error);
                if (latcd_receive_channel_request(client, &request, &source_fd,
                        &config_fd, &reply, error, sizeof(error))) return fail(error);
            } else if (latcd_receive_request(client, &request, &source_fd, &config_fd,
                         error, sizeof(error))) return fail(error);
            if (request.operation != (capability ? LATCD_OP_REGISTER_JOURNAL_CAPABILITY : LATCD_OP_REGISTER_JOURNAL) ||
                request.request_id != 83 || request.sequence != 8 ||
                source_fd < 0 || config_fd < 0)
                return fail("invalid journal registration request");
            close(source_fd); close(config_fd);
            LatcdResponseV2 response = {
                .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
                .size = sizeof(response), .request_id = request.request_id,
                .source_sha256 = {7},
            };
            strcpy(response.message, epoch_text);
            if (variant == 1) response.source_sha256[0] ^= 1;
            if (variant == 2) response.accepted_sequence = 1;
            if (variant == 3) response.published_sequence = 1;
            if (variant == 4) response.message[0] = 'g';
            if (variant == 5) response.message[31] = 0;
            if (variant == 6) response.request_id++;
            if (variant == 7) response.status = LATCD_STATUS_QUEUE_FULL;
            if (variant == 8) response.message[0] = 'A';
            if (variant == 10) {
                if (send(channel_mode ? reply : client, &response, 16, MSG_NOSIGNAL) != 16)
                    return fail("cannot send short journal reply");
            } else if (variant != 9) {
                int descriptor = capability && variant != 7 && variant != 13 ?
                    (variant == 11 ? regular_fd : directory_fd) : -1;
                if (variant == 12 && fchmod(directory_fd, 0755)) return fail("chmod capability");
                if (latcd_send_response_fd(channel_mode ? reply : client,
                         &response, descriptor, error, sizeof(error))) return fail(error);
            }
            if (reply >= 0) close(reply);
            if ((variant == 9 || variant == 10) && channel_mode) {
                if (latcd_receive_channel_request(client, &request, &source_fd,
                        &config_fd, &reply, error, sizeof(error)) ||
                    request.operation != LATCD_OP_REGISTER_JOURNAL || request.request_id != 84)
                    return fail("journal channel unusable after abandoned reply");
                close(source_fd); close(config_fd);
                response.request_id = 84;
                if (latcd_send_response(reply, &response, error, sizeof(error))) return fail(error);
                close(reply);
            }
            close(client);
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
                return fail("journal identity or watermark validation failed");
            if (variant == 12 && fchmod(directory_fd, 0700)) return fail("restore capability mode");
        }
    }
    }
    close(directory_fd);
    close(regular_fd);
    char epoch[33] = "unchanged", error[128];
    uint8_t digest[32] = {7};
    if (!latcd_client_register_journal(path, source, source, digest, 0, 83,
            epoch, error, sizeof(error)) || epoch[0] || errno != EINVAL)
        return fail("zero journal capacity accepted");
    strcpy(epoch, "unchanged");
    if (!latcd_client_register_journal(path, source, source, digest, 1048577, 83,
            epoch, error, sizeof(error)) || epoch[0] || errno != EINVAL)
        return fail("excessive journal capacity accepted");
    strcpy(epoch, "unchanged");
    if (!latcd_client_channel_register_journal(-1, source, source, digest, 8, 83,
            epoch, error, sizeof(error)) || epoch[0] || errno != EINVAL)
        return fail("invalid journal channel accepted");
    return 0;
}

static int test_concurrent_registration(int server, const char *path, int source)
{
    pid_t child = fork();
    if (child < 0) return fail("cannot fork concurrent registration client");
    if (!child) {
        uint8_t digest[32] = {7};
        char error[256];
        int channel = latcd_client_open_channel(path, "test-build", digest, error, sizeof(error));
        if (channel < 0) _exit(1);
        pid_t children[4];
        for (unsigned i = 0; i < 4; i++) {
            children[i] = fork();
            if (children[i] < 0) _exit(2);
            if (!children[i]) {
                char epoch[33], expected[33];
                snprintf(expected, sizeof(expected), "%032x", i + 1);
                int before = fd_count();
                int result = latcd_client_channel_register_journal(channel, source,
                    source, digest, 8, 100 + i, epoch, error, sizeof(error));
                _exit(result || strcmp(epoch, expected) || fd_count() != before);
            }
        }
        close(channel);
        for (unsigned i = 0; i < 4; i++) {
            int status;
            if (waitpid(children[i], &status, 0) != children[i] ||
                !WIFEXITED(status) || WEXITSTATUS(status)) _exit(3);
        }
        _exit(0);
    }
    int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    LatcdRequestV2 request;
    int source_fd, config_fd;
    char error[256];
    if (client < 0 || latcd_receive_request(client, &request, &source_fd, &config_fd,
            error, sizeof(error)) || request.operation != LATCD_OP_OPEN_CHANNEL)
        return fail("invalid concurrent registration bootstrap");
    LatcdResponseV2 response = {
        .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response), .request_id = request.request_id, .source_sha256 = {7},
    };
    strcpy(response.message, "test-build");
    if (latcd_send_response(client, &response, error, sizeof(error))) return fail(error);
    int replies[4];
    uint64_t ids[4];
    for (unsigned i = 0; i < 4; i++) {
        if (latcd_receive_channel_request(client, &request, &source_fd, &config_fd,
                &replies[i], error, sizeof(error)) ||
            request.operation != LATCD_OP_REGISTER_JOURNAL ||
            request.request_id < 100 || request.request_id >= 104 ||
            request.sequence != 8 || source_fd < 0 || config_fd < 0)
            return fail("invalid concurrent registration request");
        ids[i] = request.request_id;
        for (unsigned j = 0; j < i; j++)
            if (ids[j] == ids[i]) return fail("duplicate concurrent registration id");
        close(source_fd); close(config_fd);
    }
    for (unsigned i = 4; i-- > 0;) {
        response.request_id = ids[i];
        snprintf(response.message, sizeof(response.message), "%032x", (unsigned)(ids[i] - 99));
        if (latcd_send_response(replies[i], &response, error, sizeof(error))) return fail(error);
        close(replies[i]);
    }
    close(client);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        return fail("concurrent registration reply isolation failed");
    return 0;
}

static int test_channel(int server, const char *path, int source)
{
    for (unsigned variant = 0; variant < 3; variant++) {
        pid_t child = fork();
        if (child < 0) return fail("cannot fork channel client");
        if (!child) {
            char error[256];
            uint8_t digest[32] = {7};
            int channel = latcd_client_open_channel(path, "test-build", digest,
                                                     error, sizeof(error));
            if (variant) {
                _exit(!(channel < 0 && errno == EPROTO));
            }
            if (channel < 0 || !(fcntl(channel, F_GETFD) & FD_CLOEXEC)) {
                _exit(1);
            }
            pid_t submitters[4];
            for (unsigned i = 0; i < 4; i++) {
                submitters[i] = fork();
                if (submitters[i] < 0) _exit(2);
                if (!submitters[i]) {
                    int result = latcd_client_channel_submit_keys_fd(channel,
                        source, source, LATCD_PRIORITY_LIBRARY, 200 + i, 300 + i,
                        error, sizeof(error));
                    if (result) fprintf(stderr, "channel submit: %s\n", error);
                    close(channel);
                    _exit(!!result);
                }
            }
            close(channel);
            for (unsigned i = 0; i < 4; i++) {
                int status;
                if (waitpid(submitters[i], &status, 0) != submitters[i] ||
                    !WIFEXITED(status) || WEXITSTATUS(status)) _exit(3);
            }
            _exit(0);
        }
        int channel = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        LatcdRequestV2 request;
        int received_source, received_keys;
        char error[256];
        if (channel < 0 || latcd_receive_request(channel, &request,
                &received_source, &received_keys, error, sizeof(error)) ||
            request.operation != LATCD_OP_OPEN_CHANNEL ||
            received_source != -1 || received_keys != -1) {
            return fail("invalid channel bootstrap");
        }
        LatcdResponseV2 response = {
            .magic = LATCD_RESPONSE_MAGIC, .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(response), .request_id = request.request_id,
        };
        strcpy(response.message, variant == 1 ? "wrong-build" : "test-build");
        response.source_sha256[0] = variant == 2 ? 8 : 7;
        if (latcd_send_response(channel, &response, error, sizeof(error))) {
            return fail(error);
        }
        if (!variant) {
            int replies[4];
            uint64_t ids[4];
            for (unsigned i = 0; i < 4; i++) {
                if (latcd_receive_channel_request(channel, &request,
                        &received_source, &received_keys, &replies[i],
                        error, sizeof(error)) ||
                    request.operation != LATCD_OP_SUBMIT_KEYS ||
                    request.request_id < 200 || request.request_id >= 204 ||
                    request.sequence != request.request_id + 100 ||
                    received_source < 0 || received_keys < 0) {
                    return fail("invalid inherited channel submission");
                }
                ids[i] = request.request_id;
                for (unsigned j = 0; j < i; j++) {
                    if (ids[j] == ids[i]) return fail("duplicate channel request");
                }
                close(received_source);
                close(received_keys);
            }
            for (unsigned i = 4; i-- > 0;) {
                response.request_id = ids[i];
                if (latcd_send_response(replies[i], &response, error, sizeof(error))) {
                    return fail(error);
                }
                close(replies[i]);
            }
        }
        close(channel);
        int status;
        if (waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status)) {
            return fail("channel identity or reply isolation failed");
        }
    }
    return 0;
}

int main(void)
{
    const char *temporary = getenv("TMPDIR");
    char *fallback = NULL;
    if (!temporary || !*temporary) {
        const char *home = getenv("HOME");
        if (!home || asprintf(&fallback, "%s/tmp", home) < 0) {
            return fail("cannot find test temporary directory");
        }
        temporary = fallback;
    }
    char *directory;
    if (asprintf(&directory, "%s/test-latcd-client.XXXXXX", temporary) < 0) {
        return fail("cannot allocate socket directory");
    }
    free(fallback);
    if (!mkdtemp(directory) || chmod(directory, 0700)) {
        return fail("cannot create socket directory");
    }
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (snprintf(path, sizeof(path), "%s/socket", directory) >= (int)sizeof(path)) {
        return fail("test socket path is too long");
    }
    int server = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (server < 0 || bind(server, (const void *)&address, sizeof(address)) ||
        listen(server, 1)) {
        perror("test-latcd-client: cannot create test listener");
        return 1;
    }
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0) {
        return fail("cannot open test source");
    }
    pid_t submitter = fork();
    if (submitter < 0) {
        return fail("cannot fork submitter");
    }
    if (!submitter) {
        char error[128] = {0};
        int result = latcd_client_submit_keys_fd(path, source, source,
            LATCD_PRIORITY_STARTUP, 42, 7, error, sizeof(error));
        if (result) fprintf(stderr, "test-latcd-client: %s\n", error);
        _exit(result ? 1 : 0);
    }
    int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    LatcdRequestV2 request;
    char control[CMSG_SPACE(sizeof(int) * 2)] = {0};
    struct iovec iov = { .iov_base = &request, .iov_len = sizeof(request) };
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    if (client < 0 || recvmsg(client, &message, MSG_CMSG_CLOEXEC) !=
                      sizeof(request) ||
        request.magic != LATCD_REQUEST_MAGIC || request.request_id != 42 ||
        request.priority != LATCD_PRIORITY_STARTUP ||
        request.operation != LATCD_OP_SUBMIT_KEYS || request.sequence != 7) {
        return fail("received request does not match submission");
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    int received_fds[2] = {-1, -1};
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS) {
        return fail("submission did not carry an FD");
    }
    memcpy(received_fds, CMSG_DATA(header), sizeof(received_fds));
    if (fcntl(received_fds[0], F_GETFL) < 0 ||
        fcntl(received_fds[1], F_GETFL) < 0) {
        return fail("received FDs are invalid");
    }
    LatcdResponseV2 response = {
        .magic = LATCD_RESPONSE_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response),
        .status = LATCD_STATUS_OK,
        .request_id = request.request_id,
    };
    if (send(client, &response, sizeof(response), MSG_NOSIGNAL) !=
        sizeof(response)) {
        return fail("cannot acknowledge submission");
    }
    close(received_fds[0]);
    close(received_fds[1]);
    close(client);
    int submit_status = 0;
    if (waitpid(submitter, &submit_status, 0) != submitter ||
        !WIFEXITED(submit_status) || WEXITSTATUS(submit_status)) {
        return fail("submission was not acknowledged");
    }
    pid_t precompiler = fork();
    if (precompiler < 0) {
        return fail("cannot fork precompiler");
    }
    if (!precompiler) {
        char error[128] = {0};
        int result = latcd_client_precompile_source(path, source, 44,
                                                     error, sizeof(error));
        if (result) fprintf(stderr, "test-latcd-client: %s\n", error);
        _exit(result ? 1 : 0);
    }
    client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    int precompile_source = -1, no_keys = -1;
    char receive_error[128] = {0};
    if (client < 0 || latcd_receive_request(client, &request,
                                             &precompile_source, &no_keys,
                                             receive_error,
                                             sizeof(receive_error)) ||
        request.operation != LATCD_OP_PRECOMPILE_SOURCE ||
        request.request_id != 44 || precompile_source < 0 || no_keys >= 0) {
        return fail("received request does not match precompile");
    }
    response.request_id = request.request_id;
    if (send(client, &response, sizeof(response), MSG_NOSIGNAL) !=
        sizeof(response)) {
        return fail("cannot acknowledge precompile");
    }
    close(precompile_source);
    close(client);
    if (waitpid(precompiler, &submit_status, 0) != precompiler ||
        !WIFEXITED(submit_status) || WEXITSTATUS(submit_status)) {
        return fail("precompile was not acknowledged");
    }
    for (int variant = 0; variant < 3; variant++) {
        pid_t greeter = fork();
        if (greeter < 0) return fail("cannot fork handshake client");
        if (!greeter) {
            char error[128] = {0};
            uint8_t digest[32] = { 7 };
            int result = latcd_client_hello(path, "test-build", digest,
                                            error, sizeof(error));
            _exit(variant ? !(result && errno == EPROTO) : !!result);
        }
        client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        int no_source = -1, no_keys = -1;
        char error[128];
        if (client < 0 || latcd_receive_request(client, &request,
                &no_source, &no_keys, error, sizeof(error)) ||
            request.operation != LATCD_OP_HELLO || no_source >= 0 || no_keys >= 0)
            return fail("invalid handshake request");
        response.request_id = request.request_id;
        snprintf(response.message, sizeof(response.message), "%s",
                 variant == 1 ? "wrong-build" : "test-build");
        memset(response.source_sha256, 0, sizeof(response.source_sha256));
        response.source_sha256[0] = variant == 2 ? 8 : 7;
        if (send(client, &response, sizeof(response), MSG_NOSIGNAL) != sizeof(response))
            return fail("cannot acknowledge handshake");
        close(client);
        if (waitpid(greeter, &submit_status, 0) != greeter ||
            !WIFEXITED(submit_status) || WEXITSTATUS(submit_status))
            return fail("handshake identity validation failed");
    }
    if (test_channel(server, path, source)) return 1;
    if (test_broker_journal(server, path) || test_broker_load(server, path)) return 1;
    if (test_registration(server, path, source, directory)) return 1;
    if (test_concurrent_registration(server, path, source)) return 1;
    close(source);
    close(server);
    unlink(path);
    rmdir(directory);

    char error[128] = {0};
    errno = 0;
    if (!latcd_client_submit_keys_fd(path, STDIN_FILENO, STDIN_FILENO,
                                     LATCD_PRIORITY_LIBRARY,
                                     43, 8, error, sizeof(error)) ||
        (errno != ENOENT && errno != ECONNREFUSED)) {
        return fail("missing daemon was not reported immediately");
    }
    free(directory);
    puts("latcd acknowledged client tests: PASS");
    return 0;
}
