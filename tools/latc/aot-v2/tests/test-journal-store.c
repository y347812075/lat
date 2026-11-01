#define _GNU_SOURCE
#define LATCD_JOURNAL_SNAPSHOT_TEST
#define main latcd_program_main
#include "../../latcd/main.c"
#undef main
#include "lat-translation-config.h"
#include "latcd-client.h"
#include <sys/mman.h>
#include <sys/inotify.h>

static bool fail_task_link;
int __real_linkat(int olddirfd, const char *oldpath, int newdirfd,
                  const char *newpath, int flags);
int __wrap_linkat(int olddirfd, const char *oldpath, int newdirfd,
                  const char *newpath, int flags)
{
    if (fail_task_link) { errno = EIO; return -1; }
    return __real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

static void wait_ok(pid_t child)
{
    int status;
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
}

static pid_t start_service(const LatcdConfig *config)
{
    pid_t child = fork();
    g_assert_cmpint(child, >=, 0);
    if (!child) {
        char error[256];
        g_assert_cmpint(ensure_private_directory(config->cache_dir, error, sizeof(error)), ==, 0);
        g_assert_cmpint(prepare_metadata_directories(config->cache_dir), ==, 0);
        g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, config->cache_dir,
                                                error, sizeof(error)), ==, 0);
        latcd_cache_capacity_metadata_bind(&generation_capacity, config->max_cache_bytes);
        _exit(run_service(config));
    }
    for (unsigned i = 0; i < 500 && access(config->socket_path, F_OK); i++)
        g_usleep(10000);
    g_assert_cmpint(access(config->socket_path, F_OK), ==, 0);
    return child;
}

static LatcdResponseV2 operation(const LatcdConfig *config, int source, int snapshot,
                                 uint64_t capacity, uint32_t opcode)
{
    int socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    g_assert_cmpint(socket_fd, >=, 0);
    struct timeval timeout = { .tv_sec = 5 };
    g_assert_cmpint(setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), ==, 0);
    struct sockaddr_un address;
    int directory;
    char error[256];
    g_assert_cmpint(latcd_socket_address(config->socket_path, &address, &directory,
                                       error, sizeof(error)), ==, 0);
    g_assert_cmpint(connect(socket_fd, (void *)&address, sizeof(address)), ==, 0);
    if (directory >= 0) close(directory);
    LatcdRequestV2 sent = {
        .magic = LATCD_REQUEST_MAGIC, .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(sent), .operation = opcode,
        .request_id = 17, .sequence = capacity,
    };
    g_assert_cmpint(latcd_send_request(socket_fd, source, snapshot, &sent,
                                      error, sizeof(error)), ==, 0);
    LatcdResponseV2 response;
    g_assert_cmpint(latcd_receive_response(socket_fd, &response, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(response.request_id, ==, 17);
    close(socket_fd);
    return response;
}

static LatcdResponseV2 request(const LatcdConfig *config, int source, int snapshot,
                                uint64_t capacity)
{
    return operation(config, source, snapshot, capacity, LATCD_OP_REGISTER_JOURNAL);
}

static void check_receipt(int stream, const LatKeyJournalIdentity *identity, size_t count)
{
    int fd = openat(stream, "received.tbset", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(fd, >=, 0);
    LatTbKeySet set;
    char error[256];
    g_assert_cmpint(lat_tb_key_set_read_fd(fd, identity->source_sha256, &set,
                                         error, sizeof(error)), ==, 0);
    close(fd);
    g_assert_cmpuint(set.count, ==, count);
    g_assert_cmpuint(set.sequence, ==, 0);
    g_assert_true(lat_tb_key_set_contains(&set, 16, 3));
    if (count >= 2) g_assert_true(lat_tb_key_set_contains(&set, 24, 3));
    if (count >= 3) g_assert_true(lat_tb_key_set_contains(&set, 32, 3));
    lat_tb_key_set_destroy(&set);
}

static void remove_tree(const char *path)
{
    GDir *directory = g_dir_open(path, 0, NULL);

    if (directory) {
        const char *name;
        while ((name = g_dir_read_name(directory))) {
            char *child = g_build_filename(path, name, NULL);
            if (g_file_test(child, G_FILE_TEST_IS_DIR)) remove_tree(child);
            else g_assert_cmpint(unlink(child), ==, 0);
            g_free(child);
        }
        g_dir_close(directory);
    }
    g_assert_cmpint(rmdir(path), ==, 0);
}

static void check_shared_capacity(const LatcdConfig *original, int source, int configuration)
{
    uint64_t budget;
    g_assert_cmpint(latcd_journal_budget(source, configuration, 2, &budget), ==, 0);
    char *cache = g_strconcat(original->cache_dir, "-shared", NULL);
    char *socket = g_strconcat(original->socket_path, "-shared", NULL);
    char *name = g_strnfill(64, 'a');
    char *native = g_strdup_printf("%s/%s.native", cache, name);
    g_assert_cmpint(mkdir(cache, 0700), ==, 0);
    g_assert_true(g_file_set_contents(native, "generation", 10, NULL));
    g_assert_cmpint(chmod(native, 0400), ==, 0);
    LatcdConfig config = *original;
    config.cache_dir = cache;
    config.socket_path = socket;
    config.max_cache_bytes = budget + 9;
    pid_t child = start_service(&config);
    char *temporary = g_build_filename(cache, ".tmp", NULL);
    int watcher = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    g_assert_cmpint(watcher, >=, 0);
    g_assert_cmpint(inotify_add_watch(watcher, temporary, IN_CREATE | IN_MOVED_TO), >=, 0);
    LatcdResponseV2 response = request(&config, source, configuration, 2);
    g_assert_cmpint(response.status, !=, LATCD_STATUS_OK);
    g_assert_nonnull(strstr(response.message, "capacity:"));
    char events[4096];
    g_assert_cmpint(read(watcher, events, sizeof(events)), ==, -1);
    g_assert_cmpint(errno, ==, EAGAIN);
    close(watcher);
    g_assert_cmpint(kill(child, SIGTERM), ==, 0);
    wait_ok(child);
    g_assert_cmpint(unlink(native), ==, 0);
    LatcdCacheCapacity inventory = LATCD_CACHE_CAPACITY_INIT;
    g_assert_cmpint(latcd_cache_capacity_scan(&inventory, cache, NULL, 0), ==, 0);
    config.max_cache_bytes += inventory.metadata_committed;
    latcd_cache_capacity_close(&inventory);
    pthread_mutex_destroy(&inventory.lock);
    child = start_service(&config);
    int invalid = memfd_create("invalid-journal-source", MFD_CLOEXEC);
    g_assert_cmpint(invalid, >=, 0);
    g_assert_cmpint(ftruncate(invalid, 16), ==, 0);
    char *invalid_path = g_strdup_printf("/proc/self/fd/%d", invalid);
    int readonly = open(invalid_path, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(readonly, >=, 0);
    g_assert_cmpint(request(&config, readonly, configuration, 2).status, !=, LATCD_STATUS_OK);
    close(readonly); close(invalid); g_free(invalid_path);
    response = request(&config, source, configuration, 2);
    if (response.status != LATCD_STATUS_OK) g_error("registration after rejection: %s", response.message);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_OK);
    g_assert_cmpint(kill(child, SIGTERM), ==, 0);
    wait_ok(child);
    child = start_service(&config);
    response = request(&config, source, configuration, 2);
    g_assert_cmpint(response.status, !=, LATCD_STATUS_OK);
    g_assert_nonnull(strstr(response.message, "capacity:"));
    g_assert_cmpint(kill(child, SIGTERM), ==, 0);
    wait_ok(child);
    remove_tree(cache);
    g_free(temporary); g_free(native); g_free(name); g_free(socket); g_free(cache);
}

static void check_anonymous_snapshot(const char *parent, int source, int configuration)
{
    char *root = g_build_filename(parent, "anonymous", NULL), error[256];
    g_assert_cmpint(mkdir(root, 0700), ==, 0);
    const char *points[] = {"created", "partial", "synced"};
    for (unsigned i = 0; i < G_N_ELEMENTS(points); i++) {
        pid_t child = fork();
        g_assert_cmpint(child, >=, 0);
        if (!child) {
            int fd = -1;
            uint8_t digest[32];
            g_assert_cmpint(setenv("LATCD_TEST_JOURNAL_SNAPSHOT_CRASH", points[i], 1), ==, 0);
            snapshot_source_copy(source, root, 4096, NULL, digest, NULL, &fd, error, sizeof(error));
            _exit(127);
        }
        int status;
        g_assert_cmpint(waitpid(child, &status, 0), ==, child);
        g_assert_true(WIFSIGNALED(status));
        g_assert_cmpint(WTERMSIG(status), ==, SIGKILL);
        GDir *directory = g_dir_open(root, 0, NULL);
        g_assert_nonnull(directory);
        g_assert_null(g_dir_read_name(directory));
        g_dir_close(directory);
    }
    uint8_t digest[32], build[32], codegen[32];
    int fd = -1;
    g_assert_cmpint(snapshot_source_copy(source, root, 4096, NULL, digest, NULL, &fd,
                                        error, sizeof(error)), ==, 0);
    struct stat st;
    g_assert_cmpint(fstat(fd, &st), ==, 0);
    g_assert_cmpuint(st.st_nlink, ==, 0);
    g_assert_cmpint(journal_build_id(build), ==, 0);
    expected_codegen_id(codegen);
    char stream[33];
    g_assert_cmpint(latcd_journal_register_fd(root, source, digest, build, codegen,
        configuration, 2, 1048576, stream, NULL, error, sizeof(error)), ==, -1);
    g_assert_cmpint(latcd_journal_register_fd(root, fd, digest, build, codegen,
        configuration, 2, 1048576, stream, NULL, error, sizeof(error)), ==, 0);
    g_assert_cmpint(fstat(fd, &st), ==, 0);
    g_assert_cmpuint(st.st_nlink, ==, 1);
    close(fd);
    unsigned count;
    g_assert_cmpint(latcd_journal_recover(root, build, codegen, 1048576, &count,
                                         error, sizeof(error)), ==, 0);
    g_assert_cmpuint(count, ==, 1);
    remove_tree(root); g_free(root);
}

static void check_collection(const LatcdConfig *config, int stream,
                              const LatKeyJournalIdentity *identity)
{
    char error[256];
    check_receipt(stream, identity, 1);
    LatKeyJournal writer;
    g_assert_cmpint(lat_key_journal_open_at(stream, "keys", identity, true,
                                           &writer, error, sizeof(error)), ==, 0);
    LatTbKey key = { .guest_rva = 24, .flags = 3 };
    uint64_t slot;
    g_assert_cmpint(lat_key_journal_append(&writer, &key, &slot, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(slot, ==, 2);
    LatcdResponseV2 response = operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_OK);
    g_assert_cmpuint(response.accepted_sequence, >, 0);
    g_assert_cmpuint(response.published_sequence, <=, response.accepted_sequence);
    uint64_t first_accepted = response.accepted_sequence;
    check_receipt(stream, identity, 2);
    struct stat before, after;
    g_assert_cmpint(fstatat(stream, "received.tbset", &before, AT_SYMLINK_NOFOLLOW), ==, 0);
    response = operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_OK);
    g_assert_cmpuint(response.accepted_sequence, >=, first_accepted);
    g_assert_cmpint(fstatat(stream, "received.tbset", &after, AT_SYMLINK_NOFOLLOW), ==, 0);
    g_assert_cmpuint(before.st_ino, ==, after.st_ino);
    /* Reject non-executable loads, holes, exclusive ends and absolute VAs. */
    key.guest_rva = UINT64_MAX;
    g_assert_cmpint(lat_key_journal_append(&writer, &key, &slot, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(slot, ==, 3);
    const uint64_t invalid[] = { UINT64_MAX, 64, 127, 128, 191, 192, 255,
                                 320, 0x400010 };
    for (size_t i = 0; i < G_N_ELEMENTS(invalid); i++) {
        g_assert_cmpint(pwrite(writer.fd, &invalid[i], sizeof(invalid[i]),
                              192 + slot * 32 + 8), ==, sizeof(invalid[i]));
        response = operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS);
        g_assert_cmpint(response.status, !=, LATCD_STATUS_OK);
        check_receipt(stream, identity, 2);
        g_assert_cmpint(fstatat(stream, "received.tbset", &after,
                               AT_SYMLINK_NOFOLLOW), ==, 0);
        g_assert_cmpuint(before.st_ino, ==, after.st_ino);
    }
    uint64_t restored = 32;
    g_assert_cmpint(pwrite(writer.fd, &restored, sizeof(restored), 192 + slot * 32 + 8), ==, sizeof(restored));
    /* Loss of a previously received key is corruption, not a smaller update. */
    uint64_t state = 1;
    g_assert_cmpint(pwrite(writer.fd, &state, sizeof(state), 192 + 32), ==, sizeof(state));
    response = operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS);
    g_assert_cmpint(response.status, !=, LATCD_STATUS_OK);
    check_receipt(stream, identity, 2);
    state = 3;
    g_assert_cmpint(pwrite(writer.fd, &state, sizeof(state), 192 + 32), ==, sizeof(state));
    response = operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_OK);
    check_receipt(stream, identity, 3);
    lat_key_journal_close(&writer);
}

static void remove_stream(int root, const char *name)
{
    int stream = openat(root, name, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(stream, >=, 0);
    const char *names[] = { "source", "keys", "config", "registration" };
    for (size_t i = 0; i < G_N_ELEMENTS(names); i++)
        g_assert_cmpint(unlinkat(stream, names[i], 0), ==, 0);
    close(stream);
    g_assert_cmpint(unlinkat(root, name, AT_REMOVEDIR), ==, 0);
}

static void check_limits(const char *parent, const char *snapshot,
                          const LatKeyJournalIdentity *identity, int config_fd,
                          size_t config_size)
{
    char *cache = g_build_filename(parent, "limit-cache", NULL);
    g_assert_cmpint(mkdir(cache, 0700), ==, 0);
    char error[256], stream[33], first[33];
    struct stat st;
    g_assert_cmpint(stat(snapshot, &st), ==, 0);
    uint64_t per_stream = 160 + config_size + 192 + 2 * 32 +
                          2 * (64 + 2 * sizeof(LatTbKey)) + st.st_size;
    uint64_t quota = 2 * per_stream - 1;
    g_assert_cmpint(latcd_journal_register(cache, snapshot, identity->source_sha256,
        identity->build_sha256, identity->codegen_sha256, config_fd, 2, quota,
        first, error, sizeof(error)), ==, 0);
    g_assert_cmpint(latcd_journal_register(cache, snapshot, identity->source_sha256,
        identity->build_sha256, identity->codegen_sha256, config_fd, 2, quota,
        stream, error, sizeof(error)), ==, -1);
    g_assert_cmpint(stream[0], ==, 0);
    unsigned recovered;
    g_assert_cmpint(latcd_journal_recover(cache, identity->build_sha256,
        identity->codegen_sha256, quota, &recovered, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(recovered, ==, 1);
    for (unsigned i = 1; i < LATCD_JOURNAL_MAX_STREAMS; i++)
        g_assert_cmpint(latcd_journal_register(cache, snapshot, identity->source_sha256,
            identity->build_sha256, identity->codegen_sha256, config_fd, 2, 1048576,
            stream, error, sizeof(error)), ==, 0);
    g_assert_cmpint(latcd_journal_register(cache, snapshot, identity->source_sha256,
        identity->build_sha256, identity->codegen_sha256, config_fd, 2, 1048576,
        stream, error, sizeof(error)), ==, -1);
    g_assert_cmpint(stream[0], ==, 0);
    g_assert_cmpint(latcd_journal_recover(cache, identity->build_sha256,
        identity->codegen_sha256, 1048576, &recovered, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(recovered, ==, LATCD_JOURNAL_MAX_STREAMS);
    char *root_path = g_build_filename(cache, ".journals", NULL);
    int root = open(root_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(root, >=, 0);
    GDir *entries = g_dir_open(root_path, 0, NULL);
    g_assert_nonnull(entries);
    const char *name;
    while ((name = g_dir_read_name(entries))) remove_stream(root, name);
    g_dir_close(entries);
    close(root);
    g_assert_cmpint(rmdir(root_path), ==, 0);
    g_assert_cmpint(rmdir(cache), ==, 0);
    g_free(root_path); g_free(cache);
}

static void check_content_binding(const char *cache, int stream,
                                   const uint8_t build[32], const uint8_t codegen[32],
                                   const char *name, off_t offset)
{
    char error[256];
    unsigned recovered;
    g_assert_cmpint(fchmodat(stream, name, 0600, 0), ==, 0);
    int fd = openat(stream, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(fd, >=, 0);
    uint8_t original;
    g_assert_cmpint(pread(fd, &original, 1, offset), ==, 1);
    uint8_t changed = original ^ 1;
    g_assert_cmpint(pwrite(fd, &changed, 1, offset), ==, 1);
    g_assert_cmpint(fchmod(fd, 0400), ==, 0);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, 1048576,
        &recovered, error, sizeof(error)), ==, -1);
    g_assert_cmpint(pwrite(fd, &original, 1, offset), ==, 1);
    close(fd);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, 1048576,
        &recovered, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(recovered, ==, 1);
}

static void check_registration_clients(const LatcdConfig *config, int source,
                                        int snapshot, const LatKeyJournalIdentity *identity)
{
    char error[256], epoch[33];
    char *canonical = realpath(config->cache_dir, NULL);
    g_assert_nonnull(canonical);
    uint8_t cache_digest[32];
    GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(hash, (void *)canonical, strlen(canonical));
    gsize size = sizeof(cache_digest);
    g_checksum_get_digest(hash, cache_digest, &size);
    g_checksum_free(hash);
    free(canonical);
    int channel = latcd_client_open_channel(config->socket_path, LATC_BUILD_ID,
        cache_digest, error, sizeof(error));
    g_assert_cmpint(channel, >=, 0);
    for (unsigned mode = 0; mode < 2; mode++) {
        if (!mode) {
            g_assert_cmpint(latcd_client_register_journal(config->socket_path,
                source, snapshot, identity->source_sha256, 2, 91, epoch,
                error, sizeof(error)), ==, 0);
        } else {
            char *hidden = g_strconcat(config->socket_path, ".hidden", NULL);
            g_assert_cmpint(rename(config->socket_path, hidden), ==, 0);
            g_assert_cmpint(access(config->socket_path, F_OK), ==, -1);
            int ready[2];
            g_assert_cmpint(pipe(ready), ==, 0);
            pid_t child = fork();
            g_assert_cmpint(child, >=, 0);
            if (!child) {
                close(ready[0]);
                g_assert_cmpint(latcd_client_channel_register_journal(channel,
                    source, snapshot, identity->source_sha256, 2, 92, epoch,
                    error, sizeof(error)), ==, 0);
                g_assert_cmpint(write(ready[1], epoch, sizeof(epoch)), ==, sizeof(epoch));
                close(ready[1]);
                close(channel);
                _exit(0);
            }
            close(ready[1]);
            g_assert_cmpint(read(ready[0], epoch, sizeof(epoch)), ==, sizeof(epoch));
            close(ready[0]);
            wait_ok(child);
            g_assert_cmpint(rename(hidden, config->socket_path), ==, 0);
            g_free(hidden);
        }
        char *root_path = g_build_filename(config->cache_dir, ".journals", NULL);
        int root = open(root_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        int stream = openat(root, epoch, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        g_assert_cmpint(stream, >=, 0);
        LatKeyJournalIdentity bound = *identity;
        for (size_t i = 0; i < 16; i++)
            bound.epoch[i] = (g_ascii_xdigit_value(epoch[2 * i]) << 4) |
                             g_ascii_xdigit_value(epoch[2 * i + 1]);
        LatKeyJournal journal;
        g_assert_cmpint(lat_key_journal_open_at(stream, "keys", &bound, true,
            &journal, error, sizeof(error)), ==, 0);
        LatTbKey key = {.guest_rva = 16, .flags = 3};
        g_assert_cmpint(lat_key_journal_append(&journal, &key, NULL,
            error, sizeof(error)), ==, 0);
        lat_key_journal_close(&journal);
        g_assert_cmpint(operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS).status,
                       ==, LATCD_STATUS_OK);
        check_receipt(stream, &bound, 1);
        g_assert_cmpint(unlinkat(stream, "received.tbset", 0), ==, 0);
        close(stream);
        remove_stream(root, epoch);
        close(root);
        g_free(root_path);
    }
    close(channel);
}

static void check_directory_capability(const LatcdConfig *config, int source,
    int snapshot, const LatKeyJournalIdentity *identity)
{
    char error[256], epoch[33];
    uint8_t cache_digest[32];
    char *canonical = realpath(config->cache_dir, NULL);
    g_assert_nonnull(canonical);
    GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(hash, (void *)canonical, strlen(canonical));
    gsize digest_size = sizeof(cache_digest);
    g_checksum_get_digest(hash, cache_digest, &digest_size);
    g_checksum_free(hash);
    free(canonical);
    int channel = latcd_client_open_channel(config->socket_path, LATC_BUILD_ID,
        cache_digest, error, sizeof(error));
    g_assert_cmpint(channel, >=, 0);
    for (unsigned mode = 0; mode < 2; mode++) {
        int stream = -1;
        int result = mode ? latcd_client_channel_register_journal_capability(channel,
            source, snapshot, identity->source_sha256, 4, 111, epoch, &stream, error, sizeof(error)) :
            latcd_client_register_journal_capability(config->socket_path, source,
            snapshot, identity->source_sha256, 4, 110, epoch, &stream, error, sizeof(error));
        g_assert_cmpint(result, ==, 0);
        g_assert_cmpint(stream, >=, 0);
        g_assert_true(fcntl(stream, F_GETFD) & FD_CLOEXEC);
        LatKeyJournalIdentity bound = *identity;
        for (unsigned i = 0; i < 16; i++)
            bound.epoch[i] = (g_ascii_xdigit_value(epoch[2 * i]) << 4) |
                             g_ascii_xdigit_value(epoch[2 * i + 1]);
        uint64_t journal_id = 0;
        for (unsigned i = 0; i < 8; i++)
            journal_id |= (uint64_t)bound.epoch[i] << (8 * i);
        g_assert_cmpint(latcd_client_append_journal(config->socket_path,
            source, snapshot, identity->source_sha256,
            journal_id ^ UINT64_C(1), 31, error, sizeof(error)), ==, -1);
        g_assert_cmpint(latcd_client_append_journal(config->socket_path,
            snapshot, snapshot, identity->source_sha256,
            journal_id, 31, error, sizeof(error)), ==, -1);
        g_assert_cmpint(latcd_client_append_journal(config->socket_path,
            source, source, identity->source_sha256,
            journal_id, 31, error, sizeof(error)), ==, -1);
        result = mode ? latcd_client_channel_append_journal(channel, source,
            snapshot, identity->source_sha256, journal_id, 32, error, sizeof(error)) :
            latcd_client_append_journal(config->socket_path, source, snapshot,
            identity->source_sha256, journal_id, 32, error, sizeof(error));
        if (result) g_error("journal append mode=%u failed: %s", mode, error);
        g_assert_cmpint(result, ==, 0);
        LatKeyJournal writer;
        g_assert_cmpint(lat_key_journal_open_at(stream, "keys", &bound, true,
            &writer, error, sizeof(error)), ==, 0);
        LatTbKey key = {.guest_rva = 16, .flags = 3};
        g_assert_cmpint(lat_key_journal_append(&writer, &key, NULL, error, sizeof(error)), ==, 0);
        char *root = g_build_filename(config->cache_dir, ".journals", NULL);
        char *hidden = g_strconcat(root, ".hidden", NULL);
        g_assert_cmpint(rename(root, hidden), ==, 0);
        int ready[2];
        g_assert_cmpint(pipe(ready), ==, 0);
        pid_t child = fork();
        g_assert_cmpint(child, >=, 0);
        if (!child) {
            close(ready[0]);
            /* An inherited view is invalid, even though it still has an fd. */
            key.guest_rva = 24;
            g_assert_cmpint(lat_key_journal_append(&writer, &key, NULL, error, sizeof(error)), ==, -1);
            lat_key_journal_close(&writer);
            g_assert_cmpint(access(root, F_OK), ==, -1);
            g_assert_cmpint(lat_key_journal_open_at(stream, "keys", &bound, true,
                &writer, error, sizeof(error)), ==, 0);
            g_assert_cmpint(lat_key_journal_append(&writer, &key, NULL, error, sizeof(error)), ==, 0);
            g_assert_cmpint(write(ready[1], "x", 1), ==, 1);
            for (;;) pause();
        }
        close(ready[1]);
        char byte;
        g_assert_cmpint(read(ready[0], &byte, 1), ==, 1);
        close(ready[0]);
        g_assert_cmpint(kill(child, SIGKILL), ==, 0);
        int status;
        g_assert_cmpint(waitpid(child, &status, 0), ==, child);
        g_assert_true(WIFSIGNALED(status));
        g_assert_cmpint(WTERMSIG(status), ==, SIGKILL);
        g_assert_cmpint(rename(hidden, root), ==, 0);
        g_assert_cmpint(operation(config, -1, -1, 0, LATCD_OP_COLLECT_JOURNALS).status,
                       ==, LATCD_STATUS_OK);
        check_receipt(stream, &bound, 3);
        lat_key_journal_close(&writer);
        g_assert_cmpint(unlinkat(stream, "received.tbset", 0), ==, 0);
        close(stream);
        int root_fd = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        g_assert_cmpint(root_fd, >=, 0);
        remove_stream(root_fd, epoch);
        close(root_fd);
        g_free(root);
        g_free(hidden);
    }
    close(channel);
}

static void reject_receipt(const char *cache, int stream,
                            const LatKeyJournalIdentity *identity)
{
    char error[256];
    unsigned count;
    uint64_t received;
    struct stat before, after;
    uint8_t keys_before[320], keys_after[320];
    int fd = openat(stream, "keys", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(pread(fd, keys_before, sizeof(keys_before), 0), ==, sizeof(keys_before));
    g_assert_cmpint(fstatat(stream, "received.tbset", &before, AT_SYMLINK_NOFOLLOW), ==, 0);
    g_assert_cmpint(latcd_journal_recover(cache, identity->build_sha256,
        identity->codegen_sha256, 1048576, &count, error, sizeof(error)), ==, -1);
    g_assert_cmpint(latcd_journal_collect(cache, identity->build_sha256,
        identity->codegen_sha256, 1048576, &count, &received, error, sizeof(error)), ==, -1);
    g_assert_cmpint(fstatat(stream, "received.tbset", &after, AT_SYMLINK_NOFOLLOW), ==, 0);
    g_assert_cmpuint(before.st_ino, ==, after.st_ino);
    g_assert_cmpint(before.st_size, ==, after.st_size);
    g_assert_cmpint(pread(fd, keys_after, sizeof(keys_after), 0), ==, sizeof(keys_after));
    g_assert_cmpmem(keys_before, sizeof(keys_before), keys_after, sizeof(keys_after));
    close(fd);
}

static void check_bad_receipts(const char *cache, int stream,
                                const LatKeyJournalIdentity *identity)
{
    g_assert_cmpint(fchmodat(stream, "received.tbset", 0600, 0), ==, 0);
    reject_receipt(cache, stream, identity);
    int fd = openat(stream, "received.tbset", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(fchmod(fd, 0400), ==, 0);
    /* Source SHA, sequence, semantic flags, RVA and declared record count. */
    const off_t offsets[] = {16, 56, 72, 64, 48};
    for (size_t i = 0; i < G_N_ELEMENTS(offsets); i++) {
        uint8_t original;
        g_assert_cmpint(pread(fd, &original, 1, offsets[i]), ==, 1);
        uint8_t changed = original ^ (offsets[i] == 64 ? 64 : 1);
        g_assert_cmpint(pwrite(fd, &changed, 1, offsets[i]), ==, 1);
        reject_receipt(cache, stream, identity);
        g_assert_cmpint(pwrite(fd, &original, 1, offsets[i]), ==, 1);
        check_receipt(stream, identity, 3);
    }
    uint8_t tail;
    struct stat st;
    g_assert_cmpint(fstat(fd, &st), ==, 0);
    g_assert_cmpint(pread(fd, &tail, 1, st.st_size - 1), ==, 1);
    g_assert_cmpint(ftruncate(fd, st.st_size - 1), ==, 0);
    reject_receipt(cache, stream, identity);
    g_assert_cmpint(pwrite(fd, &tail, 1, st.st_size - 1), ==, 1);
    close(fd);
    g_assert_cmpint(linkat(stream, "received.tbset", stream, "receipt-link", 0), ==, 0);
    reject_receipt(cache, stream, identity);
    g_assert_cmpint(unlinkat(stream, "receipt-link", 0), ==, 0);
    check_receipt(stream, identity, 3);
}

static void check_range_edges(const char *parent, const char *source,
                               const LatKeyJournalIdentity *identity, int config)
{
    char *cache = g_build_filename(parent, "edge-cache", NULL);
    g_assert_cmpint(mkdir(cache, 0700), ==, 0);
    char name[33], error[256];
    g_assert_cmpint(latcd_journal_register(cache, source, identity->source_sha256,
        identity->build_sha256, identity->codegen_sha256, config, 8, 1048576,
        name, error, sizeof(error)), ==, 0);
    char *root = g_build_filename(cache, ".journals", NULL);
    int root_fd = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    int stream = openat(root_fd, name, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(stream, >=, 0);
    LatKeyJournalIdentity bound = *identity;
    for (size_t i = 0; i < 16; i++)
        bound.epoch[i] = (g_ascii_xdigit_value(name[2 * i]) << 4) |
                         g_ascii_xdigit_value(name[2 * i + 1]);
    LatKeyJournal journal;
    g_assert_cmpint(lat_key_journal_open_at(stream, "keys", &bound, true,
        &journal, error, sizeof(error)), ==, 0);
    const uint64_t submitted[] = {319, 0, 63, 0, 256, 319};
    const uint64_t edges[] = {0, 63, 256, 319};
    for (size_t i = 0; i < G_N_ELEMENTS(submitted); i++) {
        LatTbKey key = {.guest_rva = submitted[i], .flags = 3};
        g_assert_cmpint(lat_key_journal_append(&journal, &key, NULL,
            error, sizeof(error)), ==, 0);
    }
    unsigned count;
    uint64_t received;
    g_assert_cmpint(latcd_journal_collect(cache, bound.build_sha256,
        bound.codegen_sha256, 1048576, &count, &received, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(count, ==, 1);
    g_assert_cmpuint(received, ==, G_N_ELEMENTS(edges));
    int fd = openat(stream, "received.tbset", O_RDONLY | O_CLOEXEC);
    LatTbKeySet set;
    g_assert_cmpint(lat_tb_key_set_read_fd(fd, bound.source_sha256, &set,
        error, sizeof(error)), ==, 0);
    g_assert_cmpuint(set.count, ==, G_N_ELEMENTS(edges));
    for (size_t i = 0; i < G_N_ELEMENTS(edges); i++)
        g_assert_true(lat_tb_key_set_contains(&set, edges[i], 3));
    lat_tb_key_set_destroy(&set);
    close(fd);
    struct stat before, after;
    g_assert_cmpint(fstatat(stream, "received.tbset", &before, AT_SYMLINK_NOFOLLOW), ==, 0);
    LatTbKey duplicate = {.guest_rva = 63, .flags = 3};
    g_assert_cmpint(lat_key_journal_append(&journal, &duplicate, NULL,
        error, sizeof(error)), ==, 0);
    lat_key_journal_close(&journal);
    g_assert_cmpint(latcd_journal_collect(cache, bound.build_sha256,
        bound.codegen_sha256, 1048576, &count, &received, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(received, ==, G_N_ELEMENTS(edges));
    g_assert_cmpint(fstatat(stream, "received.tbset", &after, AT_SYMLINK_NOFOLLOW), ==, 0);
    g_assert_cmpuint(before.st_ino, ==, after.st_ino);
    g_assert_cmpint(unlinkat(stream, "received.tbset", 0), ==, 0);
    close(stream);
    remove_stream(root_fd, name);
    close(root_fd);
    g_assert_cmpint(rmdir(root), ==, 0);
    g_assert_cmpint(rmdir(cache), ==, 0);
    g_free(root); g_free(cache);
}

int main(void)
{
    /* These fixtures invoke run_service directly, after simulated startup. */
    atomic_store(&compiler_budget_recovery_state, 1);
    alarm(60);
    LatcdConfig managed = { .managed = true };
    char isolation_error[128] = {0};
    uint64_t reservation = 0;
    uint8_t digest[32] = {0};
    GPtrArray *tasks_for_compile = g_ptr_array_new_with_free_func(g_free);
    g_assert_cmpint(run_compiler(&managed, 0, NULL, NULL, false, NULL, NULL,
                                 NULL, NULL, NULL, digest, tasks_for_compile,
                                 &reservation, isolation_error,
                                 sizeof(isolation_error)), ==, -1);
    g_assert_cmpstr(isolation_error, ==, "managed compiler isolation unavailable");
    g_assert_cmpuint(tasks_for_compile->len, ==, 0);
    g_assert_cmpuint(reservation, ==, 0);
    g_assert_false(managed_replay_sandbox_ready(&managed));
    managed.worker_bootstrap = "/bootstrap";
    g_assert_false(managed_replay_sandbox_ready(&managed));
    managed.worker_real_compile = true;
    g_assert_true(managed_replay_sandbox_ready(&managed));
    g_ptr_array_free(tasks_for_compile, TRUE);
    int pins[4] = {-1, -1, -1, -1}, copies[4] = {-1, -1, -1, -1};
    pins[0] = syscall(SYS_memfd_create, "snapshot-test", MFD_CLOEXEC);
    g_assert_cmpint(pins[0], >=, 0);
    g_assert_cmpint(write(pins[0], "original", 8), ==, 8);
    GChecksum *snapshot_hash = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(snapshot_hash, (const guchar *)"original", 8);
    uint8_t snapshot_digest[32];
    gsize snapshot_digest_length = sizeof(snapshot_digest);
    g_checksum_get_digest(snapshot_hash, snapshot_digest, &snapshot_digest_length);
    g_checksum_free(snapshot_hash);
    g_assert_cmpint(snapshot_managed_inputs(pins, copies, digest, isolation_error,
                                            sizeof(isolation_error)), ==, -1);
    g_assert_cmpint(copies[0], ==, -1);
    g_assert_cmpint(snapshot_managed_inputs(pins, copies, snapshot_digest, isolation_error,
                                            sizeof(isolation_error)), ==, 0);
    struct stat original_stat, copy_stat;
    g_assert_cmpint(fstat(pins[0], &original_stat), ==, 0);
    g_assert_cmpint(fstat(copies[0], &copy_stat), ==, 0);
    g_assert_true(original_stat.st_dev != copy_stat.st_dev ||
                  original_stat.st_ino != copy_stat.st_ino);
    g_assert_cmpint(pwrite(pins[0], "changed!", 8, 0), ==, 8);
    char snapshot[8];
    g_assert_cmpint(read(copies[0], snapshot, sizeof(snapshot)), ==, 8);
    g_assert_cmpmem(snapshot, sizeof(snapshot), "original", 8);
    errno = 0;
    g_assert_cmpint(pwrite(copies[0], "x", 1, 0), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    close_compiler_inputs(copies);
    close_compiler_inputs(pins);
    char *directory = g_dir_make_tmp("journal-store-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *socket_path = g_build_filename(directory, "socket", NULL);
    char *source_path = g_build_filename(directory, "original", NULL);
    char *cache = g_build_filename(directory, "cache", NULL);
    int task_dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(task_dir, >=, 0);
    GKeyFile *task_record = g_key_file_new();
    g_key_file_set_string(task_record, "task", "state", "BOUND");
    fail_task_link = true;
    errno = 0;
    g_assert_cmpint(persist_task_record(task_dir, "fault", task_record), ==, -1);
    g_assert_cmpint(errno, ==, EIO);
    fail_task_link = false;
    g_key_file_free(task_record);
    close(task_dir);
    char *fault_cache = g_build_filename(directory, "fault-cache", NULL);
    g_assert_cmpint(mkdir(fault_cache, 0700), ==, 0);
    g_assert_cmpint(prepare_metadata_directories(fault_cache), ==, 0);
    LatcdConfig future_config = { .cache_dir = fault_cache };
    char *future_tasks = g_build_filename(fault_cache, ".gc", "tasks", NULL);
    int future_dir = open(future_tasks, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(future_dir, >=, 0);
    const char *future_id = "26d7b68c-64f2-4bb7-bcb5-5f6ab4049f11";
    GKeyFile *future = g_key_file_new();
    g_key_file_set_string(future, "task", "version", "3");
    g_key_file_set_string(future, "task", "id", future_id);
    g_key_file_set_string(future, "task", "state", "BOUND");
    int future_lease = persist_task_record(future_dir, future_id, future);
    g_assert_cmpint(future_lease, >=, 0);
    struct stat future_identity;
    g_assert_cmpint(fstat(future_lease, &future_identity), ==, 0);
    close(future_lease);
    g_assert_cmpint(record_compiler_release(&future_config, future_id, &future_identity, false), ==, -1);
    g_assert_cmpint(record_compiler_release(&future_config, future_id, &future_identity, true), ==, -1);
    char *future_release = g_build_filename(fault_cache, ".gc", "compiler-releases",
                                            "26d7b68c-64f2-4bb7-bcb5-5f6ab4049f11.ini", NULL);
    g_assert_cmpint(access(future_release, F_OK), ==, -1);
    g_free(future_release);
    g_key_file_free(future);
    close(future_dir);
    g_free(future_tasks);
    LatcdCacheCapacity fault_capacity = LATCD_CACHE_CAPACITY_INIT;
    g_assert_cmpint(latcd_cache_capacity_scan(&fault_capacity, fault_cache, NULL, 0), ==, 0);
    latcd_cache_capacity_metadata_bind(&fault_capacity, 1024 * 1024);
    char *tasks = g_build_filename(fault_cache, ".gc", "tasks", NULL);
    task_dir = open(tasks, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(task_dir, >=, 0);
    task_record = g_key_file_new();
    g_key_file_set_string(task_record, "task", "state", "BOUND");
    fail_task_link = true;
    errno = 0;
    g_assert_cmpint(persist_task_record(task_dir, "fault", task_record), ==, -1);
    g_assert_cmpint(errno, ==, EIO);
    g_assert_cmpuint(fault_capacity.metadata_reserved, ==, 0);
    fail_task_link = false;
    g_key_file_free(task_record);
    close(task_dir);
    latcd_cache_capacity_close(&fault_capacity);
    pthread_mutex_destroy(&fault_capacity.lock);
    remove_tree(fault_cache);
    g_free(tasks);
    g_free(fault_cache);
    struct { Elf64_Ehdr header; Elf64_Phdr loads[3]; } elf = {0};
    memcpy(elf.header.e_ident, ELFMAG, SELFMAG);
    elf.header.e_ident[EI_CLASS] = ELFCLASS64;
    elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
    elf.header.e_machine = EM_X86_64;
    elf.header.e_type = ET_EXEC;
    elf.header.e_phoff = sizeof(Elf64_Ehdr);
    elf.header.e_phentsize = sizeof(Elf64_Phdr);
    elf.header.e_phnum = G_N_ELEMENTS(elf.loads);
    for (size_t i = 0; i < G_N_ELEMENTS(elf.loads); i++) {
        elf.loads[i].p_type = PT_LOAD;
        elf.loads[i].p_flags = i == 1 ? PF_R : PF_R | PF_X;
        elf.loads[i].p_vaddr = 0x400000 + i * 128;
        elf.loads[i].p_memsz = 64;
    }
    elf.loads[0].p_filesz = 64;
    g_assert_true(g_file_set_contents(source_path, (void *)&elf, sizeof(elf), NULL));
    int source = open(source_path, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(source, >=, 0);
    LatTranslationConfig captured;
    char error[256];
    g_assert_cmpint(lat_translation_config_init(&captured, LATC_BUILD_ID,
        LAT_CONFIG_ABI_X86_64, 1, error, sizeof(error)), ==, 0);
    GBytes *bytes;
    g_assert_cmpint(lat_translation_config_encode(&captured, &bytes, error, sizeof(error)), ==, 0);
    gsize size;
    const void *data = g_bytes_get_data(bytes, &size);
    int configuration = memfd_create("journal-config", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    g_assert_cmpint(configuration, >=, 0);
    g_assert_cmpint(write(configuration, data, size), ==, size);
    LatcdConfig config = {
        .socket_path = socket_path, .cache_dir = cache, .workers = 1,
        .flush_only = true, .max_input = 4096, .max_jobs = 8,
        .max_queue_bytes = 4096, .max_negative = 8, .max_cache_bytes = 1048576,
    };
    pid_t daemon = start_service(&config);
    g_assert_cmpint(request(&config, source, configuration, 2).status, !=, LATCD_STATUS_OK);
    g_assert_cmpint(fcntl(configuration, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL), ==, 0);
    check_shared_capacity(&config, source, configuration);
    check_anonymous_snapshot(directory, source, configuration);
    g_assert_cmpint(request(&config, source, configuration, 0).status, !=, LATCD_STATUS_OK);
    LatcdResponseV2 registered = request(&config, source, configuration, 4);
    g_assert_cmpint(registered.status, ==, LATCD_STATUS_OK);
    g_assert_cmpuint(strlen(registered.message), ==, 32);
    g_assert_cmpuint(registered.accepted_sequence, ==, 0);
    g_assert_cmpuint(registered.published_sequence, ==, 0);
    char *stream = g_build_filename(cache, ".journals", registered.message, NULL);
    int stream_fd = open(stream, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(stream_fd, >=, 0);
    LatKeyJournalIdentity identity = {0};
    memcpy(identity.source_sha256, registered.source_sha256, 32);
    g_assert_cmpint(journal_build_id(identity.build_sha256), ==, 0);
    expected_codegen_id(identity.codegen_sha256);
    g_assert_cmpint(lat_translation_config_digest(&captured, identity.config_sha256,
                                                 error, sizeof(error)), ==, 0);
    for (size_t i = 0; i < 16; i++)
        identity.epoch[i] = (g_ascii_xdigit_value(registered.message[2 * i]) << 4) |
                            g_ascii_xdigit_value(registered.message[2 * i + 1]);
    check_registration_clients(&config, source, configuration, &identity);
    check_directory_capability(&config, source, configuration, &identity);
    int ready[2];
    g_assert_cmpint(pipe(ready), ==, 0);
    pid_t producer = fork();
    g_assert_cmpint(producer, >=, 0);
    if (!producer) {
        close(ready[0]);
        LatKeyJournal writer;
        g_assert_cmpint(lat_key_journal_open_at(stream_fd, "keys", &identity, true,
                                               &writer, error, sizeof(error)), ==, 0);
        LatTbKey key = { .guest_rva = 16, .flags = 3 };
        uint64_t abandoned;
        g_assert_cmpint(lat_key_journal_reserve(&writer, &abandoned, error, sizeof(error)), ==, 0);
        g_assert_cmpuint(abandoned, ==, 0);
        g_assert_cmpint(lat_key_journal_append(&writer, &key, NULL, error, sizeof(error)), ==, 0);
        g_assert_cmpint(write(ready[1], "C", 1), ==, 1);
        for (;;) pause();
    }
    close(ready[1]);
    char committed;
    g_assert_cmpint(read(ready[0], &committed, 1), ==, 1);
    g_assert_cmpint(committed, ==, 'C');
    close(ready[0]);
    g_assert_cmpint(kill(producer, SIGKILL), ==, 0);
    int producer_status;
    g_assert_cmpint(waitpid(producer, &producer_status, 0), ==, producer);
    g_assert_true(WIFSIGNALED(producer_status));
    g_assert_cmpint(WTERMSIG(producer_status), ==, SIGKILL);
    /* The original source can disappear; recovery must use daemon-owned bytes. */
    close(source);
    g_assert_cmpint(unlink(source_path), ==, 0);
    g_assert_cmpint(kill(daemon, SIGKILL), ==, 0);
    int daemon_status;
    g_assert_cmpint(waitpid(daemon, &daemon_status, 0), ==, daemon);
    g_assert_true(WIFSIGNALED(daemon_status));
    g_assert_cmpint(WTERMSIG(daemon_status), ==, SIGKILL);
    g_assert_cmpint(unlink(socket_path), ==, 0);
    uint8_t build[32], codegen[32];
    g_assert_cmpint(journal_build_id(build), ==, 0);
    expected_codegen_id(codegen);
    unsigned recovered;
    char *root = g_build_filename(cache, ".journals", NULL);
    g_assert_cmpint(chmod(root, 0755), ==, 0);
    errno = ENOENT;
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, config.max_cache_bytes,
                                         &recovered, error, sizeof(error)), ==, -1);
    g_assert_cmpint(chmod(root, 0700), ==, 0);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, config.max_cache_bytes,
                                         &recovered, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(recovered, ==, 1);
    int receipt_watch = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    g_assert_cmpint(receipt_watch, >=, 0);
    char watch_path[64];
    g_snprintf(watch_path, sizeof(watch_path), "/proc/self/fd/%d", stream_fd);
    g_assert_cmpint(inotify_add_watch(receipt_watch, watch_path, IN_CREATE | IN_MOVED_TO), >=, 0);
    daemon = start_service(&config);
    if (faccessat(stream_fd, "received.tbset", F_OK, 0)) {
        struct pollfd ready = {.fd = receipt_watch, .events = POLLIN};
        int64_t deadline = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
        while (faccessat(stream_fd, "received.tbset", F_OK, 0)) {
            int64_t remaining = deadline - g_get_monotonic_time();
            g_assert_cmpint(remaining, >, 0);
            int result = poll(&ready, 1, (remaining + 999) / 1000);
            if (result < 0 && errno == EINTR) continue;
            g_assert_cmpint(result, >, 0);
            char events[4096];
            g_assert_cmpint(read(receipt_watch, events, sizeof(events)), >, 0);
        }
    }
    close(receipt_watch);
    check_collection(&config, stream_fd, &identity);
    g_assert_cmpint(kill(daemon, SIGTERM), ==, 0);
    wait_ok(daemon);
    int receipt_before = openat(stream_fd, "received.tbset", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(receipt_before, >=, 0);
    char managed_receipt_before[65], managed_receipt_after[65];
    g_assert_true(receipt_digest(receipt_before, managed_receipt_before));
    close(receipt_before);
    LatcdConfig managed_config = config;
    managed_config.managed = true;
    LatcdService managed_service = {0};
    LatcdResponseV2 managed_response = { .request_id = 42 };
    g_assert_cmpint(journal_queue_receipts(&managed_config, &managed_service,
        build, codegen, false, &managed_response), ==, -1);
    g_assert_cmpint(managed_response.status, ==, LATCD_STATUS_IO_ERROR);
    g_assert_nonnull(strstr(managed_response.message,
                            "journal configuration replay is not admitted"));
    g_assert_cmpuint(managed_response.accepted_sequence, ==, 0);
    g_assert_cmpuint(managed_response.published_sequence, ==, 0);
    g_assert_cmpuint(managed_service.next_sequence, ==, 0);
    g_assert_cmpuint(managed_service.queued, ==, 0);
    int receipt_after = openat(stream_fd, "received.tbset", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(receipt_after, >=, 0);
    g_assert_true(receipt_digest(receipt_after, managed_receipt_after));
    close(receipt_after);
    g_assert_cmpstr(managed_receipt_before, ==, managed_receipt_after);
    check_receipt(stream_fd, &identity, 3);
    LatcdJournalCompileInput input;
    g_assert_cmpint(latcd_journal_open_compile_input(cache, registered.message,
        build, codegen, config.max_cache_bytes, &input, error, sizeof(error)), ==, 0);
    g_assert_cmpmem(&input.identity, sizeof(input.identity), &identity, sizeof(identity));
    int journal_pins[4] = {input.source_fd, input.receipt_fd, input.config_fd, -1};
    int worker_inputs[4] = {-1, -1, -1, -1};
    g_assert_cmpint(snapshot_journal_replay_input(&input, config.max_cache_bytes,
        worker_inputs, error, sizeof(error)), ==, 0);
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, worker_inputs,
        config.max_cache_bytes, error, sizeof(error)), ==, 0);
    input.receipt_sha256[0] ^= 1;
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, worker_inputs,
        config.max_cache_bytes, error, sizeof(error)), ==, -1);
    input.receipt_sha256[0] ^= 1;
    input.identity.config_sha256[0] ^= 1;
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, worker_inputs,
        config.max_cache_bytes, error, sizeof(error)), ==, -1);
    input.identity.config_sha256[0] ^= 1;
    int swapped_inputs[3] = {worker_inputs[0], worker_inputs[2], worker_inputs[1]};
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, swapped_inputs,
        config.max_cache_bytes, error, sizeof(error)), ==, -1);
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, journal_pins,
        config.max_cache_bytes, error, sizeof(error)), ==, -1);
    g_assert_cmpint(latcd_journal_validate_frozen_input(&input, worker_inputs,
        1, error, sizeof(error)), ==, -1);
    for (unsigned i = 0; i < 3; i++) {
        struct stat original, copy;
        g_assert_cmpint(fstat(journal_pins[i], &original), ==, 0);
        g_assert_cmpint(fstat(worker_inputs[i], &copy), ==, 0);
        g_assert_true(original.st_dev != copy.st_dev || original.st_ino != copy.st_ino);
        g_assert_cmpint(original.st_size, ==, copy.st_size);
        g_assert_cmpint(fcntl(worker_inputs[i], F_GET_SEALS) &
            (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL), ==,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        g_assert_cmpint(pwrite(worker_inputs[i], "x", 1, 0), ==, -1);
        g_assert_cmpint(errno, ==, EPERM);
        char original_digest[65], copied_digest[65];
        g_assert_true(receipt_digest(journal_pins[i], original_digest));
        g_assert_true(receipt_digest(worker_inputs[i], copied_digest));
        g_assert_cmpstr(original_digest, ==, copied_digest);
    }
    close_compiler_inputs(worker_inputs);
    g_assert_cmpint(snapshot_journal_replay_input(&input, 1, worker_inputs,
        error, sizeof(error)), ==, -1);
    for (unsigned i = 0; i < G_N_ELEMENTS(worker_inputs); i++)
        g_assert_cmpint(worker_inputs[i], ==, -1);
    input.receipt_sha256[0] ^= 1;
    g_assert_cmpint(snapshot_journal_replay_input(&input, config.max_cache_bytes,
        worker_inputs, error, sizeof(error)), ==, -1);
    for (unsigned i = 0; i < G_N_ELEMENTS(worker_inputs); i++)
        g_assert_cmpint(worker_inputs[i], ==, -1);
    input.receipt_sha256[0] ^= 1;
    uint8_t wrong_source[32];
    memcpy(wrong_source, input.identity.source_sha256, sizeof(wrong_source));
    wrong_source[0] ^= 1;
    g_assert_cmpint(snapshot_managed_inputs(journal_pins, worker_inputs,
        wrong_source, error, sizeof(error)), ==, -1);
    for (unsigned i = 0; i < G_N_ELEMENTS(worker_inputs); i++)
        g_assert_cmpint(worker_inputs[i], ==, -1);
    gsize captured_size;
    const void *captured_data = g_bytes_get_data(bytes, &captured_size);
    g_assert_cmpmem(input.config, input.config_size, captured_data, captured_size);
    uint8_t sequential_config[LATCD_JOURNAL_CONFIG_LIMIT];
    g_assert_cmpint(read(input.config_fd, sequential_config, input.config_size),
                    ==, input.config_size);
    g_assert_cmpmem(sequential_config, input.config_size, captured_data, captured_size);
    g_assert_cmpint(lseek(input.config_fd, 0, SEEK_SET), ==, 0);
    g_assert_cmpint(lseek(input.receipt_fd, 0, SEEK_CUR), ==, 0);
    int config_seals = fcntl(input.config_fd, F_GET_SEALS);
    g_assert_cmpint(config_seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL),
        ==, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    g_assert_cmpint(pwrite(input.config_fd, "x", 1, 0), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    g_assert_cmpint(renameat(stream_fd, "config", stream_fd, "config.saved"), ==, 0);
    int config_replacement = openat(stream_fd, "config", O_CREAT | O_EXCL | O_WRONLY, 0400);
    g_assert_cmpint(config_replacement, >=, 0);
    g_assert_cmpint(write(config_replacement, "replacement", 11), ==, 11);
    close(config_replacement);
    uint8_t frozen_config[LATCD_JOURNAL_CONFIG_LIMIT];
    g_assert_cmpint(pread(input.config_fd, frozen_config, input.config_size, 0),
                    ==, input.config_size);
    g_assert_cmpmem(frozen_config, input.config_size, captured_data, captured_size);
    g_assert_cmpint(unlinkat(stream_fd, "config", 0), ==, 0);
    g_assert_cmpint(renameat(stream_fd, "config.saved", stream_fd, "config"), ==, 0);
    int seals = fcntl(input.receipt_fd, F_GET_SEALS);
    g_assert_cmpint(seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL),
        ==, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    g_assert_cmpint(pwrite(input.receipt_fd, "x", 1, 0), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    char receipt_hash[65], after_hash[65];
    g_assert_true(receipt_digest(input.receipt_fd, receipt_hash));
    g_assert_cmpint(renameat(stream_fd, "received.tbset", stream_fd, "receipt.saved"), ==, 0);
    int replacement = openat(stream_fd, "received.tbset", O_CREAT | O_EXCL | O_WRONLY, 0400);
    g_assert_cmpint(replacement, >=, 0);
    g_assert_cmpint(write(replacement, "replacement", 11), ==, 11);
    close(replacement);
    g_assert_true(receipt_digest(input.receipt_fd, after_hash));
    g_assert_cmpstr(receipt_hash, ==, after_hash);
    g_assert_cmpint(unlinkat(stream_fd, "received.tbset", 0), ==, 0);
    g_assert_cmpint(renameat(stream_fd, "receipt.saved", stream_fd, "received.tbset"), ==, 0);
    latcd_journal_close_compile_input(&input);
    uint8_t bad_build[32]; memcpy(bad_build, build, sizeof(bad_build)); bad_build[0] ^= 1;
    g_assert_cmpint(latcd_journal_open_compile_input(cache, registered.message,
        bad_build, codegen, config.max_cache_bytes, &input, error, sizeof(error)), ==, -1);
    g_assert_cmpint(input.source_fd, ==, -1);
    g_assert_cmpint(input.receipt_fd, ==, -1);
    g_assert_cmpint(input.config_fd, ==, -1);
    g_assert_cmpint(fchmodat(stream_fd, "config", 0600, 0), ==, 0);
    g_assert_cmpint(latcd_journal_open_compile_input(cache, registered.message,
        build, codegen, config.max_cache_bytes, &input, error, sizeof(error)), ==, -1);
    g_assert_cmpint(fchmodat(stream_fd, "config", 0400, 0), ==, 0);
    check_bad_receipts(cache, stream_fd, &identity);
    LatKeyJournal reader;
    g_assert_cmpint(lat_key_journal_open_at(stream_fd, "keys", &identity, false,
                                           &reader, error, sizeof(error)), ==, 0);
    LatTbKey recovered_key;
    g_assert_cmpint(lat_key_journal_read(&reader, 0, &recovered_key, error, sizeof(error)), ==, 0);
    g_assert_cmpint(lat_key_journal_read(&reader, 1, &recovered_key, error, sizeof(error)), ==, 1);
    g_assert_cmpuint(recovered_key.guest_rva, ==, 16);
    g_assert_cmpuint(recovered_key.flags, ==, 3);
    lat_key_journal_close(&reader);
    char *retained_source = g_build_filename(stream, "source", NULL);
    check_range_edges(directory, retained_source, &identity, configuration);
    check_limits(directory, retained_source, &identity, configuration, size);
    g_free(retained_source);
    check_content_binding(cache, stream_fd, build, codegen, "source", 0);
    /* Byte64 is a legal value field, not a malformed configuration header. */
    check_content_binding(cache, stream_fd, build, codegen, "config", 64);
    uint8_t wrong[32]; memcpy(wrong, build, 32); wrong[0] ^= 1;
    g_assert_cmpint(latcd_journal_recover(cache, wrong, codegen, config.max_cache_bytes,
                                         &recovered, error, sizeof(error)), ==, -1);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, 1,
                                         &recovered, error, sizeof(error)), ==, -1);
    g_assert_cmpint(fchmodat(stream_fd, "config", 0600, 0), ==, 0);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, config.max_cache_bytes,
                                         &recovered, error, sizeof(error)), ==, -1);
    g_assert_cmpint(fchmodat(stream_fd, "config", 0400, 0), ==, 0);
    int journal = openat(stream_fd, "keys", O_RDWR | O_CLOEXEC);
    g_assert_cmpint(journal, >=, 0);
    g_assert_cmpint(ftruncate(journal, 200), ==, 0);
    close(journal);
    g_assert_cmpint(latcd_journal_recover(cache, build, codegen, config.max_cache_bytes,
                                         &recovered, error, sizeof(error)), ==, -1);
    /* Corrupt recovery must fail startup rather than silently discard records. */
    daemon = fork();
    g_assert_cmpint(daemon, >=, 0);
    if (!daemon) _exit(run_service(&config));
    int status;
    g_assert_cmpint(waitpid(daemon, &status, 0), ==, daemon);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 1);
    for (size_t i = 0; i < 4; i++) {
        const char *names[] = { "source", "keys", "config", "registration" };
        g_assert_cmpint(unlinkat(stream_fd, names[i], 0), ==, 0);
    }
    g_assert_cmpint(unlinkat(stream_fd, "received.tbset", 0), ==, 0);
    close(stream_fd);
    g_assert_cmpint(rmdir(stream), ==, 0);
    g_assert_cmpint(rmdir(root), ==, 0);
    g_free(root); g_free(stream);
    char *temporary = g_build_filename(cache, ".tmp", NULL);
    remove_tree(temporary);
    g_free(temporary);
    remove_tree(cache);
    g_assert_cmpint(rmdir(directory), ==, 0);
    close(configuration); g_bytes_unref(bytes);
    g_free(socket_path); g_free(source_path); g_free(cache); g_free(directory);
    puts("journal registration/receipt admission recovery: PASS");
    return 0;
}
