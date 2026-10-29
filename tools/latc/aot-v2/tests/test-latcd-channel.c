#define main latcd_program_main
#include "../../latcd/main.c"
#undef main
#include "latcd-client.h"
#include "internal-fd-registry.h"
#include <sys/mman.h>

static int protected_fds[3], protected_count, fail_registration;
static int register_test_fd(int fd)
{
    if (fail_registration && protected_count == fail_registration - 1) {
        errno = ENOMEM;
        return -1;
    }
    if (lat_aot_v2_internal_fd_register_locked(fd)) return -1;
    protected_fds[protected_count++] = fd;
    return 0;
}
static void close_test_fd(int fd)
{
    lat_aot_v2_internal_fd_lock();
    g_assert_cmpint(lat_aot_v2_internal_fd_unregister_close_locked(fd), ==, 0);
    lat_aot_v2_internal_fd_unlock();
}
static const LatcdClientFdProtection test_protection = {
    .allocation_lock = lat_aot_v2_internal_fd_allocation_lock,
    .unlock = lat_aot_v2_internal_fd_unlock,
    .register_locked = register_test_fd,
    .close_fd = close_test_fd,
};

typedef struct ProtectedRequestTest { int channel, cache, result; bool sent; } ProtectedRequestTest;
static void *protected_request_thread(void *opaque)
{
    ProtectedRequestTest *test = opaque;
    uint8_t digest[32] = {0};
    test->result = latcd_client_channel_prepare_source_lock_protected(test->channel,
        test->cache, digest, 11, &test->sent, &test_protection, NULL, 0);
    return NULL;
}

static void test_protected_lock_request(void)
{
    int sockets[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), ==, 0);
    int cache = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(cache, >=, 0);
    uint8_t digest[32] = {0};
    char error[256];
    bool sent;
    for (int fail = 1; fail <= 3; fail++) {
        protected_count = 0; fail_registration = fail;
        g_assert_cmpint(latcd_client_channel_prepare_source_lock_protected(sockets[0], cache,
            digest, fail, &sent, &test_protection, error, sizeof(error)), ==, -1);
        g_assert_false(sent);
        for (int i = 0; i < protected_count; i++)
            g_assert_false(lat_aot_v2_internal_fd_is_protected(protected_fds[i]));
    }
    fail_registration = 0; protected_count = 0;
    g_assert_cmpint(setenv("LATX_AOT_V2_HELLO_TIMEOUT_MS", "20", 1), ==, 0);
    g_assert_cmpint(latcd_client_channel_prepare_source_lock_protected(sockets[0], cache,
        digest, 10, &sent, &test_protection, error, sizeof(error)), ==, -1);
    g_assert_true(sent);
    g_assert_cmpint(errno, ==, ETIMEDOUT);
    g_assert_cmpint(protected_count, ==, 3);
    for (int i = 0; i < protected_count; i++)
        g_assert_false(lat_aot_v2_internal_fd_is_protected(protected_fds[i]));
    unsetenv("LATX_AOT_V2_HELLO_TIMEOUT_MS");
    close(cache); close(sockets[0]); close(sockets[1]);

    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), ==, 0);
    cache = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(cache, >=, 0);
    protected_count = 0;
    ProtectedRequestTest request_test = {.channel = sockets[0], .cache = cache};
    pthread_t thread;
    g_assert_cmpint(pthread_create(&thread, NULL, protected_request_thread, &request_test), ==, 0);
    LatcdRequestV2 request;
    int root_fd, digest_fd, reply_fd;
    g_assert_cmpint(latcd_receive_channel_request(sockets[1], &request, &root_fd,
        &digest_fd, &reply_fd, error, sizeof(error)), ==, 0);
    g_assert_cmpint(protected_count, ==, 3);
    g_assert_true(lat_aot_v2_internal_fd_is_protected(protected_fds[1]));
    g_assert_cmpint(lat_aot_v2_internal_fd_close_guest(protected_fds[1]), ==, -1);
    g_assert_cmpint(errno, ==, EACCES);
    close(root_fd); close(digest_fd); close(reply_fd);
    g_assert_cmpint(pthread_join(thread, NULL), ==, 0);
    g_assert_true(request_test.sent);
    g_assert_cmpint(request_test.result, ==, -1);
    close(cache); close(sockets[0]); close(sockets[1]);
}

static void timeout_signal_handler(int signal_number) { (void)signal_number; }

static void *interrupt_waiter(void *opaque)
{
    pthread_t *target = opaque;
    for (unsigned i = 0; i < 100; i++) {
        g_usleep(5000);
        pthread_kill(*target, SIGUSR1);
    }
    return NULL;
}

static void test_lock_timeout_interrupted(void)
{
    struct sigaction action = {.sa_handler = timeout_signal_handler}, previous;
    sigemptyset(&action.sa_mask);
    g_assert_cmpint(sigaction(SIGUSR1, &action, &previous), ==, 0);
    int sockets[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), ==, 0);
    int cache = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(cache, >=, 0);
    uint8_t digest[32] = {0};
    char error[256];
    bool sent = false;
    g_assert_cmpint(setenv("LATX_AOT_V2_HELLO_TIMEOUT_MS", "80", 1), ==, 0);
    pthread_t target = pthread_self(), sender;
    g_assert_cmpint(pthread_create(&sender, NULL, interrupt_waiter, &target), ==, 0);
    int64_t start = g_get_monotonic_time();
    g_assert_cmpint(latcd_client_channel_prepare_source_lock_ex(sockets[0], cache,
        digest, 55, &sent, error, sizeof(error)), ==, -1);
    int saved = errno;
    int64_t elapsed = g_get_monotonic_time() - start;
    g_assert_true(sent);
    g_assert_cmpint(saved, ==, ETIMEDOUT);
    g_assert_cmpint(elapsed, <, 400000);
    g_assert_cmpint(pthread_join(sender, NULL), ==, 0);
    g_assert_cmpint(sigaction(SIGUSR1, &previous, NULL), ==, 0);
    unsetenv("LATX_AOT_V2_HELLO_TIMEOUT_MS");
    close(cache); close(sockets[0]); close(sockets[1]);
}

static void test_offline_daemon_owner_race(void)
{
    char *root = g_dir_make_tmp("latcd-offline-owner-XXXXXX", NULL);
    g_assert_nonnull(root);
    const char *source = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    int source_fd = lat_aot_v2_cache_source_lock(root, source, LOCK_EX, false, NULL, 0);
    g_assert_cmpint(source_fd, >=, 0);
    char *owner_path = g_build_filename(root, ".latcd.lock", NULL);
    LatcdConfig config = {.cache_dir = root, .socket_path = "offline-owner-test"};
    char error[256];
    for (unsigned protected = 0; protected < 2; protected++) {
        g_assert_cmpint(lat_aot_v2_cache_source_lock_offline(root, source, LOCK_SH,
            protected, error, sizeof(error)), ==, -1);
        g_assert_cmpint(errno, ==, EWOULDBLOCK);
    }
    int owner = acquire_cache_owner(&config, error, sizeof(error));
    g_assert_cmpint(owner, >=, 0);
    close(source_fd);
    const char *other = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    g_assert_cmpint(lat_aot_v2_cache_source_lock_offline(root, other, LOCK_SH,
        false, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EWOULDBLOCK);
    char *other_name = g_strconcat(other, ".lock", NULL);
    char *other_path = g_build_filename(root, ".gc", "source-locks", other_name, NULL);
    g_assert_cmpint(access(other_path, F_OK), ==, -1);
    g_assert_cmpint(errno, ==, ENOENT);
    g_free(other_path); g_free(other_name);
    close(owner);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *locks = g_build_filename(gc, "source-locks", NULL);
    char *name = g_strconcat(source, ".lock", NULL);
    char *lock = g_build_filename(locks, name, NULL);
    g_assert_cmpint(unlink(lock), ==, 0);
    g_assert_cmpint(rmdir(locks), ==, 0);
    g_assert_cmpint(rmdir(gc), ==, 0);
    g_assert_cmpint(unlink(owner_path), ==, 0);
    g_assert_cmpint(rmdir(root), ==, 0);
    g_free(lock); g_free(name); g_free(locks); g_free(gc); g_free(owner_path); g_free(root);
}

static void test_lock_request_sent_state(void)
{
    int sockets[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets), ==, 0);
    int cache = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(cache, >=, 0);
    uint8_t digest[32] = {0};
    char error[256];
    bool sent = false;
    g_assert_cmpint(setenv("LATX_AOT_V2_HELLO_TIMEOUT_MS", "20", 1), ==, 0);
    g_assert_cmpint(latcd_client_channel_prepare_source_lock_ex(sockets[0], cache,
        digest, 1, &sent, error, sizeof(error)), ==, -1);
    g_assert_true(sent);
    g_assert_cmpint(errno, ==, ETIMEDOUT);
    close(sockets[1]);
    sent = true;
    g_assert_cmpint(latcd_client_channel_prepare_source_lock_ex(sockets[0], cache,
        digest, 2, &sent, error, sizeof(error)), ==, -1);
    g_assert_false(sent);
    close(sockets[0]); close(cache);
    unsetenv("LATX_AOT_V2_HELLO_TIMEOUT_MS");
}

static void test_prepare_source_lock_request(void)
{
    char *root = g_dir_make_tmp("latcd-lock-request-XXXXXX", NULL);
    char *other = g_dir_make_tmp("latcd-lock-other-XXXXXX", NULL);
    g_assert_nonnull(root);
    g_assert_nonnull(other);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *locks = g_build_filename(gc, "source-locks", NULL);
    g_assert_cmpint(mkdir(gc, 0700), ==, 0);
    g_assert_cmpint(mkdir(locks, 0700), ==, 0);
    uint8_t digest[32] = {1};
    char hex[65];
    digest_hex(digest, hex);
    char *current_name = g_strconcat(hex, ".current", NULL);
    char *current = g_build_filename(root, current_name, NULL);
    g_assert_true(g_file_set_contents(current, "{}", 2, NULL));
    g_assert_cmpint(chmod(current, 0600), ==, 0);
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, root, NULL, 0), ==, 0);
    latcd_cache_capacity_metadata_bind(&generation_capacity, 1048576);
    int cache = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int wrong = open(other, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int data = memfd_create("source-digest", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    g_assert_cmpint(cache, >=, 0);
    g_assert_cmpint(wrong, >=, 0);
    g_assert_cmpint(data, >=, 0);
    g_assert_cmpint(write(data, digest, sizeof(digest)), ==, sizeof(digest));
    LatcdConfig config = {.cache_dir = root};
    LatcdResponseV2 response;
    response_init(&response, 1);
    prepare_source_lock_request(&config, cache, data, &response);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_BAD_REQUEST);
    g_assert_cmpint(fcntl(data, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW), ==, 0);
    response_init(&response, 2);
    prepare_source_lock_request(&config, wrong, data, &response);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_IO_ERROR);
    g_assert_true(latcd_cache_capacity_poll(&generation_capacity));
    for (unsigned i = 0; i < 2; i++) {
        response_init(&response, 3 + i);
        prepare_source_lock_request(&config, cache, data, &response);
        g_assert_cmpint(response.status, ==, LATCD_STATUS_OK);
        g_assert_cmpmem(response.source_sha256, 32, digest, 32);
        g_assert_true(latcd_cache_capacity_poll(&generation_capacity));
    }
    close(data); close(wrong); close(cache);
    latcd_cache_capacity_close(&generation_capacity);
    char *lock_name = g_strconcat(hex, ".lock", NULL);
    char *lock = g_build_filename(locks, lock_name, NULL);
    g_assert_cmpint(unlink(lock), ==, 0);
    g_assert_cmpint(unlink(current), ==, 0);
    g_assert_cmpint(rmdir(locks), ==, 0);
    g_assert_cmpint(rmdir(gc), ==, 0);
    g_assert_cmpint(rmdir(root), ==, 0);
    g_assert_cmpint(rmdir(other), ==, 0);
    g_free(lock); g_free(lock_name); g_free(current); g_free(current_name);
    g_free(locks); g_free(gc); g_free(root); g_free(other);
}

static void wait_child(pid_t child)
{
    int status;
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
}

static void test_flush_snapshot(void)
{
    LatcdService service = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .ready = PTHREAD_COND_INITIALIZER,
        .active = g_hash_table_new(g_str_hash, g_str_equal),
        .source_states = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free),
        .static_barriers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free),
    };
    const char *key = "1111111111111111111111111111111111111111111111111111111111111111";
    LatcdSourceState *state = source_state_locked(&service, key);
    state->accepted_sequence = 1;
    state->runtime_accepted_sequence = 1;
    LatcdRequestV2 request = {.operation = LATCD_OP_FLUSH_ALL, .request_id = 17};
    LatcdFlushRequest flush = {.client_fd = -1};
    g_assert_cmpint(prepare_flush_request(&service, -1, &request, &flush), ==, 0);
    g_assert_cmpuint(flush.response.request_id, ==, 17);
    g_assert_cmpuint(flush.response.accepted_sequence, ==, 1);
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 0);
    state->accepted_sequence = 2;
    state->runtime_accepted_sequence = 2;
    LatcdSourceState *later = source_state_locked(&service, "later-source");
    later->accepted_sequence = 3;
    state->published_sequence = 1;
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 1);
    g_assert_cmpuint(flush.response.accepted_sequence, ==, 1);
    LatcdStaticBarrier *barrier = g_new0(LatcdStaticBarrier, 1);
    g_strlcpy(barrier->source_key, key, sizeof(barrier->source_key));
    barrier->first_sequence = 2;
    barrier->failed = true;
    g_hash_table_insert(service.static_barriers, g_strdup("static"), barrier);
    state->published_sequence = 0;
    /* A later static failure must not fail the earlier runtime barrier. */
    LatcdJob failed_static = {.static_tbset = true, .accepted_sequence = 2};
    g_strlcpy(failed_static.key, "static", sizeof(failed_static.key));
    g_strlcpy(failed_static.source_key, key, sizeof(failed_static.source_key));
    mark_job_failed_locked(&service, &failed_static);
    g_assert_cmpuint(state->failed_sequence, ==, 0);
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 0);
    state->published_sequence = 1;
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 1);
    barrier->first_sequence = 1;
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, -1);
    barrier->failed = false;
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 0);
    g_hash_table_remove(service.static_barriers, "static");
    state->published_sequence = 0;
    LatcdJob failed_runtime = {.accepted_sequence = 1};
    g_strlcpy(failed_runtime.source_key, key, sizeof(failed_runtime.source_key));
    mark_job_failed_locked(&service, &failed_runtime);
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, -1);
    state->failed_sequence = 0;
    /* A static-only source needs no runtime publication watermark. */
    g_array_index(flush.targets, LatcdFlushTarget, 0).runtime_sequence = 0;
    g_assert_cmpint(flush_request_state_locked(&service, &flush), ==, 1);
    g_assert_cmpuint(flush.response.published_sequence, ==, 1);
    g_array_free(flush.targets, TRUE);
    g_hash_table_destroy(service.active);
    g_hash_table_destroy(service.source_states);
    g_hash_table_destroy(service.static_barriers);
    pthread_cond_destroy(&service.ready);
    pthread_mutex_destroy(&service.lock);
}

static void test_active_source_reuse(const char *directory, const char *source_path)
{
    char error[256];
    int source = open(source_path, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(source, >=, 0);
    LatcdConfig config = {.max_input = 4096};
    LatcdService service = {.config = &config,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .active = g_hash_table_new(g_str_hash, g_str_equal)};
    LatcdJob job = {0};
    g_assert_cmpint(snapshot_source(source, directory, config.max_input,
        &job.snapshot, job.digest, &job.source_identity, error, sizeof(error)), ==, 0);
    g_hash_table_insert(service.active, "source", &job);
    uint8_t digest[32];
    struct stat identity;
    char *reused = reuse_active_source(&service, source, directory, digest, &identity);
    g_assert_nonnull(reused);
    g_assert_cmpmem(digest, 32, job.digest, 32);
    g_assert_true(metadata_equal(&identity, &job.source_identity));
    struct stat original, pinned;
    g_assert_cmpint(stat(job.snapshot, &original), ==, 0);
    g_assert_cmpint(stat(reused, &pinned), ==, 0);
    g_assert_cmpuint(original.st_ino, ==, pinned.st_ino);
    unlink(reused);
    g_free(reused);

    int writable = open(source_path, O_RDWR | O_CLOEXEC);
    g_assert_cmpint(writable, >=, 0);
    g_assert_null(reuse_active_source(&service, writable, directory, digest, &identity));
    /* Even matching candidate metadata must not bypass byte comparison. */
    unsigned char byte;
    g_assert_cmpint(pread(writable, &byte, 1, 0), ==, 1);
    unsigned char changed = byte ^ 1;
    g_assert_cmpint(pwrite(writable, &changed, 1, 0), ==, 1);
    g_assert_cmpint(fstat(source, &job.source_identity), ==, 0);
    g_assert_null(reuse_active_source(&service, source, directory, digest, &identity));
    g_assert_cmpint(pwrite(writable, &byte, 1, 0), ==, 1);
    g_assert_cmpint(fstat(source, &job.source_identity), ==, 0);
    reused = reuse_active_source(&service, source, directory, digest, &identity);
    g_assert_nonnull(reused);
    unlink(job.snapshot);
    g_assert_cmpint(access(reused, R_OK), ==, 0);
    g_assert_null(reuse_active_source(&service, source, directory, digest, &identity));
    unlink(reused);
    g_free(reused);
    g_free(job.snapshot);
    close(writable);
    close(source);
    g_hash_table_destroy(service.active);
    pthread_mutex_destroy(&service.lock);
}

int main(void)
{
    test_protected_lock_request();
    test_lock_timeout_interrupted();
    test_offline_daemon_owner_race();
    test_lock_request_sent_state();
    test_prepare_source_lock_request();
    test_flush_snapshot();
    char *directory = g_dir_make_tmp("latcd-channel-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *socket_path = g_build_filename(directory, "socket", NULL);
    char *stats = g_build_filename(directory, "stats.json", NULL);
    char *cache = g_build_filename(directory, "cache", NULL);
    char *source_path = g_build_filename(directory, "source", NULL);
    struct {
        Elf64_Ehdr header;
        Elf64_Phdr load;
    } elf = {0};
    memcpy(elf.header.e_ident, ELFMAG, SELFMAG);
    elf.header.e_ident[EI_CLASS] = ELFCLASS64;
    elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
    elf.header.e_machine = EM_X86_64;
    elf.header.e_type = ET_EXEC;
    elf.header.e_phoff = sizeof(Elf64_Ehdr);
    elf.header.e_phentsize = sizeof(Elf64_Phdr);
    elf.header.e_phnum = 1;
    elf.load.p_type = PT_LOAD;
    elf.load.p_flags = PF_R | PF_X;
    elf.load.p_filesz = sizeof(elf);
    elf.load.p_memsz = sizeof(elf);
    g_assert_true(g_file_set_contents(source_path, (void *)&elf, sizeof(elf), NULL));
    test_active_source_reuse(directory, source_path);
    int source = open(source_path, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(source, >=, 0);
    uint8_t digest[32], cache_digest[32];
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (void *)&elf, sizeof(elf));
    gsize size = sizeof(digest);
    g_checksum_get_digest(checksum, digest, &size);
    g_checksum_free(checksum);
    char hex[65];
    digest_hex(digest, hex);
    g_assert_cmpint(mkdir(cache, 0700), ==, 0);
    char *gc_dir = g_build_filename(cache, ".gc", NULL);
    char *lock_dir = g_build_filename(gc_dir, "source-locks", NULL);
    char *current_name = g_strconcat(hex, ".current", NULL);
    char *current = g_build_filename(cache, current_name, NULL);
    g_assert_cmpint(mkdir(gc_dir, 0700), ==, 0);
    g_assert_cmpint(mkdir(lock_dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(current, "{}", 2, NULL));
    g_assert_cmpint(chmod(current, 0600), ==, 0);
    LatcdConfig config = {
        .socket_path = socket_path, .cache_dir = cache, .stats_path = stats,
        .workers = 1, .flush_only = true, .idle_seconds = 1,
        .max_input = 4096, .max_jobs = 8, .max_queue_bytes = 4096,
        .max_negative = 8, .max_cache_bytes = 1048576,
    };
    pid_t daemon = fork();
    g_assert_cmpint(daemon, >=, 0);
    if (!daemon) {
        close(source);
        g_assert_cmpint(prepare_metadata_directories(cache), ==, 0);
        g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, cache, NULL, 0), ==, 0);
        latcd_cache_capacity_metadata_bind(&generation_capacity, config.max_cache_bytes);
        _exit(run_service(&config));
    }
    for (unsigned i = 0; i < 500 && access(socket_path, F_OK); i++) {
        g_usleep(10000);
    }
    g_assert_cmpint(access(socket_path, F_OK), ==, 0);
    checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (void *)cache, strlen(cache));
    size = sizeof(cache_digest);
    g_checksum_get_digest(checksum, cache_digest, &size);
    g_checksum_free(checksum);
    char error[256];
    uint8_t wrong[32] = {0};
    g_assert_cmpint(latcd_client_open_channel(socket_path, "wrong-build",
        cache_digest, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EPROTO);
    g_assert_cmpint(latcd_client_open_channel(socket_path, LATC_BUILD_ID,
        wrong, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EPROTO);
    protected_count = 0; fail_registration = 1;
    g_assert_cmpint(latcd_client_open_channel_protected(socket_path, LATC_BUILD_ID,
        cache_digest, &test_protection, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, ENOMEM);
    fail_registration = 0; protected_count = 0;
    g_assert_cmpint(latcd_client_open_channel_protected(socket_path, "wrong-build",
        cache_digest, &test_protection, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EPROTO);
    g_assert_cmpint(protected_count, ==, 1);
    g_assert_false(lat_aot_v2_internal_fd_is_protected(protected_fds[0]));
    protected_count = 0;
    int protected_channel = latcd_client_open_channel_protected(socket_path, LATC_BUILD_ID,
        cache_digest, &test_protection, error, sizeof(error));
    g_assert_cmpint(protected_channel, >=, 0);
    g_assert_true(lat_aot_v2_internal_fd_is_protected(protected_channel));
    g_assert_cmpint(lat_aot_v2_internal_fd_close_guest(protected_channel), ==, -1);
    g_assert_cmpint(errno, ==, EACCES);
    close_test_fd(protected_channel);
    int channel = latcd_client_open_channel(socket_path, LATC_BUILD_ID,
                                             cache_digest, error, sizeof(error));
    g_assert_cmpint(channel, >=, 0);
    int cache_fd = open(cache, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int wrong_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(cache_fd, >=, 0);
    g_assert_cmpint(wrong_fd, >=, 0);
    g_assert_cmpint(latcd_client_channel_prepare_source_lock(channel, wrong_fd, digest,
        701, error, sizeof(error)), ==, -1);
    int start[2];
    g_assert_cmpint(pipe(start), ==, 0);
    pid_t lock_children[4];
    for (unsigned i = 0; i < G_N_ELEMENTS(lock_children); i++) {
        lock_children[i] = fork();
        g_assert_cmpint(lock_children[i], >=, 0);
        if (!lock_children[i]) {
            char byte;
            close(start[1]);
            if (read(start[0], &byte, 1) != 1) _exit(1);
            _exit(latcd_client_channel_prepare_source_lock(channel, cache_fd, digest,
                702 + i, error, sizeof(error)) ? 2 : 0);
        }
    }
    close(start[0]);
    g_assert_cmpint(write(start[1], "xxxx", 4), ==, 4);
    close(start[1]);
    for (unsigned i = 0; i < G_N_ELEMENTS(lock_children); i++) wait_child(lock_children[i]);
    int data = memfd_create("lost-lock-reply", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    int replies[2];
    g_assert_cmpint(data, >=, 0);
    g_assert_cmpint(write(data, digest, sizeof(digest)), ==, sizeof(digest));
    g_assert_cmpint(fcntl(data, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK), ==, 0);
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               0, replies), ==, 0);
    LatcdRequestV2 abandoned = {.magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION, .size = sizeof(abandoned),
        .operation = LATCD_OP_PREPARE_SOURCE_LOCK, .request_id = 710};
    g_assert_cmpint(latcd_send_channel_request(channel, cache_fd, data, replies[1],
        &abandoned, error, sizeof(error)), ==, 0);
    close(data); close(replies[0]); close(replies[1]);
    g_assert_cmpint(latcd_client_channel_prepare_source_lock(channel, cache_fd, digest,
        711, error, sizeof(error)), ==, 0);
    char *lock_name = g_strconcat(hex, ".lock", NULL);
    char *lock_path = g_build_filename(lock_dir, lock_name, NULL);
    g_assert_cmpint(access(lock_path, F_OK), ==, 0);
    close(cache_fd); close(wrong_fd);
    int admitted[LATCD_MAX_CHANNELS - 1];
    for (unsigned i = 0; i < G_N_ELEMENTS(admitted); i++) {
        admitted[i] = latcd_client_open_channel(socket_path, LATC_BUILD_ID,
                                                 cache_digest, error, sizeof(error));
        g_assert_cmpint(admitted[i], >=, 0);
    }
    g_assert_cmpint(latcd_client_open_channel(socket_path, LATC_BUILD_ID,
        cache_digest, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EIO);
    for (unsigned i = 0; i < G_N_ELEMENTS(admitted); i++) close(admitted[i]);
    /* Reclaiming closed channels must make room for a fresh handshake. */
    int replacement = latcd_client_open_channel(socket_path, LATC_BUILD_ID,
                                                  cache_digest, error, sizeof(error));
    g_assert_cmpint(replacement, >=, 0);
    close(replacement);
    /* An idle authenticated channel must neither stall HELLO nor expire. */
    g_usleep(1300000);
    g_assert_cmpint(latcd_client_hello(socket_path, LATC_BUILD_ID,
        cache_digest, error, sizeof(error)), ==, 0);
    int invalid = open("/dev/null", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(invalid, >=, 0);
    g_assert_cmpint(latcd_client_channel_submit_keys_fd(channel, invalid,
        invalid, LATCD_PRIORITY_LIBRARY, 1, 1, error, sizeof(error)), ==, -1);
    g_assert_cmpint(errno, ==, EIO);
    close(invalid);
    pid_t children[4];
    for (unsigned i = 0; i < 4; i++) {
        children[i] = fork();
        g_assert_cmpint(children[i], >=, 0);
        if (!children[i]) {
            LatTbKey key = {.guest_rva = i, .flags = 3};
            LatTbKeySet set = {.keys = &key, .count = 1};
            memcpy(set.source_sha256, digest, sizeof(digest));
            char *path = g_strdup_printf("%s/keys-%u", directory, i);
            int keys = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            g_assert_cmpint(keys, >=, 0);
            g_assert_cmpint(lat_tb_key_set_write_fd(keys, &set,
                error, sizeof(error)), ==, 0);
            close(keys);
            keys = open(path, O_RDONLY | O_CLOEXEC);
            g_assert_cmpint(keys, >=, 0);
            int result = latcd_client_channel_submit_keys_fd(channel,
                source, keys, LATCD_PRIORITY_LIBRARY, 100 + i, 100 + i,
                error, sizeof(error));
            if (result) fprintf(stderr, "channel child: %s\n", error);
            g_assert_cmpint(result, ==, 0);
            close(keys);
            close(source);
            close(channel);
            unlink(path);
            g_free(path);
            _exit(0);
        }
    }
    for (unsigned i = 0; i < 4; i++) wait_child(children[i]);
    char *canonical = g_strdup_printf("%s/.tbsets/%s.tbset", cache, hex);
    LatTbKeySet accepted = {0};
    g_assert_cmpint(lat_tb_key_set_read_file(canonical, digest, &accepted,
        error, sizeof(error)), ==, 0);
    g_assert_cmpuint(accepted.count, ==, 4);
    for (size_t i = 0; i < accepted.count; i++) {
        g_assert_cmpuint(accepted.keys[i].guest_rva, ==, i);
    }
    lat_tb_key_set_destroy(&accepted);
    g_assert_cmpint(kill(daemon, SIGTERM), ==, 0);
    wait_child(daemon);
    g_assert_cmpint(latcd_client_channel_submit_keys_fd(channel, source,
        source, LATCD_PRIORITY_LIBRARY, 200, 200, error, sizeof(error)), ==, -1);
    close(channel);
    close(source);
    g_free(lock_path); g_free(lock_name); g_free(current); g_free(current_name);
    g_free(lock_dir); g_free(gc_dir);
    g_free(canonical);
    g_free(source_path);
    g_free(cache);
    g_free(stats);
    g_free(socket_path);
    g_free(directory);
    puts("latcd persistent channel service tests: PASS");
    return 0;
}
