#define main latcd_program_main
#include "../../latcd/main.c"
#undef main
#include "latcd-client.h"

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
    int channel = latcd_client_open_channel(socket_path, LATC_BUILD_ID,
                                             cache_digest, error, sizeof(error));
    g_assert_cmpint(channel, >=, 0);
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
    char hex[65];
    digest_hex(digest, hex);
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
    g_free(canonical);
    g_free(source_path);
    g_free(cache);
    g_free(stats);
    g_free(socket_path);
    g_free(directory);
    puts("latcd persistent channel service tests: PASS");
    return 0;
}
