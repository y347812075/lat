#define _GNU_SOURCE
#include "../latcd/managed-launch.h"
#include "../latcd/cache-capacity.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define TASK_ID "12345678-1234-1234-1234-123456789abc"

static int make_file(const char *path, const void *data, size_t size)
{
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(write(fd, data, size) == (ssize_t)size);
    assert(!fchmod(fd, 0400));
    return fd;
}

static int make_memfd(const char *bytes)
{
    int fd = memfd_create("managed-launch-test", MFD_CLOEXEC);
    assert(fd >= 0);
    assert(write(fd, bytes, strlen(bytes)) == (ssize_t)strlen(bytes));
    assert(!lseek(fd, 0, SEEK_SET));
    return fd;
}

static void rewrite_digest(uint8_t digest[32], uint8_t value)
{
    memset(digest, value, 32);
}

/* Replace the record content in place while keeping its length, then restore
 * the read-only mode the reader requires. */
static void rewrite_record(const char *path, const char *text, size_t size)
{
    assert(!chmod(path, 0600));
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(pwrite(fd, text, size, 0) == (ssize_t)size);
    assert(!fsync(fd));
    assert(!close(fd));
    assert(!chmod(path, 0400));
}

int main(void)
{
    GError *gerror = NULL;
    char *root = g_dir_make_tmp("latcd-managed-launch-XXXXXX", &gerror);
    assert(root != NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *tasks = g_build_filename(gc, "tasks", NULL);
    char *launches = g_build_filename(gc, "managed-launch", NULL);
    char *task = g_build_filename(tasks, "task.ini", NULL);
    assert(!mkdir(gc, 0700));
    assert(!mkdir(tasks, 0700));
    assert(!mkdir(launches, 0700));
    int task_fd = make_file(task, "authenticated task", strlen("authenticated task"));

    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    char error[256] = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    const uint64_t metadata_base = capacity.metadata_committed;

    int compiler = make_memfd("compiler");
    int runner = make_memfd("runner");
    int runtime = make_memfd("runtime");
    int launcher = make_memfd("launcher");
    int bootstrap = make_memfd("bootstrap");
    int baseline = make_memfd("baseline");
    GPtrArray *options = g_ptr_array_new();
    g_ptr_array_add(options, "--ro-bind-data");
    g_ptr_array_add(options, "4");
    g_ptr_array_add(options, "/input/source");
    g_ptr_array_add(options, "--seccomp");
    g_ptr_array_add(options, "9");
    GPtrArray *exec = g_ptr_array_new();
    g_ptr_array_add(exec, "/launcher");
    g_ptr_array_add(exec, "--args");
    g_ptr_array_add(exec, "15");
    g_ptr_array_add(exec, "--");
    g_ptr_array_add(exec, "/bootstrap");
    g_ptr_array_add(exec, "/usr/bin/latc");
    g_ptr_array_add(exec, "compile-replay-native");
    const char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
    LatcdManagedLaunchInput input = {
        .receipt_size = 4096,
        .compiler_fd = compiler,
        .runner_fd = runner,
        .runtime_fd = runtime,
        .launcher_fd = launcher,
        .bootstrap_fd = bootstrap,
        .baseline_fd = baseline,
        .options = options,
        .exec = exec,
        .environment = environment,
    };
    rewrite_digest(input.build_sha256, 1);
    rewrite_digest(input.codegen_sha256, 2);
    rewrite_digest(input.config_sha256, 3);
    rewrite_digest(input.source_sha256, 4);
    rewrite_digest(input.receipt_sha256, 5);
    rewrite_digest(input.closure_sha256, 6);

    /* An invalid task identifier is rejected before anything is written. */
    struct stat identity;
    char digest[65];
    assert(latcd_managed_launch_prepare(root, "not-a-uuid", task_fd, &input, &identity,
        digest, error, sizeof(error)));
    assert(latcd_managed_launch_validate_self(root, TASK_ID, task_fd, error, sizeof(error)));

    char *launch = g_build_filename(launches, TASK_ID ".launch", NULL);
    assert(!latcd_managed_launch_prepare(root, TASK_ID, task_fd, &input, &identity,
        digest, error, sizeof(error)));
    assert(capacity.metadata_committed > metadata_base);
    assert(!latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));
    assert(!latcd_managed_launch_validate_bound(root, TASK_ID, task_fd, &identity, digest,
        error, sizeof(error)));
    struct stat wrong_identity = identity;
    wrong_identity.st_ino++;
    assert(latcd_managed_launch_validate_bound(root, TASK_ID, task_fd, &wrong_identity, digest,
        error, sizeof(error)));
    char wrong_digest[65];
    g_strlcpy(wrong_digest, digest, sizeof(wrong_digest));
    wrong_digest[0] = wrong_digest[0] == '0' ? '1' : '0';
    assert(latcd_managed_launch_validate_bound(root, TASK_ID, task_fd, &identity, wrong_digest,
        error, sizeof(error)));

    /* A different task identity never matches the recorded contract. */
    assert(latcd_managed_launch_validate_self(root, "12345678-1234-1234-1234-123456789abd",
        task_fd, error, sizeof(error)));

    g_ptr_array_index(options, 2) = "/input/changed";
    assert(latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));
    g_ptr_array_index(options, 2) = "/input/source";
    assert(!latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));

    /* The bound tool content, not only argv, identifies the launch. */
    assert(pwrite(baseline, "BASE", 4, 0) == 4);
    assert(latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));
    assert(pwrite(baseline, "baseline", 8, 0) == 8);
    assert(!latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));

    /* Removal releases the metadata charge and stays idempotent. */
    assert(!latcd_managed_launch_discard(root, TASK_ID, task_fd, error, sizeof(error)));
    assert(capacity.metadata_committed == metadata_base);
    assert(!latcd_managed_launch_discard(root, TASK_ID, task_fd, error, sizeof(error)));
    assert(latcd_managed_launch_validate_self(root, TASK_ID, task_fd, error, sizeof(error)));
    assert(latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));

    /*
     * A corrupted record must be rejected rather than dereferenced. A tampered
     * record is intentionally not removed afterwards: the write invalidates the
     * capacity inventory, and retaining an unprovable record is the contract.
     */
    assert(!latcd_managed_launch_prepare(root, TASK_ID, task_fd, &input, &identity,
        digest, error, sizeof(error)));
    char *text = NULL;
    gsize text_size = 0;
    assert(g_file_get_contents(launch, &text, &text_size, NULL));
    char first = text[0];
    text[0] = (char)(first ^ 1);
    rewrite_record(launch, text, text_size);
    assert(latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));
    assert(latcd_managed_launch_validate_self(root, TASK_ID, task_fd, error, sizeof(error)));

    /* A key that exists but cannot be decoded yields a NULL value in GLib. */
    text[0] = first;
    char *field = strstr(text, "version=1");
    assert(field != NULL);
    text[field - text + 8] = '\\';
    rewrite_record(launch, text, text_size);
    assert(latcd_managed_launch_verify(root, TASK_ID, task_fd, &identity, digest, &input,
        error, sizeof(error)));
    assert(latcd_managed_launch_validate_self(root, TASK_ID, task_fd, error, sizeof(error)));
    assert(!unlink(launch));
    g_free(text);

    close(baseline);
    close(bootstrap);
    close(launcher);
    close(runtime);
    close(runner);
    close(compiler);
    close(task_fd);
    g_ptr_array_free(exec, TRUE);
    g_ptr_array_free(options, TRUE);
    latcd_cache_capacity_close(&capacity);
    assert(!unlink(task));
    assert(!rmdir(tasks));
    assert(!rmdir(launches));
    assert(!rmdir(gc));
    assert(!rmdir(root));
    g_free(launch);
    g_free(task);
    g_free(launches);
    g_free(tasks);
    g_free(gc);
    g_free(root);
    g_clear_error(&gerror);
    return 0;
}
