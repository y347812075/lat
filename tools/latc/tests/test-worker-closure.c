#define _GNU_SOURCE
#include "../latcd/worker-closure.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_file(const char *path, const char *data)
{
    assert(g_file_set_contents(path, data, -1, NULL));
}

int main(void)
{
    char *dir = g_build_filename(g_get_home_dir(), "tmp", "latcd-closure-XXXXXX", NULL);
    assert(mkdtemp(dir));
    char *source = g_build_filename(dir, "source", NULL);
    char *old = g_build_filename(dir, "old", NULL);
    char *manifest = g_build_filename(dir, "manifest", NULL);
    write_file(source, "original");
    char *sha = g_compute_checksum_for_string(G_CHECKSUM_SHA256, "original", -1);
    char *entry = g_strdup_printf("{\"source\":\"%s\",\"destination\":\"/usr/bin/tool\",\"sha256\":\"%s\"}", source, sha);
    char *json = g_strdup_printf("{\"version\":1,\"build_id\":\"build\",\"files\":[%s]}", entry);
    write_file(manifest, json);
    LatcdWorkerClosure closure = {0};
    assert(!latcd_worker_closure_load(manifest, "build", FALSE, &closure));
    LatcdClosureFile *file = g_ptr_array_index(closure.files, 0);
    char identity[65], changed_identity[65];
    assert(!latcd_worker_closure_identity(&closure, identity));
    assert(!fchmod(file->fd, 0700));
    assert(!latcd_worker_closure_identity(&closure, changed_identity));
    assert(strcmp(identity, changed_identity));
    assert(!fchmod(file->fd, 0600));
    struct stat before, after;
    assert(!fstat(file->fd, &before));
    assert(!rename(source, old));
    write_file(source, "replacement");
    assert(!fstat(file->fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino);
    char buf[9] = {0};
    assert(pread(file->fd, buf, 8, 0) == 8 && !strcmp(buf, "original"));
    assert(!latcd_worker_closure_verify(&closure));
    assert(!latcd_worker_closure_identity(&closure, changed_identity));
    int saved_fd = file->fd;
    file->fd = open(old, O_RDONLY);
    assert(file->fd >= 0 && latcd_worker_closure_verify(&closure) < 0);
    assert(latcd_worker_closure_identity(&closure, changed_identity) < 0);
    assert(!close(file->fd));
    file->fd = saved_fd;
    int changed = open(old, O_WRONLY);
    assert(changed >= 0 && pwrite(changed, "modified", 8, 0) == 8);
    assert(!latcd_worker_closure_verify(&closure));
    LatcdClosureFile second = {.destination = "/usr/bin/other", .fd = file->fd};
    memcpy(second.sha256, file->sha256, sizeof(second.sha256));
    g_ptr_array_add(closure.files, &second);
    assert(!latcd_worker_closure_identity(&closure, identity));
    closure.files->pdata[0] = &second;
    closure.files->pdata[1] = file;
    assert(!latcd_worker_closure_identity(&closure, changed_identity));
    assert(!strcmp(identity, changed_identity));
    second.destination = "/usr/bin/tool/child";
    assert(latcd_worker_closure_identity(&closure, changed_identity) < 0);
    closure.files->pdata[0] = file;
    g_ptr_array_steal_index(closure.files, 1);
    assert(pwrite(file->fd, "modified", 8, 0) < 0);
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", file->fd);
    int reader1 = open(proc, O_RDONLY), reader2 = open(proc, O_RDONLY);
    assert(reader1 >= 0 && reader2 >= 0);
    char c;
    assert(read(reader1, &c, 1) == 1 && c == 'o');
    assert(read(reader2, &c, 1) == 1 && c == 'o');
    assert(!close(reader1) && !close(reader2));
    assert(pwrite(changed, "original", 8, 0) == 8 && !close(changed));
    assert(!latcd_worker_closure_verify(&closure));
    latcd_worker_closure_clear(&closure);
    assert(latcd_worker_closure_load(manifest, "build", FALSE, &closure) < 0 && !closure.files);
    assert(!rename(old, source));
    char *duplicate = g_strdup_printf("{\"version\":1,\"build_id\":\"build\",\"files\":[%s,%s]}", entry, entry);
    write_file(manifest, duplicate);
    assert(latcd_worker_closure_load(manifest, "build", FALSE, &closure) < 0 && !closure.files);
    char *escape = g_strdup_printf("{\"version\":1,\"build_id\":\"build\",\"files\":[{\"source\":\"%s\",\"destination\":\"/usr/../escape\",\"sha256\":\"%s\"}]}", source, sha);
    write_file(manifest, escape);
    assert(latcd_worker_closure_load(manifest, "build", FALSE, &closure) < 0 && !closure.files);
    write_file(manifest, json);
    assert(latcd_worker_closure_load(manifest, "other-build", FALSE, &closure) < 0 && !closure.files);
    assert(!unlink(source) && !unlink(manifest) && !rmdir(dir));
    g_free(escape); g_free(duplicate); g_free(json); g_free(entry); g_free(sha);
    g_free(manifest); g_free(old); g_free(source); g_free(dir);
    return 0;
}
