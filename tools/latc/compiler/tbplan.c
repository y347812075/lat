#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tbplan.h"
#include "tbset.h"
#include "lat-tb-key-set.h"
#include "lat-aot-v2.h"
#include "latc-build-id.h"
#include "elf_image.h"
#include "module-inspect.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list args;
        va_start(args, format);
        vsnprintf(error, size, format, args);
        va_end(args);
    }
    return -1;
}

static char *file_sha(const char *path, bool source)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | (source ? 0 : O_NOFOLLOW));
    struct stat status;
    if (fd < 0) return NULL;
    if (fstat(fd, &status) || !S_ISREG(status.st_mode)) {
        close(fd);
        return NULL;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char buffer[65536];
    ssize_t bytes;
    while ((bytes = read(fd, buffer, sizeof(buffer))) != 0) {
        if (bytes < 0) {
            if (errno == EINTR) continue;
            g_checksum_free(sum);
            close(fd);
            return NULL;
        }
        g_checksum_update(sum, buffer, bytes);
    }
    close(fd);
    char *result = g_strdup(g_checksum_get_string(sum));
    g_checksum_free(sum);
    return result;
}

static int compare_key(const void *a, const void *b)
{
    const LatTbKey *left = a, *right = b;
    if (left->guest_rva != right->guest_rva)
        return left->guest_rva < right->guest_rva ? -1 : 1;
    return (left->flags > right->flags) - (left->flags < right->flags);
}

static void unique_keys(GArray *keys)
{
    g_array_sort(keys, compare_key);
    guint count = 0;
    for (guint i = 0; i < keys->len; i++) {
        LatTbKey key = g_array_index(keys, LatTbKey, i);
        if (!count || compare_key(&key, &g_array_index(keys, LatTbKey, count - 1)))
            g_array_index(keys, LatTbKey, count++) = key;
    }
    g_array_set_size(keys, count);
}

/* Identity is independent of shard boundaries, but includes provenance. */
static void hash_key(GChecksum *sum, unsigned kind, const LatTbKey *key)
{
    uint8_t type = kind;
    uint64_t pc = GUINT64_TO_LE(key->guest_rva);
    uint32_t flags = GUINT32_TO_LE(key->flags);
    g_checksum_update(sum, &type, sizeof(type));
    g_checksum_update(sum, (const guchar *)&pc, sizeof(pc));
    g_checksum_update(sum, (const guchar *)&flags, sizeof(flags));
}

static int save_shard(const char *directory, GKeyFile *manifest, size_t index,
                       unsigned kind, const LatTbKeySet *keys, GPtrArray *created,
                       char *error, size_t error_size)
{
    char *name = g_strdup_printf("%s-%08zu.tbset", kind ? "static" : "required", index);
    char *path = g_build_filename(directory, name, NULL);
    char *group = g_strdup_printf("shard%zu", index);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    int result = fd < 0 ? fail(error, error_size, "cannot create plan shard") : 0;
    if (fd >= 0) {
        g_ptr_array_add(created, g_strdup(path));
        result = lat_tb_key_set_write_fd(fd, keys, error, error_size);
        if (!result && (fchmod(fd, 0400) || fsync(fd)))
            result = fail(error, error_size, "cannot synchronize plan shard");
        if (close(fd) && !result) result = fail(error, error_size, "cannot close plan shard");
    }
    char *sha = result ? NULL : file_sha(path, false);
    if (!result && !sha) result = fail(error, error_size, "cannot hash plan shard");
    if (!result) {
        g_key_file_set_string(manifest, group, "name", name);
        g_key_file_set_string(manifest, group, "mode", kind ? "exact-static" : "exact");
        g_key_file_set_string(manifest, group, "sha256", sha);
        g_key_file_set_uint64(manifest, group, "keys", keys->count);
    }
    g_free(sha);
    g_free(group);
    g_free(path);
    g_free(name);
    return result;
}

int latc_tbplan_write(const char *source, const char *input, const char *directory,
                       bool static_input, size_t batch_size, size_t work_budget,
                       char *error, size_t error_size)
{
    if (!batch_size || batch_size > LAT_AOT_V2_TBSET_RECORD_LIMIT || !work_budget)
        return fail(error, error_size, "invalid plan budget");
    CfgProgram program = {0};
    CfgAnalyzeOptions options = {.resolve_jump_tables = true};
    LatTbKeySet requested = {0};
    uint8_t digest[32];
    GArray *sets[2] = {g_array_new(FALSE, FALSE, sizeof(LatTbKey)),
                       g_array_new(FALSE, FALSE, sizeof(LatTbKey))};
    GPtrArray *created = g_ptr_array_new_with_free_func(g_free);
    GKeyFile *manifest = g_key_file_new();
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    LatcTbClosure *closure = NULL;
    char *source_sha = NULL;
    bool made_directory = false;
    int result = -1;
    if (cfg_analyze_elf(source, &options, &program, error, error_size) ||
        latc_tbset_prepare_discovery(input, source, &program, static_input,
                                      digest, error, error_size) ||
        lat_tb_key_set_read_file(input, digest, &requested, error, error_size)) goto out;
    source_sha = file_sha(source, true);
    if (!source_sha) { fail(error, error_size, "cannot hash plan source"); goto out; }
    for (unsigned i = 0; i < 32; i++) {
        unsigned byte = (g_ascii_xdigit_value(source_sha[2*i]) << 4) |
                        g_ascii_xdigit_value(source_sha[2*i+1]);
        if (digest[i] != byte) { fail(error, error_size, "plan source identity changed"); goto out; }
    }
    ElfFile elf;
    elf_load(source, &elf);
    uint64_t base = UINT64_MAX;
    const Elf64_Phdr *ph = (const void *)(elf.data + elf.eh->e_phoff);
    for (unsigned i = 0; i < elf.eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < base) base = ph[i].p_vaddr;
    elf_free(&elf);
    if (base == UINT64_MAX) { fail(error, error_size, "plan source has no load base"); goto out; }
    for (size_t i = 0; i < program.tb_count; i++) {
        const CfgTb *tb = &program.tbs[i];
        if (!tb->selected || !(tb->semantic_flags & CFG_TB_PARALLEL)) continue;
        if (tb->start < base) { fail(error, error_size, "plan key before load base"); goto out; }
        LatTbKey key = {.guest_rva = tb->start - base, .flags = 3};
        g_array_append_val(sets[tb->observed ? 0 : 1], key);
    }
    closure = latc_tb_closure_new(source, &program, error, error_size);
    if (!closure) goto out;
    bool done = false;
    while (!done) {
        CfgTb *targets;
        size_t count;
        if (latc_tb_closure_advance(closure, work_budget, batch_size,
            &targets, &count, &done, error, error_size)) goto out;
        if (count > G_MAXUINT - sets[1]->len) {
            g_free(targets);
            fail(error, error_size, "plan candidate collection too large");
            goto out;
        }
        for (size_t i = 0; i < count; i++) {
            if (targets[i].start < base) {
                g_free(targets);
                fail(error, error_size, "plan candidate before load base");
                goto out;
            }
            LatTbKey key = {.guest_rva = targets[i].start - base, .flags = 3};
            g_array_append_val(sets[1], key);
        }
        g_free(targets);
    }
    for (unsigned kind = 0; kind < 2; kind++) unique_keys(sets[kind]);
    size_t supported = sets[1]->len;
    latc_tbset_filter_static_keys(source, base, (LatTbKey *)sets[1]->data, &supported);
    g_array_set_size(sets[1], supported);
    if (mkdir(directory, 0700)) { fail(error, error_size, "cannot create plan directory"); goto out; }
    made_directory = true;
    size_t shards = 0;
    uint64_t total = 0;
    for (unsigned kind = 0; kind < 2; kind++) {
        for (size_t i = 0; i < sets[kind]->len; i += batch_size) {
            LatTbKeySet part = {.keys = &g_array_index(sets[kind], LatTbKey, i),
                .count = MIN(batch_size, sets[kind]->len - i), .sequence = requested.sequence};
            memcpy(part.source_sha256, digest, 32);
            if (save_shard(directory, manifest, shards++, kind, &part, created,
                             error, error_size)) goto out;
            for (size_t j = 0; j < part.count; j++) hash_key(sum, kind, &part.keys[j]);
            total += part.count;
        }
    }
    if (!shards) { fail(error, error_size, "empty translation plan"); goto out; }
    g_key_file_set_uint64(manifest, "plan", "version", 1);
    g_key_file_set_boolean(manifest, "plan", "complete", true);
    g_key_file_set_string(manifest, "plan", "source", source_sha);
    g_key_file_set_string(manifest, "plan", "build", LATC_BUILD_ID);
    g_key_file_set_string(manifest, "plan", "identity", g_checksum_get_string(sum));
    g_key_file_set_uint64(manifest, "plan", "shards", shards);
    g_key_file_set_uint64(manifest, "plan", "keys", total);
    char *path = g_build_filename(directory, "plan.ini", NULL);
    gsize length;
    char *data = g_key_file_to_data(manifest, &length, NULL);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd >= 0) g_ptr_array_add(created, g_strdup(path));
    if (fd < 0 || write(fd, data, length) != (ssize_t)length || fchmod(fd, 0400) || fsync(fd))
        fail(error, error_size, "cannot commit translation plan");
    else result = 0;
    if (fd >= 0 && close(fd) && !result) result = fail(error, error_size, "cannot close plan");
    g_free(path);
    g_free(data);
    if (!result) {
        fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0 || fsync(fd)) result = fail(error, error_size, "cannot synchronize plan directory");
        if (fd >= 0) close(fd);
    }
    if (!result) fprintf(stderr,
        "latc: discovery plan complete required=%u static=%u shards=%zu frontier=0\n",
        sets[0]->len, sets[1]->len, shards);
out:
    if (result) {
        for (guint i = 0; i < created->len; i++) unlink(g_ptr_array_index(created, i));
        if (made_directory) rmdir(directory);
    }
    g_free(source_sha);
    latc_tb_closure_free(closure);
    lat_tb_key_set_destroy(&requested);
    cfg_program_destroy(&program);
    g_array_free(sets[0], TRUE);
    g_array_free(sets[1], TRUE);
    g_ptr_array_free(created, TRUE);
    g_key_file_free(manifest);
    g_checksum_free(sum);
    return result;
}

static bool private_file(const char *path)
{
    struct stat status;
    return !lstat(path, &status) && S_ISREG(status.st_mode) &&
        status.st_uid == getuid() && status.st_nlink == 1 &&
        (status.st_mode & 0777) == 0400;
}

static int inspect_plan(const char *source, const char *directory, const char *module,
                      char *error, size_t error_size)
{
    struct stat status;
    if (lstat(directory, &status) || !S_ISDIR(status.st_mode) ||
        status.st_uid != getuid() || (status.st_mode & 0777) != 0700)
        return fail(error, error_size, "invalid private plan directory");
    GKeyFile *manifest = g_key_file_new();
    char *path = g_build_filename(directory, "plan.ini", NULL);
    int result = -1;
    char *actual_source = file_sha(source, true), *recorded_source = NULL, *build = NULL, *identity = NULL;
    GString *listing = g_string_new(NULL);
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    if (!private_file(path) || !g_key_file_load_from_file(manifest, path, G_KEY_FILE_NONE, NULL)) goto out;
    recorded_source = g_key_file_get_string(manifest, "plan", "source", NULL);
    build = g_key_file_get_string(manifest, "plan", "build", NULL);
    identity = g_key_file_get_string(manifest, "plan", "identity", NULL);
    uint64_t shards = g_key_file_get_uint64(manifest, "plan", "shards", NULL);
    if (!actual_source || !recorded_source || strcmp(actual_source, recorded_source) ||
        !build || strcmp(build, LATC_BUILD_ID) || !identity ||
        g_key_file_get_uint64(manifest, "plan", "version", NULL) != 1 ||
        !g_key_file_get_boolean(manifest, "plan", "complete", NULL) ||
        !shards || shards > G_MAXUINT) goto out;
    uint8_t digest[32];
    if (strlen(actual_source) != 64) goto out;
    for (unsigned i = 0; i < 32; i++) digest[i] =
        (g_ascii_xdigit_value(actual_source[2*i]) << 4) | g_ascii_xdigit_value(actual_source[2*i+1]);
    uint64_t total = 0;
    unsigned previous_kind = 0;
    LatTbKey previous = {0};
    bool have_previous = false;
    for (uint64_t i = 0; i < shards; i++) {
        char *group = g_strdup_printf("shard%" G_GUINT64_FORMAT, i);
        char *name = g_key_file_get_string(manifest, group, "name", NULL);
        char *mode = g_key_file_get_string(manifest, group, "mode", NULL);
        char *sha = g_key_file_get_string(manifest, group, "sha256", NULL);
        uint64_t count = g_key_file_get_uint64(manifest, group, "keys", NULL);
        unsigned kind = mode && !strcmp(mode, "exact-static");
        char *expected = g_strdup_printf("%s-%08" G_GUINT64_FORMAT ".tbset",
                                          kind ? "static" : "required", i);
        char *shard_path = g_build_filename(directory, expected, NULL);
        char *actual_sha = file_sha(shard_path, false);
        LatTbKeySet keys = {0};
        bool valid = name && !strcmp(name, expected) && mode &&
            (kind || !strcmp(mode, "exact")) && sha && actual_sha && !strcmp(sha, actual_sha) &&
            count && count <= LAT_AOT_V2_TBSET_RECORD_LIMIT && private_file(shard_path) &&
            !lat_tb_key_set_read_file(shard_path, digest, &keys, error, error_size) &&
            count == keys.count && kind >= previous_kind;
        for (size_t j = 0; valid && j < keys.count; j++) {
            if (have_previous && kind == previous_kind && compare_key(&previous, &keys.keys[j]) >= 0)
                valid = false;
            previous = keys.keys[j];
            previous_kind = kind;
            have_previous = true;
            hash_key(sum, kind, &keys.keys[j]);
        }
        if (valid && module && lat_aot_v2_module_validate_tbset_file(
                module, shard_path, error, error_size)) valid = false;
        if (valid) {
            total += keys.count;
            g_string_append_printf(listing, "%s %s\n", mode, name);
        }
        lat_tb_key_set_destroy(&keys);
        g_free(actual_sha); g_free(shard_path); g_free(expected);
        g_free(sha); g_free(mode); g_free(name); g_free(group);
        if (!valid) goto out;
    }
    if (total != g_key_file_get_uint64(manifest, "plan", "keys", NULL) ||
        strcmp(identity, g_checksum_get_string(sum))) goto out;
    if (!module && fwrite(listing->str, 1, listing->len, stdout) != listing->len) goto out;
    result = 0;
out:
    if (result && error && error_size) fail(error, error_size, "invalid or incomplete translation plan");
    g_free(path); g_free(actual_source); g_free(recorded_source); g_free(build); g_free(identity);
    g_key_file_free(manifest); g_string_free(listing, TRUE); g_checksum_free(sum);
    return result;
}

int latc_tbplan_list(const char *source, const char *directory,
                      char *error, size_t error_size)
{
    return inspect_plan(source, directory, NULL, error, error_size);
}

int latc_tbplan_validate_module(const char *source, const char *directory,
                                 const char *module, char *error, size_t error_size)
{
    return inspect_plan(source, directory, module, error, error_size);
}
