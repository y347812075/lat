#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "journal-store.h"
#include "lat-translation-config.h"

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct Registration {
    uint8_t magic[8];
    uint64_t capacity;
    LatKeyJournalIdentity identity;
} Registration;

_Static_assert(sizeof(Registration) == 160, "registration layout");

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

static void hex(const uint8_t *bytes, size_t size, char *text)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        text[2 * i] = digits[bytes[i] >> 4];
        text[2 * i + 1] = digits[bytes[i] & 15];
    }
    text[2 * size] = 0;
}

static bool stream_name(const char *name)
{
    if (strlen(name) != 32) return false;
    for (size_t i = 0; i < 32; i++)
        if (!(name[i] >= '0' && name[i] <= '9') &&
            !(name[i] >= 'a' && name[i] <= 'f')) return false;
    return true;
}

static int directory_at(int parent, const char *name, bool create)
{
    if (create && mkdirat(parent, name, 0700) && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    int result = fstat(fd, &st);
    if (!result && st.st_uid == geteuid() && (st.st_mode & 0777) == 0700) return fd;
    int saved = result ? errno : EPERM;
    close(fd);
    errno = saved;
    return -1;
}

static int root_open(const char *cache, bool create)
{
    int parent = open(cache, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0) return -1;
    int fd = directory_at(parent, ".journals", create);
    if (fd >= 0 && create && fsync(parent)) {
        close(fd);
        fd = -1;
    }
    int saved = errno;
    close(parent);
    errno = saved;
    return fd;
}

static bool read_exact(int fd, void *bytes, size_t size)
{
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(fd, (char *)bytes + done, size - done, done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += count;
    }
    return true;
}

static int sealed_copy(int source, off_t size)
{
    int target = memfd_create("latcd-journal-receipt", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (target < 0) return -1;
    uint8_t buffer[65536];
    off_t offset = 0;
    while (offset < size) {
        ssize_t n = pread(source, buffer, MIN(sizeof(buffer), (size_t)(size - offset)), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto fail;
        size_t written = 0;
        while (written < (size_t)n) {
            ssize_t count = write(target, buffer + written, n - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) goto fail;
            written += count;
        }
        offset += n;
    }
    if (fcntl(target, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW |
              F_SEAL_SHRINK | F_SEAL_SEAL)) goto fail;
    return target;
fail:
    close(target);
    return -1;
}

static bool write_file(int directory, const char *name, const void *bytes, size_t size)
{
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                    O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t done = 0;
    while (done < size) {
        ssize_t count = write(fd, (const char *)bytes + done, size - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        done += count;
    }
    bool ok = done == size && !fchmod(fd, 0400) && !fsync(fd);
    if (close(fd)) ok = false;
    return ok;
}

static int readonly_file(int directory, const char *name, uint64_t limit,
                          bool single_link, struct stat *st)
{
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd >= 0 && !fstat(fd, st) && S_ISREG(st->st_mode) &&
        st->st_uid == geteuid() && (st->st_mode & 0777) == 0400 &&
        (!single_link || st->st_nlink == 1) && st->st_size > 0 &&
        (uint64_t)st->st_size <= limit) return fd;
    if (fd >= 0) close(fd);
    return -1;
}

static bool hash_fd(int fd, uint8_t digest[32])
{
    GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t buffer[65536];
    off_t offset = 0;
    struct stat before, after;
    bool ok = !fstat(fd, &before);
    while (ok && offset < before.st_size) {
        ssize_t count = pread(fd, buffer, MIN(sizeof(buffer), (size_t)(before.st_size - offset)), offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        g_checksum_update(hash, buffer, count);
        offset += count;
    }
    ok = ok && !fstat(fd, &after) && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    gsize size = 32;
    if (ok) g_checksum_get_digest(hash, digest, &size);
    g_checksum_free(hash);
    return ok;
}

static uint64_t stream_storage(uint64_t capacity)
{
    /* Reserve final receipt plus one atomic replacement at maximum size. */
    return 192 + capacity * 32 + 2 * (64 + capacity * sizeof(LatTbKey));
}

int latcd_journal_budget(int snapshot_fd, int config_fd, uint64_t capacity, uint64_t *bytes)
{
    struct stat source, config;
    *bytes = 0;
    int seals = fcntl(config_fd, F_GET_SEALS);
    if (!capacity || capacity > LAT_KEY_JOURNAL_MAX_SLOTS || seals < 0 ||
        (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) !=
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK) ||
        fstat(snapshot_fd, &source) || !S_ISREG(source.st_mode) || source.st_size < 0 ||
        fstat(config_fd, &config) || config.st_size <= 0 || config.st_size > LATCD_JOURNAL_CONFIG_LIMIT)
        return -1;
    uint64_t overhead = sizeof(Registration) + config.st_size + stream_storage(capacity);
    if ((uint64_t)source.st_size > UINT64_MAX - overhead) return -1;
    *bytes = source.st_size + overhead;
    return 0;
}

static bool executable_keys(int fd, const LatTbKeySet *keys)
{
    struct stat st;
    Elf64_Ehdr header;
    if (fstat(fd, &st) || !read_exact(fd, &header, sizeof(header)) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_X86_64 || (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum || header.e_phnum > 4096 ||
        header.e_phoff > (uint64_t)st.st_size ||
        header.e_phnum > ((uint64_t)st.st_size - header.e_phoff) / sizeof(Elf64_Phdr)) return false;
    Elf64_Phdr *programs = g_new(Elf64_Phdr, header.e_phnum);
    size_t size = header.e_phnum * sizeof(*programs);
    bool ok = pread(fd, programs, size, header.e_phoff) == (ssize_t)size;
    uint64_t base = UINT64_MAX;
    for (unsigned i = 0; ok && i < header.e_phnum; i++) {
        Elf64_Phdr *p = &programs[i];
        if (p->p_offset > (uint64_t)st.st_size || p->p_filesz > (uint64_t)st.st_size - p->p_offset ||
            (p->p_type == PT_LOAD && (p->p_filesz > p->p_memsz || p->p_vaddr > UINT64_MAX - p->p_memsz))) {
            ok = false;
            break;
        }
        if (p->p_type == PT_LOAD && p->p_memsz && p->p_vaddr < base) base = p->p_vaddr;
    }
    ok = ok && base != UINT64_MAX;
    for (size_t k = 0; ok && k < keys->count; k++) {
        bool found = false;
        for (unsigned i = 0; i < header.e_phnum; i++) {
            Elf64_Phdr *p = &programs[i];
            if (p->p_type == PT_LOAD && (p->p_flags & PF_X) && p->p_vaddr >= base &&
                keys->keys[k].guest_rva >= p->p_vaddr - base &&
                keys->keys[k].guest_rva - (p->p_vaddr - base) < p->p_memsz) found = true;
        }
        ok = found;
    }
    g_free(programs);
    return ok;
}

static int receipt_read(int directory, const Registration *record, int source,
                         LatTbKeySet *set, char *error, size_t error_size)
{
    memset(set, 0, sizeof(*set));
    memcpy(set->source_sha256, record->identity.source_sha256, 32);
    struct stat st;
    if (fstatat(directory, "received.tbset", &st, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? 0 : -1;
    int fd = readonly_file(directory, "received.tbset", 64 + record->capacity * sizeof(LatTbKey), true, &st);
    if (fd < 0) return fail(error, error_size, "invalid journal receipt file");
    int result = lat_tb_key_set_read_fd(fd, record->identity.source_sha256, set, error, error_size);
    close(fd);
    if (!result && (set->sequence || !executable_keys(source, set))) {
        lat_tb_key_set_destroy(set);
        result = fail(error, error_size, "invalid journal receipt range/sequence");
    }
    return result;
}

static int receipt_collect(int directory, const Registration *record, int source,
                            const LatKeyJournal *journal, uint64_t *received,
                            char *error, size_t error_size)
{
    LatTbKeySet old = {0}, current = {0};
    if (receipt_read(directory, record, source, &old, error, error_size)) return -1;
    memcpy(current.source_sha256, record->identity.source_sha256, 32);
    current.keys = g_new(LatTbKey, journal->capacity);
    int result = -1;
    for (uint64_t i = 0; i < journal->capacity; i++) {
        LatTbKey key;
        int ready = lat_key_journal_read(journal, i, &key, error, error_size);
        if (ready < 0) goto out;
        if (ready) current.keys[current.count++] = key;
    }
    if (lat_tb_key_set_sort_unique(&current, error, error_size) || !executable_keys(source, &current)) {
        fail(error, error_size, "journal keys outside executable source ranges");
        goto out;
    }
    for (size_t i = 0; i < old.count; i++) {
        if (!lat_tb_key_set_contains(&current, old.keys[i].guest_rva, old.keys[i].flags)) {
            fail(error, error_size, "journal lost previously received key");
            goto out;
        }
    }
    if (old.count != current.count) {
        /* Leftover replacement from a killed writer is unacknowledged; original
         * journal and receipt remain authoritative. Never follow an old link.
         */
        struct stat st;
        if (!fstatat(directory, "received.next", &st, AT_SYMLINK_NOFOLLOW)) {
            if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
                unlinkat(directory, "received.next", 0)) goto out;
        } else if (errno != ENOENT) goto out;
        int output = openat(directory, "received.next", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (output < 0) goto out;
        bool ok = !lat_tb_key_set_write_fd(output, &current, error, error_size) &&
            !fchmod(output, 0400) && !fsync(output);
        if (close(output)) ok = false;
        if (ok) ok = !renameat(directory, "received.next", directory, "received.tbset") && !fsync(directory);
        if (!ok) goto out;
    }
    *received += current.count;
    result = 0;
out:
    lat_tb_key_set_destroy(&old);
    lat_tb_key_set_destroy(&current);
    return result;
}

static int recover_stream(int root, const char *name, const uint8_t build[32],
                           const uint8_t codegen[32], uint64_t max_bytes,
                           uint64_t *bytes, uint64_t *received, char *error, size_t error_size)
{
    int directory = directory_at(root, name, false);
    int fd = -1;
    Registration record;
    struct stat st;
    bool ok = directory >= 0;
    if (ok) fd = readonly_file(directory, "registration", sizeof(record), true, &st);
    ok = ok && fd >= 0 && st.st_size == sizeof(record) && read_exact(fd, &record, sizeof(record));
    if (fd >= 0) close(fd);
    char epoch[33];
    if (ok) hex(record.identity.epoch, 16, epoch);
    ok = ok && !memcmp(record.magic, "LATJREG1", 8) && !strcmp(epoch, name) &&
        !memcmp(record.identity.build_sha256, build, 32) &&
        !memcmp(record.identity.codegen_sha256, codegen, 32) &&
        record.capacity && record.capacity <= LAT_KEY_JOURNAL_MAX_SLOTS;
    uint8_t config[LATCD_JOURNAL_CONFIG_LIMIT], digest[32];
    fd = ok ? readonly_file(directory, "config", sizeof(config), true, &st) : -1;
    ok = ok && fd >= 0 && read_exact(fd, config, st.st_size);
    if (fd >= 0) close(fd);
    LatTranslationConfig decoded;
    ok = ok && !lat_translation_config_decode(config, st.st_size, build, &decoded,
                                                error, error_size) &&
        !lat_translation_config_digest(&decoded, digest, error, error_size) &&
        !memcmp(digest, record.identity.config_sha256, 32);
    uint64_t size = ok ? sizeof(record) + st.st_size + stream_storage(record.capacity) : 0;
    fd = ok ? readonly_file(directory, "source", max_bytes, false, &st) : -1;
    ok = ok && fd >= 0 && hash_fd(fd, digest) &&
        !memcmp(digest, record.identity.source_sha256, 32);
    if (ok) size += st.st_size;
    ok = ok && size <= max_bytes && *bytes <= max_bytes - size;
    LatKeyJournal journal;
    if (ok && lat_key_journal_open_at(directory, "keys", &record.identity, false,
                                     &journal, error, error_size)) ok = false;
    else if (ok) {
        ok = journal.capacity == record.capacity;
        if (ok && received) ok = !receipt_collect(directory, &record, fd, &journal, received, error, error_size);
        else if (ok) {
            LatTbKeySet previous;
            ok = !receipt_read(directory, &record, fd, &previous, error, error_size);
            if (ok) lat_tb_key_set_destroy(&previous);
        }
        lat_key_journal_close(&journal);
    }
    if (fd >= 0) close(fd);
    if (directory >= 0) close(directory);
    if (!ok || size > max_bytes || *bytes > max_bytes - size)
        return fail(error, error_size, "invalid or over-quota journal stream %s", name);
    *bytes += size;
    return 0;
}

void latcd_journal_close_compile_input(LatcdJournalCompileInput *input)
{
    if (input->source_fd >= 0) close(input->source_fd);
    if (input->receipt_fd >= 0) close(input->receipt_fd);
    if (input->config_fd >= 0) close(input->config_fd);
    input->source_fd = input->receipt_fd = input->config_fd = -1;
}

int latcd_journal_open_compile_input(const char *cache, const char *stream,
    const uint8_t build[32], const uint8_t codegen[32], uint64_t max_bytes,
    LatcdJournalCompileInput *input, char *error, size_t error_size)
{
    if (!input) return fail(error, error_size, "missing journal input");
    memset(input, 0, sizeof(*input));
    input->source_fd = input->receipt_fd = input->config_fd = -1;
    if (!cache || !stream || !build || !codegen || !stream_name(stream))
        return fail(error, error_size, "invalid journal input identity");
    int root = root_open(cache, false);
    int directory = root >= 0 ? directory_at(root, stream, false) : -1;
    int fd = -1;
    struct stat st;
    Registration record;
    uint8_t digest[32];
    char epoch[33];
    bool ok = directory >= 0;
    if (ok) fd = readonly_file(directory, "registration", sizeof(record), true, &st);
    ok = ok && fd >= 0 && st.st_size == sizeof(record) &&
        read_exact(fd, &record, sizeof(record));
    if (fd >= 0) close(fd);
    if (ok) hex(record.identity.epoch, 16, epoch);
    ok = ok && !memcmp(record.magic, "LATJREG1", 8) && !strcmp(epoch, stream) &&
        !memcmp(record.identity.build_sha256, build, 32) &&
        !memcmp(record.identity.codegen_sha256, codegen, 32) &&
        record.capacity && record.capacity <= LAT_KEY_JOURNAL_MAX_SLOTS;
    fd = ok ? readonly_file(directory, "config", sizeof(input->config), true, &st) : -1;
    input->config_fd = fd >= 0 ? sealed_copy(fd, st.st_size) : -1;
    ok = ok && input->config_fd >= 0 &&
        read_exact(input->config_fd, input->config, st.st_size);
    if (ok) input->config_size = st.st_size;
    if (fd >= 0) close(fd);
    LatTranslationConfig decoded;
    ok = ok && !lat_translation_config_decode(input->config, input->config_size,
        build, &decoded, error, error_size) &&
        !lat_translation_config_digest(&decoded, digest, error, error_size) &&
        !memcmp(digest, record.identity.config_sha256, 32);
    input->source_fd = ok ? readonly_file(directory, "source", max_bytes, false, &st) : -1;
    ok = ok && input->source_fd >= 0 && hash_fd(input->source_fd, digest) &&
        !memcmp(digest, record.identity.source_sha256, 32);
    fd = ok ? readonly_file(directory, "received.tbset",
        64 + record.capacity * sizeof(LatTbKey), true, &st) : -1;
    input->receipt_fd = fd >= 0 ? sealed_copy(fd, st.st_size) : -1;
    if (fd >= 0) close(fd);
    LatTbKeySet set = {0};
    ok = ok && input->receipt_fd >= 0 &&
        !lat_tb_key_set_read_fd(input->receipt_fd, record.identity.source_sha256,
                                &set, error, error_size) &&
        !set.sequence && executable_keys(input->source_fd, &set) &&
        hash_fd(input->receipt_fd, input->receipt_sha256);
    lat_tb_key_set_destroy(&set);
    if (ok) input->identity = record.identity;
    if (directory >= 0) close(directory);
    if (root >= 0) close(root);
    if (!ok) {
        latcd_journal_close_compile_input(input);
        return fail(error, error_size, "invalid journal compile input %s", stream);
    }
    return 0;
}

static int scan(int root, const uint8_t build[32], const uint8_t codegen[32],
                 uint64_t max_bytes, unsigned *count, uint64_t *bytes,
                 uint64_t *received, char *error, size_t error_size)
{
    int copy = openat(root, ".", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    DIR *directory = copy >= 0 ? fdopendir(copy) : NULL;
    if (!directory) { if (copy >= 0) close(copy); return -1; }
    *count = 0; *bytes = 0;
    int result = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!stream_name(entry->d_name) || ++*count > LATCD_JOURNAL_MAX_STREAMS ||
            recover_stream(root, entry->d_name, build, codegen, max_bytes,
                            bytes, received, error, error_size)) { result = -1; break; }
        errno = 0;
    }
    if (!entry && errno) result = -1;
    closedir(directory);
    return result;
}

int latcd_journal_inventory(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count, uint64_t *bytes,
    char *error, size_t error_size)
{
    *count = 0;
    *bytes = 0;
    int root = root_open(cache, false);
    if (root < 0) {
        if (errno == ENOENT) return 0;
        return fail(error, error_size, "cannot open journal store");
    }
    int result = scan(root, build, codegen, max_bytes, count, bytes, NULL, error, error_size);
    close(root);
    return result;
}

int latcd_journal_recover(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count,
    char *error, size_t error_size)
{
    uint64_t bytes;
    return latcd_journal_inventory(cache, build, codegen, max_bytes, count, &bytes, error, error_size);
}

int latcd_journal_collect(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count,
    uint64_t *received_keys, char *error, size_t error_size)
{
    *count = 0;
    *received_keys = 0;
    int root = root_open(cache, false);
    if (root < 0) return errno == ENOENT ? 0 : fail(error, error_size, "cannot open journal store");
    uint64_t bytes;
    int result = scan(root, build, codegen, max_bytes, count, &bytes, received_keys, error, error_size);
    close(root);
    return result;
}

static int hex_digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static bool journal_id_matches_name(uint64_t journal_id, const char *name)
{
    uint64_t value = 0;

    if (!stream_name(name)) return false;
    for (unsigned i = 0; i < 8; i++) {
        int high = hex_digit(name[2 * i]);
        int low = hex_digit(name[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        value |= (uint64_t)((high << 4) | low) << (8 * i);
    }
    return value == journal_id;
}

int latcd_journal_append(const char *cache, uint64_t journal_id,
    int source_fd, int config_fd, const uint8_t build[32],
    const uint8_t codegen[32], const LatTbKey *key, uint8_t source_sha[32],
    uint64_t *slot, char *error, size_t error_size)
{
    if (!cache || source_fd < 0 || config_fd < 0 || !build || !codegen ||
        !key || !source_sha || key->flags != 3 || key->reserved) {
        return fail(error, error_size, "invalid journal append arguments");
    }
    if (slot) *slot = 0;
    int root = root_open(cache, false);
    if (root < 0) return fail(error, error_size, "cannot open journal store");
    int copy = openat(root, ".", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    DIR *directory_list = copy >= 0 ? fdopendir(copy) : NULL;
    if (!directory_list) {
        if (copy >= 0) close(copy);
        close(root);
        return fail(error, error_size, "cannot scan journal store");
    }
    bool found = false;
    int result = -1;
    char stream[33] = {0};
    Registration selected = {0};
    struct dirent *entry;
    while ((entry = readdir(directory_list))) {
        if (!journal_id_matches_name(journal_id, entry->d_name)) continue;
        if (found) {
            fail(error, error_size, "ambiguous journal epoch");
            goto out;
        }
        int directory = directory_at(root, entry->d_name, false);
        struct stat st;
        int registration = directory >= 0 ?
            readonly_file(directory, "registration", sizeof(Registration), true,
                          &st) : -1;
        bool valid = registration >= 0 && st.st_size == sizeof(selected) &&
            read_exact(registration, &selected, sizeof(selected));
        if (registration >= 0) close(registration);
        if (directory >= 0) close(directory);
        valid = valid && !memcmp(selected.magic, "LATJREG1", 8) &&
            !memcmp(selected.identity.epoch, &journal_id, sizeof(journal_id)) &&
            !memcmp(selected.identity.build_sha256, build, 32) &&
            !memcmp(selected.identity.codegen_sha256, codegen, 32);
        if (!valid) {
            fail(error, error_size, "invalid journal registration for epoch");
            goto out;
        }
        memcpy(stream, entry->d_name, 33);
        found = true;
    }
    if (!found) {
        fail(error, error_size, "journal epoch not found");
        goto out;
    }
    uint8_t digest[32];
    if (!hash_fd(source_fd, digest) ||
        memcmp(digest, selected.identity.source_sha256, 32)) {
        fail(error, error_size, "journal source identity mismatch");
        goto out;
    }
    memcpy(source_sha, digest, 32);
    uint8_t config[LATCD_JOURNAL_CONFIG_LIMIT];
    struct stat config_stat;
    int seals = fcntl(config_fd, F_GET_SEALS);
    if (seals < 0 ||
        (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) !=
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK) ||
        fstat(config_fd, &config_stat) || config_stat.st_size <= 0 ||
        (uint64_t)config_stat.st_size > sizeof(config) ||
        !read_exact(config_fd, config, config_stat.st_size)) {
        fail(error, error_size, "journal configuration is invalid or unsealed");
        goto out;
    }
    LatTranslationConfig decoded;
    if (lat_translation_config_decode(config, config_stat.st_size, build,
                                      &decoded, error, error_size) ||
        lat_translation_config_digest(&decoded, digest, error, error_size)) {
        goto out;
    }
    if (memcmp(digest, selected.identity.config_sha256, 32)) {
        fail(error, error_size, "journal configuration identity mismatch");
        goto out;
    }
    int directory = directory_at(root, stream, false);
    LatKeyJournal journal;
    if (directory < 0) {
        fail(error, error_size, "cannot open journal epoch directory");
        goto out;
    }
    if (lat_key_journal_open_at(directory, "keys", &selected.identity, true,
                                &journal, error, error_size)) {
        close(directory);
        goto out;
    }
    result = lat_key_journal_append(&journal, key, slot, error, error_size);
    lat_key_journal_close(&journal);
    close(directory);
out:
    closedir(directory_list);
    close(root);
    return result;
}

static int register_stream(const char *cache, const char *snapshot, int snapshot_fd,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], int *directory_fd, char *error, size_t error_size)
{
    stream[0] = 0;
    if (directory_fd) *directory_fd = -1;
    uint8_t config[LATCD_JOURNAL_CONFIG_LIMIT];
    struct stat st;
    int seals = fcntl(config_fd, F_GET_SEALS);
    if (!capacity || capacity > LAT_KEY_JOURNAL_MAX_SLOTS ||
        seals < 0 || (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) !=
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK) ||
        fstat(config_fd, &st) || st.st_size <= 0 || (uint64_t)st.st_size > sizeof(config) ||
        !read_exact(config_fd, config, st.st_size))
        return fail(error, error_size, "invalid journal capacity or unsealed configuration");
    size_t config_size = st.st_size;
    LatTranslationConfig decoded;
    Registration record = { .magic = "LATJREG1", .capacity = capacity };
    memcpy(record.identity.build_sha256, build, 32);
    memcpy(record.identity.codegen_sha256, codegen, 32);
    memcpy(record.identity.source_sha256, source_sha, 32);
    if (lat_translation_config_decode(config, config_size, build, &decoded, error, error_size) ||
        lat_translation_config_digest(&decoded, record.identity.config_sha256, error, error_size))
        return -1;
    if (decoded.guest_abi != LAT_CONFIG_ABI_X86_64)
        return fail(error, error_size, "journal source requires x86-64 configuration");
    int root = root_open(cache, true);
    if (root < 0) return fail(error, error_size, "cannot create journal store");
    unsigned count;
    uint64_t bytes;
    if (scan(root, build, codegen, max_bytes, &count, &bytes, NULL, error, error_size) ||
        count >= LATCD_JOURNAL_MAX_STREAMS ||
        (snapshot_fd < 0 ? stat(snapshot, &st) : fstat(snapshot_fd, &st)) || st.st_size < 0) {
        close(root);
        return fail(error, error_size, "journal store invalid or full");
    }
    uint64_t needed = sizeof(record) + config_size + stream_storage(capacity);
    if ((uint64_t)st.st_size > max_bytes || needed > max_bytes - st.st_size ||
        bytes > max_bytes - st.st_size - needed) {
        close(root);
        return fail(error, error_size, "journal byte quota exceeded");
    }
    ssize_t random;
    do { random = getrandom(record.identity.epoch, 16, 0); } while (random < 0 && errno == EINTR);
    if (random != 16) { close(root); return fail(error, error_size, "cannot allocate journal epoch"); }
    char name[33];
    hex(record.identity.epoch, 16, name);
    /* Incomplete directories are not registered: recovery fails visibly rather
     * than discarding possibly acknowledged data. No restart GC is attempted.
     */
    if (mkdirat(root, name, 0700)) { close(root); return fail(error, error_size, "cannot create journal stream"); }
    int directory = directory_at(root, name, false);
    bool ok = directory >= 0;
    /* Pin the verified snapshot without duplicating the large source bytes. */
    char descriptor[64];
    if (snapshot_fd >= 0) snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", snapshot_fd);
    ok = ok && !linkat(AT_FDCWD, snapshot_fd < 0 ? snapshot : descriptor, directory,
                        "source", snapshot_fd < 0 ? 0 : AT_SYMLINK_FOLLOW) &&
        !fchmodat(directory, "source", 0400, 0) &&
        write_file(directory, "config", config, config_size);
    LatKeyJournal journal;
    if (ok && !lat_key_journal_create_at(directory, "keys", capacity, &record.identity,
                                        &journal, error, error_size)) {
        ok = !fsync(journal.fd);
        lat_key_journal_close(&journal);
    } else ok = false;
    ok = ok && write_file(directory, "registration", &record, sizeof(record)) &&
        !fsync(directory) && !fsync(root);
    if (!ok && directory >= 0) {
        unlinkat(directory, "registration", 0); unlinkat(directory, "keys", 0);
        unlinkat(directory, "config", 0); unlinkat(directory, "source", 0);
    }
    if (ok && directory_fd) *directory_fd = directory;
    else if (directory >= 0) close(directory);
    if (!ok) unlinkat(root, name, AT_REMOVEDIR);
    close(root);
    if (!ok) return fail(error, error_size, "cannot persist journal registration");
    memcpy(stream, name, sizeof(name));
    return 0;
}

int latcd_journal_register(const char *cache, const char *snapshot,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], char *error, size_t error_size)
{
    return register_stream(cache, snapshot, -1, source_sha, build, codegen, config_fd,
                           capacity, max_bytes, stream, NULL, error, error_size);
}

int latcd_journal_register_capability(const char *cache, const char *snapshot,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], int *directory_fd, char *error, size_t error_size)
{
    if (!directory_fd) {
        errno = EINVAL;
        return fail(error, error_size, "missing journal directory output");
    }
    return register_stream(cache, snapshot, -1, source_sha, build, codegen, config_fd,
                           capacity, max_bytes, stream, directory_fd, error, error_size);
}

int latcd_journal_register_fd(const char *cache, int snapshot_fd,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], int *directory_fd, char *error, size_t error_size)
{
    struct stat st;
    int flags = fcntl(snapshot_fd, F_GETFL);
    if (snapshot_fd < 0 || flags < 0 || (flags & O_TMPFILE) != O_TMPFILE ||
        fstat(snapshot_fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink)
        return fail(error, error_size, "journal requires an anonymous source snapshot");
    return register_stream(cache, NULL, snapshot_fd, source_sha, build, codegen,
        config_fd, capacity, max_bytes, stream, directory_fd, error, error_size);
}
