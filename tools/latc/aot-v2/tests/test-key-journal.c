#define _GNU_SOURCE

#include "lat-key-journal.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static LatKeyJournalIdentity identity = {
    .epoch = {1}, .source_sha256 = {2}, .build_sha256 = {3},
    .codegen_sha256 = {4}, .config_sha256 = {5},
};
static char error[256];
static int named_directory = -1;
static char named_path[4096];

static void setup_named(void)
{
    const char *temporary = getenv("TMPDIR");
    const char *home = getenv("HOME");
    assert(temporary || home);
    int count = temporary ?
        snprintf(named_path, sizeof(named_path), "%s/key-journal-XXXXXX", temporary) :
        snprintf(named_path, sizeof(named_path), "%s/tmp/key-journal-XXXXXX", home);
    assert(count > 0 && (size_t)count < sizeof(named_path));
    assert(mkdtemp(named_path));
    named_directory = open(named_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(named_directory >= 0);
}

static void check_named_recovery(void)
{
    for (unsigned stage = 0; stage < 3; stage++) {
        int pipefd[2];
        assert(!pipe(pipefd));
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            close(pipefd[0]);
            LatKeyJournal writer;
            assert(!lat_key_journal_create_at(named_directory, "recover", 3, &identity,
                                              &writer, error, sizeof(error)));
            uint64_t slot;
            assert(!lat_key_journal_reserve(&writer, &slot, error, sizeof(error)));
            assert(slot == 0);
            LatTbKey key = { .guest_rva = 123, .flags = 3 };
            if (stage == 1) {
                uint64_t partial[] = {2, 123};
                assert(pwrite(writer.fd, partial, sizeof(partial), 192) == sizeof(partial));
            } else if (stage == 2) {
                assert(!lat_key_journal_commit(&writer, slot, &key, error, sizeof(error)));
            }
            assert(write(pipefd[1], &slot, sizeof(slot)) == sizeof(slot));
            for (;;) pause();
        }
        close(pipefd[1]);
        uint64_t slot;
        assert(read(pipefd[0], &slot, sizeof(slot)) == sizeof(slot));
        close(pipefd[0]);
        assert(!kill(child, SIGKILL));
        int status;
        assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
        assert(WTERMSIG(status) == SIGKILL);
        /* No journal fd or mapping was ever retained by the parent. */
        LatKeyJournal reader, writer;
        assert(!lat_key_journal_open_at(named_directory, "recover", &identity, false,
                                        &reader, error, sizeof(error)));
        LatTbKey output;
        assert(lat_key_journal_read(&reader, 0, &output, error, sizeof(error)) ==
               (stage == 2 ? 1 : 0));
        if (stage == 2) assert(output.guest_rva == 123);
        assert(!lat_key_journal_open_at(named_directory, "recover", &identity, true,
                                        &writer, error, sizeof(error)));
        LatTbKey later = { .guest_rva = 456, .flags = 3 };
        assert(!lat_key_journal_append(&writer, &later, &slot, error, sizeof(error)));
        assert(slot == 1);
        lat_key_journal_close(&writer);
        lat_key_journal_close(&reader);
        assert(!lat_key_journal_open_at(named_directory, "recover", &identity, false,
                                        &reader, error, sizeof(error)));
        assert(lat_key_journal_read(&reader, 1, &output, error, sizeof(error)) == 1);
        assert(output.guest_rva == 456);
        lat_key_journal_close(&reader);
        assert(!unlinkat(named_directory, "recover", 0));
    }
}

static void check_named_rejection(void)
{
    LatKeyJournal journal, rejected;
    assert(lat_key_journal_create_at(named_directory, "../escape", 2, &identity,
                                    &journal, error, sizeof(error)) < 0);
    assert(lat_key_journal_create_at(named_directory, ".", 2, &identity,
                                    &journal, error, sizeof(error)) < 0);
    assert(!fchmod(named_directory, 0755));
    assert(lat_key_journal_create_at(named_directory, "bad", 2, &identity,
                                    &journal, error, sizeof(error)) < 0);
    assert(!fchmod(named_directory, 0700));
    assert(!lat_key_journal_create_at(named_directory, "valid", 2, &identity,
                                      &journal, error, sizeof(error)));
    assert(lat_key_journal_create_at(named_directory, "valid", 2, &identity,
                                    &rejected, error, sizeof(error)) < 0 && errno == EEXIST);
    assert(!symlinkat("valid", named_directory, "symlink"));
    assert(lat_key_journal_open_at(named_directory, "symlink", &identity, false,
                                  &rejected, error, sizeof(error)) < 0);
    assert(!unlinkat(named_directory, "symlink", 0));
    assert(!linkat(named_directory, "valid", named_directory, "hardlink", 0));
    assert(lat_key_journal_open_at(named_directory, "valid", &identity, false,
                                  &rejected, error, sizeof(error)) < 0);
    assert(!unlinkat(named_directory, "hardlink", 0));
    assert(!fchmod(journal.fd, 0644));
    assert(lat_key_journal_open_at(named_directory, "valid", &identity, false,
                                  &rejected, error, sizeof(error)) < 0);
    assert(!fchmod(journal.fd, 0600));
    LatKeyJournalIdentity different = identity;
    different.epoch[0]++;
    assert(lat_key_journal_open_at(named_directory, "valid", &different, false,
                                  &rejected, error, sizeof(error)) < 0);
    unsigned char header[192];
    assert(pread(journal.fd, header, sizeof(header), 0) == sizeof(header));
    for (size_t i = 0; i < sizeof(header); i++) {
        unsigned char changed = header[i] ^ 0x80;
        assert(pwrite(journal.fd, &changed, 1, i) == 1);
        assert(lat_key_journal_open_at(named_directory, "valid", &identity, false,
                                      &rejected, error, sizeof(error)) < 0);
        assert(pwrite(journal.fd, header + i, 1, i) == 1);
    }
    uint64_t slot;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(lat_key_journal_reserve(&journal, &slot, error, sizeof(error)) < 0);
        assert(errno == ECHILD);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    LatTbKey key = { .guest_rva = 42, .flags = 3 }, output;
    assert(!lat_key_journal_reserve(&journal, &slot, error, sizeof(error)));
    assert(!ftruncate(journal.fd, 192));
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) < 0);
    assert(lat_key_journal_commit(&journal, slot, &key, error, sizeof(error)) < 0);
    assert(lat_key_journal_reserve(&journal, &slot, error, sizeof(error)) < 0);
    assert(lat_key_journal_open_at(named_directory, "valid", &identity, false,
                                  &rejected, error, sizeof(error)) < 0);
    lat_key_journal_close(&journal);
    assert(!unlinkat(named_directory, "valid", 0));
}

static void check_named_commit_contention(unsigned variant)
{
    LatKeyJournal owner;
    assert(!lat_key_journal_create_at(named_directory, "contention", 2, &identity,
                                      &owner, error, sizeof(error)));
    uint64_t slot;
    assert(!lat_key_journal_reserve(&owner, &slot, error, sizeof(error)));
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = 192 + slot * 32, .l_len = 32 };
    assert(!fcntl(owner.fd, F_OFD_SETLK, &lock));
    int pipefd[2];
    assert(!pipe(pipefd));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close(pipefd[0]);
        /* Do not retain the parent's OFD: only its parent copy owns this lock. */
        if (variant != 3) lat_key_journal_close(&owner);
        LatKeyJournal writer;
        assert(!lat_key_journal_open_at(named_directory, "contention", &identity, true,
                                        &writer, error, sizeof(error)));
        assert(write(pipefd[1], "R", 1) == 1);
        LatTbKey key = { .guest_rva = 789, .flags = 3 };
        int result = lat_key_journal_commit(&writer, slot, &key, error, sizeof(error));
        int saved = errno;
        assert(write(pipefd[1], &result, sizeof(result)) == sizeof(result));
        assert(write(pipefd[1], &saved, sizeof(saved)) == sizeof(saved));
        lat_key_journal_close(&writer);
        if (variant == 3) lat_key_journal_close(&owner);
        _exit(0);
    }
    close(pipefd[1]);
    char ready;
    assert(read(pipefd[0], &ready, 1) == 1 && ready == 'R');
    if (variant == 3) lat_key_journal_close(&owner);
    struct pollfd pollfd = { .fd = pipefd[0], .events = POLLIN };
    assert(poll(&pollfd, 1, 100) == 0);
    if (variant == 1) {
        /* Preserve the slot's RESERVED word, remove its payload and later slots. */
        assert(!ftruncate(owner.fd, 200));
    }
    if (variant >= 2) assert(poll(&pollfd, 1, 500) == 1);
    if (variant != 3) {
        lock.l_type = F_UNLCK;
        assert(!fcntl(owner.fd, F_OFD_SETLK, &lock));
    }
    int result;
    assert(read(pipefd[0], &result, sizeof(result)) == sizeof(result));
    int saved;
    assert(read(pipefd[0], &saved, sizeof(saved)) == sizeof(saved));
    if (!variant) assert(!result);
    else assert(result < 0 && saved == (variant == 1 ? EIO : ETIMEDOUT));
    close(pipefd[0]);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    if (variant == 3)
        assert(!lat_key_journal_open_at(named_directory, "contention", &identity, true,
                                        &owner, error, sizeof(error)));
    LatTbKey output;
    int read_result = lat_key_journal_read(&owner, slot, &output, error, sizeof(error));
    if (!variant) assert(read_result == 1 && output.guest_rva == 789);
    else if (variant == 1) assert(read_result < 0);
    else assert(read_result == 0);
    lat_key_journal_close(&owner);
    assert(!unlinkat(named_directory, "contention", 0));
}

static void check_capacity(void)
{
    LatKeyJournal journal;
    assert(lat_key_journal_create(0, &identity, &journal, error, sizeof(error)) < 0);
    assert(lat_key_journal_create(LAT_KEY_JOURNAL_MAX_SLOTS + 1, &identity,
                                 &journal, error, sizeof(error)) < 0);
    assert(!lat_key_journal_create(3, &identity, &journal, error, sizeof(error)));
    LatTbKey key = { .guest_rva = UINT64_MAX, .flags = 3 }, output = {0};
    uint64_t slot;
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) == 0);
    key.flags = 1;
    assert(lat_key_journal_append(&journal, &key, NULL, error, sizeof(error)) < 0);
    key.flags = 3;
    key.reserved = 1;
    assert(lat_key_journal_append(&journal, &key, NULL, error, sizeof(error)) < 0);
    key.reserved = 0;
    assert(!lat_key_journal_append(&journal, &key, &slot, error, sizeof(error)));
    assert(slot == 0);
    assert(lat_key_journal_read(&journal, slot, &output, error, sizeof(error)) == 1);
    assert(!memcmp(&key, &output, sizeof(key)));
    assert(lat_key_journal_commit(&journal, slot, &key, error, sizeof(error)) < 0);
    assert(!lat_key_journal_reserve(&journal, &slot, error, sizeof(error)));
    assert(slot == 1);
    assert(lat_key_journal_read(&journal, slot, &output, error, sizeof(error)) == 0);
    key.guest_rva = 0;
    assert(!lat_key_journal_append(&journal, &key, &slot, error, sizeof(error)));
    assert(slot == 2);
    for (unsigned i = 0; i < 10; i++) {
        assert(lat_key_journal_append(&journal, &key, NULL, error, sizeof(error)) < 0);
        assert(errno == ENOSPC);
    }
    assert(lat_key_journal_read(&journal, 3, &output, error, sizeof(error)) < 0);
    assert(ftruncate(journal.fd, 0) < 0 && errno == EPERM);
    assert(ftruncate(journal.fd, journal.mapping_size + 32) < 0 && errno == EPERM);
    assert(fcntl(journal.fd, F_ADD_SEALS, F_SEAL_WRITE) < 0 && errno == EPERM);

    LatKeyJournal reader;
    assert(!lat_key_journal_open(journal.fd, &identity, false,
                                &reader, error, sizeof(error)));
    assert(fcntl(reader.fd, F_GETFD) & FD_CLOEXEC);
    assert(lat_key_journal_append(&reader, &key, NULL, error, sizeof(error)) < 0);
    lat_key_journal_close(&journal);
    assert(lat_key_journal_read(&reader, 0, &output, error, sizeof(error)) == 1);
    assert(output.guest_rva == UINT64_MAX);
    lat_key_journal_close(&reader);
}

static void check_format(void)
{
    LatKeyJournal journal, rejected;
    assert(!lat_key_journal_create(2, &identity, &journal, error, sizeof(error)));
    LatKeyJournalIdentity different;
    for (size_t i = 0; i < sizeof(identity); i++) {
        different = identity;
        ((unsigned char *)&different)[i] ^= 0x80;
        assert(lat_key_journal_open(journal.fd, &different, false,
                                   &rejected, error, sizeof(error)) < 0);
    }
    unsigned char original[192];
    assert(pread(journal.fd, original, sizeof(original), 0) == sizeof(original));
    for (size_t i = 0; i < sizeof(original); i++) {
        unsigned char changed = original[i] ^ 0x80;
        assert(pwrite(journal.fd, &changed, 1, i) == 1);
        if (lat_key_journal_open(journal.fd, &identity, false,
                                 &rejected, error, sizeof(error)) >= 0) {
            fprintf(stderr, "accepted corrupt journal header byte %zu\n", i);
            abort();
        }
        assert(pwrite(journal.fd, original + i, 1, i) == 1);
    }
    int bad = memfd_create("bad-journal", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(bad >= 0);
    assert(write(bad, original, sizeof(original)) == sizeof(original));
    assert(lat_key_journal_open(bad, &identity, false,
                               &rejected, error, sizeof(error)) < 0);
    assert(!fcntl(bad, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL));
    assert(lat_key_journal_open(bad, &identity, false,
                               &rejected, error, sizeof(error)) < 0);
    close(bad);

    const int required[] = { F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_SEAL };
    const int all_seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    for (unsigned variant = 0; variant < 5; variant++) {
        bad = memfd_create("seal-journal", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert(bad >= 0);
        assert(write(bad, original, sizeof(original)) == sizeof(original));
        assert(!ftruncate(bad, journal.mapping_size));
        int seals = variant == 0 ? 0 :
                    variant == 4 ? all_seals : all_seals & ~required[variant - 1];
        assert(!fcntl(bad, F_ADD_SEALS, seals));
        int result = lat_key_journal_open(bad, &identity, false,
                                          &rejected, error, sizeof(error));
        if (variant == 4) {
            assert(!result);
            lat_key_journal_close(&rejected);
        } else {
            assert(result < 0);
        }
        close(bad);
    }

    bad = memfd_create("oversized-journal", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(bad >= 0);
    assert(write(bad, original, sizeof(original)) == sizeof(original));
    assert(!ftruncate(bad, journal.mapping_size + 1));
    assert(!fcntl(bad, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL));
    assert(lat_key_journal_open(bad, &identity, false,
                               &rejected, error, sizeof(error)) < 0);
    close(bad);

    LatTbKey key = { .guest_rva = 42, .flags = 3 }, output;
    assert(!lat_key_journal_append(&journal, &key, NULL, error, sizeof(error)));
    uint64_t *record = (uint64_t *)((char *)journal.mapping + 192);
    __atomic_store_n(&record[0], 99, __ATOMIC_RELEASE);
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) < 0);
    __atomic_store_n(&record[0], 3, __ATOMIC_RELEASE);
    __atomic_store_n(&record[2], UINT64_C(0x100000003), __ATOMIC_RELAXED);
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) < 0);
    __atomic_store_n(&record[2], 3, __ATOMIC_RELAXED);
    __atomic_store_n(&record[3], 1, __ATOMIC_RELAXED);
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) < 0);
    __atomic_store_n(&record[3], 0, __ATOMIC_RELAXED);
    assert(lat_key_journal_read(&journal, 0, &output, error, sizeof(error)) == 1);
    __atomic_store_n(&record[4], 99, __ATOMIC_RELEASE);
    uint64_t slot;
    assert(lat_key_journal_reserve(&journal, &slot, error, sizeof(error)) < 0);
    lat_key_journal_close(&journal);
}

static void check_killed_writer(unsigned stage)
{
    LatKeyJournal owner;
    assert(!lat_key_journal_create(4, &identity, &owner, error, sizeof(error)));
    int pipefd[2];
    assert(!pipe(pipefd));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close(pipefd[0]);
        LatKeyJournal writer;
        assert(!lat_key_journal_open(owner.fd, &identity, true,
                                    &writer, error, sizeof(error)));
        uint64_t slot;
        assert(!lat_key_journal_reserve(&writer, &slot, error, sizeof(error)));
        LatTbKey key = { .guest_rva = 17, .flags = 3 };
        if (stage == 1) {
            uint64_t *record = (uint64_t *)((char *)writer.mapping + 192 + 32 * slot);
            __atomic_store_n(record, 2, __ATOMIC_RELAXED);
            __atomic_store_n(record + 1, key.guest_rva, __ATOMIC_RELAXED);
        } else if (stage == 2) {
            assert(!lat_key_journal_commit(&writer, slot, &key, error, sizeof(error)));
        }
        assert(write(pipefd[1], &slot, sizeof(slot)) == sizeof(slot));
        for (;;) pause();
    }
    close(pipefd[1]);
    uint64_t slot;
    assert(read(pipefd[0], &slot, sizeof(slot)) == sizeof(slot));
    close(pipefd[0]);
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    LatTbKey output;
    assert(lat_key_journal_read(&owner, slot, &output, error, sizeof(error)) ==
           (stage == 2 ? 1 : 0));
    if (stage == 2) assert(output.guest_rva == 17);
    LatTbKey later = { .guest_rva = 99, .flags = 3 };
    uint64_t next;
    assert(!lat_key_journal_append(&owner, &later, &next, error, sizeof(error)));
    assert(next != slot);
    /* A fresh reader after the writer died does not need a producer lock/cursor. */
    LatKeyJournal reader;
    assert(!lat_key_journal_open(owner.fd, &identity, false,
                                &reader, error, sizeof(error)));
    lat_key_journal_close(&owner);
    assert(lat_key_journal_read(&reader, next, &output, error, sizeof(error)) == 1);
    assert(output.guest_rva == 99);
    lat_key_journal_close(&reader);
}

enum { WRITERS = 4, PER_WRITER = 512 };
typedef struct Control {
    unsigned phase;
    unsigned reserved;
    unsigned committed;
} Control;
typedef struct Writer {
    int fd;
    unsigned number;
    Control *control;
    bool named;
} Writer;

static void await_value(unsigned *value, unsigned expected)
{
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != expected) sched_yield();
}

static void *write_many(void *opaque)
{
    Writer *writer = opaque;
    LatKeyJournal journal;
    char local_error[256];
    if (writer->named) {
        assert(!lat_key_journal_open_at(named_directory, "concurrent", &identity, true,
                                        &journal, local_error, sizeof(local_error)));
    } else {
        assert(!lat_key_journal_open(writer->fd, &identity, true,
                                    &journal, local_error, sizeof(local_error)));
    }
    await_value(&writer->control->phase, 1);
    uint64_t slot;
    int result;
    do {
        result = lat_key_journal_reserve(&journal, &slot, local_error, sizeof(local_error));
    } while (result && errno == EAGAIN);
    assert(!result);
    __atomic_fetch_add(&writer->control->reserved, 1, __ATOMIC_RELEASE);
    await_value(&writer->control->phase, 2);
    LatTbKey first = { .guest_rva = writer->number * PER_WRITER, .flags = 3 };
    assert(!lat_key_journal_commit(&journal, slot, &first, local_error, sizeof(local_error)));
    __atomic_fetch_add(&writer->control->committed, 1, __ATOMIC_RELEASE);
    await_value(&writer->control->phase, 3);
    for (unsigned i = 1; i < PER_WRITER; i++) {
        LatTbKey key = { .guest_rva = writer->number * PER_WRITER + i, .flags = 3 };
        do {
            result = lat_key_journal_append(&journal, &key, NULL, local_error, sizeof(local_error));
        } while (result && errno == EAGAIN);
        assert(!result);
    }
    lat_key_journal_close(&journal);
    return NULL;
}

static void check_concurrent(bool processes, bool named)
{
    LatKeyJournal owner;
    if (named) {
        assert(!lat_key_journal_create_at(named_directory, "concurrent", WRITERS * PER_WRITER,
                                          &identity, &owner, error, sizeof(error)));
    } else {
        assert(!lat_key_journal_create(WRITERS * PER_WRITER, &identity,
                                      &owner, error, sizeof(error)));
    }
    Writer writers[WRITERS];
    pthread_t threads[WRITERS];
    pid_t children[WRITERS];
    Control *control = mmap(NULL, sizeof(*control), PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    assert(control != MAP_FAILED);
    for (unsigned i = 0; i < WRITERS; i++) {
        writers[i] = (Writer){ .fd = owner.fd, .number = i, .control = control, .named = named };
        if (processes) {
            children[i] = fork();
            assert(children[i] >= 0);
            if (!children[i]) {
                write_many(&writers[i]);
                _exit(0);
            }
        } else {
            assert(!pthread_create(&threads[i], NULL, write_many, &writers[i]));
        }
    }
    __atomic_store_n(&control->phase, 1, __ATOMIC_RELEASE);
    await_value(&control->reserved, WRITERS);
    for (uint64_t slot = 0; slot < owner.capacity; slot++) {
        LatTbKey key;
        assert(lat_key_journal_read(&owner, slot, &key, error, sizeof(error)) == 0);
    }
    __atomic_store_n(&control->phase, 2, __ATOMIC_RELEASE);
    await_value(&control->committed, WRITERS);
    bool observed[WRITERS * PER_WRITER] = {0};
    size_t count = 0;
    for (uint64_t slot = 0; slot < owner.capacity; slot++) {
        LatTbKey key;
        int result = lat_key_journal_read(&owner, slot, &key, error, sizeof(error));
        assert(result >= 0);
        if (result) {
            assert(key.guest_rva < WRITERS * PER_WRITER);
            assert(key.guest_rva % PER_WRITER == 0);
            assert(!observed[key.guest_rva]);
            observed[key.guest_rva] = true;
            count++;
        }
    }
    assert(count == WRITERS);
    __atomic_store_n(&control->phase, 3, __ATOMIC_RELEASE);
    while (count < WRITERS * PER_WRITER) {
        for (uint64_t slot = 0; slot < owner.capacity; slot++) {
            LatTbKey key;
            int result = lat_key_journal_read(&owner, slot, &key, error, sizeof(error));
            assert(result >= 0);
            if (result) {
                assert(key.guest_rva < WRITERS * PER_WRITER);
                if (!observed[key.guest_rva]) {
                    observed[key.guest_rva] = true;
                    count++;
                }
            }
        }
    }
    for (unsigned i = 0; i < WRITERS; i++) {
        if (processes) {
            int status;
            assert(waitpid(children[i], &status, 0) == children[i]);
            assert(WIFEXITED(status) && !WEXITSTATUS(status));
        } else {
            assert(!pthread_join(threads[i], NULL));
        }
    }
    LatTbKey extra = { .flags = 3 };
    assert(lat_key_journal_append(&owner, &extra, NULL, error, sizeof(error)) < 0);
    assert(errno == ENOSPC);
    lat_key_journal_close(&owner);
    if (named) assert(!unlinkat(named_directory, "concurrent", 0));
    assert(!munmap(control, sizeof(*control)));
}

int main(void)
{
    alarm(60);
    check_capacity();
    check_format();
    for (unsigned stage = 0; stage < 3; stage++) check_killed_writer(stage);
    check_concurrent(false, false);
    check_concurrent(true, false);
    setup_named();
    check_named_recovery();
    check_named_rejection();
    for (unsigned variant = 0; variant < 4; variant++)
        check_named_commit_contention(variant);
    check_concurrent(false, true);
    check_concurrent(true, true);
    close(named_directory);
    assert(!rmdir(named_path));
    puts("test-key-journal: PASS (format, bounded capacity, SIGKILL, thread/fork concurrency)");
    return 0;
}
