#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "lat-key-journal.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Key journals require a little-endian host"
#endif

enum {
    JOURNAL_VERSION = 1,
    SLOT_EMPTY = 0,
    SLOT_RESERVED = 1,
    SLOT_WRITING = 2,
    SLOT_COMMITTED = 3,
};

typedef struct JournalHeader {
    uint8_t magic[8];
    uint32_t version;
    uint32_t header_size;
    uint64_t capacity;
    uint32_t slot_size;
    uint32_t flags;
    LatKeyJournalIdentity identity;
    uint64_t hint;
    uint8_t reserved[8];
} JournalHeader;

typedef struct JournalSlot {
    uint64_t state;
    uint64_t rva;
    uint64_t flags;
    uint64_t reserved;
} JournalSlot;

_Static_assert(sizeof(LatKeyJournalIdentity) == 144, "journal identity layout");
_Static_assert(sizeof(JournalHeader) == 192, "journal header layout");
_Static_assert(sizeof(JournalSlot) == 32, "journal slot layout");
_Static_assert(__atomic_always_lock_free(8, 0), "shared atomics must be lock-free");

static int fail(int code, char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list args;
        va_start(args, format);
        vsnprintf(error, size, format, args);
        va_end(args);
    }
    errno = code;
    return -1;
}

static bool nonzero(const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (bytes[i]) {
            return true;
        }
    }
    return false;
}

static bool valid_identity(const LatKeyJournalIdentity *identity)
{
    return identity && nonzero(identity->epoch, sizeof(identity->epoch)) &&
        nonzero(identity->source_sha256, 32) &&
        nonzero(identity->build_sha256, 32) &&
        nonzero(identity->codegen_sha256, 32) &&
        nonzero(identity->config_sha256, 32);
}

static bool valid_key(const LatTbKey *key)
{
    return key && key->flags == 3 && !key->reserved;
}

static bool valid_name(const char *name)
{
    return name && *name && strcmp(name, ".") && strcmp(name, "..") &&
        !strchr(name, '/');
}

static bool private_directory(int fd)
{
    struct stat stat;
    return !fstat(fd, &stat) && S_ISDIR(stat.st_mode) &&
        stat.st_uid == geteuid() && (stat.st_mode & 0777) == 0700;
}

static bool full_io(int fd, void *data, size_t size, off_t offset, bool write_data)
{
    char *bytes = data;
    while (size) {
        ssize_t count = write_data ? pwrite(fd, bytes, size, offset) :
                                    pread(fd, bytes, size, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (!count) errno = EIO;
            return false;
        }
        bytes += count;
        size -= count;
        offset += count;
    }
    return true;
}

static bool valid_header(const JournalHeader *header,
                          const LatKeyJournalIdentity *identity, off_t size)
{
    return !memcmp(header->magic, "LATKJNL", 8) &&
        header->version == JOURNAL_VERSION &&
        header->header_size == sizeof(*header) &&
        header->slot_size == sizeof(JournalSlot) &&
        header->capacity && header->capacity <= LAT_KEY_JOURNAL_MAX_SLOTS &&
        header->hint < header->capacity &&
        !header->flags && !nonzero(header->reserved, sizeof(header->reserved)) &&
        !memcmp(&header->identity, identity, sizeof(*identity)) &&
        size == (off_t)(sizeof(*header) + header->capacity * sizeof(JournalSlot));
}

static JournalSlot *slots(const LatKeyJournal *journal)
{
    return (JournalSlot *)((char *)journal->mapping + sizeof(JournalHeader));
}

static void clear_view(LatKeyJournal *journal)
{
    memset(journal, 0, sizeof(*journal));
    journal->fd = -1;
}

void lat_key_journal_close(LatKeyJournal *journal)
{
    if (!journal) {
        return;
    }
    if (journal->mapping) {
        munmap(journal->mapping, journal->mapping_size);
    }
    if (journal->fd >= 0) {
        close(journal->fd);
    }
    clear_view(journal);
}

int lat_key_journal_open(int fd, const LatKeyJournalIdentity *expected,
                         bool writable, LatKeyJournal *journal,
                         char *error, size_t error_size)
{
    if (!journal || !valid_identity(expected)) {
        return fail(EINVAL, error, error_size, "invalid journal identity/view");
    }
    clear_view(journal);
    int owned = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (owned < 0) {
        return fail(errno, error, error_size, "cannot duplicate journal fd");
    }
    struct stat stat;
    JournalHeader header;
    int seals = fcntl(owned, F_GET_SEALS);
    ssize_t count;
    do {
        count = pread(owned, &header, sizeof(header), 0);
    } while (count < 0 && errno == EINTR);
    const int required = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (seals < 0 || (seals & required) != required ||
        fstat(owned, &stat) || !S_ISREG(stat.st_mode) ||
        count != sizeof(header) || memcmp(header.magic, "LATKJNL", 8) ||
        header.version != JOURNAL_VERSION ||
        header.header_size != sizeof(header) || header.slot_size != sizeof(JournalSlot) ||
        !header.capacity || header.capacity > LAT_KEY_JOURNAL_MAX_SLOTS ||
        header.hint >= header.capacity ||
        header.flags || nonzero(header.reserved, sizeof(header.reserved)) ||
        memcmp(&header.identity, expected, sizeof(*expected)) ||
        stat.st_size != (off_t)(sizeof(header) + header.capacity * sizeof(JournalSlot))) {
        close(owned);
        return fail(EINVAL, error, error_size, "invalid journal format/seals/identity");
    }
    size_t size = sizeof(header) + header.capacity * sizeof(JournalSlot);
    void *mapping = mmap(NULL, size, PROT_READ | (writable ? PROT_WRITE : 0),
                          MAP_SHARED, owned, 0);
    if (mapping == MAP_FAILED) {
        int saved = errno;
        close(owned);
        return fail(saved, error, error_size, "cannot map journal");
    }
    journal->fd = owned;
    journal->mapping = mapping;
    journal->mapping_size = size;
    journal->capacity = header.capacity;
    journal->hint = header.hint;
    journal->writable = writable;
    journal->owner_pid = getpid();
    return 0;
}

int lat_key_journal_open_at(int directory_fd, const char *name,
                            const LatKeyJournalIdentity *expected,
                            bool writable, LatKeyJournal *journal,
                            char *error, size_t error_size)
{
    if (!journal || !valid_identity(expected) || !valid_name(name) ||
        !private_directory(directory_fd)) {
        return fail(EINVAL, error, error_size, "invalid journal directory/name/identity");
    }
    clear_view(journal);
    int fd = openat(directory_fd, name, (writable ? O_RDWR : O_RDONLY) |
                    O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return fail(errno, error, error_size, "cannot open named journal");
    struct stat stat;
    JournalHeader header;
    bool valid = !fstat(fd, &stat) && S_ISREG(stat.st_mode) &&
        stat.st_uid == geteuid() && (stat.st_mode & 0777) == 0600 &&
        stat.st_nlink == 1 &&
        full_io(fd, &header, sizeof(header), 0, false) &&
        valid_header(&header, expected, stat.st_size);
    if (!valid) {
        close(fd);
        return fail(EINVAL, error, error_size, "invalid named journal format/owner/identity");
    }
    journal->fd = fd;
    journal->capacity = header.capacity;
    journal->mapping_size = sizeof(header) + header.capacity * sizeof(JournalSlot);
    journal->hint = header.hint;
    journal->writable = writable;
    journal->file_backed = true;
    journal->owner_pid = getpid();
    return 0;
}

int lat_key_journal_create_at(int directory_fd, const char *name,
                              uint64_t capacity,
                              const LatKeyJournalIdentity *identity,
                              LatKeyJournal *journal,
                              char *error, size_t error_size)
{
    if (!journal || !valid_identity(identity) || !valid_name(name) ||
        !private_directory(directory_fd) ||
        !capacity || capacity > LAT_KEY_JOURNAL_MAX_SLOTS) {
        return fail(EINVAL, error, error_size, "invalid named journal arguments");
    }
    clear_view(journal);
    int fd = openat(directory_fd, name, O_RDWR | O_CREAT | O_EXCL |
                    O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return fail(errno, error, error_size, "cannot create named journal");
    size_t size = sizeof(JournalHeader) + capacity * sizeof(JournalSlot);
    int allocation = posix_fallocate(fd, 0, size);
    JournalHeader header = {
        .magic = "LATKJNL", .version = JOURNAL_VERSION,
        .header_size = sizeof(header), .capacity = capacity,
        .slot_size = sizeof(JournalSlot), .identity = *identity,
    };
    bool ready = !allocation && !fchmod(fd, 0600) &&
        full_io(fd, &header, sizeof(header), 0, true);
    if (!ready) {
        int saved = allocation ? allocation : errno;
        close(fd);
        unlinkat(directory_fd, name, 0);
        return fail(saved, error, error_size, "cannot initialize named journal");
    }
    close(fd);
    return lat_key_journal_open_at(directory_fd, name, identity, true,
                                    journal, error, error_size);
}

static int file_lock_mode(LatKeyJournal *journal, uint64_t slot, short type, bool wait)
{
    struct flock lock = {
        .l_type = type, .l_whence = SEEK_SET,
        .l_start = sizeof(JournalHeader) + slot * sizeof(JournalSlot),
        .l_len = sizeof(JournalSlot),
    };
    struct timespec start, now;
    if (wait && clock_gettime(CLOCK_MONOTONIC, &start)) return -1;
    for (;;) {
        int result = fcntl(journal->fd, F_OFD_SETLK, &lock);
        if (!result || !wait || (errno != EAGAIN && errno != EACCES && errno != EINTR))
            return result;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
        int64_t elapsed = (int64_t)(now.tv_sec - start.tv_sec) * 1000000000 +
                          now.tv_nsec - start.tv_nsec;
        if (elapsed >= 250000000) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct timespec delay = { .tv_nsec = 1000000 };
        nanosleep(&delay, NULL);
    }
}

static int file_lock(LatKeyJournal *journal, uint64_t slot, short type)
{
    return file_lock_mode(journal, slot, type, false);
}

static bool file_size_valid(const LatKeyJournal *journal)
{
    struct stat stat;
    if (fstat(journal->fd, &stat)) return false;
    if (stat.st_size != (off_t)journal->mapping_size) {
        errno = EIO;
        return false;
    }
    return true;
}

static int file_reserve(LatKeyJournal *journal, uint64_t *slot,
                         char *error, size_t error_size)
{
    if (journal->owner_pid != getpid())
        return fail(ECHILD, error, error_size, "reopen named writer after fork");
    if (!file_size_valid(journal))
        return fail(EIO, error, error_size, "named journal size changed");
    bool busy = false;
    for (uint64_t offset = 0; offset < journal->capacity; offset++) {
        uint64_t index = (journal->hint + offset) % journal->capacity;
        if (file_lock(journal, index, F_WRLCK)) {
            if (errno != EAGAIN && errno != EACCES)
                return fail(errno, error, error_size, "cannot lock named journal");
            busy = true;
            continue;
        }
        uint64_t state;
        off_t position = sizeof(JournalHeader) + index * sizeof(JournalSlot);
        bool read = file_size_valid(journal) &&
            full_io(journal->fd, &state, sizeof(state), position, false);
        bool invalid = read && state > SLOT_COMMITTED;
        bool reserved = false;
        if (read && state == SLOT_EMPTY) {
            state = SLOT_RESERVED;
            reserved = full_io(journal->fd, &state, sizeof(state), position, true) &&
                file_size_valid(journal);
            if (!reserved) read = false;
        }
        int saved = errno;
        if (reserved) {
            uint64_t hint = (index + 1) % journal->capacity;
            reserved = full_io(journal->fd, &hint, sizeof(hint),
                               offsetof(JournalHeader, hint), true) &&
                       file_size_valid(journal);
            if (!reserved) {
                saved = errno;
                read = false;
            }
        }
        if (file_lock(journal, index, F_UNLCK))
            return fail(errno, error, error_size, "cannot unlock named journal");
        if (!read || invalid)
            return fail(invalid ? EINVAL : saved, error, error_size, "invalid/short named journal slot");
        if (reserved) {
            journal->hint = (index + 1) % journal->capacity;
            *slot = index;
            return 0;
        }
    }
    return fail(busy ? EAGAIN : ENOSPC, error, error_size, "named journal busy/full");
}

static int file_commit(LatKeyJournal *journal, uint64_t slot, const LatTbKey *key,
                        char *error, size_t error_size)
{
    if (journal->owner_pid != getpid())
        return fail(ECHILD, error, error_size, "reopen named writer after fork");
    if (!file_size_valid(journal))
        return fail(EIO, error, error_size, "named journal size changed");
    if (file_lock_mode(journal, slot, F_WRLCK, true))
        return fail(errno, error, error_size, "cannot lock named journal commit");
    if (!file_size_valid(journal)) {
        file_lock(journal, slot, F_UNLCK);
        return fail(EIO, error, error_size, "named journal size changed while waiting");
    }
    off_t position = sizeof(JournalHeader) + slot * sizeof(JournalSlot);
    uint64_t state;
    bool ready = full_io(journal->fd, &state, sizeof(state), position, false);
    if (ready && state != SLOT_RESERVED) {
        file_lock(journal, slot, F_UNLCK);
        return fail(EINVAL, error, error_size, "named journal slot is not reserved");
    }
    state = SLOT_WRITING;
    uint64_t payload[] = { key->guest_rva, key->flags, 0 };
    ready = ready && full_io(journal->fd, &state, sizeof(state), position, true) &&
        full_io(journal->fd, payload, sizeof(payload), position + sizeof(state), true) &&
        file_size_valid(journal);
    state = SLOT_COMMITTED;
    ready = ready && full_io(journal->fd, &state, sizeof(state), position, true) &&
        file_size_valid(journal);
    int saved = errno;
    if (file_lock(journal, slot, F_UNLCK))
        return fail(errno, error, error_size, "cannot unlock named journal commit");
    return ready ? 0 : fail(saved, error, error_size, "cannot commit named journal");
}

int lat_key_journal_create(uint64_t capacity,
                           const LatKeyJournalIdentity *identity,
                           LatKeyJournal *journal,
                           char *error, size_t error_size)
{
    if (!journal || !valid_identity(identity) ||
        !capacity || capacity > LAT_KEY_JOURNAL_MAX_SLOTS) {
        return fail(EINVAL, error, error_size, "invalid journal capacity/identity");
    }
    clear_view(journal);
    int fd = memfd_create("lat-key-journal", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        return fail(errno, error, error_size, "cannot create journal");
    }
    size_t size = sizeof(JournalHeader) + capacity * sizeof(JournalSlot);
    int allocation = posix_fallocate(fd, 0, size);
    JournalHeader header = {
        .magic = "LATKJNL", .version = JOURNAL_VERSION,
        .header_size = sizeof(header), .capacity = capacity,
        .slot_size = sizeof(JournalSlot), .identity = *identity,
    };
    ssize_t count = -1;
    if (!allocation) {
        do {
            count = pwrite(fd, &header, sizeof(header), 0);
        } while (count < 0 && errno == EINTR);
    }
    if (allocation || count != sizeof(header) ||
        fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)) {
        int saved = allocation ? allocation : (errno ? errno : EIO);
        close(fd);
        return fail(saved, error, error_size, "cannot allocate/seal journal");
    }
    int result = lat_key_journal_open(fd, identity, true, journal, error, error_size);
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}

int lat_key_journal_reserve(LatKeyJournal *journal, uint64_t *slot,
                            char *error, size_t error_size)
{
    if (!journal || (!journal->mapping && !journal->file_backed) || !journal->writable || !slot) {
        return fail(EINVAL, error, error_size, "journal is not writable");
    }
    if (journal->file_backed) return file_reserve(journal, slot, error, error_size);
    JournalSlot *records = slots(journal);
    for (uint64_t offset = 0; offset < journal->capacity; offset++) {
        uint64_t index = (journal->hint + offset) % journal->capacity;
        uint64_t expected = SLOT_EMPTY;
        if (__atomic_compare_exchange_n(&records[index].state, &expected,
                SLOT_RESERVED, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            journal->hint = (index + 1) % journal->capacity;
            *slot = index;
            return 0;
        }
        if (expected > SLOT_COMMITTED) {
            return fail(EINVAL, error, error_size, "invalid journal slot state");
        }
    }
    return fail(ENOSPC, error, error_size, "journal is full");
}

int lat_key_journal_commit(LatKeyJournal *journal, uint64_t slot,
                           const LatTbKey *key, char *error, size_t error_size)
{
    if (!journal || (!journal->mapping && !journal->file_backed) || !journal->writable ||
        slot >= journal->capacity || !valid_key(key)) {
        return fail(EINVAL, error, error_size, "invalid journal commit");
    }
    if (journal->file_backed) return file_commit(journal, slot, key, error, error_size);
    JournalSlot *record = &slots(journal)[slot];
    uint64_t expected = SLOT_RESERVED;
    if (!__atomic_compare_exchange_n(&record->state, &expected, SLOT_WRITING,
            false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        return fail(EINVAL, error, error_size, "journal slot is not reserved");
    }
    __atomic_store_n(&record->rva, key->guest_rva, __ATOMIC_RELAXED);
    __atomic_store_n(&record->flags, key->flags, __ATOMIC_RELAXED);
    __atomic_store_n(&record->reserved, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&record->state, SLOT_COMMITTED, __ATOMIC_RELEASE);
    return 0;
}

int lat_key_journal_append(LatKeyJournal *journal, const LatTbKey *key,
                           uint64_t *slot, char *error, size_t error_size)
{
    if (!valid_key(key)) {
        return fail(EINVAL, error, error_size, "invalid journal key");
    }
    uint64_t index;
    if (lat_key_journal_reserve(journal, &index, error, error_size) ||
        lat_key_journal_commit(journal, index, key, error, error_size)) {
        return -1;
    }
    if (slot) {
        *slot = index;
    }
    return 0;
}

int lat_key_journal_read(const LatKeyJournal *journal, uint64_t slot,
                         LatTbKey *key, char *error, size_t error_size)
{
    if (!journal || (!journal->mapping && !journal->file_backed) || slot >= journal->capacity || !key) {
        return fail(EINVAL, error, error_size, "invalid journal read");
    }
    if (journal->file_backed) {
        if (!file_size_valid(journal))
            return fail(EIO, error, error_size, "named journal size changed");
        JournalSlot record, second;
        off_t position = sizeof(JournalHeader) + slot * sizeof(record);
        if (!full_io(journal->fd, &record, sizeof(record), position, false) ||
            !full_io(journal->fd, &second, sizeof(second), position, false) ||
            !file_size_valid(journal))
            return fail(EIO, error, error_size, "short named journal read");
        if (record.state > SLOT_COMMITTED)
            return fail(EINVAL, error, error_size, "invalid named journal state");
        if (record.state != SLOT_COMMITTED) return 0;
        if (memcmp(&record, &second, sizeof(record)) || record.flags != 3 || record.reserved)
            return fail(EINVAL, error, error_size, "invalid/changing named journal record");
        *key = (LatTbKey){ .guest_rva = record.rva, .flags = 3 };
        return 1;
    }
    const JournalSlot *record = &slots(journal)[slot];
    uint64_t state = __atomic_load_n(&record->state, __ATOMIC_ACQUIRE);
    if (state > SLOT_COMMITTED) {
        return fail(EINVAL, error, error_size, "invalid journal slot state");
    }
    if (state != SLOT_COMMITTED) {
        return 0;
    }
    uint64_t rva = __atomic_load_n(&record->rva, __ATOMIC_RELAXED);
    uint64_t flags = __atomic_load_n(&record->flags, __ATOMIC_RELAXED);
    uint64_t reserved = __atomic_load_n(&record->reserved, __ATOMIC_RELAXED);
    if (flags != 3 || reserved ||
        __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) != SLOT_COMMITTED ||
        rva != __atomic_load_n(&record->rva, __ATOMIC_RELAXED) ||
        flags != __atomic_load_n(&record->flags, __ATOMIC_RELAXED) ||
        reserved != __atomic_load_n(&record->reserved, __ATOMIC_RELAXED)) {
        return fail(EINVAL, error, error_size, "invalid or changing journal record");
    }
    *key = (LatTbKey){ .guest_rva = rva, .flags = (uint32_t)flags };
    return 1;
}
