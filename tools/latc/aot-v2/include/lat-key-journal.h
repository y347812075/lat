#ifndef LAT_KEY_JOURNAL_H
#define LAT_KEY_JOURNAL_H

#include "lat-tb-key-set.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LAT_KEY_JOURNAL_MAX_SLOTS UINT64_C(1048576)

typedef struct LatKeyJournalIdentity {
    uint8_t epoch[16];
    uint8_t source_sha256[32];
    uint8_t build_sha256[32];
    uint8_t codegen_sha256[32];
    uint8_t config_sha256[32];
} LatKeyJournalIdentity;

typedef struct LatKeyJournal {
    int fd;
    void *mapping;
    size_t mapping_size;
    uint64_t capacity;
    uint64_t hint;
    bool writable;
    bool file_backed;
    int owner_pid;
} LatKeyJournal;

/* The caller must retain an external fd before relying on a producer commit.
 * This memfd primitive does not provide discovery or daemon-restart durability.
 * A writable view has one caller at a time; separate views may share the fd.
 */
int lat_key_journal_create(uint64_t capacity,
                           const LatKeyJournalIdentity *identity,
                           LatKeyJournal *journal,
                           char *error, size_t error_size);
int lat_key_journal_open(int fd, const LatKeyJournalIdentity *expected,
                         bool writable, LatKeyJournal *journal,
                         char *error, size_t error_size);
/* Named journals use bounded positioned I/O, never mmap an unsealed file.
 * directory_fd must name a private current-user directory (mode 0700).
 * Each writer opens its own view; an inherited writable view must be reopened
 * after fork. These APIs and file-backed append/commit perform I/O and must not
 * run under the translation mmap_lock. They provide process-death recovery,
 * not ordered power-loss durability or source registration/authentication.
 * Commit lock waits are bounded to 250ms (ETIMEDOUT); an inherited OFD may
 * retain a dead owner's lock. Failed commits do not reclaim their reservation.
 * Callers may retry the same reserved slot after a lock timeout, not overwrite
 * it or interpret a failed append as successful collection.
 * Fork children must close inherited named-journal fds before opening writers.
 * A cooperating participant never truncates or resizes a segment; size checks
 * detect observed corruption but cannot authenticate a hostile same-user writer
 * that changes bytes/size and restores them between checks.
 */
int lat_key_journal_create_at(int directory_fd, const char *name,
                              uint64_t capacity,
                              const LatKeyJournalIdentity *identity,
                              LatKeyJournal *journal,
                              char *error, size_t error_size);
int lat_key_journal_open_at(int directory_fd, const char *name,
                            const LatKeyJournalIdentity *expected,
                            bool writable, LatKeyJournal *journal,
                            char *error, size_t error_size);
void lat_key_journal_close(LatKeyJournal *journal);

/* Slots are never reused. A failed reservation returns ENOSPC, not success.
 * A killed writer may leave a slot reserved/writing; readers skip that slot.
 */
int lat_key_journal_reserve(LatKeyJournal *journal, uint64_t *slot,
                            char *error, size_t error_size);
int lat_key_journal_commit(LatKeyJournal *journal, uint64_t slot,
                           const LatTbKey *key, char *error, size_t error_size);
int lat_key_journal_append(LatKeyJournal *journal, const LatTbKey *key,
                           uint64_t *slot, char *error, size_t error_size);
/* Returns 1 for a committed key, 0 for incomplete/empty, -1 for invalid data.
 * Consumers still validate source bytes/configuration and executable RVA ranges.
 * Identity matching binds bytes; it does not authenticate the supplied identity.
 */
int lat_key_journal_read(const LatKeyJournal *journal, uint64_t slot,
                         LatTbKey *key, char *error, size_t error_size);

#endif
