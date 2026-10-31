#ifndef LATCD_JOURNAL_STORE_H
#define LATCD_JOURNAL_STORE_H

#include "lat-key-journal.h"

#define LATCD_JOURNAL_MAX_STREAMS 128u
#define LATCD_JOURNAL_CONFIG_LIMIT 4096u

typedef struct LatcdJournalCompileInput {
    int source_fd;
    int receipt_fd;
    int config_fd;
    LatKeyJournalIdentity identity;
    uint8_t receipt_sha256[32];
    uint8_t config[LATCD_JOURNAL_CONFIG_LIMIT];
    size_t config_size;
} LatcdJournalCompileInput;

/* A verified request provenance snapshot, not compilation authorization.
 * receipt_fd and config_fd are sealed; caller owns all descriptors. */
int latcd_journal_open_compile_input(const char *cache, const char *stream,
    const uint8_t build[32], const uint8_t codegen[32], uint64_t max_bytes,
    LatcdJournalCompileInput *input, char *error, size_t error_size);
void latcd_journal_close_compile_input(LatcdJournalCompileInput *input);

/* Conservative stream quota includes source, config, journal and atomic receipt
 * replacement. Inventory validates persisted streams, not just file sizes. */
int latcd_journal_budget(int snapshot_fd, int config_fd, uint64_t capacity, uint64_t *bytes);
int latcd_journal_inventory(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count, uint64_t *bytes,
    char *error, size_t error_size);

/* snapshot is a daemon-owned verified copy, never the producer's original.
 * Functions perform I/O; callers must not hold translation/service/cache locks.
 * Registration/recovery do not accept keys or authorize config compatibility.
 */
int latcd_journal_register(const char *cache, const char *snapshot,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], char *error, size_t error_size);
/* Anonymous O_TMPFILE snapshot; caller retains ownership until registration
 * finishes, then closes it. No named temporary snapshot is created. */
int latcd_journal_register_fd(const char *cache, int snapshot_fd,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], int *directory_fd, char *error, size_t error_size);
/* Returns ownership of a CLOEXEC stream directory, not the cache/root directory.
 * Fork children close inherited writers and open a fresh OFD via this directory.
 */
int latcd_journal_register_capability(const char *cache, const char *snapshot,
    const uint8_t source_sha[32], const uint8_t build[32], const uint8_t codegen[32],
    int config_fd, uint64_t capacity, uint64_t max_bytes,
    char stream[33], int *directory_fd, char *error, size_t error_size);
int latcd_journal_recover(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count,
    char *error, size_t error_size);
/* Copy committed records into per-stream received.tbset, atomically preserving
 * prior received keys. This is quarantined receipt, NOT compile admission or a
 * protocol accepted/published sequence. Sources and executable RVAs are checked.
 */
int latcd_journal_collect(const char *cache, const uint8_t build[32],
    const uint8_t codegen[32], uint64_t max_bytes, unsigned *count,
    uint64_t *received_keys, char *error, size_t error_size);
/* Append one executable key to the unique live epoch selected by journal_id.
 * source_fd and sealed config_fd must match the persisted registration.
 */
int latcd_journal_append(const char *cache, uint64_t journal_id,
    int source_fd, int config_fd, const uint8_t build[32],
    const uint8_t codegen[32], const LatTbKey *key, uint8_t source_sha[32],
    uint64_t *slot, char *error, size_t error_size);

#endif
