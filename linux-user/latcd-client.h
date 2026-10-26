#ifndef LATCD_CLIENT_H
#define LATCD_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int latcd_client_hello(const char *socket_path, const char *build_id,
                        const uint8_t cache_identity[32],
                        char *error, size_t error_size);

/* The authenticated channel is a CLOEXEC capability shared by fork children. */
int latcd_client_open_channel(const char *socket_path, const char *build_id,
                              const uint8_t cache_identity[32],
                              char *error, size_t error_size);
int latcd_client_channel_submit_keys_fd(int channel_fd, int source_fd,
                                        int keys_fd, uint32_t priority,
                                        uint64_t request_id, uint64_t sequence,
                                        char *error, size_t error_size);

/* Registration retains source/config and returns a random epoch basename.
 * Success is not key acceptance or publication. Output is empty on failure,
 * including a lost reply (which may leave a registered stream on the daemon).
 */
int latcd_client_register_journal(const char *socket_path, int source_fd,
                                   int config_fd, const uint8_t source_sha256[32],
                                   uint64_t capacity, uint64_t request_id,
                                   char epoch[33], char *error, size_t error_size);
int latcd_client_channel_register_journal(int channel_fd, int source_fd,
                                           int config_fd,
                                           const uint8_t source_sha256[32],
                                           uint64_t capacity, uint64_t request_id,
                                           char epoch[33], char *error,
                                           size_t error_size);
/* As above, additionally returns an owned CLOEXEC private stream directory fd.
 * No cache pathname is needed for open_at("keys"). Expected journal identity
 * must still be validated by the caller. Failure clears epoch and sets fd=-1.
 * This capability does not prove availability of host syscalls under seccomp.
 */
int latcd_client_register_journal_capability(const char *socket_path,
    int source_fd, int config_fd, const uint8_t source_sha256[32],
    uint64_t capacity, uint64_t request_id, char epoch[33], int *directory_fd,
    char *error, size_t error_size);
int latcd_client_channel_register_journal_capability(int channel_fd,
    int source_fd, int config_fd, const uint8_t source_sha256[32],
    uint64_t capacity, uint64_t request_id, char epoch[33], int *directory_fd,
    char *error, size_t error_size);

int latcd_client_submit_keys_fd(const char *socket_path, int source_fd,
                                int keys_fd, uint32_t priority,
                                uint64_t request_id, uint64_t sequence,
                                char *error, size_t error_size);
int latcd_client_flush_source(const char *socket_path, int source_fd,
                              uint64_t request_id,
                              char *error, size_t error_size);
int latcd_client_flush_all(const char *socket_path, uint64_t request_id,
                           char *error, size_t error_size);
int latcd_client_precompile_source(const char *socket_path, int source_fd,
                                   uint64_t request_id,
                                   char *error, size_t error_size);

#endif
