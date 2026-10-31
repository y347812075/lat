#ifndef LATCD_WORKER_DOMAIN_H
#define LATCD_WORKER_DOMAIN_H
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Initialize a fresh, caller-owned delegated cgroup before starting threads.
 * The caller is moved into manager; parent remains open for task cgroups.
 * Failure may leave manager in place and must not be retried in the same scope. */
int latcd_worker_delegation_init(int parent, int *manager);

/* All operations use a held cgroup v2 directory, never a worker path. */
int latcd_worker_domain_create(int parent, const char *name, struct stat *identity);
int latcd_worker_domain_populated(int parent, const char *name,
                                  const struct stat *identity, int *populated);
int latcd_worker_domain_kill(int parent, const char *name,
                             const struct stat *identity);
int latcd_worker_domain_set_limits(int domain, uint64_t memory_bytes,
                                   uint64_t processes);
/* Child must use only async-signal-safe operations before exec. */
pid_t latcd_worker_domain_clone(int domain);
#endif
