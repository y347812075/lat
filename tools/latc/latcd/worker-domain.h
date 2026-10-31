#ifndef LATCD_WORKER_DOMAIN_H
#define LATCD_WORKER_DOMAIN_H
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Initialize a caller-owned delegated cgroup before starting threads. A fresh
 * caller is moved into manager; an existing manager may be rejoined only by
 * a caller already placed there. The caller must validate the delegation. */
int latcd_worker_delegation_init(int parent, int *manager);
/* Open an absolute delegation path without following symlinks. */
int latcd_worker_delegation_open(const char *path);

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
