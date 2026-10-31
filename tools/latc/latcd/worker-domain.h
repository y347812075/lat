#ifndef LATCD_WORKER_DOMAIN_H
#define LATCD_WORKER_DOMAIN_H
#include <sys/stat.h>

/* All operations use a held cgroup v2 directory, never a worker path. */
int latcd_worker_domain_create(int parent, const char *name, struct stat *identity);
int latcd_worker_domain_populated(int parent, const char *name,
                                  const struct stat *identity, int *populated);
int latcd_worker_domain_kill(int parent, const char *name,
                             const struct stat *identity);
#endif
