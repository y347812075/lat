#ifndef LATCD_WORKER_CLOSURE_H
#define LATCD_WORKER_CLOSURE_H

#include <glib.h>

typedef struct {
    char *destination;
    int fd;
    char sha256[65];
} LatcdClosureFile;

typedef struct {
    GPtrArray *files;
} LatcdWorkerClosure;

int latcd_worker_closure_load(const char *manifest, const char *build_id,
                              gboolean trusted, LatcdWorkerClosure *closure);
void latcd_worker_closure_clear(LatcdWorkerClosure *closure);
/* Recheck the held file contents, not the manifest paths. */
int latcd_worker_closure_verify(const LatcdWorkerClosure *closure);
/* Identity of the sealed files and their mount destinations, independent of order. */
int latcd_worker_closure_identity(const LatcdWorkerClosure *closure, char digest[65]);

#endif
