#ifndef LATCD_WORKER_CLOSURE_H
#define LATCD_WORKER_CLOSURE_H

#include <glib.h>

typedef struct {
    char *destination;
    int fd;
} LatcdClosureFile;

typedef struct {
    GPtrArray *files;
} LatcdWorkerClosure;

int latcd_worker_closure_load(const char *manifest, const char *build_id,
                              gboolean trusted, LatcdWorkerClosure *closure);
void latcd_worker_closure_clear(LatcdWorkerClosure *closure);

#endif
