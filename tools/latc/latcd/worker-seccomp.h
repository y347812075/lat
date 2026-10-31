#ifndef LATCD_WORKER_SECCOMP_H
#define LATCD_WORKER_SECCOMP_H

/* Returns a CLOEXEC fd containing a bwrap-compatible seccomp BPF program. */
int latcd_worker_seccomp_fd(void);

#endif
