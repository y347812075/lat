#!/usr/bin/env python3
"""Execute the canonical submission-thread creation policy with real pthreads."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[3]
    source = (root / "linux-user/latc-aot-v2-runner.c").read_text()
    begin = source.index("static void schedule_runtime_tbset_submission(void)\n{")
    end = source.index("\nvoid latc_aot_v2_start_deferred_submission", begin)
    harness = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
static pthread_mutex_t submission_control_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t submission_control_cond = PTHREAD_COND_INITIALIZER;
static uint64_t submission_generation;
static bool submission_thread_started, deferred, fail_create;
static unsigned int creates;
static pthread_t created_thread;
static sigset_t worker_mask;
static bool rcu_atfork_child_is_deferred(void) { return deferred; }
static void *runtime_tbset_submission_thread(void *arg)
{
    (void)arg;
    assert(pthread_sigmask(SIG_SETMASK, NULL, &worker_mask) == 0);
    return NULL;
}
static int checked_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg)
{
    creates++;
    if (fail_create) return EAGAIN;
    int rc = pthread_create(thread, attr, start, arg);
    if (!rc) created_thread = *thread;
    return rc;
}
static int checked_detach(pthread_t thread) { (void)thread; return 0; }
#define pthread_create checked_create
#define pthread_detach checked_detach
'''
    checks = r'''
static void check_parent_mask(const sigset_t *expected)
{
    sigset_t actual;
    assert(pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0);
    for (int sig = 1; sig < NSIG; sig++)
        assert(sigismember(&actual, sig) == sigismember(expected, sig));
}
int main(void)
{
    sigset_t original, parent;
    sigemptyset(&parent);
    sigaddset(&parent, SIGUSR2);
    assert(pthread_sigmask(SIG_SETMASK, &parent, &original) == 0);
    deferred = true;
    schedule_runtime_tbset_submission();
    assert(creates == 0 && !submission_thread_started);
    check_parent_mask(&parent);
    deferred = false;
    fail_create = true;
    schedule_runtime_tbset_submission();
    assert(creates == 1 && !submission_thread_started);
    check_parent_mask(&parent);
    fail_create = false;
    schedule_runtime_tbset_submission();
    assert(creates == 2 && submission_thread_started);
    check_parent_mask(&parent);
    assert(pthread_join(created_thread, NULL) == 0);
    assert(sigismember(&worker_mask, SIGCHLD) == 1);
    assert(sigismember(&worker_mask, SIGUSR1) == 1);
    assert(sigismember(&worker_mask, SIGUSR2) == 1);
    assert(sigismember(&worker_mask, SIGTERM) == 1);
    assert(sigismember(&worker_mask, SIGSEGV) == 0);
    assert(sigismember(&worker_mask, SIGFPE) == 0);
    assert(sigismember(&worker_mask, SIGILL) == 0);
    schedule_runtime_tbset_submission();
    assert(creates == 2 && submission_generation == 4);
    check_parent_mask(&parent);
    assert(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="latc-submission-signals-") as temp:
        path = Path(temp)
        (path / "test.c").write_text(harness + source[begin:end] + checks)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu99", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(path / "test.c"), "-o", str(path / "test"),
        ], check=True)
        subprocess.run([str(path / "test")], check=True)
    print("test-aot-v2-submission-signals: PASS")


if __name__ == "__main__":
    main()
