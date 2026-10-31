#define _GNU_SOURCE
#include "../latcd/worker-domain.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int replacement_parent = -1;
ssize_t __real_read(int fd, void *buffer, size_t count);
ssize_t __wrap_read(int fd, void *buffer, size_t count)
{
    ssize_t result = __real_read(fd, buffer, count);
    if (replacement_parent >= 0) {
        int parent = replacement_parent;
        replacement_parent = -1;
        assert(!unlinkat(parent, "latcd-domain-test", AT_REMOVEDIR));
        assert(!mkdirat(parent, "latcd-domain-test", 0700));
    }
    return result;
}

int main(int argc, char **argv)
{
    struct stat identity;
    int value;
    int ordinary = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(ordinary >= 0);
    assert(latcd_worker_domain_create(ordinary, "../bad", &identity) < 0 && errno == EINVAL);
    assert(latcd_worker_domain_create(ordinary, "test", &identity) < 0 && errno == EINVAL);
    close(ordinary);
    if (argc != 2) return 0;
    int parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(parent >= 0);
    int domain = latcd_worker_domain_create(parent, "latcd-domain-test", &identity);
    assert(domain >= 0);
    assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) && !value);
    struct stat wrong = identity;
    wrong.st_ino++;
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &wrong, &value) < 0 && errno == ESTALE);
    assert(latcd_worker_domain_kill(parent, "latcd-domain-test", &wrong) < 0 && errno == ESTALE);
    int ready[2];
    assert(!pipe(ready));
    struct clone_args args = { .flags = CLONE_INTO_CGROUP, .exit_signal = SIGCHLD, .cgroup = domain };
    pid_t child = syscall(SYS_clone3, &args, sizeof(args));
    assert(child >= 0);
    if (!child) {
        close(ready[0]);
        pid_t descendant = fork();
        if (descendant < 0) _exit(1);
        if (!descendant) {
            if (setsid() < 0 || write(ready[1], "1", 1) != 1) _exit(1);
            sleep(60);
            _exit(0);
        }
        _exit(0);
    }
    close(ready[1]);
    char signal_byte;
    assert(read(ready[0], &signal_byte, 1) == 1);
    close(ready[0]);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) && value);
    assert(!latcd_worker_domain_kill(parent, "latcd-domain-test", &identity));
    for (int i = 0; i < 500; i++) {
        assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value));
        if (!value) break;
        usleep(10000);
    }
    assert(!value);
    replacement_parent = parent;
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) < 0 && errno == ESTALE);
    close(domain);
    assert(!unlinkat(parent, "latcd-domain-test", AT_REMOVEDIR));
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) < 0 && errno == ENOENT);
    assert(latcd_worker_domain_kill(parent, "latcd-domain-test", &identity) < 0 && errno == ENOENT);
    close(parent);
    return 0;
}
