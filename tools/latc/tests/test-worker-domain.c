#define _GNU_SOURCE
#include "../latcd/worker-domain.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
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
    assert(latcd_worker_domain_set_limits(ordinary, 1, 1) < 0 && errno == EINVAL);
    assert(latcd_worker_domain_clone(ordinary) < 0 && errno == EINVAL);
    int manager = -1;
    assert(latcd_worker_delegation_init(ordinary, &manager) < 0 && errno == EINVAL);
    close(ordinary);
    if (argc != 2) return 0;
    int parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(parent >= 0);
    assert(!latcd_worker_delegation_init(parent, &manager) && manager >= 0);
    int domain = latcd_worker_domain_create(parent, "latcd-domain-test", &identity);
    assert(domain >= 0);
    int rejoined = -1;
    assert(!latcd_worker_delegation_init(parent, &rejoined) && rejoined >= 0);
    close(rejoined);
    int hold[2], ready_manager[2];
    assert(!pipe(hold) && !pipe(ready_manager));
    pid_t competing = fork();
    assert(competing >= 0);
    if (!competing) {
        close(hold[1]); close(ready_manager[0]);
        char byte = '1';
        if (write(ready_manager[1], &byte, 1) != 1 || read(hold[0], &byte, 1) != 0) _exit(1);
        _exit(0);
    }
    close(hold[0]); close(ready_manager[1]);
    char manager_ready;
    assert(read(ready_manager[0], &manager_ready, 1) == 1);
    close(ready_manager[0]);
    assert(latcd_worker_delegation_init(parent, &rejoined) < 0 && errno == EBUSY);
    close(hold[1]);
    int competing_status;
    assert(waitpid(competing, &competing_status, 0) == competing &&
           WIFEXITED(competing_status) && !WEXITSTATUS(competing_status));
    assert(latcd_worker_domain_set_limits(domain, 0, 1) < 0 && errno == EINVAL);
    assert(!latcd_worker_domain_set_limits(domain, 268435456, 32));
    assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) && !value);
    struct stat wrong = identity;
    wrong.st_ino++;
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &wrong, &value) < 0 && errno == ESTALE);
    assert(latcd_worker_domain_kill(parent, "latcd-domain-test", &wrong) < 0 && errno == ESTALE);
    int ready[2], gate[2];
    assert(!pipe(ready) && !pipe(gate));
    pid_t child = latcd_worker_domain_clone(domain);
    assert(child >= 0);
    if (!child) {
        close(ready[0]);
        close(gate[1]);
        char permit;
        if (read(gate[0], &permit, 1) != 1 || permit != '1') _exit(2);
        close(gate[0]);
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
    close(gate[0]);
    assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) && value);
    struct pollfd pollfd = { .fd = ready[0], .events = POLLIN };
    assert(poll(&pollfd, 1, 50) == 0);
    assert(write(gate[1], "1", 1) == 1);
    close(gate[1]);
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
    assert(!pipe(gate));
    child = latcd_worker_domain_clone(domain);
    assert(child >= 0);
    if (!child) {
        close(gate[1]);
        char permit;
        _exit(read(gate[0], &permit, 1) == 1 && permit == '1' ? 0 : 2);
    }
    close(gate[0]);
    close(gate[1]);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 2);
    assert(!latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) && !value);
    replacement_parent = parent;
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) < 0 && errno == ESTALE);
    close(domain);
    assert(!unlinkat(parent, "latcd-domain-test", AT_REMOVEDIR));
    assert(latcd_worker_domain_populated(parent, "latcd-domain-test", &identity, &value) < 0 && errno == ENOENT);
    assert(latcd_worker_domain_kill(parent, "latcd-domain-test", &identity) < 0 && errno == ENOENT);
    close(manager);
    close(parent);
    return 0;
}
