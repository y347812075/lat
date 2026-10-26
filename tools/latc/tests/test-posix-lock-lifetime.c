#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static bool ready, stop;
static int owner_fd, owner_error;
static const char *owner_exec_self, *owner_exec_path;
static bool owner_expect_lock;

static int set_lock(int fd, short type)
{
    struct flock lock = { .l_type = type, .l_whence = SEEK_SET, .l_len = 1 };
    return fcntl(fd, F_SETLK, &lock);
}

/* Probe in a different process, so the process-owned lock conflicts. */
static void probe(const char *path, bool conflict, pid_t owner)
{
    pid_t child = fork();
    int status;

    assert(child >= 0);
    if (!child) {
        int fd = open(path, O_RDWR);
        struct flock lock = {
            .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1,
        };
        assert(fd >= 0);
        assert(!fcntl(fd, F_GETLK, &lock));
        assert((lock.l_type != F_UNLCK) == conflict);
        if (conflict) {
            assert(lock.l_pid == owner);
            assert(set_lock(fd, F_WRLCK) == -1);
            assert(errno == EAGAIN || errno == EACCES);
        } else {
            assert(!set_lock(fd, F_WRLCK));
        }
        assert(!close(fd));
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *private_owner(void *unused)
{
    (void)unused;
    int error = 0;
    if (unshare(CLONE_FILES) || set_lock(owner_fd, F_WRLCK)) {
        error = errno;
    }
    pthread_mutex_lock(&mutex);
    owner_error = error;
    ready = true;
    pthread_cond_broadcast(&condition);
    while (!stop) {
        pthread_cond_wait(&condition, &mutex);
    }
    pthread_mutex_unlock(&mutex);
    if (owner_exec_self) {
        char pid[32];
        execl("/nonexistent/lock-owner-exec", "missing", NULL);
        assert(errno == ENOENT);
        probe(owner_exec_path, true, getpid());
        snprintf(pid, sizeof(pid), "%ld", (long)getpid());
        execl(owner_exec_self, owner_exec_self, "exec-check", owner_exec_path,
              owner_expect_lock ? "1" : "0", pid, NULL);
        _exit(3);
    }
    return NULL;
}

static void start_owner(pthread_t *thread, int fd)
{
    owner_fd = fd;
    ready = stop = false;
    owner_error = 0;
    assert(!pthread_create(thread, NULL, private_owner, NULL));
    pthread_mutex_lock(&mutex);
    while (!ready) {
        pthread_cond_wait(&condition, &mutex);
    }
    pthread_mutex_unlock(&mutex);
    if (owner_error) {
        fprintf(stderr, "private files owner: %s\n", strerror(owner_error));
        exit(2);
    }
}

static void stop_owner(pthread_t thread)
{
    pthread_mutex_lock(&mutex);
    stop = true;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);
    assert(!pthread_join(thread, NULL));
}

static void exec_case(const char *self, const char *path, int mode,
                      bool cloexec, bool cloexec_alias)
{
    pid_t child = fork();
    int status;

    assert(child >= 0);
    if (!child) {
        int fd = open(path, O_RDWR | (cloexec ? O_CLOEXEC : 0));
        pthread_t thread;
        char pid[32];
        assert(fd >= 0);
        if (cloexec_alias) {
            assert(fcntl(fd, F_DUPFD_CLOEXEC, 0) >= 0);
        }
        bool expect_lock = mode != 1 && !cloexec && !cloexec_alias;
        if (mode) {
            if (mode == 2) {
                owner_exec_self = self;
                owner_exec_path = path;
                owner_expect_lock = expect_lock;
            }
            start_owner(&thread, fd);
        } else {
            assert(!set_lock(fd, F_WRLCK));
        }
        probe(path, true, getpid());
        execl("/nonexistent/lock-owner-exec", "missing", NULL);
        assert(errno == ENOENT);
        probe(path, true, getpid());
        if (mode == 2) {
            stop_owner(thread);
            _exit(4);
        }
        snprintf(pid, sizeof(pid), "%ld", (long)getpid());
        execl(self, self, "exec-check", path, expect_lock ? "1" : "0", pid, NULL);
        _exit(3);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "exec-check")) {
        assert(getpid() == (pid_t)strtol(argv[4], NULL, 10));
        probe(argv[2], atoi(argv[3]) != 0, getpid());
        return 0;
    }
    assert(argc == 2);
    char path[4096];
    assert(snprintf(path, sizeof(path), "%s/record-lock-XXXXXX", argv[1]) <
           (int)sizeof(path));
    int retired = mkstemp(path);
    assert(retired >= 0);
    int fresh = open(path, O_RDWR);
    assert(fresh >= 0);
    assert(!set_lock(retired, F_WRLCK));
    assert(!set_lock(retired, F_UNLCK));
    assert(!set_lock(fresh, F_WRLCK));
    probe(path, true, getpid());
    assert(!close(retired));
    probe(path, false, getpid());
    puts("delayed original backend close removes a later lock: CONFIRMED");

    pthread_t thread;
    start_owner(&thread, fresh);
    probe(path, true, getpid());
    int alias = dup(fresh);
    assert(alias >= 0);
    assert(!close(alias));
    assert(!close(fresh));
    probe(path, true, getpid());
    puts("private files owner survives data-table closes, reports TGID: CONFIRMED");
    stop_owner(thread);
    probe(path, false, getpid());
    puts("private owner exit releases lock: CONFIRMED");

    exec_case(argv[0], path, 0, false, false);
    puts("native owner retains non-CLOEXEC lock across successful exec: CONFIRMED");
    exec_case(argv[0], path, 1, false, false);
    puts("private helper loses lock across successful exec: INCOMPATIBILITY CONFIRMED");
    exec_case(argv[0], path, 2, false, false);
    puts("exec by private owner preserves lock and TGID: CONFIRMED");
    exec_case(argv[0], path, 0, true, false);
    exec_case(argv[0], path, 2, true, false);
    exec_case(argv[0], path, 0, false, true);
    exec_case(argv[0], path, 2, false, true);
    puts("CLOEXEC fd or same-inode alias releases lock across exec: CONFIRMED");
    assert(!unlink(path));
    return 0;
}
