/* A waiting identity query or fork must not prevent an unrelated peer close. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int sender, peer, replacement;
static const char *operation, *observer;
static atomic_int started, sender_done, observer_result;
static int sender_result;
static double sender_ms;

static double now_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1000000.0;
}

static int check_error_paths(int fd)
{
    struct stat st;

    if (close(-1) != -1 || errno != EBADF ||
        dup2(-1, fd) != -1 || errno != EBADF || dup2(fd, fd) != fd ||
        syscall(SYS_dup3, -1, fd, O_CLOEXEC) != -1 || errno != EBADF ||
        syscall(SYS_dup3, fd, fd, O_CLOEXEC) != -1 || errno != EINVAL ||
        syscall(SYS_dup3, fd, -1, O_NONBLOCK) != -1 || errno != EINVAL) {
        return -1;
    }
    /* A leaked active-operation count would prevent this query completing. */
    return fstat(fd, &st);
}

static void *release_sender(void *unused)
{
    double begin;

    (void)unused;
    begin = now_ms();
    atomic_store(&started, 1);
    if (!strcmp(operation, "close")) {
        sender_result = close(sender);
    } else if (!strcmp(operation, "dup2")) {
        sender_result = dup2(replacement, sender);
    } else {
        sender_result = syscall(SYS_dup3, replacement, sender, O_CLOEXEC);
    }
    sender_ms = now_ms() - begin;
    atomic_store(&sender_done, 1);
    return NULL;
}

static void *observe(void *opaque)
{
    const char *kind = opaque;
    struct stat st;
    int result;

    while (!atomic_load(&started)) {
        sched_yield();
    }
    usleep(50000);
    if (!strcmp(kind, "fstat")) {
        result = fstat(replacement, &st);
    } else {
        int status;
        pid_t child = fork();

        if (!child) {
            int fd = dup(replacement);
            int bad = fd < 0 || fstat(replacement, &st);

            if (fd >= 0) {
                bad |= close(fd) != 0;
            }
            _exit(bad ? 1 : 0);
        }
        result = child < 0 || waitpid(child, &status, 0) != child ||
                 !WIFEXITED(status) || WEXITSTATUS(status);
    }
    atomic_fetch_or(&observer_result, result != 0);
    return NULL;
}

int main(int argc, char **argv)
{
    struct sockaddr_in address = { .sin_family = AF_INET };
    struct linger linger = { .l_onoff = 1, .l_linger = 3 };
    socklen_t len = sizeof(address);
    pthread_t writer, reader[2];
    char buffer[65536] = { 0 };
    int listener, size = 4096, queued = 0, have_observer, early;
    int peer_result, reused = -1, bad;
    double begin, peer_ms, peer_at_ms;
    size_t sent = 0;

    if (argc != 3 || (strcmp(argv[1], "close") &&
                      strcmp(argv[1], "dup2") && strcmp(argv[1], "dup3")) ||
        (strcmp(argv[2], "none") && strcmp(argv[2], "fstat") &&
         strcmp(argv[2], "fork") && strcmp(argv[2], "both") &&
         strcmp(argv[2], "reuse")) ||
        (!strcmp(argv[2], "reuse") && strcmp(argv[1], "close"))) {
        return 2;
    }
    operation = argv[1];
    observer = argv[2];
    have_observer = !strcmp(observer, "both") ? 2 :
                    (!strcmp(observer, "fstat") || !strcmp(observer, "fork"));
    alarm(12);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    sender = socket(AF_INET, SOCK_STREAM, 0);
    replacement = open("/dev/null", O_RDONLY);
    if (replacement < 0 || check_error_paths(replacement)) {
        fputs("FAIL: descriptor error paths\n", stderr);
        return 11;
    }
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || sender < 0 || replacement < 0 ||
        setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) ||
        setsockopt(sender, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&address, &len) ||
        connect(sender, (struct sockaddr *)&address, sizeof(address))) {
        perror("TCP setup");
        return 3;
    }
    peer = accept(listener, NULL, NULL);
    close(listener);
    if (peer < 0) {
        return 4;
    }
    for (int round = 0; round < 3; round++) {
        ssize_t n;

        while ((n = send(sender, buffer, sizeof(buffer),
                         MSG_DONTWAIT | MSG_NOSIGNAL)) > 0) {
            sent += n;
            if (sent > 16 * 1024 * 1024) {
                return 5;
            }
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("fill send queue");
            return 6;
        }
        usleep(50000);
    }
    if (ioctl(sender, TIOCOUTQ, &queued) || queued <= 0 ||
        setsockopt(sender, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) {
        fputs("FAIL: no pending TCP data for linger\n", stderr);
        return 7;
    }
    begin = now_ms();
    if (pthread_create(&writer, NULL, release_sender, NULL)) {
        return 8;
    }
    for (int i = 0; i < have_observer; i++) {
        const char *kind = have_observer == 1 ? observer :
                           (i ? "fork" : "fstat");

        if (pthread_create(&reader[i], NULL, observe, (void *)kind)) {
            return 8;
        }
    }
    while (!atomic_load(&started)) {
        sched_yield();
    }
    usleep(200000);
    early = atomic_load(&sender_done);
    peer_at_ms = now_ms() - begin;
    if (!strcmp(observer, "reuse")) {
        /* The slot is detached even though SO_LINGER has not returned. */
        if (fcntl(sender, F_GETFD) != -1 || errno != EBADF) {
            fputs("FAIL: sender fd was not detached during linger\n", stderr);
            return 9;
        }
        reused = fcntl(peer, F_DUPFD_CLOEXEC, sender);
        if (reused != sender) {
            fputs("FAIL: peer did not reuse the detached sender slot\n",
                  stderr);
            return 10;
        }
    }
    peer_ms = now_ms();
    peer_result = close(peer);
    if (reused >= 0) {
        peer_result |= close(reused);
    }
    peer_ms = now_ms() - peer_ms;
    pthread_join(writer, NULL);
    for (int i = 0; i < have_observer; i++) {
        pthread_join(reader[i], NULL);
    }
    bad = peer_result || sender_result < 0 || observer_result ||
          sender_ms > 1500 || peer_ms > 1000 || peer_at_ms > 1500 ||
          (early && sender_ms < 150);
    printf("%s/%s: queued=%d sender_ms=%.3f peer_at_ms=%.3f "
           "peer_close_ms=%.3f observer=%d bad=%d\n", operation, observer,
           queued, sender_ms, peer_at_ms, peer_ms, observer_result, bad);
    if (strcmp(operation, "close")) {
        close(sender);
    }
    close(replacement);
    return bad ? 1 : 0;
}
