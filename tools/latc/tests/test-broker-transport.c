#define _GNU_SOURCE
#include "../latcd/broker-transport.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    assert(dir);
    int count = 0;
    while (readdir(dir)) count++;
    closedir(dir);
    return count;
}

static void send_many(int socket, int file, unsigned count)
{
    char byte = 'x';
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int) * 16)]; } control = {0};
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = control.bytes, .msg_controllen = CMSG_SPACE(sizeof(int) * count) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * count);
    for (unsigned i = 0; i < count; i++) memcpy((char *)CMSG_DATA(c) + i * sizeof(int), &file, sizeof(file));
    assert(sendmsg(socket, &msg, 0) == 1);
}

int main(void)
{
    int s[2]; uid_t uid; gid_t gid;
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, s));
    assert(!latcd_broker_peer(s[0], getuid(), &uid, &gid));
    assert(latcd_broker_peer(s[1], getuid() + 1, &uid, &gid) < 0);
    assert(!latcd_broker_peer(s[1], getuid(), &uid, &gid));
    int file = open("/dev/null", O_RDONLY | O_CLOEXEC), received = -1;
    char sent = 'a', got = 0;
    assert(file >= 0 && !latcd_broker_send(s[1], &sent, 1, file));
    assert(!latcd_broker_receive(s[0], uid, gid, &got, 1, &received));
    assert(got == sent && received >= 0 && (fcntl(received, F_GETFD) & FD_CLOEXEC));
    close(received);
    assert(!latcd_broker_send(s[1], "ab", 2, file));
    assert(latcd_broker_receive(s[0], uid, gid, &got, 1, &received) < 0 && received == -1);
    int before = fd_count();
    for (unsigned n = 2; n <= 16; n += 14) {
        send_many(s[1], file, n);
        assert(latcd_broker_receive(s[0], uid, gid, &got, 1, &received) < 0 && received == -1);
        assert(fd_count() == before);
    }
    assert(!latcd_broker_send(s[1], &sent, 1, file));
    assert(latcd_broker_receive(s[0], uid + 1, gid, &got, 1, &received) < 0 && received == -1);
    assert(fd_count() == before);
    close(file); close(s[0]); close(s[1]);
    return 0;
}
