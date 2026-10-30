#define _GNU_SOURCE
#include "../latcd/broker-transport.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

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
    close(file); close(s[0]); close(s[1]);
    return 0;
}
