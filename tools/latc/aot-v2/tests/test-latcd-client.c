#define _GNU_SOURCE

#include "latcd-client.h"
#include "latcd-protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int fail(const char *message)
{
    fprintf(stderr, "test-latcd-client: %s\n", message);
    return 1;
}

int main(void)
{
    char directory[] = "/tmp/test-latcd-client.XXXXXX";
    if (!mkdtemp(directory) || chmod(directory, 0700)) {
        return fail("cannot create socket directory");
    }
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    snprintf(path, sizeof(path), "%s/socket", directory);
    int server = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (server < 0 || bind(server, (const void *)&address, sizeof(address)) ||
        listen(server, 1)) {
        return fail("cannot create test listener");
    }
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char error[128] = {0};
    if (source < 0 || latcd_client_submit_fd(path, source,
            LATCD_PRIORITY_STARTUP, 42, error, sizeof(error))) {
        return fail(error);
    }
    int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    LatcdRequestV1 request;
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = { .iov_base = &request, .iov_len = sizeof(request) };
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    if (client < 0 || recvmsg(client, &message, MSG_CMSG_CLOEXEC) !=
                      sizeof(request) ||
        request.magic != LATCD_REQUEST_MAGIC || request.request_id != 42 ||
        request.priority != LATCD_PRIORITY_STARTUP) {
        return fail("received request does not match submission");
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    int received_fd = -1;
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS) {
        return fail("submission did not carry an FD");
    }
    memcpy(&received_fd, CMSG_DATA(header), sizeof(received_fd));
    if (fcntl(received_fd, F_GETFL) < 0) {
        return fail("received FD is invalid");
    }
    close(received_fd);
    close(client);
    close(source);
    close(server);
    unlink(path);
    rmdir(directory);

    errno = 0;
    if (!latcd_client_submit_fd(path, STDIN_FILENO, LATCD_PRIORITY_LIBRARY,
                                43, error, sizeof(error)) ||
        (errno != ENOENT && errno != ECONNREFUSED)) {
        return fail("missing daemon was not reported immediately");
    }
    puts("latcd nonblocking client tests: PASS");
    return 0;
}
