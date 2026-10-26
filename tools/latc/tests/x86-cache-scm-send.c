#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 5) return 2;
    int socket = atoi(argv[1]), ordinary = atoi(argv[2]), pin = atoi(argv[3]);
    int mode = atoi(argv[4]);
    struct mmsghdr messages[2] = {0};
    struct iovec vectors[2];
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } controls[2];
    memset(controls, 0, sizeof(controls));
    for (unsigned i = 0; i < 2; i++) {
        vectors[i] = (struct iovec){.iov_base = "x", .iov_len = 1};
        struct msghdr *message = &messages[i].msg_hdr;
        message->msg_iov = &vectors[i];
        message->msg_iovlen = 1;
        message->msg_control = controls[i].bytes;
        unsigned count = mode == 2 ? 2 : 1;
        message->msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *control = CMSG_FIRSTHDR(message);
        control->cmsg_level = SOL_SOCKET;
        control->cmsg_type = SCM_RIGHTS;
        control->cmsg_len = CMSG_LEN(count * sizeof(int));
        int *fds = (int *)CMSG_DATA(control);
        fds[0] = (mode == 1 || mode == 4 || (mode == 5 && i)) ? pin : ordinary;
        if (count == 2) fds[1] = pin;
    }
    puts("READY");
    fflush(stdout);
    if (getchar() == EOF) return 3;
    errno = 0;
    int result = mode < 3 ? sendmsg(socket, &messages[0].msg_hdr, 0) :
                           sendmmsg(socket, messages, 2, 0);
    printf("%d %d\n", result, errno);
    fflush(stdout);
    if (getchar() == EOF) return 4;
    return 0;
}
