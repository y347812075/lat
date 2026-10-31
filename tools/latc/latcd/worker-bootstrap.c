#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

/* fd 3 is a private SOCK_SEQPACKET channel to the daemon. */
int main(int argc, char **argv, char **envp)
{
    if (argc < 2 || argv[1][0] != '/') return 126;
    int work = open("/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    struct statfs fs;
    if (work < 0 || fstat(work, &st) || !S_ISDIR(st.st_mode) ||
        fstatfs(work, &fs) || (unsigned long)fs.f_type != TMPFS_MAGIC)
        return 126;
    const char payload[] = "LATCD-WORKSPACE-1";
    struct iovec iov = { .iov_base = (void *)payload, .iov_len = sizeof(payload) };
    union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = control.data, .msg_controllen = sizeof(control.data) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &work, sizeof(work));
    ssize_t n;
    do { n = sendmsg(3, &msg, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    close(work);
    if (n != sizeof(payload)) return 126;
    char ack;
    do { n = recv(3, &ack, 1, 0); } while (n < 0 && errno == EINTR);
    close(3);
    if (n != 1 || ack != '1') return 126;
    execve(argv[1], argv + 1, envp);
    return 127;
}
