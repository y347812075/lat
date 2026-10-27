#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail(void)
{
    return 1;
}

int main(void)
{
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 3) return fail();

    if (syscall(SYS_close_range, fd, fd, CLOSE_RANGE_CLOEXEC) ||
        !(fcntl(fd, F_GETFD) & FD_CLOEXEC) ||
        syscall(SYS_close_range, fd, fd, 0) ||
        fcntl(fd, F_GETFD) != -1 || errno != EBADF) return fail();

    errno = 0;
    if (syscall(SYS_close_range, 5, 4, 0) != -1 || errno != EINVAL) return fail();
    errno = 0;
    if (syscall(SYS_close_range, 3, 4, CLOSE_RANGE_UNSHARE) != -1 ||
        errno != EOPNOTSUPP) return fail();

    /* Registry, cache-object and executable-identity descriptors may lie in
     * this range. They must remain usable while ordinary guest fds close. */
    if (syscall(SYS_close_range, 3, 1024, 0)) return fail();
    if (write(STDOUT_FILENO, "CLOSED\n", 7) != 7) return fail();
    sleep(30);
    return 0;
}
