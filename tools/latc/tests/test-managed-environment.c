#define _GNU_SOURCE
#include "../latcd/managed-config.h"
#include "../latcd/managed-path.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char *valid[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
    char *missing[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL};
    char *duplicate[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "LANG=C", NULL};
    char *injected[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "LD_PRELOAD=x", NULL};
    char *override[] = {"PATH=/tmp", "LANG=C", "LC_ALL=C", NULL};
    assert(!latcd_managed_environment_validate(valid));
    assert(latcd_managed_environment_validate(NULL) < 0 && errno == EINVAL);
    assert(latcd_managed_environment_validate(missing) < 0 && errno == EACCES);
    assert(latcd_managed_environment_validate(duplicate) < 0 && errno == EACCES);
    assert(latcd_managed_environment_validate(injected) < 0 && errno == EACCES);
    assert(latcd_managed_environment_validate(override) < 0 && errno == EACCES);
    assert(latcd_managed_directory(NULL, 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_directory("relative", 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_directory("/", 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_directory("/usr//bin", 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_directory("/usr/../bin", 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_directory_matches(-1, "/usr", 0, 0755) < 0 && errno == EINVAL);
    assert(latcd_managed_file("relative", 1) < 0 && errno == EINVAL);
    assert(latcd_managed_file("/usr/bin/..", 1) < 0 && errno == EINVAL);
    assert(latcd_managed_config_read("relative", valid[0], 1, NULL) < 0 && errno == EINVAL);
    LatcdManagedConfig invalid = {0};
    assert(latcd_managed_config_validate(&invalid) < 0 && errno == EACCES);
    char path[4096], moved[4096];
    const char *home = getenv("HOME");
    assert(home && snprintf(path, sizeof(path), "%s/tmp/latcd-launcher-XXXXXX", home) < (int)sizeof(path));
    assert(mkdtemp(path));
    assert(snprintf(moved, sizeof(moved), "%s/old", path) < (int)sizeof(moved));
    char file[4096];
    assert(snprintf(file, sizeof(file), "%s/tool", path) < (int)sizeof(file));
    int fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0700);
    assert(fd >= 0 && write(fd, "old", 3) == 3 && !close(fd));
    int held[2];
    assert(!latcd_managed_launcher_open(file, file, 0, held));
    struct stat original, pinned, replacement;
    assert(!fstat(held[0], &original) && !rename(file, moved));
    fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0700);
    assert(fd >= 0 && !fstat(fd, &replacement) && !close(fd));
    assert(!fstat(held[0], &pinned) && pinned.st_ino == original.st_ino &&
           pinned.st_dev == original.st_dev && pinned.st_ino != replacement.st_ino);
    close(held[0]); close(held[1]);
    fd = open(file, O_RDWR | O_TRUNC);
    assert(fd >= 0);
    Elf64_Ehdr header = {0};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_version = EV_CURRENT;
    header.e_machine = EM_LOONGARCH;
    header.e_type = ET_EXEC;
    header.e_ehsize = sizeof(header);
    header.e_phoff = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 2;
    Elf64_Phdr phdr[2] = {
        {.p_type = PT_LOAD, .p_flags = PF_R | PF_X},
        {.p_type = PT_LOAD, .p_flags = PF_R},
    };
    assert(write(fd, &header, sizeof(header)) == sizeof(header));
    assert(write(fd, phdr, sizeof(phdr)) == sizeof(phdr));
    assert(!latcd_managed_static_launcher(fd));
    phdr[1].p_type = PT_INTERP;
    assert(pwrite(fd, &phdr[1], sizeof(phdr[1]), sizeof(header) + sizeof(phdr[0])) == sizeof(phdr[1]));
    assert(!latcd_managed_static_launcher(fd));
    phdr[1].p_type = PT_DYNAMIC;
    assert(pwrite(fd, &phdr[1], sizeof(phdr[1]), sizeof(header) + sizeof(phdr[0])) == sizeof(phdr[1]));
    assert(!latcd_managed_static_launcher(fd));
    assert(!ftruncate(fd, sizeof(header)));
    assert(latcd_managed_static_launcher(fd) < 0);
    close(fd);
    assert(!unlink(file) && !unlink(moved) && !rmdir(path));
    return 0;
}
