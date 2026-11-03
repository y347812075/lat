#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "managed-config.h"
#include "managed-path.h"
#include "parson/parson.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int latcd_managed_static_launcher(int fd)
{
    Elf64_Ehdr header;
    struct stat before, after;
    if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT ||
        header.e_machine != EM_LOONGARCH || header.e_type != ET_EXEC ||
        header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Elf64_Phdr) ||
        !header.e_phnum || header.e_phnum == PN_XNUM ||
        header.e_phoff > (uint64_t)before.st_size ||
        (uint64_t)header.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)before.st_size - header.e_phoff) {
        errno = EINVAL; return -1;
    }
    bool load = false;
    for (unsigned i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr), header.e_phoff + i * sizeof(phdr)) != sizeof(phdr) ||
            phdr.p_type == PT_INTERP || phdr.p_type == PT_DYNAMIC) {
            errno = EINVAL; return -1;
        }
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) load = true;
    }
    if (!load || fstat(fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        errno = ESTALE; return -1;
    }
    return 0;
}

void latcd_managed_config_clear(LatcdManagedConfig *c)
{
    if (!c) return;
    free(c->cache); free(c->admin); free(c->broker);
    free(c->compiler); free(c->runner); free(c->runtime);
    free(c->worker_cgroup);
    free(c->worker_bwrap); free(c->worker_bootstrap); free(c->worker_closure);
    memset(c, 0, sizeof(*c));
}

int latcd_managed_launcher_open(const char *bwrap, const char *bootstrap,
                                int managed, int fds[2])
{
    const char *paths[] = {bwrap, bootstrap};
    fds[0] = fds[1] = -1;
    for (unsigned i = 0; i < 2; i++) {
        struct stat st;
        if (!paths[i] || paths[i][0] != '/') { errno = EINVAL; goto fail; }
        fds[i] = managed ? latcd_managed_file(paths[i], 1) :
            open(paths[i], O_PATH | O_CLOEXEC | O_NOFOLLOW);
        if (fds[i] < 0 || fstat(fds[i], &st) || !S_ISREG(st.st_mode) ||
            !(st.st_mode & 0111)) { errno = EACCES; goto fail; }
        if (managed && i == 0 && latcd_managed_static_launcher(fds[i])) goto fail;
    }
    return 0;
fail:
    {
        int saved = errno;
        for (unsigned i = 0; i < 2; i++) {
            if (fds[i] >= 0) close(fds[i]);
            fds[i] = -1;
        }
        errno = saved;
        return -1;
    }
}

static int uid_value(const char *s, uid_t *out)
{
    uint64_t value = 0;
    if (!s || !*s || strlen(s) > 10 || (s[0] == '0' && s[1])) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        value = value * 10 + (*s - '0');
        if (value >= UINT32_MAX) return -1;
    }
    *out = (uid_t)value;
    return (uint64_t)*out == value ? 0 : -1;
}

int latcd_managed_environment_validate(char *const environment[])
{
    unsigned seen = 0;
    if (!environment) { errno = EINVAL; return -1; }
    for (size_t i = 0; environment[i]; i++) {
        unsigned bit;
        if (!strcmp(environment[i], "PATH=/usr/bin:/bin")) bit = 1;
        else if (!strcmp(environment[i], "LANG=C")) bit = 2;
        else if (!strcmp(environment[i], "LC_ALL=C")) bit = 4;
        else { errno = EACCES; return -1; }
        if (seen & bit) { errno = EACCES; return -1; }
        seen |= bit;
    }
    if (seen != 7) { errno = EACCES; return -1; }
    return 0;
}

int latcd_managed_config_load(const char *path, LatcdManagedConfig *c)
{
    if (!c) { errno = EINVAL; return -1; }
    memset(c, 0, sizeof(*c));
    char raw[8192]; size_t length;
    if (latcd_managed_config_read(path, raw, sizeof(raw), &length)) return -1;
    if (memchr(raw, '\0', length)) { errno = EINVAL; return -1; }
    JSON_Value *value = json_parse_string(raw);
    JSON_Object *object = value ? json_value_get_object(value) : NULL;
    const char *keys[] = {"service_uid", "client_uid", "cache", "admin", "broker", "compiler", "runner", "runtime"};
    char **paths[] = {&c->cache, &c->admin, &c->broker, &c->compiler, &c->runner, &c->runtime};
    int result = -1;
    size_t count = object ? json_object_get_count(object) : 0;
    bool automatic_present = object && json_object_has_value(object, "automatic_retirement");
    bool grace_present = object && json_object_has_value(object, "retirement_grace_us");
    if (!object || count < sizeof(keys) / sizeof(keys[0]) ||
        count > sizeof(keys) / sizeof(keys[0]) + 6 ||
        !json_object_get_string(object, keys[0]) || !json_object_get_string(object, keys[1]) ||
        strlen(json_object_get_string(object, keys[0])) != json_object_get_string_len(object, keys[0]) ||
        strlen(json_object_get_string(object, keys[1])) != json_object_get_string_len(object, keys[1]) ||
        uid_value(json_object_get_string(object, keys[0]), &c->service_uid) ||
        uid_value(json_object_get_string(object, keys[1]), &c->client_uid) ||
        !c->service_uid || c->service_uid == c->client_uid) goto out;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        const char *s = json_object_get_string(object, keys[i + 2]);
        if (!s || s[0] != '/' || !s[1] || strlen(s) != json_object_get_string_len(object, keys[i + 2])) goto out;
        *paths[i] = strdup(s);
        if (!*paths[i]) goto out;
    }
    if (json_object_has_value(object, "worker_cgroup")) {
        const char *s = json_object_get_string(object, "worker_cgroup");
        if (!s || s[0] != '/' || !s[1] ||
            strlen(s) != json_object_get_string_len(object, "worker_cgroup")) goto out;
        c->worker_cgroup = strdup(s);
        if (!c->worker_cgroup) goto out;
    }
    if (automatic_present) {
        JSON_Value *automatic = json_object_get_value(object, "automatic_retirement");
        if (!automatic || json_value_get_type(automatic) != JSONBoolean) goto out;
        c->automatic_retirement = json_value_get_boolean(automatic) != 0;
    }
    if (grace_present) {
        JSON_Value *grace = json_object_get_value(object, "retirement_grace_us");
        double value = grace ? json_value_get_number(grace) : 0;
        if (!grace || json_value_get_type(grace) != JSONNumber || value < 1000000 ||
            value > (double)(UINT64_C(30) * 24 * 60 * 60 * 1000000)) goto out;
        c->retirement_grace_us = (uint64_t)value;
        if ((double)c->retirement_grace_us != value) goto out;
    }
    const char *optional[] = {"worker_bwrap", "worker_bootstrap", "worker_closure"};
    char **targets[] = {&c->worker_bwrap, &c->worker_bootstrap, &c->worker_closure};
    for (unsigned i = 0; i < 3; i++) if (json_object_has_value(object, optional[i])) {
        const char *s = json_object_get_string(object, optional[i]);
        if (!s || s[0] != '/' || !s[1] ||
            strlen(s) != json_object_get_string_len(object, optional[i])) goto out;
        *targets[i] = strdup(s);
        if (!*targets[i]) goto out;
    }
    if (!!c->worker_bwrap != !!c->worker_bootstrap || (c->worker_closure && !c->worker_bwrap) ||
        count != sizeof(keys) / sizeof(keys[0]) + !!c->worker_cgroup +
                 !!c->worker_bwrap + !!c->worker_bootstrap + !!c->worker_closure +
                 automatic_present + grace_present) goto out;
    result = 0;
out:
    if (value) json_value_free(value);
    if (result) { latcd_managed_config_clear(c); errno = EINVAL; }
    return result;
}

int latcd_managed_config_validate(const LatcdManagedConfig *c)
{
    uid_t real, effective, saved;
    gid_t real_gid, effective_gid, saved_gid;
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (!c || !c->cache || !c->admin || !c->broker || !c->compiler ||
        !c->runner || !c->runtime || !c->service_uid ||
        (c->retirement_grace_us && !c->automatic_retirement) ||
        c->service_uid == c->client_uid || getresuid(&real, &effective, &saved) ||
        real != c->service_uid || effective != c->service_uid || saved != c->service_uid ||
        getresgid(&real_gid, &effective_gid, &saved_gid) || !real_gid ||
        real_gid != effective_gid || real_gid != saved_gid || getgroups(0, NULL) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps) || caps[0].effective || caps[0].permitted ||
        caps[0].inheritable || caps[1].effective || caps[1].permitted || caps[1].inheritable) {
        errno = EACCES;
        return -1;
    }
    int fds[6] = {-1, -1, -1, -1, -1, -1};
    int result = -1;
    struct stat dirs[3];
    fds[0] = latcd_managed_directory(c->cache, c->service_uid, 0700);
    if (fds[0] < 0) goto out;
    fds[1] = latcd_managed_directory(c->admin, c->service_uid, 0700);
    if (fds[1] < 0) goto out;
    fds[2] = latcd_managed_directory(c->broker, c->service_uid, 0755);
    if (fds[2] < 0) goto out;
    for (int i = 0; i < 3; i++) {
        if (fstat(fds[i], &dirs[i])) goto out;
        for (int j = 0; j < i; j++) {
            if (dirs[i].st_dev == dirs[j].st_dev && dirs[i].st_ino == dirs[j].st_ino) {
                errno = EINVAL;
                goto out;
            }
        }
    }
    fds[3] = latcd_managed_file(c->compiler, 1);
    if (fds[3] < 0) goto out;
    fds[4] = latcd_managed_file(c->runner, 1);
    if (fds[4] < 0) goto out;
    fds[5] = latcd_managed_directory(c->runtime, 0, 0755);
    if (fds[5] < 0) goto out;
    char *runtime = NULL;
    if (asprintf(&runtime, "%s/liblat-aot-runtime.so.2", c->runtime) < 0) goto out;
    int library = latcd_managed_file(runtime, 0);
    free(runtime);
    if (library < 0) goto out;
    close(library);
    if (c->worker_bwrap) {
        int launcher[2];
        if (latcd_managed_launcher_open(c->worker_bwrap, c->worker_bootstrap, 1, launcher)) goto out;
        close(launcher[0]); close(launcher[1]);
    }
    result = 0;
out:
    {
        int error = errno;
        for (int i = 0; i < 6; i++) if (fds[i] >= 0) close(fds[i]);
        errno = error;
        return result;
    }
}
