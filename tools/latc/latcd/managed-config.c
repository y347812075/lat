#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "managed-config.h"
#include "managed-path.h"
#include "parson/parson.h"
#include <errno.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

void latcd_managed_config_clear(LatcdManagedConfig *c)
{
    if (!c) return;
    free(c->cache); free(c->admin); free(c->broker);
    free(c->compiler); free(c->runner); free(c->runtime);
    memset(c, 0, sizeof(*c));
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
    if (!object || json_object_get_count(object) != sizeof(keys) / sizeof(keys[0]) ||
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
    result = 0;
out:
    {
        int error = errno;
        for (int i = 0; i < 6; i++) if (fds[i] >= 0) close(fds[i]);
        errno = error;
        return result;
    }
}
