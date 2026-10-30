#include "../latcd/managed-config.h"
#include "../latcd/managed-path.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>

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
    return 0;
}
