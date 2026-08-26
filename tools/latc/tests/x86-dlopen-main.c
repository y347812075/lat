#include <dlfcn.h>
#include <stdio.h>

#define LATC_DLOPEN_PLUGIN "/tmp/latc-m3-dlopen-plugin.so"

typedef int (*latc_plugin_apply_fn)(int value, int (*callback)(int));

static int main_callback(int value)
{
    return value * 3;
}

int main(void)
{
    void *handle = dlopen(LATC_DLOPEN_PLUGIN, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    dlerror();
    latc_plugin_apply_fn apply =
        (latc_plugin_apply_fn)dlsym(handle, "latc_plugin_apply");
    const char *error = dlerror();
    if (error || !apply) {
        fprintf(stderr, "dlsym failed: %s\n", error ? error : "null symbol");
        dlclose(handle);
        return 3;
    }
    int result = apply(11, main_callback);
    if (dlclose(handle)) {
        fprintf(stderr, "dlclose failed: %s\n", dlerror());
        return 4;
    }
    printf("dlopen callback result=%d\n", result);
    return result == 40 ? 0 : 5;
}
