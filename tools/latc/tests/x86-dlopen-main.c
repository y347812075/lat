#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#define LATC_DLOPEN_PLUGIN "/tmp/latc-m3-dlopen-plugin.so"

typedef int (*latc_plugin_apply_fn)(int value, int (*callback)(int));

static int main_callback(int value)
{
    return value * 3;
}

int main(void)
{
    uintptr_t first_base = 0;
    uintptr_t last_base = 0;
    int result = 0;
    for (int iteration = 0; iteration < 100; iteration++) {
        void *handle = dlopen(LATC_DLOPEN_PLUGIN, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 2;
        }
        dlerror();
        latc_plugin_apply_fn apply =
            (latc_plugin_apply_fn)dlsym(handle, "latc_plugin_apply");
        const char *error = dlerror();
        Dl_info info;
        if (error || !apply || !dladdr((void *)apply, &info)) {
            fprintf(stderr, "dlsym failed: %s\n", error ? error : "null symbol");
            dlclose(handle);
            return 3;
        }
        result = apply(11, main_callback);
        last_base = (uintptr_t)info.dli_fbase;
        if (!first_base) {
            first_base = last_base;
        }
        if (dlclose(handle)) {
            fprintf(stderr, "dlclose failed: %s\n", dlerror());
            return 4;
        }
        mmap((void *)last_base, 0x5000, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    }
    printf("dlopen loads=100 result=%d moved=%d\n", result,
           first_base != last_base);
    return result == 40 && first_base != last_base ? 0 : 5;
}
