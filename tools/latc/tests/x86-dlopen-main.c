#define _GNU_SOURCE

#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>

#define LATC_DLOPEN_PLUGIN "/tmp/latc-m3-dlopen-plugin.so"

typedef int (*latc_plugin_apply_fn)(int value, int (*callback)(int));
typedef int (*latc_plugin_signal_fn)(void);

static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t concurrent_invalidation;
static uintptr_t expected_signal_pc;
static uintptr_t signal_resume_pc;

static void handle_sigfpe(int signal, siginfo_t *info, void *opaque)
{
    ucontext_t *context = opaque;

    if (signal != SIGFPE || info->si_signo != SIGFPE || !context ||
        (uintptr_t)context->uc_mcontext.gregs[REG_RIP] !=
            expected_signal_pc ||
        (uint64_t)context->uc_mcontext.gregs[REG_R8] !=
            UINT64_C(0x445566778899aabb)) {
        _Exit(10);
    }
    if (concurrent_invalidation) {
    }
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)signal_resume_pc;
    signal_count++;
}

static int main_callback(int value)
{
    return value * 3;
}

int main(void)
{
    struct sigaction action = {
        .sa_sigaction = handle_sigfpe,
        .sa_flags = SA_SIGINFO,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGFPE, &action, NULL)) {
        return 1;
    }
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
        latc_plugin_signal_fn signal_site = (latc_plugin_signal_fn)dlsym(
            handle, "latc_plugin_signal_site");
        expected_signal_pc = (uintptr_t)dlsym(
            handle, "latc_plugin_signal_fault");
        signal_resume_pc = (uintptr_t)dlsym(
            handle, "latc_plugin_signal_resume");
        const char *error = dlerror();
        Dl_info info;
        if (error || !apply || !signal_site || !expected_signal_pc ||
            !signal_resume_pc || !dladdr((void *)apply, &info)) {
            fprintf(stderr, "dlsym failed: %s\n", error ? error : "null symbol");
            dlclose(handle);
            return 3;
        }
        result = apply(11, main_callback);
        concurrent_invalidation = iteration == 99;
        if (signal_site()) {
            return 6;
        }
        last_base = (uintptr_t)info.dli_fbase;
        if (!first_base) {
            first_base = last_base;
        }
        if (concurrent_invalidation) {
            if (dlclose(handle)) {
                return 8;
            }
        } else {
            if (dlclose(handle)) {
                fprintf(stderr, "dlclose failed: %s\n", dlerror());
                return 4;
            }
        }
        mmap((void *)last_base, 0x5000, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    }
    printf("dlopen loads=100 signals=%d concurrent_invalidation=1 result=%d "
           "moved=%d\n", signal_count, result, first_base != last_base);
    return result == 40 && signal_count == 100 &&
           first_base != last_base ? 0 : 5;
}
