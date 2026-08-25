#include "lat-aot-v2.h"

#include <errno.h>
#include <stdlib.h>

static _Thread_local LatAotRuntimeSyscallCallbackV2 syscall_callback;
static _Thread_local void *syscall_opaque;

uint32_t lat_aot_runtime_abi_version(void)
{
    return LAT_AOT_V2_ABI_VERSION;
}

int lat_aot_runtime_bind_syscall(LatAotRuntimeSyscallCallbackV2 callback,
                                 void *opaque)
{
    if (!callback) {
        errno = EINVAL;
        return -1;
    }
    syscall_callback = callback;
    syscall_opaque = opaque;
    return 0;
}

void lat_aot_runtime_raise_syscall(void)
{
    if (syscall_callback) {
        syscall_callback(syscall_opaque);
    }
    abort();
}
