/*
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "qemu/osdep.h"

#include "aot_exit.h"

int main(void)
{
    g_assert(aot_exit_worker_should_daemonize(false));
    g_assert(!aot_exit_worker_should_daemonize(true));
    return 0;
}
