#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucontext.h>

static void recovered(void) __attribute__((noreturn));

static void recovered(void)
{
    static const char message[] = "AOT v2 signal recovery works\n";

    if (write(STDOUT_FILENO, message, sizeof(message) - 1) < 0) {
        _Exit(5);
    }
    _Exit(0);
}

static void handle_sigfpe(int signal, siginfo_t *info, void *opaque)
{
    ucontext_t *context = opaque;

    if (signal != SIGFPE || info->si_signo != SIGFPE) {
        _Exit(2);
    }
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)recovered;
}

int main(void)
{
    struct sigaction action = {
        .sa_sigaction = handle_sigfpe,
        .sa_flags = SA_SIGINFO,
    };
    volatile unsigned int divisor = 0;
    unsigned int dividend = 42;

    sigemptyset(&action.sa_mask);
    if (sigaction(SIGFPE, &action, NULL)) {
        return 3;
    }
    __asm__ volatile("divl %2"
                     : "+a"(dividend)
                     : "d"(0), "r"(divisor)
                     : "cc");
    return 4;
}
