#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

extern int signal_boundary_site(void);
extern char signal_boundary_fault[], signal_boundary_resume[];
extern int signal_internal_site(void);
extern char signal_internal_fault[], signal_internal_resume[];
extern int signal_helper_site(void);
extern char signal_helper_fault[], signal_helper_resume[];

enum SignalCase {
    SIGNAL_BOUNDARY = 1,
    SIGNAL_INTERNAL,
    SIGNAL_HELPER,
};

static volatile sig_atomic_t current_case;
static volatile sig_atomic_t nested_seen;
static volatile sig_atomic_t recovered_cases;
static uintptr_t expected_pc;
static uintptr_t resume_pc;
static uint64_t expected_r8;
static uintptr_t altstack_begin;
static uintptr_t altstack_end;

static int on_altstack(const void *address)
{
    uintptr_t value = (uintptr_t)address;
    return value >= altstack_begin && value < altstack_end;
}

static void fail_from_handler(int code)
{
    _Exit(code);
}

static void handle_nested(int signal, siginfo_t *info, void *opaque)
{
    volatile unsigned char stack_byte = 0;
    ucontext_t *context = opaque;

    if (signal != SIGUSR1 || info->si_signo != SIGUSR1 ||
        !context || !on_altstack((const void *)&stack_byte)) {
        fail_from_handler(20);
    }
    nested_seen++;
}

static void handle_fault(int signal, siginfo_t *info, void *opaque)
{
    volatile unsigned char stack_byte = 0;
    ucontext_t *context = opaque;
    int expected_signal = current_case == SIGNAL_HELPER ? SIGILL : SIGFPE;

    if (signal != expected_signal || info->si_signo != expected_signal ||
        !context || (uintptr_t)context->uc_mcontext.gregs[REG_RIP] !=
                        expected_pc ||
        (uint64_t)context->uc_mcontext.gregs[REG_R8] != expected_r8 ||
        !on_altstack((const void *)&stack_byte)) {
        fail_from_handler(21 + current_case);
    }
    if (current_case == SIGNAL_INTERNAL) {
        long tid = syscall(SYS_gettid);
        if (tid <= 0 || syscall(SYS_tgkill, getpid(), tid, SIGUSR1) ||
            nested_seen != 1) {
            fail_from_handler(25);
        }
    }
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)resume_pc;
    recovered_cases++;
}

static int run_case(enum SignalCase test, uintptr_t fault, uintptr_t resume,
                    uint64_t r8, int (*site)(void))
{
    current_case = test;
    expected_pc = fault;
    resume_pc = resume;
    expected_r8 = r8;
    return site();
}

int main(void)
{
    size_t stack_size = (size_t)SIGSTKSZ * 2;
    void *stack = malloc(stack_size);
    if (!stack) {
        return 2;
    }
    altstack_begin = (uintptr_t)stack;
    altstack_end = altstack_begin + stack_size;
    stack_t alternate = {
        .ss_sp = stack,
        .ss_size = stack_size,
    };
    struct sigaction fault_action = {
        .sa_sigaction = handle_fault,
        .sa_flags = SA_SIGINFO | SA_ONSTACK,
    };
    struct sigaction nested_action = {
        .sa_sigaction = handle_nested,
        .sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER,
    };
    sigemptyset(&fault_action.sa_mask);
    sigemptyset(&nested_action.sa_mask);
    if (sigaltstack(&alternate, NULL) ||
        sigaction(SIGFPE, &fault_action, NULL) ||
        sigaction(SIGILL, &fault_action, NULL) ||
        sigaction(SIGUSR1, &nested_action, NULL)) {
        return 3;
    }
    if (run_case(SIGNAL_BOUNDARY, (uintptr_t)signal_boundary_fault,
                 (uintptr_t)signal_boundary_resume,
                 UINT64_C(0x1122334455667788), signal_boundary_site) ||
        run_case(SIGNAL_INTERNAL, (uintptr_t)signal_internal_fault,
                 (uintptr_t)signal_internal_resume,
                 UINT64_C(0x2233445566778899), signal_internal_site) ||
        run_case(SIGNAL_HELPER, (uintptr_t)signal_helper_fault,
                 (uintptr_t)signal_helper_resume,
                 UINT64_C(0x33445566778899aa), signal_helper_site) ||
        recovered_cases != 3 || nested_seen != 1) {
        return 4;
    }
    puts("AOT v2 signal recovery boundary=1 internal=1 helper=1 "
         "registers=1 nested=1 altstack=1 sigreturn=1");
    return 0;
}
