#include "qemu/osdep.h"

#include "qemu/rcu.h"
#include "qemu/thread.h"

typedef struct TestRcuCallback {
    struct rcu_head rcu;
    QemuEvent done;
} TestRcuCallback;

static void test_callback(struct rcu_head *head)
{
    TestRcuCallback *callback = container_of(head, TestRcuCallback, rcu);

    qemu_event_set(&callback->done);
}

int main(void)
{
    TestRcuCallback callback;

#ifdef CONFIG_LATX
    g_assert_false(rcu_call_thread_is_running());
    g_assert_false(rcu_atfork_child_is_deferred());
    g_assert_false(rcu_defer_atfork_child());
    g_assert_true(rcu_atfork_child_is_deferred());
    rcu_restore_atfork_child_defer(false);
    g_assert_false(rcu_atfork_child_is_deferred());
#endif

    qemu_event_init(&callback.done, false);
    call_rcu1(&callback.rcu, test_callback);
    qemu_event_wait(&callback.done);
    g_assert_true(rcu_call_thread_is_running());
    qemu_event_destroy(&callback.done);

    return 0;
}
