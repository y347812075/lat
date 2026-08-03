if host_machine.cpu_family() == 'loongarch64' and \
   'x86_64-linux-user' in target_dirs
  test(
    'test-cef-userns-nested',
    find_program('test-cef-userns-nested.sh'),
    args: [
      emulators['latx-x86_64'],
      files('cef-userns-nested.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-cef-userns-exec',
    find_program('test-cef-userns-exec.sh'),
    args: [
      emulators['latx-x86_64'],
      files('cef-userns-exec.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-proc-readdir',
    find_program('test-proc-readdir.sh'),
    args: [
      emulators['latx-x86_64'],
      files('proc-readdir.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-rcu-thread-visibility',
    find_program('test-rcu-thread-visibility.sh'),
    args: [
      emulators['latx-x86_64'],
      files('rcu-thread-visibility.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-proc-thread-count',
    find_program('test-proc-thread-count.sh'),
    args: [
      emulators['latx-x86_64'],
      files('proc-thread-count.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-clone-namespaces',
    find_program('test-clone-namespaces.sh'),
    args: [
      emulators['latx-x86_64'],
      files('clone-namespaces.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-clone-parent-settid',
    find_program('test-clone-parent-settid.sh'),
    args: [
      emulators['latx-x86_64'],
      files('clone-parent-settid.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-guest-fatal-signal-status',
    find_program('test-guest-fatal-signal-status.sh'),
    args: [
      emulators['latx-x86_64'],
      files('guest-fatal-signal-status.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-setns-ipc-mqueue',
    find_program('test-setns-ipc-mqueue.sh'),
    args: [
      emulators['latx-x86_64'],
      files('setns-ipc-mqueue.S'),
      files('exec-with-pidfd.py'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
  test(
    'test-seccomp-filter-ordering',
    find_program('test-seccomp-filter-ordering.sh'),
    args: [
      emulators['latx-x86_64'],
      files('seccomp-filter-ordering.S'),
    ],
    protocol: 'exitcode',
    suite: 'latx-integration',
    timeout: 30,
  )
endif
