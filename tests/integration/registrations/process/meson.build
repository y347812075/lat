if 'x86_64-linux-user' in target_dirs
  latx_integration_tests += [{
    'name': 'test-add-jcc',
    'runner': find_program('../../test-add-jcc.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../add-jcc.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-shift-jcc',
    'runner': find_program('../../test-shift-jcc.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../shift-jcc.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-or-jcc',
    'runner': find_program('../../test-or-jcc.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../or-jcc.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-jcc-conditions',
    'runner': find_program('../../test-jcc-conditions.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../jcc-conditions.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-instptn-options',
    'runner': find_program('../../test-instptn-options.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../instptn-options-fork.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-proc-readdir',
    'runner': find_program('../../test-proc-readdir.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../proc-readdir.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-rcu-thread-visibility',
    'runner': find_program('../../test-rcu-thread-visibility.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../rcu-thread-visibility.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-proc-thread-count',
    'runner': find_program('../../test-proc-thread-count.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../proc-thread-count.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-clone-parent-settid',
    'runner': find_program('../../test-clone-parent-settid.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../clone-parent-settid.S'),
    ],
  }]
  latx_integration_tests += [{
    'name': 'test-guest-fatal-signal-status',
    'runner': find_program('../../test-guest-fatal-signal-status.sh'),
    'args': [
      emulators['latx-x86_64'],
      files('../../guest-fatal-signal-status.S'),
    ],
  }]
  if 'CONFIG_LATX_KZT' in config_host
    latx_integration_tests += [{
      'name': 'test-int3-sigtrap-rip',
      'runner': find_program('../../test-int3-sigtrap-rip.sh'),
      'args': [
        emulators['latx-x86_64'],
        files('../../int3-sigtrap-rip.S'),
      ],
    }]
  endif
endif

if 'i386-linux-user' in target_dirs
  latx_integration_tests += [{
    'name': 'test-fd-transform-race-i386',
    'runner': find_program('../../test-fd-transform-race-i386.sh'),
    'args': [
      emulators['latx-i386'],
      files('../../fd-transform-race-i386.S'),
      files('../../fd-transform-race-shim.c'),
    ],
  }]
endif
