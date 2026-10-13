if host_machine.system() == 'linux'
  latu_runtime_manager = executable(
    'latu-runtime-manager',
    files('latu-runtime-manager.c'),
    dependencies: glib,
    link_args: qemu_static_link_args,
    install: true,
  )
endif
