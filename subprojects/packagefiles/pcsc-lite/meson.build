# Minimal meson.build for pcsc-lite client library only.
# This replaces the upstream meson.build which unconditionally builds the
# pcscd daemon and requires flex, systemd, udev, etc.
#
# We only need the client library (libpcsclite) for linking against.
# At runtime the real pcscd daemon and libpcsclite.so from the host system
# will be used via dlopen/dynamic linking.

project('pcsc-lite', 'c',
  meson_version : '>=0.58.0',
  version : '2.4.1')

cc = meson.get_compiler('c')
threads_dep = dependency('threads')
dl_dep = cc.find_library('dl', required : false)

# Generate pcsclite.h from template
confgen_data = configuration_data({
  'VERSION' : meson.project_version(),
  'ipcdir' : '/run/pcscd',
  'sysconfdir' : '/etc',
  'sbindir_exp' : '/usr/sbin',
  'PCSCLITE_CONFIG_DIR' : '/etc/reader.conf.d',
  'usbdropdir' : '/usr/lib/pcsc/drivers',
})

pcsclite_h = configure_file(
  output : 'pcsclite.h',
  input : 'src/PCSC/pcsclite.h.in',
  configuration : confgen_data)

# Generate pcscd.h from template (needed by winscard_clnt.c, winscard_msg.c, utils.c)
pcscd_h = configure_file(
  output : 'pcscd.h',
  input : 'src/pcscd.h.in',
  configuration : confgen_data)

# Generate config.h (minimal, client-only needs)
conf_data = configuration_data({
  'VERSION' : '"' + meson.project_version() + '"',
  'PCSCLITE_HP_DROPDIR' : '"/usr/lib/pcsc/drivers"',
  'HAVE_NANOSLEEP' : true,
  'NO_LOG' : false,
})
if cc.has_function('getrandom', prefix : '#include <sys/random.h>')
  conf_data.set('HAVE_GETRANDOM', true)
endif
if cc.has_function('secure_getenv')
  conf_data.set('HAVE_SECURE_GETENV', true)
endif
configure_file(output : 'config.h', configuration : conf_data)

incdir = include_directories(['src', 'src/PCSC'])

# Static client library: combines all client sources into a single archive.
# This is what upstream builds for default_library=static.
libpcsclite_static_src = files([
  'src/debug.c',
  'src/error.c',
  'src/g_defines.c',
  'src/simclist.c',
  'src/sys_unix.c',
  'src/utils.c',
  'src/winscard_clnt.c',
  'src/winscard_msg.c',
])

libpcsclite = static_library('pcsclite',
  libpcsclite_static_src,
  include_directories : incdir,
  dependencies : [dl_dep, threads_dep],
  c_args : ['-DLIBPCSCLITE', '-DSIMCLIST_NO_DUMPRESTORE', '-fvisibility=hidden'],
  install : false)

# Dependency object for parent project
libpcsclite_dep = declare_dependency(
  link_with : libpcsclite,
  dependencies : [dl_dep, threads_dep],
  include_directories : [incdir, include_directories('.')])
