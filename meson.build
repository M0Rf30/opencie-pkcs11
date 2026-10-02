project(
    'libopencie-pkcs11',
    'cpp',
    'c',
    version: '1.2.3',
    license: 'LGPL-3.0-or-later',
    meson_version: '>=0.56',
    default_options: [
        'cpp_std=c++20',
        'warning_level=2',
    ],
)

cpp = meson.get_compiler('cpp')
cc = meson.get_compiler('c')

if host_machine.system() != 'windows'
  add_project_arguments('-fPIC', language: 'cpp')
endif

# --- Hardening flags for this security-sensitive shared library (it parses
# untrusted ASN.1/CMS/OCSP/XML input from smart cards and the network).
# Every flag is probed with has_argument()/has_link_argument() so a
# toolchain that rejects it (MinGW ld, macOS ld64, Android NDK lld) just
# skips it instead of breaking configure.
hardening_cpp_args = []
hardening_c_args = []
hardening_link_args = []

# Stack canaries on every function with a vulnerable stack layout.
foreach a : ['-fstack-protector-strong']
  if cpp.has_argument(a)
    hardening_cpp_args += [a]
  endif
  if cc.has_argument(a)
    hardening_c_args += [a]
  endif
endforeach

# _FORTIFY_SOURCE needs optimisation to do anything (glibc only installs the
# checked __*_chk intrinsics when inlining/const-folding is active); skip it
# on unoptimised debug builds where it would be a no-op.
# Distro flags often set it already (Arch: -Wp,-D_FORTIFY_SOURCE=3); adding
# ours on top triggers "'_FORTIFY_SOURCE' redefined" and could downgrade it.
fortify_preset = (' '.join(get_option('cpp_args')).contains('_FORTIFY_SOURCE')
                  or ' '.join(get_option('c_args')).contains('_FORTIFY_SOURCE'))
if get_option('optimization') not in ['0', 'g'] and not fortify_preset
  foreach a : ['-D_FORTIFY_SOURCE=2']
    if cpp.has_argument(a)
      hardening_cpp_args += [a]
    endif
    if cc.has_argument(a)
      hardening_c_args += [a]
    endif
  endforeach
endif

# PIE compile flags are for executables; this project's security-sensitive
# target is the shared library above (already -fPIC, which subsumes -fPIE
# for a .so). The only executable is the optional test binary
# (tests/meson.build), out of scope here.

# -fvisibility=hidden: safe now that CK_ENTRY expands to
# __attribute__((visibility("default"))) on non-Windows
# (include/opencie/cie_ext.h). Verified empirically: the shared library
# exports exactly the same 88 symbols with and without this flag, so nothing
# in the public ABI is lost. It shrinks the dynamic symbol table and stops
# internal C++/OpenSSL/podofo symbols from being interposable, which matters
# because this .so is dlopen'd into browsers that ship their own copies.
# Windows uses __declspec(dllexport) and needs no equivalent.
if host_machine.system() != 'windows'
  foreach a : ['-fvisibility=hidden']
    if cpp.has_argument(a)
      hardening_cpp_args += [a]
    endif
    if cc.has_argument(a)
      hardening_c_args += [a]
    endif
  endforeach
endif

add_project_arguments(hardening_cpp_args, language: 'cpp')
add_project_arguments(hardening_c_args, language: 'c')

# RELRO/BIND_NOW: GNU ld / lld only. macOS ld64 does not understand -z at
# all; MinGW's ld does not implement RELRO. Applied only to the shared
# library's own link step below (pkcs11_link_args), not project-wide, since
# it is the target this hardening pass is scoped to.
if host_machine.system() != 'darwin' and cpp.has_multi_link_arguments('-Wl,-z,relro', '-Wl,-z,now')
  hardening_link_args += ['-Wl,-z,relro', '-Wl,-z,now']
endif
libdir = meson.current_source_dir() + '/lib'

crypto_dep = dependency('libcrypto')
thread_dep = dependency('threads')

if host_machine.system() == 'windows'
  pcsclite_dep = cpp.find_library('winscard')
  shlwapi_dep = cpp.find_library('shlwapi')
  ws2_32_dep = cpp.find_library('ws2_32')
elif host_machine.system() == 'android'
  # Android uses NFC transport instead of PC/SC
  pcsclite_dep = declare_dependency()
elif host_machine.system() == 'darwin'
  # macOS provides PCSC as a system framework (PCSC.framework)
  pcsclite_dep = dependency('appleframeworks', modules: ['PCSC'])
else
  pcsclite_dep = dependency('libpcsclite', fallback : ['pcsc-lite', 'libpcsclite_dep'])
endif

curl_dep = dependency('libcurl')

# JPEG 2000 decoder for cie_read_photo (DG2 portrait decoding)
openjp2_dep = dependency('libopenjp2', required: false)
if openjp2_dep.found()
  add_project_arguments('-DHAVE_LIBOPENJP2=1', language: 'cpp')
endif

# Library version reported by C_GetInfo (CK_VERSION holds major.minor only).
version_parts = meson.project_version().split('.')
add_project_arguments(
    '-DOPENCIE_VERSION_MAJOR=' + version_parts[0],
    '-DOPENCIE_VERSION_MINOR=' + version_parts[1],
    language: 'cpp',
)

# Sign SDK is available on all platforms (dependencies now built for Android too)
build_sign_sdk = true

if build_sign_sdk
  if host_machine.system() == 'windows' or host_machine.system() == 'android'
    fontconfig_dep = dependency('fontconfig', required: false)
    freetype_dep = dependency('freetype2', required: false)
  else
    fontconfig_dep = dependency('fontconfig')
    freetype_dep = dependency('freetype2')
  endif

  png_dep = dependency('libpng')

  # Discover libxml2 before the libpodofo cmake.subproject so we can forward
  # its include flags into the subproject's compile commands (see below).
  #
  # Portable builds (-Dportable=true) must not pick up a distro libxml2 that
  # was itself built against ICU: recent Debian/Ubuntu (>=24.04 "noble")
  # link their libxml2 package against libicuuc/libicui18n/libicudata,
  # which then leaks into our output as extra dynamic NEEDED entries that
  # are absent on older/other distros (see GH issue #25). Two sources feed
  # libxml2_dep here, in priority order:
  #
  #   1. LIBXML2_STATIC_PREFIX env var: the portable CI job pre-builds
  #      libxml2 from source with ICU disabled and installs it to this
  #      prefix *before* meson runs (see .github/workflows/main.yml). This
  #      is the only path that also fixes the libpodofo cmake.subproject()
  #      below (its own find_package(LibXml2) runs at meson-configure time,
  #      too early to consume a Meson subproject_dep's build output).
  #   2. subprojects/libxml2.wrap: a from-source fallback so a bare
  #      `meson setup -Dportable=true` still configures and still yields a
  #      static, ICU-free libxml2 for this project's own direct uses
  #      (sign-sdk XAdES generation, pkcs11_extra_deps below) even without
  #      the CI bootstrap step. It cannot help libpodofo's XMP support for
  #      the same ordering reason as (1); on a plain local portable build
  #      PoDoFo's libxml2 linkage stays whatever the host's CMake
  #      find_package(LibXml2) resolves to.
  libxml2_static_prefix = ''
  if get_option('portable')
    libxml2_static_prefix = run_command(
      'sh', '-c', 'echo "${LIBXML2_STATIC_PREFIX:-}"', check: false,
    ).stdout().strip()
  endif

  if libxml2_static_prefix != ''
    libxml2_dep = declare_dependency(
      compile_args: ['-I' + libxml2_static_prefix + '/include/libxml2'],
      link_args: [libxml2_static_prefix + '/lib/libxml2.a'],
    )
    xml2_dep = declare_dependency()
  elif get_option('portable')
    libxml2_sub = subproject('libxml2', default_options: [
        'default_library=static',
        'icu=disabled',
        'python=disabled',
        'http=disabled',
        'readline=disabled',
        'history=disabled',
        'docs=disabled',
    ])
    libxml2_dep = libxml2_sub.get_variable('xml_dep')
    xml2_dep = declare_dependency()
  else
    libxml2_dep = dependency('libxml-2.0', required: false)
    xml2_dep = dependency('xml2', required: false)
  endif

  # liblzma is a transitive dep of libtiff (pulled in by podofo >=1.1.0).
  # Declare it here so it is linked when podofo is built as a cmake subproject
  # and libtiff.a is linked statically (portable / cross builds).
  lzma_dep = dependency('liblzma', required: false)

  podofo_dep = dependency('libpodofo', version: '>=1.1.0', required: false,
      include_type: 'system')
  if not podofo_dep.found()
    cmake = import('cmake')
    podofo_opts = cmake.subproject_options()
    # If PKG_CONFIG_LIBDIR points into a vcpkg/custom prefix (e.g. portable
    # builds, cross-compiles), derive CMAKE_PREFIX_PATH from it so that
    # podofo's find_package(ZLIB), find_package(Freetype), etc. resolve
    # against the same prefix rather than the system sysroot.
    pkg_libdir = run_command('sh', '-c', 'echo "${PKG_CONFIG_LIBDIR:-}"',
                             check: false).stdout().strip()
    cmake_prefix = ''
    if pkg_libdir != ''
      # PKG_CONFIG_LIBDIR is typically <prefix>/lib/pkgconfig; strip two levels.
      cmake_prefix = run_command('sh', '-c',
        'echo "$PKG_CONFIG_LIBDIR" | sed "s|/lib/pkgconfig||;s|/lib64/pkgconfig||"',
        check: false).stdout().strip()
    endif

    podofo_cmake_defines = {
      'PODOFO_BUILD_STATIC': true,
      'PODOFO_BUILD_LIB_ONLY': true,
      'CMAKE_POSITION_INDEPENDENT_CODE': true,
      # Silence CMP0156/CMP0179 dev/policy warnings from PoDoFo's own
      # add_library() calls (3rdparty/CMakeLists.txt,
      # src/podofo/CMakeLists.txt, .../private): this is vendored code, so
      # opting into the newer static-library de-duplication behaviour here
      # (rather than patching the vendored CMakeLists.txt) is acceptable
      # and avoids repeated warnings on every configure, on both older
      # CMake (which only knows CMP0156) and newer CMake (which also
      # knows CMP0179; unrecognized CMAKE_POLICY_DEFAULT_CMPxxxx entries
      # are silently ignored by older CMake, so this is safe everywhere).
      'CMAKE_POLICY_DEFAULT_CMP0156': 'NEW',
      'CMAKE_POLICY_DEFAULT_CMP0179': 'NEW',
      # CMake >= 4.2 warns (CMP0200) that NEW would pick a different
      # configuration of imported targets such as LibXml2::LibXml2; keep
      # today's selection explicitly rather than changing what gets linked.
      'CMAKE_POLICY_DEFAULT_CMP0200': 'OLD',
      # Blanket-suppress remaining CMake dev warnings from this vendored
      # subproject only (never applied to our own project-wide CMakeLists).
      'CMAKE_SUPPRESS_DEVELOPER_WARNINGS': true,
    }
    if libxml2_static_prefix != ''
      # Pre-seed CMake's FindLibXml2 cache result variables so
      # find_package(LibXml2 REQUIRED) in PoDoFo's CMakeLists.txt skips its
      # own search and resolves to the same static, ICU-free libxml2 build
      # used above, instead of the distro/vcpkg one it would otherwise find
      # via CMAKE_PREFIX_PATH / pkg-config.
      podofo_cmake_defines += {
        'LIBXML2_INCLUDE_DIR': libxml2_static_prefix + '/include/libxml2',
        'LIBXML2_LIBRARY': libxml2_static_prefix + '/lib/libxml2.a',
      }
    endif
    if cmake_prefix != ''
      podofo_cmake_defines += {
        'CMAKE_PREFIX_PATH': cmake_prefix,
        # CMake 4.x Find* modules require explicit *_ROOT hints when the
        # library lives in a non-system prefix (e.g. vcpkg). Without these,
        # FindZLIB/FindOpenSSL/FindFreetype find the header via CMAKE_PREFIX_PATH
        # but fail to locate the library because the search order changed.
        'ZLIB_ROOT': cmake_prefix,
        'OPENSSL_ROOT_DIR': cmake_prefix,
        'FREETYPE_DIR': cmake_prefix,
        'PNG_ROOT': cmake_prefix,
        'LibLZMA_ROOT': cmake_prefix,
        'LibXml2_ROOT': cmake_prefix,
      }
    endif
    # PoDoFo 1.1.1 makes Fontconfig a hard requirement of the font search
    # mechanism (find_package(Fontconfig REQUIRED)). The Windows (mingw) and
    # Android cross targets don't ship fontconfig, and pulling it via vcpkg
    # drags in a host gperf/autotools chain unavailable on the CI runners.
    # Disable the font manager for these targets; SearchFont() stays available
    # and simply returns null when no search backend is compiled in.
    if host_machine.system() == 'windows' or host_machine.system() == 'android'
      podofo_cmake_defines += {'PODOFO_WITH_FONTMANAGER': false}
    endif
    podofo_opts.add_cmake_defines(podofo_cmake_defines)
    # CMAKE_POSITION_INDEPENDENT_CODE above already makes cmake.subproject()
    # apply Meson's 'pic' kwarg internally; do not also pass '-fPIC' as a
    # manual compile arg, or Meson warns "Use the 'pic' kwarg instead of
    # passing '-fpic' manually" for every podofo_* target.
    podofo_opts.append_compile_args('cpp', '-w')
    podofo_opts.append_compile_args('c', '-w')
    # PoDoFo deliberately gives PdfEncryptContext::m_cryptCtx a different
    # type in PdfEncrypt.cpp (EVP_CIPHER_CTX*) than everywhere else (void*).
    # Under LTO (e.g. Arch's arch-meson: -Db_lto=true) GCC merges those
    # translation units and reports -Wodr. Keep the vendored PoDoFo out of
    # LTO; our own code is still LTO-optimised.
    if cpp.has_argument('-fno-lto')
      podofo_opts.append_compile_args('cpp', '-fno-lto')
    endif
    if cc.has_argument('-fno-lto')
      podofo_opts.append_compile_args('c', '-fno-lto')
    endif

    # Meson's cmake.subproject captures the subproject's own target include
    # directories but does not propagate INTERFACE_INCLUDE_DIRECTORIES of
    # imported find_package() targets (Freetype::Freetype, PNG::PNG,
    # OpenSSL::SSL, ...). Without this, podofo's 3rdparty/afdko fails with
    # 'libxml/tree.h not found' on cross-compiles where the toolchain's
    # default include path doesn't include the dep's headers. Forward
    # include flags from pkg-config (PKG_CONFIG_LIBDIR is set per arch by
    # CI / Containerfile) so the flags reach the actual compile commands.
    #
    # libxml-2.0 is deliberately excluded from this list when
    # libxml2_static_prefix is set: pkg-config would otherwise resolve it
    # to the distro's libxml2-dev package (e.g. /usr/include/libxml2) and
    # that -I ends up on the CXX_FLAGS ahead of the per-target include
    # dirs CMake derives from the LIBXML2_INCLUDE_DIR seed above, so the
    # system 2.9.x headers would win the compiler's search order over the
    # vendored static libxml2 (GH issue #25 follow-up: XMPUtils.cpp failing
    # to find xmlRelaxNGValidCtxtClearErrors from the older system header).
    pkgcfg = find_program('pkg-config', required: false)
    if pkgcfg.found()
      podofo_pkg_deps = [
        'freetype2',
        'libpng',
        'libssl',
        'libcrypto',
        'fontconfig',
      ]
      if libxml2_static_prefix == ''
        podofo_pkg_deps += ['libxml-2.0']
      else
        # Meson drops CMake's interface includes for the imported LibXml2
        # target, so hand the vendored headers to every PoDoFo target.
        xml_inc = '-I' + libxml2_static_prefix + '/include/libxml2'
        podofo_opts.append_compile_args('c', xml_inc)
        podofo_opts.append_compile_args('cpp', xml_inc)
      endif
      foreach pkg : podofo_pkg_deps
        r = run_command(pkgcfg, '--cflags-only-I', pkg, check: false)
        if r.returncode() == 0
          foreach a : r.stdout().strip().split()
            if a != ''
              podofo_opts.append_compile_args('c', a)
              podofo_opts.append_compile_args('cpp', a)
            endif
          endforeach
        endif
      endforeach
    endif

    podofo_sub = cmake.subproject('libpodofo', options: podofo_opts)
    # Treat PoDoFo as a system include for our own targets: PoDoFo 1.1.1
    # headers (e.g. PdfObjectStream.h) trigger -Wunnecessary-virtual-specifier
    # under our -Wall/-Wextra on clang/macOS; system-include suppresses
    # warnings from headers we don't own without touching vendored code.
    podofo_dep = podofo_sub.dependency('podofo_static', include_type: 'system')
  endif
  zlib_dep = dependency('zlib')
endif

inc_shared = include_directories('shared/src/', 'include/')
inc_so = include_directories('pkcs11/src/.', 'shared/src/', 'include/')

inc_a = include_directories(
    'sign-sdk/include',
    'sign-sdk/src',
    'shared/src/',
    'shared/src/util/',
)

# Common dependencies used by both targets
common_deps = [
    crypto_dep,
    pcsclite_dep,
    thread_dep,
    curl_dep,
] + (host_machine.system() == 'windows' ? [shlwapi_dep, ws2_32_dep] : [])

# Android-specific dependencies
if host_machine.system() == 'android'
  common_deps += [cpp.find_library('log')]
endif

# Shared sources compiled once into a static library to avoid duplication
shared_sources = [
    'shared/src/util/crashlytics_stub.cpp',
    'shared/src/util/log.cpp',
    'shared/src/util/func_call_info.cpp',
    'shared/src/util/properties.cpp',
    'shared/src/util/tlv.cpp',
    'shared/src/util/syncro_mutex.cpp',
    'shared/src/util/syncro_event.cpp',
    'shared/src/util/module_info.cpp',
    'shared/src/util/ini_settings.cpp',
    'shared/src/util/cache_lib.cpp',
    'shared/src/util/array.cpp',
    'shared/src/util/util.cpp',
    'shared/src/util/util_exception.cpp',
    'shared/src/pcsc/token.cpp',
    'shared/src/pcsc/pcsc.cpp',
    'shared/src/pcsc/card_locker.cpp',
    'shared/src/pcsc/apdu.cpp',
    'shared/src/pcsc/transport_factory.cpp',
    'shared/src/crypto/sha512.cpp',
    'shared/src/crypto/sha256.cpp',
    'shared/src/crypto/sha1.cpp',
    'shared/src/crypto/rsa.cpp',
    'shared/src/crypto/md5.cpp',
    'shared/src/crypto/mac.cpp',
     'shared/src/crypto/des3.cpp',
     'shared/src/crypto/cipher_base.cpp',
     'shared/src/crypto/base64.cpp',
    'shared/src/crypto/asn_parser.cpp',
    'shared/src/crypto/aes.cpp',
    'shared/src/csp/atr.cpp',
    'shared/src/csp/ext_auth_key.cpp',
    'shared/src/csp/ias.cpp',
]

# Android NFC transport backend (replaces PC/SC on Android)
if host_machine.system() == 'android'
  shared_sources += ['shared/src/pcsc/android_nfc_transport.cpp']
endif

# Linux kernel NFC transport backend (opt-in at runtime for Linux phones;
# PC/SC stays the default on desktop Linux)
if host_machine.system() == 'linux'
  shared_sources += ['shared/src/pcsc/linux_nfc_transport.cpp']
endif

libcie_shared = static_library(
    'cie-shared',
    shared_sources,
    include_directories: inc_shared,
    dependencies: common_deps,
    install: false,
)

cie_pkcs11_sources = [
    'pkcs11/src/pkcs11/session.cpp',
    'pkcs11/src/pkcs11/slot.cpp',
    'pkcs11/src/pkcs11/pkcs11_functions.cpp',
    'pkcs11/src/pkcs11/p11_object.cpp',
    'pkcs11/src/pkcs11/mechanism.cpp',
    'pkcs11/src/pkcs11/card_template.cpp',
    'pkcs11/src/pkcs11/card_context.cpp',
    'pkcs11/src/pkcs11/cie_p11_template.cpp',
    'pkcs11/src/logger/logger.cpp',
    'pkcs11/src/csp/pin_manager.cpp',
    'pkcs11/src/csp/cie_enable.cpp',
    'pkcs11/src/csp/cie_get_certificate.cpp',
    'pkcs11/src/csp/cie_read_chip.cpp',
    # Public C entry points must be compiled into the shared library itself:
    # -Wl,--exclude-libs,ALL demotes every symbol coming from a static
    # archive to local, so cie_classify_sw/cie_last_error would not be
    # exported if this lived in the cie-shared static library.
    'shared/src/csp/cie_error.cpp',
]

# Sign-related sources (require sign SDK; skip on Android)
if build_sign_sdk
  cie_pkcs11_sources += [
      'pkcs11/src/sign/cie_verify.cpp',
      'pkcs11/src/sign/cie_sign.cpp',
      'pkcs11/src/csp/cie_verify_csp.cpp',
      'pkcs11/src/csp/cie_sign_csp.cpp',
      'pkcs11/src/csp/cie_timestamp_csp.cpp',
  ]
endif

cie_sign_sdk_sources = [
    'sign-sdk/src/cie_sign_api.cpp',
    'sign-sdk/src/definitions.cpp',
    'sign-sdk/src/xades_verifier.cpp',
    'sign-sdk/src/xades_generator.cpp',
    'sign-sdk/src/tsa_client.cpp',
    'sign-sdk/src/signer_info_generator.cpp',
    'sign-sdk/src/signed_document.cpp',
    'sign-sdk/src/signed_data_generator_ex.cpp',
    'sign-sdk/src/signature_generator.cpp',
    'sign-sdk/src/pdf_verifier.cpp',
    'sign-sdk/src/pdf_signature_generator.cpp',
    'sign-sdk/src/m7m_parser.cpp',
    'sign-sdk/src/counter_signature_generator.cpp',
    'sign-sdk/src/cert_store.cpp',
    'sign-sdk/src/cie_signer.cpp',
    'sign-sdk/src/digest_info.c',
    'sign-sdk/src/big_unsigned_in_a_base.cpp',
    'sign-sdk/src/big_unsigned.cpp',
    'sign-sdk/src/big_integer_utils.cpp',
    'sign-sdk/src/big_integer_algorithms.cpp',
    'sign-sdk/src/big_integer.cpp',
    'sign-sdk/src/asn1/buffered_reader.cpp',
    'sign-sdk/src/asn1/time_stamp_token.cpp',
    'sign-sdk/src/asn1/time_stamp_response.cpp',
    'sign-sdk/src/asn1/time_stamp_request.cpp',
    'sign-sdk/src/asn1/time_stamp_data.cpp',
    'sign-sdk/src/asn1/tst_info.cpp',
    'sign-sdk/src/asn1/subject_public_key_info.cpp',
    'sign-sdk/src/asn1/signer_info.cpp',
    'sign-sdk/src/asn1/signed_data.cpp',
    'sign-sdk/src/asn1/relative_distinguished_name.cpp',
    'sign-sdk/src/asn1/rsa_public_key.cpp',
    'sign-sdk/src/asn1/rsa_private_key.cpp',
    'sign-sdk/src/asn1/pki_status_info.cpp',
    'sign-sdk/src/asn1/ocsp_request.cpp',
    'sign-sdk/src/asn1/name.cpp',
    'sign-sdk/src/asn1/issuer_and_serial_number.cpp',
    'sign-sdk/src/asn1/digest_info.cpp',
    'sign-sdk/src/asn1/crl.cpp',
    'sign-sdk/src/asn1/content_type.cpp',
    'sign-sdk/src/asn1/content_info.cpp',
    'sign-sdk/src/asn1/certificate_info.cpp',
    'sign-sdk/src/asn1/certificate.cpp',
    'sign-sdk/src/asn1/algorithm_identifier.cpp',
    'sign-sdk/src/asn1/asn1_utc_time.cpp',
    'sign-sdk/src/asn1/asn1_set_of.cpp',
    'sign-sdk/src/asn1/asn1_sequence.cpp',
    'sign-sdk/src/asn1/asn1_optional_field.cpp',
    'sign-sdk/src/asn1/asn1_octet_string.cpp',
    'sign-sdk/src/asn1/asn1_object_identifier.cpp',
    'sign-sdk/src/asn1/asn1_object.cpp',
    'sign-sdk/src/asn1/asn1_null.cpp',
    'sign-sdk/src/asn1/asn1_integer.cpp',
    'sign-sdk/src/asn1/asn1_generic_sequence.cpp',
    'sign-sdk/src/asn1/asn1_boolean.cpp',
    'sign-sdk/src/asn1/asn1_bit_string.cpp',
]

if build_sign_sdk
  libcie_sign_sdk = static_library(
      'opencie-sign-sdk',
      cie_sign_sdk_sources,
      include_directories: inc_a,
      link_with: libcie_shared,
      dependencies: common_deps + [
          libxml2_dep,
          fontconfig_dep,
          freetype_dep,
          png_dep,
          podofo_dep,
          xml2_dep,
          zlib_dep,
      ],
      install: false,
  )
endif

# Hide all internal symbols from statically linked libraries and only export
# the PKCS#11 C_* functions + CIE-specific public API (cie_enable, etc.).
# Without this, 1500+ OpenSSL/PoDoFo symbols leak into the global
# namespace and collide with the host application's own imports (e.g. Firefox).
pkcs11_link_args = hardening_link_args
pkcs11_link_depends = []

# Version script / exported symbols: export only public API, hide everything else
if host_machine.system() == 'darwin'
  # macOS uses -exported_symbols_list (different format from Linux version scripts)
  exports_file = meson.current_source_dir() / 'linker/libopencie-pkcs11.exp'
  if cpp.has_link_argument('-Wl,-exported_symbols_list,' + exports_file)
    pkcs11_link_args += ['-Wl,-exported_symbols_list,' + exports_file]
    pkcs11_link_depends = files('linker/libopencie-pkcs11.exp')
  endif
elif host_machine.system() != 'windows'
  # Linux/BSD/Android use version scripts
  version_script = meson.current_source_dir() / 'linker/libopencie-pkcs11.map'
  vs_arg = '-Wl,--version-script=' + version_script
  if cpp.has_link_argument(vs_arg)
    pkcs11_link_args += [vs_arg]
    pkcs11_link_depends = files('linker/libopencie-pkcs11.map')
  elif cpp.has_multi_link_arguments(vs_arg, '-Wl,--undefined-version')
    # Android NDK's lld requires --undefined-version for the meson check
    # (lld errors on version script symbols missing in the test binary)
    pkcs11_link_args += [vs_arg, '-Wl,--undefined-version']
    pkcs11_link_depends = files('linker/libopencie-pkcs11.map')
  endif
endif

# Hide symbols from statically linked archives (.a files).
# NOTE: --exclude-libs,ALL conflicts with lld (used by Android NDK) which
# makes the demotion unconditional — even --dynamic-list cannot override it.
# On Android, the version script's `local: *;` is sufficient to hide all
# unwanted symbols, so we skip --exclude-libs there.
if host_machine.system() != 'android' and cpp.has_link_argument('-Wl,--exclude-libs,ALL')
  pkcs11_link_args += ['-Wl,--exclude-libs,ALL']
endif

# For portable builds: statically link libstdc++ and libgcc to avoid
# runtime dependency on specific GCC versions across distros.
# Enable with: meson setup -Dportable=true
if get_option('portable')
  pkcs11_link_args += ['-static-libstdc++', '-static-libgcc']
endif

# Conditional link targets and dependencies based on platform
if build_sign_sdk
  pkcs11_link_with = [libcie_sign_sdk, libcie_shared]
  pkcs11_extra_deps = [libxml2_dep, fontconfig_dep, freetype_dep, png_dep, xml2_dep, lzma_dep, openjp2_dep]
  # cie_timestamp_csp.cpp needs tsa_client.h from sign-sdk
  pkcs11_inc = [inc_so, include_directories('sign-sdk/include', 'sign-sdk/src')]
else
  pkcs11_link_with = [libcie_shared]
  pkcs11_extra_deps = [openjp2_dep]
  pkcs11_inc = [inc_so]
endif

library_version = {}
if host_machine.system() != 'windows'
  library_version = {
    'version': meson.project_version(),
    'soversion': '1',
  }
endif

libopencie_pkcs11 = library(
    'opencie-pkcs11',
    cie_pkcs11_sources,
    include_directories: pkcs11_inc,
    link_with: pkcs11_link_with,
    dependencies: common_deps + pkcs11_extra_deps,
    link_args: pkcs11_link_args,
    link_depends: pkcs11_link_depends,
    kwargs: library_version,
    install: true,
)

install_headers(
    'include/opencie/cie_ext.h',
    subdir: 'opencie',
)

pkg = import('pkgconfig')
pkg.generate(
    libopencie_pkcs11,
    name: 'opencie-pkcs11',
    filebase: 'opencie-pkcs11',
    description: 'PKCS#11 module for the Italian electronic ID card (CIE)',
    version: meson.project_version(),
)

if get_option('tests')
    subdir('tests')
endif
