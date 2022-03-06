project(
    'libopencie-pkcs11',
    'cpp',
    'c',
    version: '1.5.9',
    license: 'GPL-2.0-or-later',
    default_options: [
        'cpp_std=c++17',
        'warning_level=2',
    ],
)

if host_machine.system() != 'windows'
  add_project_arguments('-fPIC', language: 'cpp')
else
  # Force-include the byte ambiguity fix header for MinGW builds.
  # This resolves the std::byte vs rpcndr.h byte conflict when
  # "using namespace std;" is present in headers.
  mingw_byte_fix = join_paths(meson.current_source_dir(), 'shared/src/mingw_byte_fix.h')
  add_project_arguments('-include', mingw_byte_fix, language: 'cpp')
endif

cpp = meson.get_compiler('cpp')
libdir = meson.current_source_dir() + '/lib'

crypto_dep = dependency('libcrypto')
thread_dep = dependency('threads')

# Crypto++ is packaged under different names depending on the distro/vcpkg.
# Try all known names and use whichever is found.
cryptopp_dep = dependency('libcrypto++', required: false)
if not cryptopp_dep.found()
  cryptopp_dep = dependency('libcryptopp', required: false)
endif
if not cryptopp_dep.found()
  cryptopp_dep = dependency('cryptopp', required: false)
endif

if host_machine.system() == 'windows'
  pcsclite_dep = cpp.find_library('winscard')
  shlwapi_dep = cpp.find_library('shlwapi')
  version_dep = cpp.find_library('version', required: false)
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

# Sign SDK dependencies (not available/needed on Android)
build_sign_sdk = host_machine.system() != 'android'

if build_sign_sdk
  if host_machine.system() != 'windows'
    fontconfig_dep = dependency('fontconfig')
    freetype_dep = dependency('freetype2')
  else
    fontconfig_dep = dependency('fontconfig', required: false)
    freetype_dep = dependency('freetype2', required: false)
  endif

  png_dep = dependency('libpng')
  podofo_dep = dependency('libpodofo', version: '>=1.0.0', required: false)
  if not podofo_dep.found()
    podofo_dep = dependency('libpodofo', fallback: ['libpodofo', 'podofo_shared_dep'])
  endif
  libxml2_dep = dependency('libxml-2.0', required: false)
  xml2_dep = dependency('xml2', required: false)
  zlib_dep = dependency('zlib')
endif

inc_shared = include_directories('shared/src/')
inc_so = include_directories('pkcs11/src/.', 'shared/src/')

inc_a = include_directories(
    'sign-sdk/include',
    'sign-sdk/src',
    'shared/src/',
    'shared/src/Util/',
)

# Common dependencies used by both targets
common_deps = [
    crypto_dep,
    cryptopp_dep,
    pcsclite_dep,
    thread_dep,
    curl_dep,
] + (host_machine.system() == 'windows' ? [shlwapi_dep] : [])

# Android-specific dependencies
if host_machine.system() == 'android'
  common_deps += [cpp.find_library('log')]
endif

# Shared sources compiled once into a static library to avoid duplication
shared_sources = [
    'shared/src/Util/log.cpp',
    'shared/src/Util/func_call_info.cpp',
    'shared/src/Util/text_file_reader.cpp',
    'shared/src/Util/string_table.cpp',
    'shared/src/Util/properties.cpp',
    'shared/src/Util/byte_array.cpp',
    'shared/src/Util/tlv.cpp',
    'shared/src/Util/syncro_mutex.cpp',
    'shared/src/Util/syncro_event.cpp',
    'shared/src/Util/module_info.cpp',
    'shared/src/Util/ini_settings.cpp',
    'shared/src/Util/cryptopp_utils.cpp',
    'shared/src/Util/cache_lib.cpp',
    'shared/src/Util/array.cpp',
    'shared/src/Util/util.cpp',
    'shared/src/Util/util_exception.cpp',
    'shared/src/pcsc/token.cpp',
    'shared/src/pcsc/pcsc.cpp',
    'shared/src/pcsc/card_locker.cpp',
    'shared/src/pcsc/apdu.cpp',
    'shared/src/crypto/sha512.cpp',
    'shared/src/crypto/sha256.cpp',
    'shared/src/crypto/sha1.cpp',
    'shared/src/crypto/rsa.cpp',
    'shared/src/crypto/md5.cpp',
    'shared/src/crypto/mac.cpp',
    'shared/src/crypto/des3.cpp',
    'shared/src/crypto/base64.cpp',
    'shared/src/crypto/asn_parser.cpp',
    'shared/src/crypto/aes.cpp',
    'shared/src/crypto/cryptopp_clang_shim.cpp',
    'shared/src/csp/atr.cpp',
    'shared/src/csp/ext_auth_key.cpp',
    'shared/src/csp/ias.cpp',
]

# Android NFC transport backend (replaces PC/SC on Android)
if host_machine.system() == 'android'
  shared_sources += ['shared/src/pcsc/AndroidNFCTransport.cpp']
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
]

# Sign-related sources (require sign SDK; skip on Android)
if build_sign_sdk
  cie_pkcs11_sources += [
      'pkcs11/src/sign/cie_verify.cpp',
      'pkcs11/src/sign/cie_sign.cpp',
      'pkcs11/src/csp/cie_verify_csp.cpp',
      'pkcs11/src/csp/cie_sign_csp.cpp',
  ]
endif

cie_sign_sdk_sources = [
    'sign-sdk/src/disigonsdk.cpp',
    'sign-sdk/src/definitions.cpp',
    'sign-sdk/src/xades_verifier.cpp',
    'sign-sdk/src/xades_generator.cpp',
    'sign-sdk/src/text_file_writer.cpp',
    'sign-sdk/src/uuc_logger.cpp',
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
      'cie-sign-sdk',
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
# Without this, 1500+ CryptoPP/OpenSSL/PoDoFo symbols leak into the global
# namespace and collide with the host application's own imports (e.g. Firefox).
pkcs11_link_args = []
pkcs11_link_depends = []

# Version script / exported symbols: export only public API, hide everything else
if host_machine.system() == 'darwin'
  # macOS uses -exported_symbols_list (different format from Linux version scripts)
  exports_file = meson.current_source_dir() / 'libopencie-pkcs11.exp'
  if cpp.has_link_argument('-Wl,-exported_symbols_list,' + exports_file)
    pkcs11_link_args += ['-Wl,-exported_symbols_list,' + exports_file]
    pkcs11_link_depends = files('libopencie-pkcs11.exp')
  endif
elif host_machine.system() != 'windows'
  # Linux/BSD/Android use version scripts
  version_script = meson.current_source_dir() / 'libopencie-pkcs11.map'
  vs_arg = '-Wl,--version-script=' + version_script
  if cpp.has_link_argument(vs_arg)
    pkcs11_link_args += [vs_arg]
    pkcs11_link_depends = files('libopencie-pkcs11.map')
  elif cpp.has_multi_link_arguments(vs_arg, '-Wl,--undefined-version')
    # Android NDK's lld requires --undefined-version for the meson check
    # (lld errors on version script symbols missing in the test binary)
    pkcs11_link_args += [vs_arg, '-Wl,--undefined-version']
    pkcs11_link_depends = files('libopencie-pkcs11.map')
  endif
endif

# Hide symbols from statically linked archives (.a files)
if cpp.has_link_argument('-Wl,--exclude-libs,ALL')
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
  pkcs11_extra_deps = [libxml2_dep, fontconfig_dep, freetype_dep, png_dep, xml2_dep]
else
  pkcs11_link_with = [libcie_shared]
  pkcs11_extra_deps = []
endif

libopencie_pkcs11 = library(
    'opencie-pkcs11',
    cie_pkcs11_sources,
    include_directories: inc_so,
    link_with: pkcs11_link_with,
    dependencies: common_deps + pkcs11_extra_deps,
    link_args: pkcs11_link_args,
    link_depends: pkcs11_link_depends,
    install: true,
)
