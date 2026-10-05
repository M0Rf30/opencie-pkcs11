catch2_dep = dependency(
    'catch2-with-main',
    fallback: ['catch2', 'catch2_with_main_dep'],
    default_options: ['tests=false'],
)

test_inc = include_directories(
    '../shared/src/', '../pkcs11/src/', '../include',
    '../sign-sdk/include', '../sign-sdk/src',
)

test_sources = [
    'test_array.cpp',
    'test_array_extended.cpp',
    'test_tlv.cpp',
    'test_crypto.cpp',
    'test_crypto_util.cpp',
    'test_cache_lib.cpp',
    'test_md5.cpp',
    'test_asn_parser.cpp',
    'test_asn_tag.cpp',
    'test_padding.cpp',
    'test_util.cpp',
    'test_properties.cpp',
    'test_ini_settings.cpp',
    'test_pcsc_reader_monitor.cpp',
    'test_cie_error.cpp',
    'test_card_link_retry.cpp',
    'test_atr.cpp',
    'test_aes.cpp',
    'test_des3.cpp',
    'test_mac.cpp',
    'test_rsa.cpp',
    'test_pace.cpp',
]

# Sign SDK ASN.1/certificate tests (AKI/SKI extraction, embedded CIE CA
# set): built as a separate executable so the main opencie-tests binary
# does not have to link the full PoDoFo/libxml2 dependency chain that
# libcie_sign_sdk pulls in.
sign_sdk_test_sources = [
    'test_certificate_key_ids.cpp',
    'sign_sdk_test_stubs.cpp',
    '../pkcs11/src/logger/logger.cpp',
]

# Sources needed by tests (no PCSC/hardware deps)
test_shared_sources = [
    '../shared/src/util/array.cpp',
    '../shared/src/util/cache_lib.cpp',
    '../shared/src/util/log.cpp',
    '../shared/src/util/func_call_info.cpp',
    '../shared/src/util/properties.cpp',
    '../shared/src/util/module_info.cpp',
    '../shared/src/util/ini_settings.cpp',
    '../shared/src/util/util.cpp',
    '../shared/src/util/util_exception.cpp',
    '../shared/src/csp/cie_error.cpp',
    '../shared/src/pcsc/token.cpp',
    '../shared/src/pcsc/apdu.cpp',
    '../shared/src/csp/atr.cpp',
    '../shared/src/util/tlv.cpp',
    '../shared/src/util/crashlytics_stub.cpp',
    '../shared/src/pcsc/pcsc.cpp',
    '../pkcs11/src/logger/logger.cpp',
    '../shared/src/crypto/base64.cpp',
    '../shared/src/crypto/sha1.cpp',
    '../shared/src/crypto/sha256.cpp',
    '../shared/src/crypto/sha512.cpp',
    '../shared/src/crypto/md5.cpp',
    '../shared/src/crypto/asn_parser.cpp',
    '../shared/src/crypto/cipher_base.cpp',
    '../shared/src/crypto/aes.cpp',
    '../shared/src/crypto/des3.cpp',
    '../shared/src/crypto/mac.cpp',
    '../shared/src/crypto/rsa.cpp',
    '../shared/src/csp/pace.cpp',
]

# Linux kernel NFC backend (ATR synthesis is pure logic, no hardware needed)
if host_machine.system() == 'linux'
  test_sources += ['test_linux_nfc_atr.cpp']
  test_shared_sources += ['../shared/src/pcsc/linux_nfc_transport.cpp']
endif

if build_sign_sdk
  sign_sdk_test_exe = executable(
      'opencie-sign-sdk-tests',
      sign_sdk_test_sources,
      include_directories: test_inc,
      link_with: [libcie_sign_sdk, libcie_shared],
      dependencies: [
          catch2_dep,
          crypto_dep,
          thread_dep,
          pcsclite_dep,
          curl_dep,
          libxml2_dep,
          fontconfig_dep,
          freetype_dep,
          png_dep,
          podofo_dep,
          xml2_dep,
          zlib_dep,
      ] + (host_machine.system() == 'windows' ? [shlwapi_dep] : []),
  )

  test('opencie sign-sdk unit tests', sign_sdk_test_exe)
endif

# IAS PIN-composition tests (OC-28): link directly against libcie_shared
# instead of adding shared/src/csp/ias.cpp + its dependency chain to
# test_shared_sources, the same rationale as the sign-sdk tests above.
# sign_sdk_test_stubs.cpp stubs the same UI/cert-store glue symbols
# shared/src/csp/ias.cpp calls into, for the same reason (see its header
# comment) — avoids dragging in cie_p11_template.cpp/cie_enable.cpp.
ias_pin_test_exe = executable(
    'opencie-ias-pin-tests',
    ['test_ias_pin.cpp', 'sign_sdk_test_stubs.cpp', '../pkcs11/src/logger/logger.cpp'],
    include_directories: test_inc,
    link_with: [libcie_shared],
    dependencies: [
        catch2_dep,
        crypto_dep,
        thread_dep,
        pcsclite_dep,
        curl_dep,
    ] + (host_machine.system() == 'windows' ? [shlwapi_dep, ws2_32_dep] : []),
)

test('opencie IAS PIN composition tests', ias_pin_test_exe)

test_exe = executable(
    'opencie-tests',
    test_sources + test_shared_sources,
    include_directories: test_inc,
    dependencies: [
        catch2_dep,
        crypto_dep,
        thread_dep,
        pcsclite_dep,
    ] + (host_machine.system() == 'windows' ? [shlwapi_dep] : []),
)

test('opencie unit tests', test_exe)

# Black-box test: dlopen() the built module like NSS/p11-kit do. Linux only:
# PCSCLITE_CSOCK_NAME is a pcsc-lite feature, and pointing it at a missing
# socket reproduces "pcscd not running" without touching the host daemon.
if host_machine.system() == 'linux' and get_option('default_library') != 'static'
  module_test_exe = executable(
      'opencie-module-tests',
      'test_pkcs11_module.cpp',
      include_directories: test_inc,
      dependencies: [
          catch2_dep,
          cpp.find_library('dl', required: false),
      ],
  )
  test(
      'opencie module load (no pcscd)',
      module_test_exe,
      depends: libopencie_pkcs11,
      env: {
          'OPENCIE_MODULE': libopencie_pkcs11.full_path(),
          'PCSCLITE_CSOCK_NAME': meson.current_build_dir() / 'no-pcscd.comm',
      },
  )
endif
