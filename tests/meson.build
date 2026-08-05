catch2_dep = dependency(
    'catch2-with-main',
    fallback: ['catch2', 'catch2_with_main_dep'],
    default_options: ['tests=false'],
)

test_inc = include_directories('../shared/src/', '../pkcs11/src/', '../include')

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
]

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
