# Repository Guidelines

## Project Overview

OpenCIE-PKCS11 is a cross-platform C++20 shared library implementing the PKCS#11 v2.40 cryptographic token interface for the Italian CIE (Carta d'Identita Elettronica) smart card. It also provides a signing SDK for PDF (CAdES/PAdES), XAdES XML, and PKCS#7/CMS signatures with RFC 3161 timestamping.

Single output artifact: `libopencie-pkcs11.so` (or `.dll`/`.dylib`), assembled from three internal static libraries. License: LGPL-3.0-or-later.

## Architecture & Data Flow

### Module Layering

```
libopencie-pkcs11 (shared)
  ├── pkcs11/    ← PKCS#11 C API surface + CIE card service provider
  ├── sign-sdk/  ← PDF/XAdES/CAdES signing + verification (static)
  └── shared/    ← crypto, PC/SC, IAS protocol, utilities (static)
```

All three are statically linked into the single shared library. Symbol visibility is controlled by linker scripts (`linker/libopencie-pkcs11.map` on Linux/Android, `.exp` on macOS) — only `C_*` PKCS#11 functions and `cie_*` extensions are exported. Everything else (OpenSSL, PoDoFo, libxml2 internals) is hidden to prevent symbol collisions with host applications.

### Call Flow: PKCS#11 API to Smart Card

```
C_* function (pkcs11_functions.cpp)
  → pkcs11_guard (exception→CK_RV)
    → CSession → CSlot → CCardTemplate callbacks (TemplateFuncList)
      → CIEtemplate* implementations (cie_p11_template.cpp)
        → IAS protocol (shared/src/csp/ias.cpp) — PACE, Secure Messaging, APDU construction
          → PC/SC layer (safeConnection/safeTransaction → CToken → SmartCardTransport)
            → physical card (SCardTransmit)
```

### Signing Flow

- **PDF**: bytes → PoDoFo `PdfMemDocument` → `PdfSignature` field placed → `CIEPdfSigner::ComputeSignature()` → `CSignatureGenerator::Generate()` → PKCS#7 embedded in `/Contents`
- **XAdES**: XML → libxml2 parse → QualifyingProperties + SignedInfo → C14N canonicalize → RSA sign → ds:Signature element
- **CAdES**: data → `CSignatureGenerator::Generate()` → SignerInfo + SignedData + optional TimeStampToken (RFC 3161)

### Thread Safety

A single global `p11Mutex` (`std::mutex`) guards every `C_*` entry point. A background monitor thread watches PC/SC readers for card insertion/removal, acquiring the same mutex for slot updates. No session-level locking — per PKCS#11 spec, the application serializes per-session access.

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `pkcs11/src/pkcs11/` | PKCS#11 C API (69 functions), session/slot/mechanism/object model |
| `pkcs11/src/csp/` | CIE card service: enrollment, PIN management, cert retrieval, signing |
| `pkcs11/src/sign/` | High-level signing wrappers delegating to sign-sdk |
| `pkcs11/src/logger/` | Structured logging (file/console/Android logcat) |
| `shared/src/crypto/` | Crypto wrappers: RSA (EVP_PKEY), AES-CBC, 3DES-CBC, SHA-*, MD5, MAC, Base64, ASN.1 TLV parser |
| `shared/src/csp/` | IAS smart card protocol: PACE, DH key exchange, Secure Messaging, APDU |
| `shared/src/pcsc/` | PC/SC abstraction: RAII handles, APDU transmission, reader monitoring, Android NFC transport |
| `shared/src/util/` | ByteArray/ByteDynArray, exceptions, cache encryption, logging macros, sync primitives |
| `shared/src/pkcs11/` | Vendored PKCS#11 v2.x spec headers (cryptoki.h, pkcs11t.h, pkcs11f.h) |
| `sign-sdk/src/asn1/` | Hand-rolled ASN.1 codec for CMS/PKCS#7 (OIDs, X.509, SignerInfo, SignedData) |
| `sign-sdk/src/` | Signature generators (PDF/XAdES/CAdES), verification, TSA client, cert store |
| `tests/` | Catch2 v3 unit tests |
| `toolchains/` | 6 Meson cross-compilation `.ini` files |
| `linker/` | Symbol visibility scripts (.map for Linux/Android, .exp for macOS) |

## Development Commands

```bash
# Configure (default: tests=true, portable=false)
meson setup build

# Build
meson compile -C build

# Run all tests
meson test -C build
# or directly:
./build/tests/opencie-tests

# Run tests by tag
./build/tests/opencie-tests "[base64]"
./build/tests/opencie-tests "[cache]"

# Run with sanitizers (as CI does)
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
meson test -C build-asan

# Cross-compile for aarch64
meson setup build-arm64 --cross-file toolchains/cross-aarch64.ini
meson compile -C build-arm64

# Cross-compile for Windows (MinGW)
meson setup build-win --cross-file toolchains/cross-clang-mingw.ini
meson compile -C build-win

# Cross-compile for Android arm64
meson setup build-android --cross-file toolchains/cross-android-arm64.ini
meson compile -C build-android

# Portable build (static libstdc++/libgcc)
meson setup build-portable -Dportable=true

# Clean
rm -rf build
```

## Code Conventions & Common Patterns

### Formatting

Google-style via `.clang-format`: 80-column limit, 2-space indent, `BreakBeforeBraces: Attach`, `PointerAlignment: Left`, `IncludeBlocks: Regroup`. Enforced by pre-commit hook (clang-format v19.1.7).

### Naming

| Element | Convention | Examples |
|---------|-----------|----------|
| Classes | `CClassName` prefix | `CRSA`, `CAES`, `CSession`, `CSlot`, `CASNParser` |
| PKCS#11 objects | `CP11*` prefix | `CP11Certificate`, `CP11PrivateKey` |
| Template callbacks | `CIEtemplate*` | `CIEtemplateLogin`, `CIEtemplateSign` |
| Functions | lowercase or camelCase | `readfile`, `SendAPDU`, `CardAuthenticateEx` |
| Files | `lowercase_with_underscores` | `cache_lib.cpp`, `asn_parser.h` |
| Constants/macros | `SCREAMING_SNAKE_CASE` | `ENCRYPTION_KEY`, `AES_BLOCK_SIZE`, `LOG_ERR` |
| PKCS#11 types | `CK_*` (spec-defined) | `CK_RV`, `CK_SESSION_HANDLE`, `CKA_VALUE` |
| Member variables | no prefix, camelCase or `_prefix` for ByteArray internals | `sessENC`, `hSlot`, `_data`, `_size` |

### Error Handling

```
std::runtime_error
  └── logged_error        ← logs via LOG_ERR on construction (util_exception.h)
        ├── scard_error   ← carries ISO 7816 StatusWord (0x9000, 0x6300, etc.)
        └── windows_error ← wraps HRESULT
```

- PKCS#11 layer: `p11_error(CK_RV)` caught by `pkcs11_guard` → converted to CK_RV return code
- Assertion macro: `ER_ASSERT(condition, message)` throws `logged_error` on false
- Sign-SDK: `__TRY/__CATCH` macros catch multiple types, return `CIE_SIGN_ERROR_UNEXPECTED`
- **Never throw raw integers.** Legacy `throw -1` was removed; use `std::runtime_error` or `logged_error`.

### Memory & Buffer Patterns

- **ByteArray**: non-owning view (pointer + size), zero-copy slicing. Defined in `shared/src/util/array.h`.
- **ByteDynArray**: owning heap buffer (`new[]`/`delete[]`), RAII. Deep-copy on construction/assignment, move semantics supported.
- **OpenSSL cleanup**: `OPENSSL_cleanse()` on keys, IVs, PINs, session keys. EVP contexts freed via `EVP_*_CTX_free()` on all paths.
- **RAII wrappers**: `std::unique_ptr<X509, decltype(&X509_free)>` for OpenSSL objects, `PinCleanser` for PIN buffers, `safeConnection`/`safeTransaction` for PC/SC handles.
- **ASN.1 trees**: `unique_ptr<CASNTag>` ownership in `CASNTagArray`.

### Platform Abstractions

- `#ifdef _WIN32` / `#else` for: symbol export (`__declspec(dllexport)` vs `__attribute__((visibility))`), DllMain, WinSCard vs libpcsclite, user directories, process spawning
- `#ifdef __ANDROID__`: NFC transport via JNI, logcat logging
- Toolchain `.ini` files handle cross-compilation flags (`-DNOMINMAX`, `-fpermissive` for MinGW)

### Include Conventions

- `#pragma once` (no `#ifndef` guards)
- Order: system/OpenSSL headers first, then project headers (`"crypto/"`, `"util/"`, `"csp/"`)
- Headers are self-contained (include their own dependencies)

### Key Typedefs

| Type | Definition | Source |
|------|-----------|--------|
| `StatusWord` | `uint16_t` (ISO 7816 SW1-SW2) | `definitions.h` |
| `DWORD` | `unsigned long` / `uint32_t` | `definitions.h` |
| `BYTE` | `uint8_t` | `definitions.h` |
| `ByteArray` | non-owning `uint8_t*` + `size_t` | `array.h` |
| `ByteDynArray` | owning heap `uint8_t[]` | `array.h` |

## Important Files

| File | Role |
|------|------|
| `pkcs11/src/pkcs11/pkcs11_functions.cpp` | PKCS#11 C API entry point (69 `C_*` functions), `pkcs11_guard`, `PinCleanser`, global mutex |
| `pkcs11/src/pkcs11/session.cpp` | Session state, operation dispatch (sign/verify/digest) |
| `pkcs11/src/pkcs11/slot.cpp` | Slot management, card monitor thread, ATR matching |
| `pkcs11/src/pkcs11/card_template.h` | `TemplateFuncList` — 24-callback plugin interface for card backends |
| `pkcs11/src/pkcs11/cie_p11_template.cpp` | CIE card template: cert parsing (`GetCertInfo`), object enumeration, login, signing |
| `pkcs11/src/pkcs11/mechanism.cpp` | `CDigest`/`CSign`/`CVerify` hierarchies (SHA, RSA PKCS#1, RSA X.509) |
| `pkcs11/src/csp/cie_enable.cpp` | Card enrollment, process spawning (`posix_spawn`/`CreateProcessA`) |
| `pkcs11/src/csp/pin_manager.cpp` | External PIN change/unblock API |
| `shared/src/crypto/crypto_util.h` | AES-128-CBC cache encrypt/decrypt (CIE1 header format, legacy zero-IV compat) |
| `shared/src/crypto/rsa.cpp` | `CRSA`: OpenSSL 3.0 EVP_PKEY RSA (raw modexp + PSS-SHA512 verify) |
| `shared/src/csp/ias.cpp` | IAS protocol: PACE, DH, Secure Messaging, APDU construction |
| `shared/src/pcsc/pcsc.cpp` | `safeConnection`, `safeTransaction`, `readerMonitor` |
| `shared/src/util/array.h` | `ByteArray` / `ByteDynArray` definitions |
| `shared/src/util/cache_lib.cpp` | On-disk certificate/PIN cache (AES-encrypted) |
| `shared/src/util/util_exception.h` | `logged_error`, `scard_error`, `windows_error` |
| `shared/src/util/openssl_utils.cpp` | Hex, Base64, UUID helpers (OpenSSL-backed) |
| `sign-sdk/src/cie_sign_api.cpp` | Public C API for signing (`CIESignOpen`, `CIESign`, `CIEVerify`) |
| `sign-sdk/src/signature_generator.cpp` | CAdES/PKCS#7 signature generation |
| `sign-sdk/src/pdf_signature_generator.cpp` | PDF signature placement via PoDoFo |
| `sign-sdk/src/xades_generator.cpp` | XAdES XML signing via libxml2 |
| `meson.build` | Root build config: dependencies, targets, linker flags |
| `linker/libopencie-pkcs11.map` | Exported symbol list (Linux/Android) |
| `.clang-format` | Code style rules |
| `.pre-commit-config.yaml` | Pre-commit hooks config |

## Runtime/Tooling Preferences

| Aspect | Choice |
|--------|--------|
| Language | C++20 (`-std=c++20`) |
| Build system | Meson >= 0.56 + Ninja |
| Crypto | OpenSSL 3.x (`libcrypto`) — no Crypto++ |
| Smart card | PC/SC (libpcsclite on Linux, WinSCard on Windows, PCSC.framework on macOS) |
| PDF | PoDoFo >= 1.1.0 |
| XML | libxml2 |
| HTTP | libcurl (OCSP, CRL, TSA) |
| Image | libopenjp2 (optional), libpng, freetype2, fontconfig, zlib |
| Formatter | clang-format v19.1.7 (Google-based, 80-col) |
| Static analysis | cppcheck (pre-commit), CodeQL + Semgrep (CI) |
| Pre-commit | trailing-whitespace, end-of-file-fixer, check-yaml, check-merge-conflict, mixed-line-ending (LF), clang-format, cppcheck |

### Cross-Compilation Targets

| Toolchain file | Target |
|---------------|--------|
| `cross-aarch64.ini` | Linux aarch64 (GCC) |
| `cross-clang-aarch64.ini` | Linux aarch64 (Clang) |
| `cross-mingw.ini` | Windows x86_64 (MinGW-w64 GCC) |
| `cross-clang-mingw.ini` | Windows x86_64 (Clang + MinGW sysroot) |
| `cross-android-arm64.ini` | Android arm64-v8a (NDK r27c, API 28) |
| `cross-android-x86_64.ini` | Android x86_64 (NDK r27c, API 28) |

## Testing & QA

- **Framework**: Catch2 v3.14.0 (with Meson subproject fallback)
- **Test executable**: `tests/opencie-tests`
- **Test files** (11): `test_array`, `test_tlv`, `test_crypto`, `test_cache_lib`, `test_md5`, `test_asn_parser`, `test_padding`, `test_ini_settings`, `test_properties`, `test_util`, `test_crypto_util`
- **Run**: `meson test -C build` or `./build/tests/opencie-tests`
- **Tags**: `./build/tests/opencie-tests "[base64]"`, `"[cache]"`, `"[crypto]"`, etc.
- **CI sanitizers**: AddressSanitizer + UBSan (`-Db_sanitize=address,undefined`), with `lsan-suppressions.txt`
- **CI static analysis**: clang `scan-build`, cppcheck, CodeQL, Semgrep (p/default + p/c rulesets)

### Writing Tests

- Tests live in `tests/test_*.cpp`, one file per module
- Use Catch2 `TEST_CASE` + `SECTION` structure with descriptive string tags
- Test the shared library's internal units directly (crypto, cache, parsing) — no smart card hardware needed
- Follow existing patterns: `#include <catch2/catch_test_macros.hpp>`, `CHECK`/`REQUIRE` assertions
- RAII test fixtures preferred; no global test state

### CI Matrix

| Job | Platform | Compiler | Special |
|-----|----------|----------|---------|
| `lint` | Linux | — | clang-format + cppcheck |
| `codeql` | Linux | GCC | CodeQL C/C++ |
| `semgrep` | Linux | — | SAST (p/default + p/c) |
| `test` | Linux x86_64 | GCC | ASan + UBSan |
| `linux` | Linux x86_64 | GCC | scan-build static analyzer |
| `linux-arm64` | Linux aarch64 | GCC cross | `cross-aarch64.ini` |
| `windows` | Windows x86_64 | Clang + MinGW | vcpkg, `cross-clang-mingw.ini` |
| `macos` | macOS arm64 | Clang | Native |
| `android` | Android arm64 | NDK r27c | vcpkg, `cross-android-arm64.ini` |
| `android-x86_64` | Android x86_64 | NDK r27c | vcpkg, `cross-android-x86_64.ini` |
| `release` | — | — | Tag-triggered, bundles artifacts |
