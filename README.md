<p align="center">
  <img src="assets/logo.svg" width="96" alt="libopencie-pkcs11 logo">
</p>

<p align="center">
  <a href="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml"><img src="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/M0Rf30/opencie-pkcs11/releases/latest"><img src="https://img.shields.io/github/v/release/M0Rf30/opencie-pkcs11" alt="Latest Release"></a>
</p>

<p align="center">
  <a href="README.it.md">🇮🇹 Italiano</a>
</p>

# opencie-pkcs11

A cross-platform C++ library implementing the PKCS#11 interface for the Italian
[CIE](https://www.cartaidentita.interno.gov.it/) (Carta d'Identità Elettronica /
Electronic Identity Card). It exposes the private key and authentication certificate
stored on the CIE chip so that standard-compliant applications — browsers, TLS
stacks, signing tools — can use them without any card-vendor middleware.

---

## Language Bindings

| Language | Repository | Install |
|---|---|---|
| Go | [opencie-pkcs11-go](https://github.com/M0Rf30/opencie-pkcs11-go) | `go get github.com/M0Rf30/opencie-pkcs11-go` |
| Rust | [opencie-pkcs11-rs](https://github.com/M0Rf30/opencie-pkcs11-rs) | `cargo add opencie-pkcs11` |


## Features

- Full PKCS#11 v2.40 token interface (57 of 69 standard functions implemented;
  12 unsupported operations return `CKR_FUNCTION_NOT_SUPPORTED`)
- PIN management: verify, change, unblock
- PDF signing and verification via an embedded sign SDK (PoDoFo-backed)
- Portable builds with minimal glibc dependency for Linux
- Native support on Linux, macOS, Windows, and Android

---

## Platforms

| Platform | Architecture | Output |
|---|---|---|
| Linux | x86\_64, aarch64 | `libopencie-pkcs11.so` |
| Windows | x86\_64 (cross-compiled via MinGW-w64) | `libopencie-pkcs11.dll` |
| macOS | arm64 | `libopencie-pkcs11.dylib` |
| Android | arm64 | `libopencie-pkcs11.so` |

All components (`shared/`, `sign-sdk/`) are compiled as internal static libraries
and linked into the single output library — no separate runtime dependencies on
project-internal archives.

---

## Public API

### PKCS#11 Standard Interface

All 69 standard `C_*` functions are present. The following 12 return
`CKR_FUNCTION_NOT_SUPPORTED`:

`C_CancelFunction`, `C_CopyObject`, `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate`,
`C_DeriveKey`, `C_DigestEncryptUpdate`, `C_DigestKey`, `C_GetFunctionStatus`,
`C_InitToken`, `C_SignEncryptUpdate`, `C_UnwrapKey`, `C_WrapKey`

### CIE-Specific Extensions

Declared in `pkcs11/src/csp/cie_enable.h` and related headers:

```c
void  cie_enable(const char *szPAN);
void  cie_disable(const char *szPAN);
int   cie_is_enabled(const char *szPAN);

int   cie_change_pin(const char *szPAN, const char *oldPIN, const char *newPIN);
int   cie_unblock_pin(const char *szPAN, const char *puk, const char *newPIN);

int   cie_sign(/* ... */);
int   cie_verify(/* ... */);
int   cie_get_sign_count(/* ... */);
int   cie_get_verify_info(/* ... */);
int   cie_extract_p7m(/* ... */);
int   make_digest_info(/* ... */);
```

---

## Project Structure

```
pkcs11/          PKCS#11 interface (produces the final shared library)
  src/
    csp/         CIE-specific CSP operations (enable/disable, sign, verify, PIN)
    pkcs11/      PKCS#11 function implementations, slot/session/object management
    sign/        High-level sign and verify wrappers
    logger/      Internal logging

shared/          Code shared between pkcs11/ and sign-sdk/
  src/
    crypto/      AES, DES3, RSA, SHA, MAC, Base64, MD5
    csp/         ATR parsing, extended auth key, IAS protocol
    pcsc/        APDU, PC/SC transport, card locking
    pkcs11/      PKCS#11 vendor headers (pkcs11.h, cryptoki.h — unmodified)
    Util/        Byte arrays, string tables, properties, cache

sign-sdk/        PDF signing SDK (statically linked into the main library)
  src/
    asn1/        ASN.1 codec (certificates, OCSP, TSA, CRL, signatures)
    *.cpp        PDF sign/verify, XAdES, CMS/PKCS#7, TSA client
  include/       Public sign-sdk headers
```

---

## Dependencies

### Runtime

| Library | Linux | Windows | macOS | Android |
|---|:---:|:---:|:---:|:---:|
| OpenSSL (libcrypto) | ✓ | ✓ | ✓ | ✓ |
| Crypto++ (libcryptopp) | ✓ | ✓ | ✓ | ✓ |
| PC/SC Lite | ✓ | — | ✓ (framework) | — |
| WinSCard | — | ✓ | — | — |
| libcurl | ✓ | ✓ | ✓ | ✓ |
| FreeType 2 | ✓ | ✓ | ✓ | ✓ |
| libpng | ✓ | ✓ | ✓ | ✓ |
| PoDoFo ≥ 1.0 | ✓ | ✓ | ✓ | ✓ |
| libxml2 | ✓ | ✓ | ✓ | ✓ |
| zlib | ✓ | ✓ | ✓ | ✓ |
| Fontconfig | ✓ | — | — | — |

### Build Tools

- [Meson](https://mesonbuild.com/) ≥ 0.56 and [Ninja](https://ninja-build.org/)
- A C++17-capable compiler (GCC, Clang, or MinGW-w64)

---

## Building

### Linux

```bash
meson setup builddir
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.so
```

### macOS

```bash
brew install openssl cryptopp curl freetype libpng libxml2 podofo zlib
meson setup builddir
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.dylib
```

### Windows (cross-compile from Linux)

Install MinGW-w64 and [vcpkg](https://github.com/microsoft/vcpkg), then:

```bash
vcpkg install --triplet x64-mingw-dynamic \
    cryptopp curl freetype libpng libxml2 openssl podofo zlib

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/x64-mingw-dynamic/lib/pkgconfig \
    meson setup builddir-win --cross-file cross-mingw.ini

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/x64-mingw-dynamic/lib/pkgconfig \
    meson compile -C builddir-win
# Output: builddir-win/libopencie-pkcs11.dll
```

---

## Browser Integration

The library registers as a PKCS#11 security device. Browsers prompt for the
**last 4 digits of your PIN** when performing an operation.

### Firefox / Librewolf / Waterfox

`about:preferences` → Privacy & Security → **Security Devices** → **Load**,
then point to the library path.

### Chromium / Chrome / Edge

Register the library in the NSS database:

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /usr/lib/libopencie-pkcs11.so
modutil -dbdir sql:$HOME/.pki/nssdb -list
```

---

## CI & Downloads

| Platform | CI | Latest build |
|---|---|---|
| Linux x86\_64 | [![CI](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux aarch64 | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux x86\_64 portable | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux aarch64 portable | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Windows x86\_64 | ↑ | [.dll](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| macOS arm64 | ↑ | [.dylib](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Android arm64 | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Sign SDK (Linux x86\_64) | ↑ | [.a](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
---

## License

Copyright (C) 2026 Gianluca Boiano.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later version.

See the [LICENSE](LICENSE.md) file for the full text.
