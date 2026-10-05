<!--
SPDX-FileCopyrightText: 2026 Gianluca Boiano
SPDX-License-Identifier: LGPL-3.0-or-later
-->
<p align="center">
  <img src="assets/logo.svg" width="112" alt="libopencie-pkcs11 logo">
</p>

<h1 align="center">opencie-pkcs11</h1>

<p align="center"><strong>PKCS#11 module for the Italian Electronic Identity Card (CIE) — cross-platform, middleware-free.</strong></p>

<p align="center">
  <a href="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml"><img src="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/M0Rf30/opencie-pkcs11/releases/latest"><img src="https://img.shields.io/github/v/release/M0Rf30/opencie-pkcs11" alt="Latest Release"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-LGPL--3.0--or--later-blue" alt="License: LGPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/platforms-Linux%20x86__64%20%7C%20aarch64%20%C2%B7%20Windows%20x86__64%20%C2%B7%20macOS%20arm64%20%C2%B7%20Android%20arm64%20%7C%20x86__64-lightgrey" alt="Platforms">
</p>

<p align="center">
  <a href="README.it.md">Italiano</a>
</p>

<p align="center">
  <a href="#release-artifacts">Release artifacts</a> · <a href="#features">Features</a> · <a href="#platforms">Platforms</a> · <a href="#public-api">Public API</a> · <a href="#building">Building</a> · <a href="#browser-integration">Browser Integration</a> · <a href="#documentation">Documentation</a> · <a href="#license">License</a>
</p>

A cross-platform C++ library implementing the PKCS#11 interface for the Italian
[CIE](https://www.cartaidentita.interno.gov.it/) (Carta d'Identità Elettronica /
Electronic Identity Card). It exposes the private key and authentication certificate
stored on the CIE chip so that standard-compliant applications — browsers, TLS
stacks, signing tools — can use them without any card-vendor middleware.

## Release artifacts

Each tagged release attaches the following assets (`<ver>` is the release tag).

| Asset | Platform | Notes |
|---|---|---|
| `libopencie-pkcs11-<ver>-linux-x86_64.so` | Linux x86\_64 | PKCS#11 module (portable build) |
| `libopencie-pkcs11-<ver>-linux-aarch64.so` | Linux aarch64 | PKCS#11 module |
| `libopencie-pkcs11-<ver>-windows-x86_64.dll` | Windows x86\_64 | PKCS#11 module |
| `windows-x86_64-runtime-deps-<ver>.zip` | Windows x86\_64 | MinGW/vcpkg runtime DLLs to ship next to the `.dll` |
| `libopencie-pkcs11-<ver>-macos-arm64.dylib` | macOS arm64 | PKCS#11 module |
| `libopencie-pkcs11-<ver>-android-arm64.so` | Android arm64-v8a | PKCS#11 module (NFC transport) |
| `libopencie-pkcs11-<ver>-android-x86_64.so` | Android x86\_64 | PKCS#11 module (emulator) |
| `libopencie-sign-sdk-<ver>-linux-x86_64.a` | Linux x86\_64 | Static archive of the PDF signing SDK |
| `SHA256SUMS` | — | Checksums of all assets |

[All releases](https://github.com/M0Rf30/opencie-pkcs11/releases)

---

## Features

- Full PKCS#11 v2.40 token interface (57 of 69 standard functions implemented;
  12 unsupported operations return `CKR_FUNCTION_NOT_SUPPORTED`)
- PIN management: verify, change, unblock
- PDF signing and verification via an embedded sign SDK (PoDoFo-backed)
- Standalone RFC 3161 timestamping via any TSA (no card required)
- Portable Linux build (`-Dportable=true`) with a statically linked, ICU-free
  libxml2 to avoid picking up distro ICU dependencies
- Native support on Linux, macOS, Windows, and Android (NFC transport on Android)

---

## Platforms

| Platform | Architecture | Output |
|---|---|---|
| Linux | x86\_64, aarch64 | `libopencie-pkcs11.so` |
| Windows | x86\_64 (cross-compiled via MinGW-w64) | `libopencie-pkcs11.dll` |
| macOS | arm64 | `libopencie-pkcs11.dylib` |
| Android | arm64-v8a, x86\_64 | `libopencie-pkcs11.so` |

All components (`shared/`, `sign-sdk/`) are compiled as internal static libraries
and linked into the single output library — no separate runtime dependencies on
project-internal archives.

---

## Language Bindings

| Language | Repository | Install |
|---|---|---|
| Go | [opencie-pkcs11-go](https://github.com/M0Rf30/opencie-pkcs11-go) | `go get github.com/M0Rf30/opencie-pkcs11-go` |
| Rust | [opencie-pkcs11-rs](https://github.com/M0Rf30/opencie-pkcs11-rs) | `cargo add opencie-pkcs11` |
| Python | [opencie-pkcs11-py](https://github.com/M0Rf30/opencie-pkcs11-py) | `pip install opencie-pkcs11` |

---

## Public API

### PKCS#11 Standard Interface

All 69 standard `C_*` functions are present. The following 12 return
`CKR_FUNCTION_NOT_SUPPORTED`:

`C_CancelFunction`, `C_CopyObject`, `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate`,
`C_DeriveKey`, `C_DigestEncryptUpdate`, `C_DigestKey`, `C_GetFunctionStatus`,
`C_InitToken`, `C_SignEncryptUpdate`, `C_UnwrapKey`, `C_WrapKey`

### CIE-Specific Extensions

Public C interface declared in [`include/opencie/cie_ext.h`](include/opencie/cie_ext.h).
All functions return `CK_RV` (PKCS#11 error code) unless otherwise noted.

<details>
<summary><b>Full C API listing (<code>cie_ext.h</code>)</b></summary>

```c
// Enrolment
CK_RV cie_enable         (const char *szPAN, const char *szPIN, int *attempts,
                           PROGRESS_CALLBACK, COMPLETED_CALLBACK);
CK_RV cie_is_enabled     (const char *szPAN);   // 1 = enrolled, 0 = not
CK_RV cie_disable        (const char *szPAN);

// PIN management
CK_RV cie_change_pin     (const char *szCurrentPIN, const char *szNewPIN,
                           int *attempts, PROGRESS_CALLBACK);
CK_RV cie_unblock_pin    (const char *szPUK, const char *szNewPIN,
                           int *attempts, PROGRESS_CALLBACK);

// Certificate retrieval
// outDer is set to a DER buffer allocated by the library; release it with
// cie_free(), not free() (different CRT heaps on Windows).
CK_RV cie_get_certificate(const char *pan, unsigned char **outDer,
                           unsigned long *outLen);
void  cie_free           (void *ptr);

// Sign / verify
CK_RV cie_sign           (const char *inFilePath, const char *type,
                           const char *pin, const char *pan,
                           int page, float x, float y, float w, float h,
                           const unsigned char *imageData, int imageDataLen,
                           const char *outFilePath,
                           PROGRESS_CALLBACK, SIGN_COMPLETED_CALLBACK);
CK_RV cie_verify         (const char *inFilePath, const char *proxyAddress,
                           int proxyPort, const char *usrPass);
CK_RV cie_get_sign_count (void);
CK_RV cie_get_verify_info(int index, struct verifyInfo_t *vInfos);
CK_RV cie_extract_p7m    (const char *inFilePath, const char *outFilePath);

// Chip data-group readers (ICAO 9303)
// Both read DG1 (MRZ) and DG2 (portrait photo) in one session; the photo is
// returned as PNG bytes (JPEG2000 decoded internally).
//
// cie_read_dgs_can: ICAO 9303-11 PACE with the 6-digit CAN printed on the
// card (no PIN). Errors via cie_last_error(): wrong CAN ->
// CKR_PIN_INCORRECT + CIE_ERR_WRONG_CAN (11); reader without extended-APDU
// support -> CKR_DEVICE_ERROR + CIE_ERR_INS_NOT_SUPPORTED (7), in which case
// fall back to cie_read_dgs.
CK_RV cie_read_dgs_can   (const char *can,
                           char *mrzOut, size_t *mrzLen,
                           unsigned char *photoOut, size_t *photoLen);
// cie_read_dgs: PIN based fallback for readers limited to short APDUs.
CK_RV cie_read_dgs       (const char *pin,
                           char *mrzOut, size_t *mrzLen,
                           unsigned char *photoOut, size_t *photoLen);

// Timestamp
CK_RV cie_timestamp      (const char *inFilePath, const char *tsaUrl,
                           const char *tsaUsername, const char *tsaPassword,
                           const char *outTokenPath, PROGRESS_CALLBACK);

// Reader discovery (int return)
int   cie_reader_count   (void);
int   cie_reader_watch   (int current_count);
int   cie_reader_name    (char *buf, int buf_len);

// Error detail for the last failed call on this thread
CK_RV cie_last_error     (cie_error_kind *outKind, uint16_t *outSw);
cie_error_kind cie_classify_sw(uint16_t sw);

// Low-level helper for raw RSA flows (1 = ok, 0 = buffer too small)
int   make_digest_info   (int algid, const unsigned char *pbtDigest,
                           size_t btDigestLen, unsigned char *pbtDigestInfo,
                           size_t *pbtDigestInfoLen);
```

</details>

On Android, three additional symbols bridge the JNI NFC transport:
`cie_set_nfc_tag`, `cie_clear_nfc_tag`, `cie_set_data_dir` (plus `JNI_OnLoad`).

---

## Project Structure

<details>
<summary><b>Source tree layout</b></summary>

```
include/opencie/  Public C headers (cie_ext.h)

pkcs11/           PKCS#11 interface (produces the final shared library)
  src/
    csp/          CIE-specific CSP operations (enable/disable, sign, verify, PIN)
    pkcs11/       PKCS#11 function implementations, slot/session/object management
    sign/         High-level sign and verify wrappers
    logger/       Internal logging

shared/           Code shared between pkcs11/ and sign-sdk/
  src/
    crypto/       AES, DES3, RSA, SHA, MAC, Base64, MD5
    csp/          ATR parsing, extended auth key, IAS protocol
    pcsc/         APDU, PC/SC transport, card locking, Android NFC transport
    pkcs11/       PKCS#11 vendor headers (pkcs11.h, cryptoki.h — unmodified)
    Util/         Byte arrays, string tables, properties, cache

sign-sdk/         PDF signing SDK (statically linked into the main library)
  src/
    asn1/         ASN.1 codec (certificates, OCSP, TSA, CRL, signatures)
    *.cpp         PDF sign/verify, XAdES, CMS/PKCS#7, TSA client
  include/        Public sign-sdk headers

toolchains/       Meson cross files (aarch64, MinGW, Android NDK)
linker/           Symbol export scripts (.map / .exp)
```

</details>

---

## Dependencies

### Runtime

| Library | Linux | Windows | macOS | Android |
|---|:---:|:---:|:---:|:---:|
| OpenSSL (libcrypto) | ✓ | ✓ | ✓ | ✓ |
| PC/SC Lite | ✓ | — | ✓ (framework) | — |
| WinSCard | — | ✓ | — | — |
| libcurl | ✓ | ✓ | ✓ | ✓ |
| FreeType 2 | ✓ | ✓ | ✓ | ✓ |
| libpng | ✓ | ✓ | ✓ | ✓ |
| OpenJPEG (libopenjp2) | ✓ | ✓ | ✓ | ✓ |
| PoDoFo ≥ 1.0 | ✓ | ✓ | ✓ | ✓ |
| libxml2 | ✓ | ✓ | ✓ | ✓ |
| zlib | ✓ | ✓ | ✓ | ✓ |
| Fontconfig | ✓ | — | — | — |

On Android the PC/SC layer is replaced by an in-process NFC transport bridged
via JNI; smart-card readers are not used.

### Build Tools

- [Meson](https://mesonbuild.com/) ≥ 0.56 and [Ninja](https://ninja-build.org/)
- A C++20-capable compiler (GCC, Clang, or MinGW-w64)
- [vcpkg](https://github.com/microsoft/vcpkg) — required for Windows and Android cross builds
- Android NDK r27c — required for Android builds

---

## Building

### Linux (native)

```bash
sudo apt install -y \
    cmake g++ libcurl4-openssl-dev \
    libfontconfig1-dev libfreetype6-dev libopenjp2-7-dev libpcsclite-dev \
    libpng-dev libssl-dev libxml2-dev pkg-config
pip install meson ninja

meson setup builddir
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.so
```

Package names are for Debian/Ubuntu. Adapt to your distribution as needed.

### Linux (portable, distro-independent)

The portable build (`-Dportable=true`) statically links `libstdc++`/`libgcc`
and vendors a static, ICU-disabled libxml2 (see `subprojects/libxml2.wrap`)
so the resulting `.so` has no dynamic `libicuuc`/`libicui18n`/`libicudata`
dependency (recent Debian/Ubuntu link their packaged libxml2 against ICU).
All other runtime libraries (curl, fontconfig, freetype, openssl, libpng,
openjpeg, PoDoFo, zlib, pcsclite) remain dynamically linked against whatever
the build host provides. This is the recipe used by the CI `linux` job to
build the `linux-x86_64` release artifact.

```bash
meson setup builddir -Dportable=true
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.so
```

### macOS

```bash
brew install openssl curl freetype libpng libxml2 openjpeg podofo zlib
meson setup builddir
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.dylib
```

### Cross-compilation

<details>
<summary><b>Windows (cross-compile from Linux)</b></summary>

Install MinGW-w64 and [vcpkg](https://github.com/microsoft/vcpkg), then:

```bash
vcpkg install --triplet x64-mingw-dynamic \
    curl freetype libpng libxml2 openjpeg openssl podofo zlib

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/x64-mingw-dynamic/lib/pkgconfig \
    meson setup builddir-win --cross-file toolchains/cross-mingw.ini

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/x64-mingw-dynamic/lib/pkgconfig \
    meson compile -C builddir-win
# Output: builddir-win/libopencie-pkcs11.dll
```

The CI workflow also stages the required MinGW and vcpkg runtime DLLs into a
`runtime/` bundle alongside the .dll — see `.github/workflows/main.yml` for the
exact list.

</details>

<details>
<summary><b>Android (cross-compile from Linux)</b></summary>

Requires Android NDK r27c and vcpkg.

```bash
# arm64-v8a
vcpkg install --triplet arm64-android \
    curl freetype libpng libxml2 openjpeg openssl zlib

sed -i "s|/opt/android-ndk|$ANDROID_NDK_ROOT|g" toolchains/cross-android-arm64.ini
sed -i "s|@SOURCE_ROOT@|$(pwd)|g"               toolchains/cross-android-arm64.ini

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/arm64-android/lib/pkgconfig \
ANDROID_ABI=arm64-v8a ANDROID_PLATFORM=android-28 \
VCPKG_INSTALLED_DIR=$VCPKG_ROOT/installed VCPKG_TARGET_TRIPLET=arm64-android \
    meson setup builddir-android --cross-file toolchains/cross-android-arm64.ini

meson compile -C builddir-android
# Output: builddir-android/libopencie-pkcs11.so
```

For x86\_64 (emulator), substitute `cross-android-x86_64.ini` and the
`x64-android` triplet.

</details>

---

## Browser Integration

The library registers as a PKCS#11 security device. Browsers prompt for the
**last 4 digits of your PIN** when performing an operation.

In the snippets below, replace `/path/to/libopencie-pkcs11.so` with the actual
location of the built (or installed) library.

### Firefox / Librewolf / Waterfox

`about:preferences` → Privacy & Security → **Security Devices** → **Load**,
then point to the library path.

### Chromium / Chrome / Edge

Register the library in the NSS database:

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /path/to/libopencie-pkcs11.so
modutil -dbdir sql:$HOME/.pki/nssdb -list
```

> **Note:** GNOME Papers, Okular and other `poppler`-based apps read the
> Firefox profile's NSS database (if Firefox is installed) instead of
> `~/.pki/nssdb`. See
> [docs/usage.md#gnome-papers-okular-and-other-poppler-based-signers](docs/usage.md#gnome-papers-okular-and-other-poppler-based-signers)
> for details.

### Supported cards

See [docs/supported-cards.md](docs/supported-cards.md) for the list of
recognised CIE chips, compatible readers, and how to report an unsupported card.

---

## Documentation

- [docs/api.md](docs/api.md) — API reference
- [docs/usage.md](docs/usage.md) — usage guide
- [docs/supported-cards.md](docs/supported-cards.md) — supported cards and readers
- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture overview
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

---

## CI & Downloads

Per-platform artifacts are produced by the CI workflow and attached to each
tagged release (see [Release artifacts](#release-artifacts)).

<details>
<summary><b>CI status per platform</b></summary>

| Platform | CI | Latest build |
|---|---|---|
| Linux x86\_64 | [![linux](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux aarch64 | [![linux-arm64](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Windows x86\_64 | [![windows](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.dll](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| macOS arm64 | [![macos](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.dylib](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Android arm64-v8a | [![android](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Android x86\_64 | [![android-x86\_64](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Sign SDK (Linux x86\_64) | [![linux](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.a](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |

The `Sign SDK` row publishes `libopencie-sign-sdk.a`: the static archive of the
embedded PDF signing SDK, intended for downstream projects that want to link
the SDK directly without going through the PKCS#11 entry points.

</details>

---

## License

Copyright (C) 2026 Gianluca Boiano.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

See the [LICENSE](LICENSE.md) file for the full text.
