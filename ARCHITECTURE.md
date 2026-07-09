# Architecture — opencie-pkcs11

## Overview

`libopencie-pkcs11` is a cross-platform C++ shared library that bridges the Italian CIE (Carta d'Identità Elettronica) smart card to the PKCS#11 v2.40 standard interface. It also embeds a PDF/XAdES signing SDK.

The library is a **single output artifact** (`libopencie-pkcs11.so` / `.dll` / `.dylib`) produced by statically linking three internal modules:

```
┌─────────────────────────────────────────────────────────┐
│              libopencie-pkcs11  (shared library)         │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   pkcs11/    │  │  sign-sdk/   │  │   shared/     │  │
│  │  (final SO)  │  │  (static .a) │  │  (static .a)  │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
│         └─────────────────┴──────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

No internal static archives are installed; only the single shared library and `include/opencie/cie_ext.h` are public.

---

## Module Map

### `pkcs11/` — PKCS#11 Interface Layer

Produces the final shared library. Implements the 69 standard `C_*` entry points and the CIE-specific extensions declared in `cie_ext.h`.

| Subdirectory | Responsibility |
|---|---|
| `pkcs11/src/pkcs11/` | Slot, session, object, and mechanism management; `C_*` function dispatch |
| `pkcs11/src/csp/` | CIE-specific operations: enrolment (`cie_enable`), certificate retrieval, PIN management, sign/verify/timestamp CSP wrappers, standalone RFC 3161 timestamping |
| `pkcs11/src/sign/` | High-level `cie_sign` / `cie_verify` wrappers that delegate to `sign-sdk/` |
| `pkcs11/src/logger/` | Internal structured logging |

### `shared/` — Shared Primitives (static library)

Code shared between `pkcs11/` and `sign-sdk/`. Compiled once into `libcie-shared.a`.

| Subdirectory | Responsibility |
|---|---|
| `shared/src/crypto/` | AES, DES3, RSA, SHA-1/256/512, MAC, MD5, Base64, ASN.1 parser |
| `shared/src/pcsc/` | APDU construction, PC/SC transport, card locking, Android NFC transport |
| `shared/src/csp/` | ATR parsing, extended authentication key derivation, IAS protocol |
| `shared/src/util/` | Byte arrays, string tables, INI settings, properties, cache, synchronisation primitives |

### `sign-sdk/` — PDF Signing SDK (static library)

Embedded signing engine compiled into `libopencie-sign-sdk.a`. Also published as a standalone artifact for downstream projects.

| File / Directory | Responsibility |
|---|---|
| `sign-sdk/src/cie_sign_api.cpp` | Top-level signing API; orchestrates the signing pipeline |
| `sign-sdk/src/pdf_signature_generator.cpp` | PDF signature field creation (PoDoFo-backed) |
| `sign-sdk/src/xades_generator.cpp` | XAdES-BES/T signature generation |
| `sign-sdk/src/tsa_client.cpp` | RFC 3161 TSA client (libcurl) |
| `sign-sdk/src/cert_store.cpp` | Certificate chain building and OCSP/CRL validation |
| `sign-sdk/src/asn1/` | Full ASN.1 codec: certificates, OCSP, TSA, CRL, CMS structures |
| `sign-sdk/src/cie_signer.cpp` | Bridges the signing SDK to the card's raw RSA operation |

### `include/opencie/` — Public API

`cie_ext.h` is the only installed header. It declares all CIE-specific extensions with full Doxygen documentation. The standard PKCS#11 `C_*` symbols are exported from the shared library but their headers (`pkcs11.h`, `cryptoki.h`) are not installed — consumers should use their own PKCS#11 headers.

---

## Data Flow

### Card Enrolment (`cie_enable`)

```
Application
  │  cie_enable(pan, pin, ...)
  ▼
pkcs11/csp/cie_enable.cpp
  │  Establish PC/SC session
  ▼
shared/pcsc/pcsc.cpp  ──────────────────────────────────────────────────────┐
  │  APDU: SELECT, EXTERNAL AUTHENTICATE                                    │ Android:
  ▼                                                                         │ shared/pcsc/android_nfc_transport.cpp
shared/csp/ias.cpp  (IAS protocol: extended auth key derivation)            │ (JNI NFC bridge)
  │  Read EF.SOD, EF.DH, certificate file                                   └──────────────
  ▼
shared/crypto/  (RSA, AES, SHA for key derivation and cert decryption)
  │
  ▼
pkcs11/csp/cie_enable.cpp
  │  AES-encrypt certificate → local cache
  ▼
COMPLETED_CALLBACK(pan, name, serial)
```

### PDF Signing (`cie_sign`)

```
Application
  │  cie_sign(inPath, "PDF", pin, pan, ...)
  ▼
pkcs11/sign/cie_sign.cpp
  │
  ▼
sign-sdk/cie_sign_api.cpp
  │  Open PDF (PoDoFo), compute document hash
  ▼
sign-sdk/cie_signer.cpp
  │  Request raw RSA signature from card
  ▼
pkcs11/csp/cie_sign_csp.cpp
  │  PC/SC APDU: INTERNAL AUTHENTICATE
  ▼
shared/pcsc/pcsc.cpp  →  smart card reader / Android NFC
  │  Raw RSA signature bytes
  ▼
sign-sdk/pdf_signature_generator.cpp
  │  Embed CMS/PKCS#7 signature into PDF
  ▼
sign-sdk/tsa_client.cpp  (optional: RFC 3161 timestamp)
  │
  ▼
Output signed PDF
```

### PKCS#11 Token Operations (`C_Sign`, `C_Login`, etc.)

```
Browser / TLS stack
  │  C_GetSlotList → C_OpenSession → C_Login(PIN) → C_Sign(data)
  ▼
pkcs11/pkcs11/pkcs11_functions.cpp  (dispatch table)
  │
  ├─ Slot/session management: pkcs11/pkcs11/slot.cpp, session.cpp
  ├─ Object management:       pkcs11/pkcs11/p11_object.cpp
  ├─ Mechanism handling:      pkcs11/pkcs11/mechanism.cpp
  │
  ▼
pkcs11/csp/  →  shared/pcsc/  →  card
```

### Timestamping (`cie_timestamp`)

```
Application
  │  cie_timestamp(inFilePath, tsaUrl, ...)
  ▼
pkcs11/csp/cie_timestamp_csp.cpp
  │  fread(inFilePath) → CSHA256::Digest
  ▼
sign-sdk/tsa_client.cpp
  │  RFC 3161 TimeStampRequest (libcurl HTTP POST)
  ▼
sign-sdk/asn1/  (parse TimeStampToken DER)
  ▼
Output: DER-encoded TimeStampToken (.tst)
```

---

## Platform Differences

| Concern | Linux / macOS | Windows | Android |
|---|---|---|---|
| PC/SC transport | `libpcsclite` / `PCSC.framework` | `WinSCard` | JNI NFC bridge (`android_nfc_transport.cpp`) |
| Symbol visibility | `--version-script` (`.map`) | `.def` file (`.exp`) | `--version-script` + `--undefined-version` |
| C++ stdlib | system `libstdc++` (or static for portable) | MinGW-w64 | NDK `libc++` |
| Portable build | `Containerfile` (Ubuntu 22.04, glibc 2.35) | vcpkg | NDK r27c + vcpkg |

---

## Symbol Visibility

Only the public API symbols are exported from the shared library. All internal symbols from statically linked archives (OpenSSL, PoDoFo, etc.) are hidden using:

- **Linux/Android:** `--version-script=linker/libopencie-pkcs11.map` + `--exclude-libs,ALL`
- **macOS:** `-exported_symbols_list linker/libopencie-pkcs11.exp`
- **Windows:** implicit via `.def` export list

This prevents symbol collisions when the library is loaded into a host process (e.g. Firefox) that already links its own OpenSSL.

---

## Dependencies

| Library | Role |
|---|---|
| OpenSSL (`libcrypto`) | RSA, AES, SHA primitives; certificate parsing |
| PC/SC Lite / WinSCard | Smart-card reader transport |
| libcurl | TSA HTTP client, OCSP/CRL fetching |
| PoDoFo ≥ 1.0 | PDF manipulation for signature embedding |
| libxml2 | XAdES XML generation and parsing |
| FreeType 2 + libpng | Signature stamp image rendering in PDFs |
| OpenJPEG (libopenjp2) | JPEG2000 decoding for CIE DG2 portrait photos (optional) |
| Fontconfig | Font discovery (Linux only) |
| zlib | Compression (PoDoFo dependency) |

---

## Build System

Meson ≥ 0.56 with Ninja. Key options:

| Option | Default | Effect |
|---|---|---|
| `portable` | `false` | Statically link `libstdc++` and `libgcc` |
| `prefer_static` | `false` | Prefer static dependency variants |
| `buildtype` | `debug` | `release` for production builds |

Cross-compilation toolchain files live in `toolchains/`:
- `cross-aarch64.ini` — Linux aarch64
- `cross-mingw.ini` — Windows x86_64 (MinGW-w64)
- `cross-android-arm64.ini` — Android arm64-v8a
- `cross-android-x86_64.ini` — Android x86_64
