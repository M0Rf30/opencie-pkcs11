<p align="center">
  <img src="assets/logo.svg" width="96" alt="libopencie-pkcs11 logo">
</p>

<p align="center">
  <a href="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml"><img src="https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/M0Rf30/opencie-pkcs11/releases/latest"><img src="https://img.shields.io/github/v/release/M0Rf30/opencie-pkcs11" alt="Ultima versione"></a>
</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a>
</p>

# opencie-pkcs11

Una libreria C++ multipiattaforma che implementa l'interfaccia PKCS#11 per la
[CIE](https://www.cartaidentita.interno.gov.it/) (Carta d'Identità Elettronica) italiana.
Espone la chiave privata e il certificato di autenticazione presenti sul chip della CIE
in modo che le applicazioni compatibili — browser, stack TLS, strumenti di firma —
possano utilizzarli senza alcun middleware proprietario.

---

## Binding per altri linguaggi

| Linguaggio | Repository | Installazione |
|---|---|---|
| Go | [opencie-pkcs11-go](https://github.com/M0Rf30/opencie-pkcs11-go) | `go get github.com/M0Rf30/opencie-pkcs11-go` |
| Rust | [opencie-pkcs11-rs](https://github.com/M0Rf30/opencie-pkcs11-rs) | `cargo add opencie-pkcs11` |


## Caratteristiche

- Interfaccia PKCS#11 v2.40 completa (57 delle 69 funzioni standard implementate;
  12 operazioni non supportate restituiscono `CKR_FUNCTION_NOT_SUPPORTED`)
- Gestione del PIN: verifica, modifica, sblocco
- Firma e verifica PDF tramite un SDK integrato (basato su PoDoFo)
- Build portabili con dipendenza minima da glibc per Linux
- Supporto nativo su Linux, macOS, Windows e Android

---

## Piattaforme

| Piattaforma | Architettura | Output |
|---|---|---|
| Linux | x86\_64, aarch64 | `libopencie-pkcs11.so` |
| Windows | x86\_64 (cross-compilato con MinGW-w64) | `libopencie-pkcs11.dll` |
| macOS | arm64 | `libopencie-pkcs11.dylib` |
| Android | arm64 | `libopencie-pkcs11.so` |

Tutti i componenti (`shared/`, `sign-sdk/`) vengono compilati come librerie statiche interne
e collegati nella singola libreria di output — nessuna dipendenza runtime da archivi interni al progetto.

---

## API pubblica

### Interfaccia standard PKCS#11

Tutte e 69 le funzioni standard `C_*` sono presenti. Le seguenti 12 restituiscono
`CKR_FUNCTION_NOT_SUPPORTED`:

`C_CancelFunction`, `C_CopyObject`, `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate`,
`C_DeriveKey`, `C_DigestEncryptUpdate`, `C_DigestKey`, `C_GetFunctionStatus`,
`C_InitToken`, `C_SignEncryptUpdate`, `C_UnwrapKey`, `C_WrapKey`

### Estensioni specifiche per la CIE

Dichiarate in `pkcs11/src/csp/cie_enable.h` e negli header correlati:

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

## Struttura del progetto

```
pkcs11/          Interfaccia PKCS#11 (produce la libreria condivisa finale)
  src/
    csp/         Operazioni CSP specifiche per la CIE (enable/disable, firma, verifica, PIN)
    pkcs11/      Implementazioni delle funzioni PKCS#11, gestione slot/sessione/oggetto
    sign/        Wrapper di alto livello per firma e verifica
    logger/      Logging interno

shared/          Codice condiviso tra pkcs11/ e sign-sdk/
  src/
    crypto/      AES, DES3, RSA, SHA, MAC, Base64, MD5
    csp/         Parsing ATR, chiave di autenticazione estesa, protocollo IAS
    pcsc/        APDU, trasporto PC/SC, blocco della carta
    pkcs11/      Header vendor PKCS#11 (pkcs11.h, cryptoki.h — non modificati)
    Util/        Array di byte, tabelle di stringhe, proprietà, cache

sign-sdk/        SDK per la firma PDF (collegato staticamente nella libreria principale)
  src/
    asn1/        Codec ASN.1 (certificati, OCSP, TSA, CRL, firme)
    *.cpp        Firma/verifica PDF, XAdES, CMS/PKCS#7, client TSA
  include/       Header pubblici del sign-sdk
```

---

## Dipendenze

### Runtime

| Libreria | Linux | Windows | macOS | Android |
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

### Strumenti di build

- [Meson](https://mesonbuild.com/) ≥ 0.56 e [Ninja](https://ninja-build.org/)
- Un compilatore C++17 (GCC, Clang o MinGW-w64)

---

## Compilazione

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

### Windows (cross-compilazione da Linux)

Installare MinGW-w64 e [vcpkg](https://github.com/microsoft/vcpkg), poi:

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

## Integrazione con il browser

La libreria si registra come dispositivo di sicurezza PKCS#11. I browser richiedono
le **ultime 4 cifre del PIN** quando si esegue un'operazione.

### Firefox / Librewolf / Waterfox

`about:preferences` → Privacy e sicurezza → **Dispositivi di sicurezza** → **Carica**,
quindi indicare il percorso della libreria.

### Chromium / Chrome / Edge

Registrare la libreria nel database NSS:

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /usr/lib/libopencie-pkcs11.so
modutil -dbdir sql:$HOME/.pki/nssdb -list
```

---

## CI & Download

| Piattaforma | CI | Ultima build |
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

## Licenza

Copyright (C) 2026 Gianluca Boiano.

Questo programma è software libero: puoi ridistribuirlo e/o modificarlo
nei termini della GNU General Public License come pubblicata dalla
Free Software Foundation, nella versione 2 o, a tua scelta, in qualsiasi versione successiva.

Consulta il file [LICENSE](LICENSE.md) per il testo completo.
