<p align="center">
  <img src="assets/logo.svg" width="96" alt="logo libopencie-pkcs11">
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

---

## Caratteristiche

- Interfaccia PKCS#11 v2.40 completa (57 delle 69 funzioni standard implementate;
  12 operazioni non supportate restituiscono `CKR_FUNCTION_NOT_SUPPORTED`)
- Gestione del PIN: verifica, modifica, sblocco
- Firma e verifica PDF tramite un SDK integrato (basato su PoDoFo)
- Build portabili con dipendenza minima da glibc per Linux
- Supporto nativo su Linux, macOS, Windows e Android (trasporto NFC su Android)

---

## Piattaforme

| Piattaforma | Architettura | Output |
|---|---|---|
| Linux | x86\_64, aarch64 | `libopencie-pkcs11.so` |
| Windows | x86\_64 (cross-compilato con MinGW-w64) | `libopencie-pkcs11.dll` |
| macOS | arm64 | `libopencie-pkcs11.dylib` |
| Android | arm64-v8a, x86\_64 | `libopencie-pkcs11.so` |

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

Interfaccia C pubblica dichiarata in [`include/opencie/cie_ext.h`](include/opencie/cie_ext.h).
Tutte le funzioni restituiscono `CK_RV` (codice di errore PKCS#11) salvo dove indicato.

```c
// Registrazione (enrolment)
CK_RV cie_enable      (const char *pan, const char *pin, int *attempts,
                       PROGRESS_CALLBACK, COMPLETED_CALLBACK);
CK_RV cie_is_enabled  (const char *pan);   // 1 = registrata, 0 = no
CK_RV cie_disable     (const char *pan);

// Gestione PIN
CK_RV cie_change_pin  (const char *cur_pin, const char *new_pin,
                       int *attempts, PROGRESS_CALLBACK);
CK_RV cie_unblock_pin (const char *puk, const char *new_pin,
                       int *attempts, PROGRESS_CALLBACK);

// Firma / verifica
CK_RV cie_sign           (const char *in_path, const char *type,
                          const char *pin, const char *pan,
                          int page, float x, float y, float w, float h,
                          const unsigned char *image, int image_len,
                          const char *out_path,
                          PROGRESS_CALLBACK, SIGN_COMPLETED_CALLBACK);
CK_RV cie_verify         (const char *in_path, const char *proxy,
                          int proxy_port, const char *user_pass);
CK_RV cie_get_sign_count (void);
CK_RV cie_get_verify_info(int index, struct verifyInfo_t *out);
CK_RV cie_extract_p7m    (const char *in_path, const char *out_path);

// Rilevamento lettori (ritorno int)
int cie_reader_count (void);
int cie_reader_watch (int current_count);
int cie_reader_name  (char *buf, int buf_len);

// Helper di basso livello per flussi RSA grezzi (1 = ok, 0 = buffer troppo piccolo)
int make_digest_info (int algid, const unsigned char *digest, size_t digest_len,
                      unsigned char *out, size_t *out_len);
```

Su Android sono esportati anche tre simboli aggiuntivi che fanno da bridge JNI per
il trasporto NFC: `cie_set_nfc_tag`, `cie_clear_nfc_tag`, `cie_set_data_dir`
(oltre a `JNI_OnLoad`).

---

## Struttura del progetto

```
include/opencie/  Header C pubblici (cie_ext.h)

pkcs11/           Interfaccia PKCS#11 (produce la libreria condivisa finale)
  src/
    csp/          Operazioni CSP specifiche per la CIE (enable/disable, firma, verifica, PIN)
    pkcs11/       Implementazioni delle funzioni PKCS#11, gestione slot/sessione/oggetto
    sign/         Wrapper di alto livello per firma e verifica
    logger/       Logging interno

shared/           Codice condiviso tra pkcs11/ e sign-sdk/
  src/
    crypto/       AES, DES3, RSA, SHA, MAC, Base64, MD5
    csp/          Parsing ATR, chiave di autenticazione estesa, protocollo IAS
    pcsc/         APDU, trasporto PC/SC, blocco della carta, trasporto NFC Android
    pkcs11/       Header vendor PKCS#11 (pkcs11.h, cryptoki.h — non modificati)
    Util/         Array di byte, tabelle di stringhe, proprietà, cache

sign-sdk/         SDK per la firma PDF (collegato staticamente nella libreria principale)
  src/
    asn1/         Codec ASN.1 (certificati, OCSP, TSA, CRL, firme)
    *.cpp         Firma/verifica PDF, XAdES, CMS/PKCS#7, client TSA
  include/        Header pubblici del sign-sdk

toolchains/       Cross file Meson (aarch64, MinGW, Android NDK)
linker/           Script di esportazione simboli (.map / .exp)
Containerfile     Build Linux portabile riproducibile (Ubuntu 22.04 / glibc 2.35)
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

Su Android il livello PC/SC è sostituito da un trasporto NFC in-process tramite
JNI; non vengono usati lettori smart card.

### Strumenti di build

- [Meson](https://mesonbuild.com/) ≥ 0.56 e [Ninja](https://ninja-build.org/)
- Un compilatore C++17 (GCC, Clang o MinGW-w64)
- [vcpkg](https://github.com/microsoft/vcpkg) — necessario per le build cross Windows e Android
- Android NDK r27c — necessario per le build Android
- Podman o Docker — necessari per la build Linux portabile

---

## Compilazione

### Linux (nativa)

```bash
sudo apt install -y \
    cmake g++ libcrypto++-dev libcurl4-openssl-dev \
    libfontconfig1-dev libfreetype6-dev libpcsclite-dev \
    libpng-dev libssl-dev libxml2-dev pkg-config
pip install meson ninja

meson setup builddir
meson compile -C builddir
# Output: builddir/libopencie-pkcs11.so
```

I nomi dei pacchetti si riferiscono a Debian/Ubuntu. Adattali alla tua distribuzione.

### Linux (portabile, indipendente dalla distro)

La build portabile collega staticamente tutte le dipendenze tranne glibc,
puntando a glibc 2.35 (Ubuntu 22.04) per garantire compatibilità con
Ubuntu 22.04+, Debian 12+, Fedora 37+, RHEL 9+, Arch ecc. Viene eseguita in container.

```bash
podman build -t libopencie-builder -f Containerfile .

mkdir -p output
podman run --rm -v $(pwd)/output:/output libopencie-builder x86_64
podman run --rm -v $(pwd)/output:/output libopencie-builder aarch64
# Output: output/libopencie-pkcs11-x86_64.so
#         output/libopencie-pkcs11-aarch64.so
```

`docker` funziona allo stesso modo. Internamente la build esegue:

```
meson setup builddir-portable-${ARCH} \
    -Dportable=true -Dprefer_static=true \
    -Dbuildtype=release -Dstrip=true \
    [--cross-file toolchains/cross-aarch64.ini]
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
    meson setup builddir-win --cross-file toolchains/cross-mingw.ini

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/x64-mingw-dynamic/lib/pkgconfig \
    meson compile -C builddir-win
# Output: builddir-win/libopencie-pkcs11.dll
```

Il workflow CI prepara anche un bundle `runtime/` con le DLL runtime di MinGW e
vcpkg necessarie a fianco della .dll — vedi `.github/workflows/main.yml` per
l'elenco esatto.

### Android (cross-compilazione da Linux)

Richiede Android NDK r27c e vcpkg.

```bash
# arm64-v8a
vcpkg install --triplet arm64-android \
    cryptopp curl freetype libpng libxml2 openssl zlib

sed -i "s|/opt/android-ndk|$ANDROID_NDK_ROOT|g" toolchains/cross-android-arm64.ini
sed -i "s|@SOURCE_ROOT@|$(pwd)|g"               toolchains/cross-android-arm64.ini

PKG_CONFIG_LIBDIR=$VCPKG_ROOT/installed/arm64-android/lib/pkgconfig \
ANDROID_ABI=arm64-v8a ANDROID_PLATFORM=android-28 \
VCPKG_INSTALLED_DIR=$VCPKG_ROOT/installed VCPKG_TARGET_TRIPLET=arm64-android \
    meson setup builddir-android --cross-file toolchains/cross-android-arm64.ini

meson compile -C builddir-android
# Output: builddir-android/libopencie-pkcs11.so
```

Per x86\_64 (emulatore) usa `cross-android-x86_64.ini` e il triplet `x64-android`.

---

## Integrazione con il browser

La libreria si registra come dispositivo di sicurezza PKCS#11. I browser richiedono
le **ultime 4 cifre del PIN** quando si esegue un'operazione.

Negli esempi seguenti sostituisci `/percorso/di/libopencie-pkcs11.so` con la
posizione reale della libreria compilata (o installata).

### Firefox / Librewolf / Waterfox

`about:preferences` → Privacy e sicurezza → **Dispositivi di sicurezza** → **Carica**,
quindi indicare il percorso della libreria.

### Chromium / Chrome / Edge

Registrare la libreria nel database NSS:

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /percorso/di/libopencie-pkcs11.so
modutil -dbdir sql:$HOME/.pki/nssdb -list
```

---

## CI & Download

L'unico badge CI qui sotto riflette lo stato complessivo del workflow (tutti i
job della matrice combinati). Gli artefatti per piattaforma sono prodotti dallo
stesso workflow e allegati a ogni release con tag.

| Piattaforma | CI | Ultima build |
|---|---|---|
| Linux x86\_64 | [![CI](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml/badge.svg)](https://github.com/M0Rf30/opencie-pkcs11/actions/workflows/main.yml) | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux aarch64 | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux x86\_64 portable | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Linux aarch64 portable | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Windows x86\_64 | ↑ | [.dll](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| macOS arm64 | ↑ | [.dylib](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Android arm64-v8a | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Android x86\_64 | ↑ | [.so](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |
| Sign SDK (Linux x86\_64) | ↑ | [.a](https://github.com/M0Rf30/opencie-pkcs11/releases/latest) |

La riga `Sign SDK` pubblica `libopencie-sign-sdk.a`: l'archivio statico dell'SDK
di firma PDF integrato, pensato per progetti a valle che vogliano collegare l'SDK
direttamente, senza passare dalle entry point PKCS#11.

---

## Licenza

Copyright (C) 2026 Gianluca Boiano.

Questo programma è software libero: puoi ridistribuirlo e/o modificarlo
nei termini della GNU General Public License come pubblicata dalla
Free Software Foundation, nella versione 2 o, a tua scelta, in qualsiasi versione successiva.

Consulta il file [LICENSE](LICENSE.md) per il testo completo.
