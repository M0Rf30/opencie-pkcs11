# Usage Guide — opencie-pkcs11

Step-by-step guide for integrating `libopencie-pkcs11` into your application.

---

## 1. Load the Library

The library is a standard shared library. Load it dynamically or link against it at build time.

### Dynamic loading (recommended for plugins)

```c
#include <dlfcn.h>
#include "opencie/cie_ext.h"

void* lib = dlopen("/usr/lib/libopencie-pkcs11.so", RTLD_LAZY);
if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 1; }

typedef CK_RV (*cie_enable_fn)(const char*, const char*, int*,
                                PROGRESS_CALLBACK, COMPLETED_CALLBACK);
cie_enable_fn enable = (cie_enable_fn)dlsym(lib, "cie_enable");
```

### Static linking (sign-sdk only)

The sign SDK is also published as `libopencie-sign-sdk.a` for downstream projects that want to link the PDF signing layer directly.

---

## 2. Detect a Reader

```c
#include "opencie/cie_ext.h"

// Wait for a reader to be connected
while (cie_reader_count() == 0) {
    cie_reader_watch(0); // blocks until count changes
}

char name[256];
cie_reader_name(name, sizeof(name));
printf("Reader: %s\n", name);
```

---

## 3. Enrol a Card

Enrolment reads the card's X.509 certificate and stores it in a local AES-encrypted cache. It must be done once per card before any signing or PKCS#11 operations.

```c
#include "opencie/cie_ext.h"

static CK_RV on_progress(int pct, const char* msg) {
    printf("[%3d%%] %s\n", pct, msg);
    return CKR_OK;
}

static CK_RV on_complete(const char* pan, const char* name, const char* serial) {
    printf("Enrolled: %s (%s), serial=%s\n", name, pan, serial);
    return CKR_OK;
}

int attempts = 0;
CK_RV rv = cie_enable("1234567890123456", "12345678",
                       &attempts, on_progress, on_complete);
if (rv != CKR_OK) {
    fprintf(stderr, "Enrolment failed (rv=%lu, attempts left=%d)\n", rv, attempts);
}
```

---

## 4. Retrieve the Certificate

```c
unsigned char* der = NULL;
unsigned long  derLen = 0;

CK_RV rv = cie_get_certificate("1234567890123456", &der, &derLen);
if (rv == CKR_OK) {
    // Use der[0..derLen-1] — parse with OpenSSL, write to file, etc.
    free(der); // caller must free
}
```

---

## 5. Sign a PDF

```c
#include "opencie/cie_ext.h"

static CK_RV on_progress(int pct, const char* msg) {
    printf("[%3d%%] %s\n", pct, msg);
    return CKR_OK;
}

static CK_RV on_sign_done(int ret) {
    printf("Sign result: %s\n", ret == 0 ? "OK" : "FAILED");
    return CKR_OK;
}

CK_RV rv = cie_sign(
    "input.pdf",          // input file
    "PDF",                // signature type
    "12345678",           // PIN
    "1234567890123456",   // PAN
    0,                    // page (0-based)
    10.0f, 10.0f,         // x, y (PDF points from bottom-left)
    200.0f, 50.0f,        // width, height
    NULL, 0,              // no stamp image
    "signed.pdf",         // output file
    on_progress,
    on_sign_done
);
```

---

## 6. Verify a Signed Document

```c
CK_RV rv = cie_verify("signed.pdf", NULL, 0, NULL);
if (rv == CKR_OK) {
    int count = (int)cie_get_sign_count();
    for (int i = 0; i < count; i++) {
        struct verifyInfo_t info = {0};
        cie_get_verify_info(i, &info);
        printf("Signer %d: %s %s, valid=%s\n",
               i, info.name, info.surname,
               info.isSignValid ? "yes" : "no");
    }
}
```

---

## 7. Timestamp a File

```c
static CK_RV on_progress(int p, const char* msg) {
    printf("[%d%%] %s\n", p, msg);
    return CKR_OK;
}

CK_RV rv = cie_timestamp(
    "document.pdf",                    // file to timestamp
    "https://freetsa.org/tsr",         // TSA endpoint
    NULL, NULL,                        // no HTTP auth
    "document.pdf.tst",                // output token path
    on_progress
);
```

---

## 8. Use as a PKCS#11 Token

The library implements the full PKCS#11 v2.40 interface. Use it with any PKCS#11-aware application.

### Firefox / Librewolf

`about:preferences` → Privacy & Security → Security Devices → **Load** → point to `libopencie-pkcs11.so`.

### Chromium / Chrome / Edge (NSS)

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /usr/lib/libopencie-pkcs11.so
```

### GNOME Papers, Okular and other poppler-based signers

These applications sign PDFs with poppler's NSS backend. poppler opens its
own NSS database, which is often not the Chromium one, so the module must be
registered in whichever database poppler actually picks:

1. **A Firefox profile**, if Firefox is installed. `poppler` searches
   `$XDG_CONFIG_HOME/mozilla/firefox` (or `~/.config/mozilla/firefox`) first,
   then `~/.mozilla/firefox`, and picks the profile directory whose name
   contains `default` with the most recently modified `cert9.db`.
2. Otherwise `sql:/etc/pki/nssdb`, if that directory exists.
3. Otherwise `~/.pki/nssdb`.

Find the exact profile `poppler` will pick with:

```bash
ls -t ~/.config/mozilla/firefox/*default*/cert9.db \
      ~/.mozilla/firefox/*default*/cert9.db 2>/dev/null | head -1
```

**Firefox users** must load the module into that profile, not into
`~/.pki/nssdb`: use `about:preferences` → Privacy & Security → Security
Devices → **Load**, or close Firefox and run:

```bash
modutil -dbdir sql:<firefox-profile-dir> -add "CIE" \
        -libfile /usr/lib/libopencie-pkcs11.so
```

**Non-Firefox users** register the module in `/etc/pki/nssdb` (root, if
present) or fall back to `~/.pki/nssdb` as shown in the Chromium example
above.

Verify with `pdfsig` (uses the same poppler NSS backend as Papers/Okular):

```bash
pdfsig -nssdir sql:<db-dir> -list-nicks
pdfsig in.pdf out.pdf -add-signature -nick "CIE:<label>" -nssdir sql:<db-dir>
```

Before opening the "Sign Digitally" dialog, make sure `pcscd` is running and
the card is already inserted:

```bash
systemctl enable --now pcscd.socket
```

Behaviour to expect:

- The PIN is requested when certificates are *listed* (right when the sign
  dialog opens), not when the signature is actually applied.
- The CIE PIN is 8 digits; 3 wrong attempts block the PIN (a PUK is then
  required to unblock it).
- The signature is `adbe.pkcs7.detached` or `ETSI.CAdES.detached` (PAdES
  B-B), SHA-256, RSA PKCS#1 v1.5, **without a trusted timestamp**. If you
  need a timestamped signature, use the SDK's `cie_sign` API with a TSA.
- The CIE authentication/signature certificate is **not** a qualified
  signature certificate; it does not produce a legally qualified electronic
  signature.

Known limitations:

- Flatpak builds of Papers cannot reach `pcscd`/`p11-kit` or load a module
  from `/usr/lib`; use your distribution's native package instead.
- Ubuntu's AppArmor profile for `/usr/bin/papers` blocks signing with a
  hardware token ([LP #2106133](https://bugs.launchpad.net/bugs/2106133),
  Debian #1099688, #1120163).

### OpenSSL (engine / provider)

```bash
openssl pkcs11 -module /usr/lib/libopencie-pkcs11.so -list-certs
```

### p11-kit

Add to `/etc/pkcs11/modules/opencie.module`:
```
module: /usr/lib/libopencie-pkcs11.so
```

---

## 9. Android Integration

On Android, the PC/SC layer is replaced by an NFC transport bridged via JNI. Before any card operation, pass the NFC tag from your `Activity`:

```java
// In your NFC dispatch handler:
NfcAdapter.getDefaultAdapter(this).enableReaderMode(this, tag -> {
    // Pass tag to native layer
    NativeLib.setNfcTag(tag);
}, NfcAdapter.FLAG_READER_NFC_B, null);
```

```c
// Native side (JNI)
extern void cie_set_nfc_tag(JNIEnv* env, jobject tag);
extern void cie_clear_nfc_tag(void);
extern void cie_set_data_dir(const char* path); // app's files dir
```

---

## Error Codes

Common `CK_RV` values returned by the API:

| Code | Value | Meaning |
|------|-------|---------|
| `CKR_OK` | 0 | Success |
| `CKR_ARGUMENTS_BAD` | 0x00000007 | Invalid argument |
| `CKR_PIN_INCORRECT` | 0x000000A0 | Wrong PIN |
| `CKR_PIN_LOCKED` | 0x000000A4 | PIN locked (no attempts left) |
| `CKR_DEVICE_ERROR` | 0x00000030 | Card/reader communication error |
| `CKR_HOST_MEMORY` | 0x00000002 | Memory allocation failure |
| `CKR_FUNCTION_FAILED` | 0x00000006 | General failure |
| `CKR_FUNCTION_NOT_SUPPORTED` | 0x00000054 | Not implemented |
| `CKR_TOKEN_NOT_PRESENT` | 0x000000E0 | No card in reader |
