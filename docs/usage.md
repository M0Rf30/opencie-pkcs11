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

## 7. Use as a PKCS#11 Token

The library implements the full PKCS#11 v2.40 interface. Use it with any PKCS#11-aware application.

### Firefox / Librewolf

`about:preferences` → Privacy & Security → Security Devices → **Load** → point to `libopencie-pkcs11.so`.

### Chromium / Chrome / Edge (NSS)

```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "CIE" \
        -libfile /usr/lib/libopencie-pkcs11.so
```

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

## 8. Android Integration

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
