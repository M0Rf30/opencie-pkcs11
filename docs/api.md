# API Reference — opencie-pkcs11

Public C interface declared in [`include/opencie/cie_ext.h`](../include/opencie/cie_ext.h).

All functions return `CK_RV` (an `unsigned long` PKCS#11 error code) unless noted otherwise.
`CKR_OK` (0) indicates success.

---

## Callback Types

```c
// Called repeatedly during long operations (0–100 progress, human-readable message)
typedef CK_RV (*PROGRESS_CALLBACK)(int progress, const char* szMessage);

// Called once when cie_enable() finishes
typedef CK_RV (*COMPLETED_CALLBACK)(const char* szPan, const char* szName,
                                    const char* ef_seriale);

// Called once when cie_sign() finishes (ret == 0 means success)
typedef CK_RV (*SIGN_COMPLETED_CALLBACK)(int ret);
```

---

## Data Structures

### `verifyInfo_t`

Filled by `cie_get_verify_info()`. All string fields are NUL-terminated, max 1024 bytes.

```c
#define OPENCIE_MAX_LEN 512

struct verifyInfo_t {
  char name[OPENCIE_MAX_LEN * 2];        // Signer given name
  char surname[OPENCIE_MAX_LEN * 2];     // Signer surname
  char cn[OPENCIE_MAX_LEN * 2];          // Certificate Common Name
  char signingTime[OPENCIE_MAX_LEN * 2]; // Signing timestamp (ISO 8601)
  char cadn[OPENCIE_MAX_LEN * 2];        // CA Distinguished Name
  int CertRevocStatus;                   // Certificate revocation status
  int isSignValid;                       // Non-zero if signature is valid
  int isCertValid;                       // Non-zero if certificate is valid
};
```

---

## Enrolment

### `cie_enable`

Enrol a CIE card. Reads the card's certificate and stores it in an AES-encrypted local cache keyed by PAN.

```c
CK_RV cie_enable(const char* szPAN,
                 const char* szPIN,
                 int* attempts,
                 PROGRESS_CALLBACK progressCallBack,
                 COMPLETED_CALLBACK completedCallBack);
```

| Parameter | Description |
|-----------|-------------|
| `szPAN` | PAN identifying the card (NUL-terminated) |
| `szPIN` | 8-digit numeric PIN (NUL-terminated) |
| `attempts` | Set to remaining PIN attempts on error; may be `NULL` |
| `progressCallBack` | Progress callback; must not be `NULL` |
| `completedCallBack` | Completion callback; must not be `NULL` |

**Returns:** `CKR_OK` on success. `CKR_PIN_INCORRECT` with `*attempts` decremented on wrong PIN.

---

### `cie_is_enabled`

Check whether a card is enrolled.

```c
CK_RV cie_is_enabled(const char* szPAN);
```

**Returns:** `1` if enrolled, `0` if not.

---

### `cie_disable`

Remove the enrolment for a card.

```c
CK_RV cie_disable(const char* szPAN);
```

**Returns:** `CKR_OK` on success, `CKR_FUNCTION_FAILED` if the card was not enrolled.

---

## PIN Management

### `cie_change_pin`

Change the card PIN.

```c
CK_RV cie_change_pin(const char* szCurrentPIN,
                     const char* szNewPIN,
                     int* attempts,
                     PROGRESS_CALLBACK progressCallBack);
```

| Parameter | Description |
|-----------|-------------|
| `szCurrentPIN` | Current PIN (NUL-terminated) |
| `szNewPIN` | New PIN (NUL-terminated) |
| `attempts` | Set to remaining attempts on error; may be `NULL` |
| `progressCallBack` | Progress callback; must not be `NULL` |

---

### `cie_unblock_pin`

Unblock the PIN using the PUK and set a new PIN.

```c
CK_RV cie_unblock_pin(const char* szPUK,
                      const char* szNewPIN,
                      int* attempts,
                      PROGRESS_CALLBACK progressCallBack);
```

| Parameter | Description |
|-----------|-------------|
| `szPUK` | PUK string (NUL-terminated) |
| `szNewPIN` | New PIN to set (NUL-terminated) |
| `attempts` | Set to remaining PUK attempts on error; may be `NULL` |
| `progressCallBack` | Progress callback; must not be `NULL` |

---

## Certificate

### `cie_get_certificate`

Retrieve the DER-encoded X.509 certificate for an enrolled card. Reads from the local AES-encrypted cache written by `cie_enable()`.

```c
CK_RV cie_get_certificate(const char* pan,
                           unsigned char** outDer,
                           unsigned long* outLen);
```

| Parameter | Description |
|-----------|-------------|
| `pan` | NUL-terminated PAN string |
| `outDer` | On success, set to a `malloc`'d buffer with the DER cert. **Caller must `free()`** |
| `outLen` | On success, set to the byte length of `*outDer` |

**Returns:** `CKR_OK`, `CKR_ARGUMENTS_BAD`, `CKR_DEVICE_ERROR`, `CKR_HOST_MEMORY`, or `CKR_FUNCTION_FAILED`.

---

## Signing & Verification

### `cie_sign`

Sign a PDF file or produce a P7M envelope using the enrolled CIE card.

```c
CK_RV cie_sign(const char* inFilePath,
               const char* type,
               const char* pin,
               const char* pan,
               int page,
               float x, float y, float w, float h,
               const unsigned char* imageData,
               int imageDataLen,
               const char* outFilePath,
               PROGRESS_CALLBACK progressCallBack,
               SIGN_COMPLETED_CALLBACK completedCallBack);
```

| Parameter | Description |
|-----------|-------------|
| `inFilePath` | Path to the input file |
| `type` | `"PDF"` for PDF signatures, `"P7M"` for CMS/PKCS#7 envelopes |
| `pin` | Card PIN (NUL-terminated) |
| `pan` | PAN of the enrolled card |
| `page` | Page index (0-based) for the PDF signature widget |
| `x`, `y`, `w`, `h` | Position and size of the signature widget in PDF points |
| `imageData` | PNG image bytes for the signature stamp; may be `NULL` |
| `imageDataLen` | Length of `imageData` in bytes; `0` if `imageData` is `NULL` |
| `outFilePath` | Path where the signed output file is written |
| `progressCallBack` | Progress callback; must not be `NULL` |
| `completedCallBack` | Sign-completion callback; must not be `NULL` |

---

### `cie_verify`

Verify a signed document (PDF or P7M). Results are stored internally and retrieved with `cie_get_sign_count` / `cie_get_verify_info`.

```c
CK_RV cie_verify(const char* inFilePath,
                 const char* proxyAddress,
                 int proxyPort,
                 const char* usrPass);
```

| Parameter | Description |
|-----------|-------------|
| `inFilePath` | Path to the signed input file |
| `proxyAddress` | HTTP proxy address; may be `NULL` |
| `proxyPort` | HTTP proxy port; `0` = no proxy |
| `usrPass` | Proxy `username:password`; may be `NULL` |

---

### `cie_get_sign_count`

Return the number of signatures found by the last `cie_verify` call.

```c
CK_RV cie_get_sign_count(void);
```

---

### `cie_get_verify_info`

Retrieve signer information for the n-th signature.

```c
CK_RV cie_get_verify_info(int index, struct verifyInfo_t* vInfos);
```

| Parameter | Description |
|-----------|-------------|
| `index` | Zero-based signature index |
| `vInfos` | Caller-allocated `verifyInfo_t` to fill |

---

### `cie_extract_p7m`

Extract the original document from a `.p7m` CMS envelope.

```c
CK_RV cie_extract_p7m(const char* inFilePath, const char* outFilePath);
```

---

## Reader Discovery

```c
int cie_reader_count(void);           // Number of connected smart-card readers
int cie_reader_watch(int current_count); // Block until reader count changes; returns new count
int cie_reader_name(char* buf, int buf_len); // Name of the first reader into buf
```

---

## Low-level Helpers

### `make_digest_info`

Build a DER-encoded PKCS#1 DigestInfo structure for raw RSA signing flows.

```c
int make_digest_info(int algid,
                     const unsigned char* pbtDigest,
                     size_t btDigestLen,
                     unsigned char* pbtDigestInfo,
                     size_t* pbtDigestInfoLen);
```

Supported `algid` values (OpenSSL NIDs):

| NID | Algorithm |
|-----|-----------|
| 65 | `NID_sha1` |
| 672 | `NID_sha256` |
| 673 | `NID_sha384` |
| 674 | `NID_sha512` |

**Returns:** `1` on success, `0` if the output buffer is too small.

---

## Android-only Symbols

On Android, three additional symbols bridge the JNI NFC transport:

```c
void cie_set_nfc_tag(JNIEnv* env, jobject tag);
void cie_clear_nfc_tag(void);
void cie_set_data_dir(const char* path);
jint JNI_OnLoad(JavaVM* vm, void* reserved);
```

---

## PKCS#11 Standard Interface

All 69 standard `C_*` functions are present. The following 12 return `CKR_FUNCTION_NOT_SUPPORTED`:

`C_CancelFunction`, `C_CopyObject`, `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate`,
`C_DeriveKey`, `C_DigestEncryptUpdate`, `C_DigestKey`, `C_GetFunctionStatus`,
`C_InitToken`, `C_SignEncryptUpdate`, `C_UnwrapKey`, `C_WrapKey`
