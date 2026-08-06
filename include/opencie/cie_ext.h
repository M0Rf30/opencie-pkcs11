// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// cie_ext.h — Public C interface for CIE-specific extensions exported by
// libopencie-pkcs11.
//
// All functions use the same CK_RV return type as the standard PKCS#11
// interface; include pkcs11/pkcs11.h (or cryptoki.h) for the type definitions.
//
// Callback types
// --------------
//   PROGRESS_CALLBACK  – periodic progress notifications
//     int  progress   : 0–100 percentage
//     char szMessage  : human-readable status string
//
//   COMPLETED_CALLBACK – fired once enrolment finishes
//     char szPan      : PAN of the enrolled card
//     char szName     : cardholder name
//     char ef_seriale : card serial number
//
//   SIGN_COMPLETED_CALLBACK – fired once cie_sign finishes
//     int ret         : result code (0 = success)

#pragma once

#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Platform portability — map the PKCS#11 calling-convention macro to nothing
// when this header is used outside the main build tree.
// ---------------------------------------------------------------------------
#ifndef CK_ENTRY
#ifdef _WIN32
#define CK_ENTRY __declspec(dllexport)
#else
#define CK_ENTRY
#endif
#endif

#ifndef CK_RV
typedef unsigned long CK_RV;
#endif

// Common PKCS#11 return codes — defined here so callers do not need to
// include the full pkcs11t.h header.
#ifndef CKR_OK
#define CKR_OK 0x00000000UL
#endif
#ifndef CKR_GENERAL_ERROR
#define CKR_GENERAL_ERROR 0x00000005UL
#endif
#ifndef CKR_ARGUMENTS_BAD
#define CKR_ARGUMENTS_BAD 0x00000007UL
#endif
#ifndef CKR_HOST_MEMORY
#define CKR_HOST_MEMORY 0x00000002UL
#endif
#ifndef CKR_FUNCTION_FAILED
#define CKR_FUNCTION_FAILED 0x00000006UL
#endif
#ifndef CKR_DEVICE_ERROR
#define CKR_DEVICE_ERROR 0x00000030UL
#endif
#ifndef CKR_TOKEN_NOT_PRESENT
#define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#endif
#ifndef CKR_TOKEN_NOT_RECOGNIZED
#define CKR_TOKEN_NOT_RECOGNIZED 0x000000E1UL
#endif

// ---------------------------------------------------------------------------
// Callback typedefs
// ---------------------------------------------------------------------------

/** Progress callback: called repeatedly during long operations. */
typedef CK_RV (*PROGRESS_CALLBACK)(int progress, const char* szMessage);

/** Completion callback: called once when enrolment (cie_enable) finishes. */
typedef CK_RV (*COMPLETED_CALLBACK)(const char* szPan, const char* szName,
                                    const char* ef_seriale);

/** Sign completion callback: called once when cie_sign finishes. */
typedef CK_RV (*SIGN_COMPLETED_CALLBACK)(int ret);

// ---------------------------------------------------------------------------
// verifyInfo_t — returned by cie_get_verify_info
// ---------------------------------------------------------------------------

#define OPENCIE_MAX_LEN 512

struct verifyInfo_t {
  char name[OPENCIE_MAX_LEN * 2];
  char surname[OPENCIE_MAX_LEN * 2];
  char cn[OPENCIE_MAX_LEN * 2];
  char signingTime[OPENCIE_MAX_LEN * 2];
  char cadn[OPENCIE_MAX_LEN * 2];
  int CertRevocStatus;
  int isSignValid; /* non-zero = valid */
  int isCertValid; /* non-zero = valid */
};

// ---------------------------------------------------------------------------
// Enrolment functions
// ---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enrol a CIE card identified by @p szPAN using the 8-digit numeric @p szPIN.
 * @param szPAN             PAN identifying the card (NUL-terminated string).
 * @param szPIN             8-digit numeric PIN (NUL-terminated string).
 * @param attempts          Set to remaining attempts on PIN error; may be NULL.
 * @param progressCallBack  Progress callback; must not be NULL.
 * @param completedCallBack Completion callback; must not be NULL.
 * @return CKR_OK on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_enable(const char* szPAN, const char* szPIN, int* attempts,
                          PROGRESS_CALLBACK progressCallBack,
                          COMPLETED_CALLBACK completedCallBack);

/**
 * Check whether the card identified by @p szPAN is currently enrolled.
 * @return 1 if enrolled, 0 if not.
 */
CK_RV CK_ENTRY cie_is_enabled(const char* szPAN);

/**
 * Remove the enrolment for the card identified by @p szPAN.
 * @return CKR_OK on success, CKR_FUNCTION_FAILED if the card was not enrolled.
 */
CK_RV CK_ENTRY cie_disable(const char* szPAN);

// ---------------------------------------------------------------------------
// PIN management functions
// ---------------------------------------------------------------------------

/**
 * Change the PIN from @p szCurrentPIN to @p szNewPIN.
 * @param szCurrentPIN     Current PIN (NUL-terminated).
 * @param szNewPIN         New PIN (NUL-terminated).
 * @param attempts         Set to remaining attempts on error; may be NULL.
 * @param progressCallBack Progress callback; must not be NULL.
 * @return CKR_OK on success.
 */
CK_RV CK_ENTRY cie_change_pin(const char* szCurrentPIN, const char* szNewPIN,
                              int* attempts,
                              PROGRESS_CALLBACK progressCallBack);

/**
 * Unblock the PIN using the PUK and set a new PIN.
 * @param szPUK            PUK string (NUL-terminated).
 * @param szNewPIN         New PIN to set (NUL-terminated).
 * @param attempts         Set to remaining PUK attempts on error; may be NULL.
 * @param progressCallBack Progress callback; must not be NULL.
 * @return CKR_OK on success.
 */
CK_RV CK_ENTRY cie_unblock_pin(const char* szPUK, const char* szNewPIN,
                               int* attempts,
                               PROGRESS_CALLBACK progressCallBack);

// ---------------------------------------------------------------------------
// Sign & verify functions
// ---------------------------------------------------------------------------

/**
 * Sign a PDF file on behalf of the card identified by @p pan.
 *
 * @param inFilePath        Path to the input PDF file.
 * @param type              Signature type string (e.g. "PDF", "P7M").
 * @param pin               Card PIN (NUL-terminated).
 * @param pan               PAN of the enrolled card.
 * @param page              Page index (0-based) for the signature widget.
 * @param x                 X position of the signature widget (points).
 * @param y                 Y position of the signature widget (points).
 * @param w                 Width of the signature widget (points).
 * @param h                 Height of the signature widget (points).
 * @param imageData         PNG image bytes for the signature stamp; may be
 * NULL.
 * @param imageDataLen      Length of imageData in bytes; 0 if imageData is
 * NULL.
 * @param outFilePath       Path where the signed output file is written.
 * @param progressCallBack  Progress callback; must not be NULL.
 * @param completedCallBack Sign-completion callback; must not be NULL.
 * @return CKR_OK on success.
 */
CK_RV CK_ENTRY cie_sign(const char* inFilePath, const char* type,
                        const char* pin, const char* pan, int page, float x,
                        float y, float w, float h,
                        const unsigned char* imageData, int imageDataLen,
                        const char* outFilePath,
                        PROGRESS_CALLBACK progressCallBack,
                        SIGN_COMPLETED_CALLBACK completedCallBack);

/**
 * Verify a signed document.
 *
 * @param inFilePath    Path to the signed input file.
 * @param proxyAddress  HTTP proxy address; may be NULL.
 * @param proxyPort     HTTP proxy port (0 = no proxy).
 * @param usrPass       Proxy username:password; may be NULL.
 * @return Number of valid signatures found, or a PKCS#11 error code.
 */
CK_RV CK_ENTRY cie_verify(const char* inFilePath, const char* proxyAddress,
                          int proxyPort, const char* usrPass);

/**
 * Return the number of signatures found by the last cie_verify call.
 * @return Signature count, or a PKCS#11 error code.
 */
CK_RV CK_ENTRY cie_get_sign_count(void);

/**
 * Retrieve signer information for the n-th signature found by the last
 * cie_verify call.
 *
 * @param index  Zero-based signature index.
 * @param vInfos Pointer to a caller-allocated verifyInfo_t structure to fill.
 * @return 0 on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_get_verify_info(int index, struct verifyInfo_t* vInfos);

int CK_ENTRY cie_reader_count(void);

int CK_ENTRY cie_reader_watch(int current_count);

int CK_ENTRY cie_reader_name(char* buf, int buf_len);

/**
 * Extract the original (unwrapped) document from a .p7m envelope.
 *
 * @param inFilePath   Path to the .p7m input file.
 * @param outFilePath  Path where the plain document is written.
 * @return 0 on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_extract_p7m(const char* inFilePath, const char* outFilePath);

/**
 * Retrieve the DER-encoded X.509 certificate for an enrolled CIE card.
 *
 * Reads from the local AES-encrypted cache written by cie_enable().
 * The caller must free *outDer with free() after use.
 *
 * @param pan     NUL-terminated PAN string identifying the card.
 * @param outDer  On success, set to a malloc'd buffer with the DER cert.
 * @param outLen  On success, set to the byte length of *outDer.
 * @return CKR_OK on success, CKR_ARGUMENTS_BAD / CKR_DEVICE_ERROR /
 *         CKR_HOST_MEMORY / CKR_FUNCTION_FAILED otherwise.
 */
CK_RV CK_ENTRY cie_get_certificate(const char* pan, unsigned char** outDer,
                                   unsigned long* outLen);

// ---------------------------------------------------------------------------
// Timestamp functions
// ---------------------------------------------------------------------------

/**
 * Request a standalone RFC 3161 timestamp for a file.
 *
 * Does not require a CIE card. Computes the SHA-256 digest of @p inFilePath
 * and sends a TimeStampRequest to @p tsaUrl. The DER-encoded TimeStampToken
 * is written to @p outTokenPath.
 *
 * @param inFilePath        Path to the file to timestamp.
 * @param tsaUrl            TSA server endpoint URL.
 * @param tsaUsername       HTTP Basic auth username; may be NULL.
 * @param tsaPassword       HTTP Basic auth password; may be NULL.
 * @param outTokenPath      Path where the .tst token is written.
 * @param progressCallBack  Progress callback; must not be NULL.
 * @return CKR_OK on success.
 */
CK_RV CK_ENTRY cie_timestamp(const char* inFilePath, const char* tsaUrl,
                             const char* tsaUsername, const char* tsaPassword,
                             const char* outTokenPath,
                             PROGRESS_CALLBACK progressCallBack);

// ---------------------------------------------------------------------------
// Chip data-group readers (ICAO 9303)
// ---------------------------------------------------------------------------

/**
 * Read DG1 (MRZ) and DG2 (portrait photo) in a single PACE session.
 *
 * Reads both data groups with a single DH key exchange and PIN verify.
 * The photo is returned as PNG bytes (JPEG2000 decoded internally).
 *
 * @param pin       NUL-terminated 8-digit numeric PIN.
 * @param mrzOut    Buffer for raw DG1 TLV bytes (≥ 4096 bytes recommended).
 * @param mrzLen    In: capacity of mrzOut; out: bytes written.
 * @param photoOut  Buffer for PNG photo bytes (≥ 524288 bytes recommended).
 * @param photoLen  In: capacity of photoOut; out: bytes written.
 * @return CKR_OK on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_read_dgs(const char* pin, char* mrzOut, size_t* mrzLen,
                            unsigned char* photoOut, size_t* photoLen);

// ---------------------------------------------------------------------------
// Low-level cryptographic helpers
// ---------------------------------------------------------------------------

/**
 * Build a DER-encoded PKCS#1 DigestInfo structure from a raw digest value.
 *
 * Used when performing raw RSA signing outside the normal cie_sign flow.
 * Supported algorithm IDs (from <openssl/obj_mac.h>):
 *   NID_sha1 (65), NID_sha256 (672), NID_sha384 (673), NID_sha512 (674)
 *
 * @param algid            OpenSSL NID of the digest algorithm.
 * @param pbtDigest        Raw digest bytes.
 * @param btDigestLen      Length of pbtDigest in bytes.
 * @param pbtDigestInfo    Output buffer to receive the DER-encoded DigestInfo.
 * @param pbtDigestInfoLen On input: size of pbtDigestInfo; on output: bytes
 * written.
 * @return 1 on success, 0 if the output buffer is too small.
 */
int CK_ENTRY make_digest_info(int algid, const unsigned char* pbtDigest,
                              size_t btDigestLen, unsigned char* pbtDigestInfo,
                              size_t* pbtDigestInfoLen);

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/**
 * Semantic classification of a CIE card failure, derived from the ISO 7816
 * status word returned by the card.
 */
typedef enum cie_error_kind {
  CIE_ERR_NONE = 0,                   /* no error recorded */
  CIE_ERR_WRONG_PIN = 1,              /* 0x63Cx, 0x6300, 0x6700 */
  CIE_ERR_PIN_BLOCKED = 2,            /* 0x6983 */
  CIE_ERR_PIN_NOT_SET = 3,            /* 0x6984 */
  CIE_ERR_SECURITY_NOT_SATISFIED = 4, /* 0x6982 */
  CIE_ERR_FILE_NOT_FOUND = 5,         /* 0x6A82 */
  CIE_ERR_WRONG_PARAMS = 6,           /* 0x6A80, 0x6A86, 0x6A88, 0x6B00 */
  CIE_ERR_INS_NOT_SUPPORTED = 7,      /* 0x6D00, 0x6E00 */
  CIE_ERR_CARD_COMMUNICATION = 8,     /* transport/SM failure, no usable SW */
  CIE_ERR_UNKNOWN = 9                 /* a status word we do not classify */
} cie_error_kind;

/**
 * Classify an ISO 7816 status word. Pure function, no card required.
 */
cie_error_kind CK_ENTRY cie_classify_sw(uint16_t sw);

/**
 * Detail for the most recent failed cie_* call on the CALLING THREAD.
 *
 * @param outKind receives the classification; may be NULL.
 * @param outSw   receives the raw status word, or 0 when the failure carried
 *                no status word; may be NULL.
 * @return CKR_OK always.
 */
CK_RV CK_ENTRY cie_last_error(cie_error_kind* outKind, uint16_t* outSw);

#ifdef __cplusplus
}
#endif
