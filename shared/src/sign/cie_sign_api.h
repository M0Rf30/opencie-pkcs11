// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cie_sign_api.h
 * @brief Public C API for CIE digital signature and verification operations.
 *
 * Defines the public interface for signing documents and verifying signatures
 * using the CIE (Carta d'Identità Elettronica) smart card. Supports multiple
 * signature formats including CAdES (PKCS#7/P7M), XAdES (XML), and PAdES
 * (PDF), with optional timestamping and certificate revocation checking.
 */

#pragma once

#ifdef CIE_SIGN_STATIC
#define CIE_SIGN_API
#else
#ifdef CIE_SIGN_EXPORTS
#define CIE_SIGN_API  //__declspec(dllexport)
#else
#define CIE_SIGN_API  //__declspec(dllimport)
#endif
#endif

#define MAX_LEN 256

#include "util/definitions.h"

#define VERIFIED_CERT_VALIDITY 0x000001
#define VERIFIED_CERT_REVOKED 0x000002
#define VERIFIED_CERT_SUSPENDED 0x000004
#define VERIFIED_CERT_GOOD 0x000008
#define VERIFIED_CERT_SHA256 0x000010
#define VERIFIED_CERT_QUALIFIED 0x000020
#define VERIFIED_CERT_CHAIN 0x000040

#define VERIFIED_CRL_LOADED 0x000080
#define VERIFIED_CRL_EXPIRED 0x000100

#define VERIFIED_SIGNED_ATTRIBUTE_CT 0x000200
#define VERIFIED_SIGNED_ATTRIBUTE_MD 0x000400
#define VERIFIED_SIGNED_ATTRIBUTE_SC 0x000800

#define VERIFIED_SIGNATURE 0x001000
#define VERIFIED_SHA256 0x002000

#define VERIFIED_CACERT_VALIDITY 0x004000
#define VERIFIED_CACERT_REVOKED 0x008000
#define VERIFIED_CACERT_SUSPENDED 0x010000
#define VERIFIED_CACERT_GOOD 0x020000
#define VERIFIED_CACERT_SIGNATURE 0x040000
#define VERIFIED_CACRL_LOADED 0x080000
#define VERIFIED_CACERT_FOUND 0x100000

#define VERIFIED_KEY_USAGE 0x200000

// TODO
// Certificate store with cache of certificate verification results.
// Revocation status and validity of certificates in the chain.

#define REVOCATION_STATUS_GOOD 0
#define REVOCATION_STATUS_REVOKED 1
#define REVOCATION_STATUS_SUSPENDED 2
#define REVOCATION_STATUS_UNKNOWN 3
#define REVOCATION_STATUS_NOTLOADED 4

#define CIE_SIGN_OPT_PKCS11 1
#define CIE_SIGN_OPT_SLOT 2
#define CIE_SIGN_OPT_PIN 3
#define CIE_SIGN_OPT_ALIAS 4
#define CIE_SIGN_OPT_CADES 5
#define CIE_SIGN_OPT_XADES 5
#define CIE_SIGN_OPT_DETACHED 6
#define CIE_SIGN_OPT_INPUTFILE 7
#define CIE_SIGN_OPT_OUTPUTFILE 8
#define CIE_SIGN_OPT_INPUTFILE_TYPE 9
#define CIE_SIGN_OPT_TSA_URL 10
#define CIE_SIGN_OPT_TSA_USERNAME 11
#define CIE_SIGN_OPT_TSA_PASSWORD 12
#define CIE_SIGN_OPT_VERIFY_REVOCATION 13
#define CIE_SIGN_OPT_LOG_LEVEL 14
#define CIE_SIGN_OPT_LOG_FILE 15
#define CIE_SIGN_OPT_INPUTFILE_PLAINTEXT 16
#define CIE_SIGN_OPT_CACERT_DIR 17
#define CIE_SIGN_OPT_PDF_SUBFILTER 18
#define CIE_SIGN_OPT_CONFIG_FILE 19
#define CIE_SIGN_OPT_PROXY 20
#define CIE_SIGN_OPT_PROXY_PORT 21
#define CIE_SIGN_OPT_PROXY_USRPASS 22
#define CIE_SIGN_OPT_OID_MAP_FILE 23
#define CIE_SIGN_OPT_TCP_TIMEOUT 24
#define CIE_SIGN_OPT_PDF_REASON 25
#define CIE_SIGN_OPT_PDF_NAME 26
#define CIE_SIGN_OPT_PDF_LOCATION 27
#define CIE_SIGN_OPT_PDF_PAGE 28
#define CIE_SIGN_OPT_PDF_LEFT 29
#define CIE_SIGN_OPT_PDF_BOTTOM 30
#define CIE_SIGN_OPT_PDF_WIDTH 31
#define CIE_SIGN_OPT_PDF_HEIGHT 32
#define CIE_SIGN_OPT_PDF_IMAGEPATH 33
#define CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA 34
#define CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA_VER 35

#define CIE_SIGN_OPT_ATR_LIST_FILE 36
#define CIE_SIGN_OPT_HASH_ALGO 37

#define CIE_SIGN_OPT_LICENSEE 38
#define CIE_SIGN_OPT_PRODUCTKEY 39

#define CIE_SIGN_OPT_RS_OTP_PIN 40
#define CIE_SIGN_OPT_RS_HSMTYPE 41
#define CIE_SIGN_OPT_RS_TYPE_OTP_AUTH 42
#define CIE_SIGN_OPT_RS_USERNAME 43
#define CIE_SIGN_OPT_RS_PASSWORD 44
#define CIE_SIGN_OPT_RS_CERTID 45
#define CIE_SIGN_OPT_RS_SERVICE_URL 46
#define CIE_SIGN_OPT_RS_USER_CODE 47
#define CIE_SIGN_OPT_RS_SERVICE_TYPE 48

#define CIE_SIGN_OPT_PDF_DESCRIPTION 50
#define CIE_SIGN_OPT_PDF_NAME_LABEL 51
#define CIE_SIGN_OPT_PDF_REASON_LABEL 52
#define CIE_SIGN_OPT_PDF_LOCATION_LABEL 53

#define CIE_SIGN_OPT_TSL_URL 60
#define CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE 61

#define CIE_SIGN_OPT_P12_FILEPATH 70
#define CIE_SIGN_OPT_P12_PASSWORD 71

#define CIE_SIGN_OPT_IAS_INSTANCE 80

#define CIE_SIGN_PDF_SUBFILTER_PKCS_DETACHED "adbe.pkcs7.detached"
#define CIE_SIGN_PDF_SUBFILTER_ETSI_CADES "ETSI.CAdES.detached"

#define CIE_SIGN_ERROR_BASE 0x84000000UL

#define CIE_SIGN_ERROR_UNEXPECTED CIE_SIGN_ERROR_BASE + 1
#define CIE_SIGN_ERROR_FILE_NOT_FOUND CIE_SIGN_ERROR_BASE + 2
#define CIE_SIGN_ERROR_DETACHED_PKCS7 CIE_SIGN_ERROR_BASE + 3
#define CIE_SIGN_ERROR_CERT_REVOKED CIE_SIGN_ERROR_BASE + 4
#define CIE_SIGN_ERROR_INVALID_FILE CIE_SIGN_ERROR_BASE + 5
#define CIE_SIGN_ERROR_INVALID_P11 CIE_SIGN_ERROR_BASE + 6
#define CIE_SIGN_ERROR_INVALID_ALIAS CIE_SIGN_ERROR_BASE + 7
#define CIE_SIGN_ERROR_INVALID_SIGOPT CIE_SIGN_ERROR_BASE + 8
#define CIE_SIGN_ERROR_ARRS_BASE CIE_SIGN_ERROR_BASE + 0x00100000
#define CIE_SIGN_ERROR_CERT_INVALID CIE_SIGN_ERROR_BASE + 9
#define CIE_SIGN_ERROR_CERT_EXPIRED CIE_SIGN_ERROR_BASE + 10
#define CIE_SIGN_ERROR_CACERT_NOTFOUND CIE_SIGN_ERROR_BASE + 11
#define CIE_SIGN_ERROR_CERT_NOTFOUND CIE_SIGN_ERROR_BASE + 12
#define CIE_SIGN_ERROR_CERT_NOT_FOR_SIGNATURE CIE_SIGN_ERROR_BASE + 13

#define CIE_SIGN_ERROR_TSL_LOAD CIE_SIGN_ERROR_BASE + 20
#define CIE_SIGN_ERROR_TSL_PARSE CIE_SIGN_ERROR_BASE + 21
#define CIE_SIGN_ERROR_TSL_INVALID CIE_SIGN_ERROR_BASE + 22
#define CIE_SIGN_ERROR_TSL_CACERTDIR_NOT_SET CIE_SIGN_ERROR_BASE + 23
#define CIE_SIGN_ERROR_TSA CIE_SIGN_ERROR_BASE + 30

#define CIE_SIGN_ERROR_WRONG_PIN CIE_SIGN_ERROR_BASE + 40
#define CIE_SIGN_ERROR_PIN_LOCKED CIE_SIGN_ERROR_BASE + 41

#define CIE_SIGN_FILETYPE_PLAINTEXT 0
#define CIE_SIGN_FILETYPE_P7M 1
#define CIE_SIGN_FILETYPE_PDF 2
#define CIE_SIGN_FILETYPE_M7M 3
#define CIE_SIGN_FILETYPE_TSR 4
#define CIE_SIGN_FILETYPE_TST 5
#define CIE_SIGN_FILETYPE_TSD 6
#define CIE_SIGN_FILETYPE_XML 7
#define CIE_SIGN_FILETYPE_AUTO 8

#define CIE_SIGN_ALGO_SHA1 1
#define CIE_SIGN_ALGO_SHA256 2
#define CIE_SIGN_ALGO_SHA512 3
#define CIE_SIGN_ALGO_MD5 4

#define LOG_TYPE_ERROR 1
#define LOG_TYPE_WARNING 2
#define LOG_TYPE_MESSAGE 3
#define LOG_TYPE_DEBUG 4

#define TYPE_OCSP 1
#define TYPE_CRL 2

#define CIE_SIGN_RS_SERVICE_TYPE_NONE 0
#define CIE_SIGN_RS_SERVICE_TYPE_ARUBA 1
#define CIE_SIGN_RS_SERVICE_TYPE_ITTELECOM 2

/** @brief Revocation information for a signer's certificate (OCSP or CRL). */
typedef struct _REVOCATION_INFO {
  int nType;             /**< Revocation check type: TYPE_OCSP or TYPE_CRL. */
  char szExpiration[60]; /**< Expiration date of the revocation data. */
  char
      szThisUpdate[60]; /**< "thisUpdate" timestamp from the revocation data. */
  int nRevocationStatus; /**< Revocation status (REVOCATION_STATUS_* constant).
                          */
  char szRevocationDate[60]; /**< Date the certificate was revoked, if
                                applicable. */
} REVOCATION_INFO;

/** @brief Information about a single signer extracted from a signed document.
 */
typedef struct _SIGNER_INFO {
  char szCN[MAX_LEN * 2];        /**< Common Name of the signer. */
  char szDN[MAX_LEN * 2];        /**< Distinguished Name of the signer. */
  char szGIVENNAME[MAX_LEN * 2]; /**< Given name of the signer. */
  char szSURNAME[MAX_LEN * 2];   /**< Surname of the signer. */
  char szSN[MAX_LEN * 2];     /**< Serial number of the signer's certificate. */
  char szCADN[MAX_LEN * 2];   /**< Distinguished Name of the issuing CA. */
  char** pszExtensions;       /**< Array of certificate extension strings. */
  int nExtensionsCount;       /**< Number of entries in pszExtensions. */
  char szExpiration[MAX_LEN]; /**< Certificate expiration date. */
  char szValidFrom[MAX_LEN];  /**< Certificate validity start date. */
  long bitmask;               /**< Bitmask of VERIFIED_* flags. */
  char szDigestAlgorithm[MAX_LEN]; /**< Digest algorithm used for signing. */
  char szSigningTime[MAX_LEN]; /**< Signing timestamp from signed attributes. */
  char szCertificateV2[MAX_LEN]; /**< ESS signing-certificate-v2 attribute. */
  BOOL b2011Error;    /**< True if 2011 regulation compliance error. */
  BYTE* pCertificate; /**< Raw DER-encoded signer certificate. */
  int nCertLen;       /**< Length of pCertificate in bytes. */
  void* pTimeStamp;   /**< Pointer to associated TS_INFO, if any. */
  REVOCATION_INFO*
      pRevocationInfo;        /**< Revocation check results for this signer. */
  void* pCounterSignatures;   /**< Pointer to counter-signature data. */
  int nCounterSignatureCount; /**< Number of counter-signatures. */
} SIGNER_INFO;

/** @brief Timestamp token information associated with a signature. */
typedef struct _TS_INFO {
  SIGNER_INFO signerInfo;                    /**< Signer info of the TSA. */
  char szTimestamp[MAX_LEN];                 /**< Timestamp value. */
  char szTimeStampImprintAlgorithm[MAX_LEN]; /**< Hash algorithm of the
                                                timestamp imprint. */
  char szTimeStampMessageImprint[MAX_LEN]; /**< Hex-encoded message imprint. */
  char szTimeStampSerial[MAX_LEN]; /**< Serial number of the timestamp token. */
} TS_INFO;

/** @brief Collection of signer information entries. */
typedef struct _SIGNER_INFOS {
  SIGNER_INFO* pSignerInfo; /**< Array of SIGNER_INFO structures. */
  int nCount;               /**< Number of entries in pSignerInfo. */
} SIGNER_INFOS;

/** @brief Complete verification result containing signers and timestamp info.
 */
typedef struct _VERIFY_INFO {
  SIGNER_INFOS* pSignerInfos; /**< Signer information array. */
  TS_INFO* pTSInfo;           /**< Timestamp information, or NULL if absent. */

} VERIFY_INFO;

/** @brief Top-level result structure returned by signature verification. */
typedef struct _VERIFY_RESULT {
  int nResultType;            /**< Result type identifier. */
  BOOL bVerifyCRL;            /**< Whether CRL verification was performed. */
  VERIFY_INFO verifyInfo;     /**< Detailed signer and timestamp information. */
  long nErrorCode;            /**< Error code (0 on success). */
  char szInputFile[MAX_PATH]; /**< Path to the signed input file. */
  char szPlainTextFile[MAX_PATH]; /**< Path to the extracted plaintext file. */
} VERIFY_RESULT;

/** @brief Information about a single certificate found in a PKCS#11 token. */
typedef struct _CERTIFICATE {
  char szLabel[MAX_LEN * 2];  /**< Certificate label/alias. */
  char szCN[MAX_LEN * 2];     /**< Subject Common Name. */
  char szSN[MAX_LEN * 2];     /**< Certificate serial number. */
  char szCACN[MAX_LEN * 2];   /**< Issuer Common Name. */
  char szExpiration[MAX_LEN]; /**< Expiration date string. */
  char szValidFrom[MAX_LEN];  /**< Validity start date string. */
  BYTE* pCertificate;         /**< Raw DER-encoded certificate. */
  int nCertLen;               /**< Length of pCertificate in bytes. */
} CERTIFICATE;

/** @brief Collection of certificates from a PKCS#11 token. */
typedef struct _CERTIFICATES {
  CERTIFICATE* pCertificate; /**< Array of CERTIFICATE structures. */
  int nCount;                /**< Number of entries in pCertificate. */
} CERTIFICATES;

/** @brief Opaque context handle for sign/verify operations. */
typedef void* CIE_SIGN_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Set a global library option (generic pointer variant).
 *  @param option  Option identifier (CIE_SIGN_OPT_* constant).
 *  @param value   Pointer to the option value.
 *  @return 0 on success, or a CIE_SIGN_ERROR_* code on failure. */
CIE_SIGN_API long cie_sign_set(int option, void* value);

/** @brief Set a global library option (integer variant). */
CIE_SIGN_API long cie_sign_set_int(int option, int value);

/** @brief Set a global library option (string variant). */
CIE_SIGN_API long cie_sign_set_string(int option, char* value);

/** @brief Release all memory allocated by the library. */
CIE_SIGN_API void cie_sign_cleanup();

///////////////////////////////////
// Digital signature functions

/** @brief Initialize a new digital signature operation.
 *  @return Opaque context handle for use with cie_sign_sign_* functions. */
CIE_SIGN_API CIE_SIGN_CTX cie_sign_sign_init(void);

/** @brief Set a signing option (integer variant).
 *  @param ctx     Context handle from cie_sign_sign_init().
 *  @param option  Option identifier (CIE_SIGN_OPT_* constant).
 *  @param value   Integer value for the option. */
CIE_SIGN_API long cie_sign_sign_set_int(CIE_SIGN_CTX ctx, int option,
                                        int value);

/** @brief Set a signing option (string variant). */
CIE_SIGN_API long cie_sign_sign_set_string(CIE_SIGN_CTX ctx, int option,
                                           char* value);

/** @brief Set a signing option (generic pointer variant). */
CIE_SIGN_API long cie_sign_sign_set(CIE_SIGN_CTX ctx, int option, void* value);

/** @brief Execute the digital signature according to the configured options.
 *  @param ctx  Context handle with all signing options set.
 *  @return 0 on success, or a CIE_SIGN_ERROR_* code on failure. */
CIE_SIGN_API long cie_sign_sign_sign(CIE_SIGN_CTX ctx);

/** @brief Release memory allocated during the signing operation. */
CIE_SIGN_API long cie_sign_sign_cleanup(CIE_SIGN_CTX ctx);

/** @brief Retrieve the list of certificates available for signing.
 *  @param ctx    Context handle from cie_sign_sign_init().
 *  @param certs  Output structure to receive the certificate list. */
CIE_SIGN_API long cie_sign_sign_getcertificates(CIE_SIGN_CTX ctx,
                                                CERTIFICATES* certs);

/** @brief Free the certificate list returned by
 * cie_sign_sign_getcertificates(). */
CIE_SIGN_API void cie_sign_sign_freecertificates(CERTIFICATES* certs);

///////////////////////////////////////////

//////////////////////////////////////////
// Signature verification functions

/** @brief Initialize a new signature verification operation.
 *  @return Opaque context handle for use with cie_sign_verify_* functions. */
CIE_SIGN_API CIE_SIGN_CTX cie_sign_verify_init(void);

/** @brief Set a verification option (generic pointer variant). */
CIE_SIGN_API long cie_sign_verify_set(CIE_SIGN_CTX ctx, int option,
                                      void* value);
/** @brief Set a verification option (integer variant). */
CIE_SIGN_API long cie_sign_verify_set_int(CIE_SIGN_CTX ctx, int option,
                                          int value);
/** @brief Set a verification option (string variant). */
CIE_SIGN_API long cie_sign_verify_set_string(CIE_SIGN_CTX ctx, int option,
                                             char* value);

/** @brief Execute the verification according to the configured options.
 *  @param ctx            Context handle with all verification options set.
 *  @param pVerifyResult  Output structure to receive the verification results.
 *  @return 0 on success, or a CIE_SIGN_ERROR_* code on failure. */
CIE_SIGN_API long cie_sign_verify_verify(CIE_SIGN_CTX ctx,
                                         VERIFY_RESULT* pVerifyResult);

/** @brief Free the VERIFY_RESULT structure populated by
 * cie_sign_verify_verify(). */
CIE_SIGN_API long cie_sign_verify_cleanup_result(VERIFY_RESULT* pVerifyResult);

/** @brief Release memory allocated during the verification operation. */
CIE_SIGN_API long cie_sign_verify_cleanup(CIE_SIGN_CTX ctx);

/** @brief Extract the original document from a PKCS#7 (P7M) signed file.
 *  @param ctx  Context handle with input/output file options set.
 *  @return 0 on success, or a CIE_SIGN_ERROR_* code on failure. */
CIE_SIGN_API long cie_sign_get_file_from_p7m(CIE_SIGN_CTX ctx);

#ifdef __cplusplus
}
#endif
