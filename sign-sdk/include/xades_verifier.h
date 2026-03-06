// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file xades_verifier.h
 * @brief XAdES (XML Advanced Electronic Signatures) verification.
 */

#pragma once

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "asn1/certificate.h"
#include "util/array.h"

/**
 * Metadata and digest values for a referenced data file in an XAdES signature.
 */
struct RefDataFile {
  char* szId;                       ///< Data file id.
  char* szFileName;                 ///< Signed document file name.
  char* szMimeType;                 ///< Data file MIME type.
  char* szContentType;              ///< DETATCHED, EMBEDDED or EMBEDDED_BASE64.
  long nSize;                       ///< File size (unencoded).
  char* szDigestType;               ///< Digest type.
  ByteDynArray mbufDigest;          ///< Actual DataFile digest value.
  ByteDynArray mbufDetachedDigest;  ///< Detached file digest.
  int nAttributes;                  ///< Number of other attributes.
  char* szCharset;                  ///< DataFile initial codepage.
  char** pAttNames;                 ///< Other attribute names.
  char** pAttValues;                ///< Other attribute values.
  ByteDynArray mbufContent;
};

/**
 * Per-signer data extracted from an XAdES signature element.
 */
struct SignatureInfo {
  char* szId;         ///< Signature id.
  int nDocs;          ///< Number of separate documents signed.
  char* szTimeStamp;  ///< Signature timestamp in format "YYYY-MM-DDTHH:MM:SSZ".
  ByteDynArray sigPropDigest;
  ByteDynArray sigPropRealDigest;
  ByteDynArray sigInfoRealDigest;
  ByteDynArray sigValue;  ///< RSA+SHA1 signature value.
  CCertificate*
      pX509Cert;  ///< X.509 certificate (used internally during loading).
  ByteDynArray mbufOrigContent;
  int nDigestAlgo;
  bool bCAdES;
};

/**
 * Parsed XAdES document containing data file references and signature info.
 */
struct XAdESDoc {
  char* szFormat;     ///< Data format name.
  char* szFormatVer;  ///< Data format version.
  int nDataFiles;
  RefDataFile** pRefDataFiles;
  int nSignatures;
  SignatureInfo** ppSignatures;
};

/**
 * Verifies XAdES-BES and XAdES-T signatures embedded in XML documents.
 */
class CXAdESVerifier {
 public:
  CXAdESVerifier(void);
  virtual ~CXAdESVerifier(void);

  /** Parse an XAdES document from a buffer. */
  long Load(BYTE* buf, int len);

  /** Parse an XAdES document from a file. */
  long Load(char* szFilename);

  /** Return the signer's X.509 certificate at @p index. */
  CCertificate* GetCertificate(int index);

  /** Return the digest algorithm OID used by signer @p index. */
  CASN1ObjectIdentifier GetDigestAlgorithm(int index);

  /** Verify the XAdES signature at @p index against the given date. */
  int verifySignature(int index, const char* szDateTime,
                      REVOCATION_INFO* pRevocationInfo);

 private:
  static XAdESDoc* parseXAdESFile(char* szFilename);
  static void parseSignatureNode(xmlXPathContextPtr xpathCtx,
                                 xmlNodeSetPtr signatureNodes,
                                 XAdESDoc* pXAdESDoc);
  static bool m_bLibXmlInitialized;
  XAdESDoc* m_pXAdESDoc;
};
