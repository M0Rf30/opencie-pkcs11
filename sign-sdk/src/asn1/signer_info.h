// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file signer_info.h
 * @brief CMS SignerInfo (RFC 5652 Section 5.3) ASN.1 structure.
 *
 * Represents a single signer's contribution within a CMS SignedData,
 * including the issuer identification, digest and encryption algorithms,
 * authenticated/unauthenticated attributes (e.g. signing time,
 * countersignatures, timestamp tokens), and the encrypted digest value.
 */

#pragma once

#include "asn1/asn1_set_of.h"
#include "asn1/certificate.h"

#define MAX_RSA_MODULUS_LEN 512

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/issuer_and_serial_number.h"
#include "asn1/time_stamp_token.h"
#include "asn1_octet_string.h"
#include "sign/cie_sign_api.h"

/**
 * @brief CMS SignerInfo structure (RFC 5652 Section 5.3).
 *
 * Contains all information pertaining to a single signer: issuer/serial
 * identification, digest algorithm, signature algorithm, the encrypted
 * digest (signature value), and optional authenticated and unauthenticated
 * attribute sets (signing time, content type, message digest,
 * countersignatures, timestamp tokens, etc.).
 */
class CSignerInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a SignerInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SignerInfo SEQUENCE.
   */
  CSignerInfo(BufferedReader& reader);

  /**
   * @brief Constructs a SignerInfo from an already-parsed ASN.1 object.
   * @param signerInfo Generic ASN.1 object containing SignerInfo encoding.
   */
  CSignerInfo(const CASN1Object& signerInfo);

  /**
   * @brief Constructs a SignerInfo from explicit components.
   * @param issuer     Issuer name and serial number identifying the signer.
   * @param digestAlgo Digest algorithm used (e.g. SHA-256).
   * @param encAlgo    Signature (encryption) algorithm (e.g. RSA).
   * @param encDigest  The encrypted digest (signature value).
   */
  CSignerInfo(const CIssuerAndSerialNumber& issuer,
              const CAlgorithmIdentifier& digestAlgo,
              const CAlgorithmIdentifier& encAlgo,
              const CASN1OctetString& encDigest);

  /**
   * @brief Adds authenticated (signed) attributes to this SignerInfo.
   * @param attributes SET OF authenticated attributes.
   */
  void addAuthenticatedAttributes(const CASN1SetOf& attributes);

  /**
   * @brief Adds unauthenticated (unsigned) attributes to this SignerInfo.
   * @param attributes SET OF unauthenticated attributes.
   */
  void addUnauthenticatedAttributes(const CASN1SetOf& attributes);

  /** @brief Returns the encrypted digest (signature value). */
  CASN1OctetString getEncryptedDigest();

  /** @brief Returns the digest algorithm identifier. */
  CAlgorithmIdentifier getDigestAlgorithn();

  /** @brief Returns the issuer and serial number identifying the signer. */
  CIssuerAndSerialNumber getIssuerAndSerialNumber();

  /** @brief Returns the SET OF authenticated (signed) attributes. */
  CASN1SetOf getAuthenticatedAttributes();

  /** @brief Returns the SET OF unauthenticated (unsigned) attributes. */
  CASN1SetOf getUnauthenticatedAttributes();

  /** @brief Extracts the RFC 3161 timestamp token from unauthenticated
   * attributes. */
  CTimeStampToken getTimeStampToken();

  /** @brief Returns the signing time from authenticated attributes. */
  CASN1UTCTime getSigningTime();

  /** @brief Extracts the message digest (content hash) from authenticated
   * attributes. */
  CASN1OctetString getContentHash();

  /** @brief Returns all countersignature attributes as a SET OF. */
  CASN1SetOf getCountersignatures();

  /**
   * @brief Replaces the countersignature at @p index.
   * @param index           Zero-based countersignature index.
   * @param countersignature The new countersignature SignerInfo.
   */
  void setCountersignatures(int index, CSignerInfo& countersignature);

  /**
   * @brief Appends a countersignature to unauthenticated attributes.
   * @param countersignature The countersignature SignerInfo to add.
   */
  void addCountersignatures(CSignerInfo& countersignature);

  /** @brief Returns the number of countersignatures. */
  int getCountersignatureCount();

  /** @brief Checks whether a timestamp token is present in unauthenticated
   * attributes. */
  bool hasTimeStampToken();

  /**
   * @brief Verifies the countersignature at index @p i.
   * @param i            Zero-based countersignature index.
   * @param certificates SET OF certificates for chain building.
   * @return 0 on success, non-zero error code on failure.
   */
  int verifyCountersignature(int i, CASN1SetOf& certificates);

  /**
   * @brief Verifies the countersignature at index @p i at a specific time.
   * @param i               Zero-based countersignature index.
   * @param certificates    SET OF certificates for chain building.
   * @param szDateTime      Reference date/time string for validation.
   * @param pRevocationInfo Output revocation details.
   * @return 0 on success, non-zero error code on failure.
   */
  int verifyCountersignature(int i, CASN1SetOf& certificates,
                             const char* szDateTime,
                             REVOCATION_INFO* pRevocationInfo);

  /**
   * @brief Attaches an RFC 3161 timestamp token to unauthenticated attributes.
   * @param tst The timestamp token to attach.
   */
  void setTimeStampToken(CTimeStampToken& tst);

  virtual ~CSignerInfo();

  /**
   * @brief Finds the certificate matching a signer within a certificate set.
   * @param signature    The SignerInfo whose issuer/serial to match.
   * @param certificates SET OF candidate certificates.
   * @return The matching X.509 certificate.
   */
  static CCertificate getSignatureCertificate(CSignerInfo& signature,
                                              CASN1SetOf& certificates);

  /**
   * @brief Verifies a detached signature against source content.
   * @param source       The original signed content (octet string).
   * @param sinfo        The SignerInfo to verify.
   * @param certificates SET OF certificates for chain building.
   * @param date         Reference date/time string (may be nullptr for now).
   * @param pRevocationInfo Output revocation details.
   * @return 0 on success, non-zero error code on failure.
   */
  static int verifySignature(CASN1OctetString& source, CSignerInfo& sinfo,
                             CASN1SetOf& certificates, const char* date,
                             REVOCATION_INFO* pRevocationInfo);
};
