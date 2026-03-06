// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file certificate.h
 * @brief X.509 certificate ASN.1 structure.
 *
 * Represents an X.509v3 certificate, providing access to its fields
 * (issuer, subject, serial number, validity period, extensions) and
 * operations for signature verification, revocation checking, and
 * qualified-certificate detection per Italian/EU eIDAS regulations.
 */

#pragma once

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1_octet_string.h"
#include "certificate_info.h"
#include "sign/cie_sign_api.h"

/**
 * @brief X.509v3 certificate (RFC 5280).
 *
 * Wraps the DER-encoded Certificate SEQUENCE and exposes accessors for
 * the TBSCertificate fields, extensions (key identifiers, certificate
 * policies, QCStatements), and verification methods including revocation
 * status checks via CRL/OCSP.
 */
class CCertificate : public CASN1Sequence {
 public:
  /**
   * @brief Parses a certificate from a DER-encoded stream.
   * @param reader Buffered reader positioned at the Certificate SEQUENCE.
   */
  CCertificate(BufferedReader& reader);

  /**
   * @brief Constructs a certificate from a raw DER byte buffer.
   * @param value Pointer to the DER-encoded certificate bytes.
   * @param len   Length of the buffer in bytes.
   */
  CCertificate(const BYTE* value, long len);

  /**
   * @brief Constructs a certificate from an already-parsed ASN.1 object.
   * @param cert Generic ASN.1 object containing certificate encoding.
   */
  CCertificate(const CASN1Object& cert);

  virtual ~CCertificate();

  /** @brief Returns the TBSCertificate (to-be-signed) portion. */
  CCertificateInfo getCertificateInfo();

  /** @brief Returns the signature algorithm identifier. */
  CAlgorithmIdentifier getAlgorithmIdentifier();

  /** @brief Returns the Authority Key Identifier extension value. */
  CASN1OctetString getAuthorithyKeyIdentifier();

  /** @brief Returns the Subject Key Identifier extension value. */
  CASN1OctetString getSubjectKeyIdentifier();

  /** @brief Returns the Certificate Policies extension as a SEQUENCE. */
  CASN1Sequence getCertificatePolicies();

  /** @brief Returns the QCStatements extension as a SEQUENCE. */
  CASN1Sequence getQCStatements();

  /** @brief Checks whether the key usage includes non-repudiation. */
  bool isNonRepudiation();

  /**
   * @brief Checks revocation status via CRL/OCSP at current time.
   * @param pRevocationInfo Output revocation details.
   * @return 0 on success, non-zero error code on failure.
   */
  int verifyStatus(REVOCATION_INFO* pRevocationInfo);

  /**
   * @brief Checks revocation status at a specific point in time.
   * @param szTime          Reference date/time string.
   * @param pRevocationInfo Output revocation details.
   * @return 0 on success, non-zero error code on failure.
   */
  int verifyStatus(const char* szTime, REVOCATION_INFO* pRevocationInfo);

  /**
   * @brief Verifies this certificate's signature against an issuer certificate.
   * @param cert The issuer certificate whose public key signs this certificate.
   * @return true if the signature is valid.
   */
  bool verifySignature(CCertificate& cert);

  /**
   * @brief Performs full certificate verification (signature + revocation).
   * @return 0 on success, non-zero error code on failure.
   */
  int verify();

  /** @brief Returns the issuer distinguished name. */
  CName getIssuer();

  /** @brief Returns the certificate serial number. */
  CASN1Integer getSerialNumber();

  /** @brief Returns the subject distinguished name. */
  CName getSubject();

  /** @brief Returns the "not after" (expiration) date. */
  CASN1UTCTime getExpiration();

  /** @brief Returns the "not before" (start of validity) date. */
  CASN1UTCTime getFrom();

  /** @brief Returns the extensions SEQUENCE from TBSCertificate. */
  CASN1Sequence getExtensions();

  /** @brief Checks whether this is an EU qualified certificate (QCStatements).
   */
  bool isQualified();

  /** @brief Checks whether the certificate is currently within its validity
   * period. */
  bool isValid();

  /**
   * @brief Checks validity at a specific date/time.
   * @param szDateTime Reference date/time string.
   * @return true if the certificate is valid at the given time.
   */
  bool isValid(const char* szDateTime);

  /** @brief Checks whether the signature algorithm uses SHA-256. */
  bool isSHA256();

  /**
   * @brief Retrieves a specific extension by OID.
   * @param oid The extension's object identifier.
   * @return The extension value as a SEQUENCE, or empty if not found.
   */
  CASN1Sequence getExtension(const CASN1ObjectIdentifier& oid);

  /**
   * @brief Factory method: creates a certificate from a DER byte array.
   * @param contentArray DER-encoded certificate bytes.
   * @return Heap-allocated certificate (caller takes ownership).
   */
  static CCertificate* createCertificate(ByteDynArray& contentArray);
};
