// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file certificate_info.h
 * @brief TBSCertificate ASN.1 structure (the "to-be-signed" portion of X.509).
 *
 * Represents the TBSCertificate SEQUENCE (RFC 5280 Section 4.1.2) that
 * contains the certificate's core fields: version, serial number,
 * signature algorithm, issuer, validity, subject, public key info,
 * and extensions.
 */

#pragma once

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "name.h"
#include "subject_public_key_info.h"

/**
 * @brief TBSCertificate (RFC 5280 Section 4.1.2).
 *
 * The to-be-signed portion of an X.509 certificate, containing the
 * version, serial number, signature algorithm, issuer and subject names,
 * validity period, subject public key info, and optional extensions.
 */
class CCertificateInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a TBSCertificate from a DER-encoded stream.
   * @param reader Buffered reader positioned at the TBSCertificate SEQUENCE.
   */
  CCertificateInfo(BufferedReader& reader);

  /**
   * @brief Constructs a TBSCertificate from an already-parsed ASN.1 object.
   * @param cert Generic ASN.1 object containing TBSCertificate encoding.
   */
  CCertificateInfo(const CASN1Object& cert);

  virtual ~CCertificateInfo();

  /** @brief Returns the certificate version (v1=0, v2=1, v3=2). */
  CASN1Integer getVersion();

  /** @brief Returns the certificate serial number. */
  CASN1Integer getSerialNumber();

  /** @brief Returns the signature algorithm used by the issuer. */
  CAlgorithmIdentifier getSignatureAlgo();

  /** @brief Returns the issuer distinguished name. */
  CName getIssuer();

  /** @brief Returns the "not after" (expiration) date. */
  CASN1UTCTime getExpiration();

  /** @brief Returns the "not before" (start of validity) date. */
  CASN1UTCTime getFrom();

  /** @brief Returns the subject distinguished name. */
  CName getSubject();

  /** @brief Returns the subject's public key information. */
  CSubjectPublicKeyInfo getSubjectPublicKeyInfo();

  /** @brief Returns the v3 extensions SEQUENCE. */
  CASN1Sequence getExtensions();
};
