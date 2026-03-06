// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file signed_data.h
 * @brief CMS SignedData (RFC 5652 Section 5) ASN.1 structure.
 *
 * Represents the top-level CMS SignedData container that bundles content,
 * signer information, certificates, and digest algorithms used in
 * CAdES / PKCS#7 digital signatures.
 */

#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1/asn1_set_of.h"
#include "asn1/certificate.h"
#include "asn1/content_info.h"
#include "sign/cie_sign_api.h"

/**
 * @brief CMS SignedData structure (RFC 5652 Section 5).
 *
 * Encapsulates the complete signed-data content type containing one or more
 * signer infos, the signed content (or a detached reference), the set of
 * certificates needed for chain validation, and the digest algorithms used.
 */
class CSignedData : public CASN1Sequence {
 public:
  /**
   * @brief Constructs a SignedData by parsing a DER-encoded stream.
   * @param reader Buffered reader positioned at the SignedData SEQUENCE.
   */
  CSignedData(BufferedReader& reader);

  /**
   * @brief Constructs a SignedData from an already-parsed ASN.1 object.
   * @param signedData Generic ASN.1 object containing SignedData encoding.
   */
  CSignedData(const CASN1Object& signedData);

  /**
   * @brief Constructs a SignedData from its individual components.
   * @param algos       SET OF digest algorithm identifiers.
   * @param contentInfo The encapsulated content info.
   * @param signerInfos SET OF signer info structures.
   * @param certificates SET OF X.509 certificates for chain building.
   */
  CSignedData(const CASN1SetOf& algos, const CContentInfo& contentInfo,
              const CASN1SetOf& signerInfos, const CASN1SetOf& certificates);

  virtual ~CSignedData();

  /** @brief Returns the SET OF digest algorithm identifiers. */
  CASN1SetOf getDigestAlgorithmIdentifiers();

  /** @brief Returns the encapsulated ContentInfo. */
  CContentInfo getContentInfo();

  /** @brief Returns the SET OF SignerInfo structures. */
  CASN1SetOf getSignerInfos();

  /** @brief Returns the SET OF embedded X.509 certificates. */
  CASN1SetOf getCertificates();

  /**
   * @brief Retrieves the certificate that corresponds to signer at @p index.
   * @param index Zero-based signer index.
   * @return The matching X.509 certificate.
   */
  CCertificate getSignerCertificate(int index);

  /**
   * @brief Converts this SignedData to a detached signature by removing the
   *        encapsulated content from ContentInfo.
   */
  void makeDetached();

  /**
   * @brief Replaces the encapsulated content with @p content.
   * @param content Raw data bytes to embed.
   */
  void setContent(ByteDynArray& content);

  /**
   * @brief Verifies the signature of the signer at index @p i.
   * @param i Zero-based signer index.
   * @return 0 on success, non-zero error code on failure.
   */
  int verify(int i);

  /**
   * @brief Verifies the signature at index @p i at a specific point in time.
   * @param i              Zero-based signer index.
   * @param dateTime       Reference date/time string for validation.
   * @param pRevocationInfo Output revocation details (CRL/OCSP results).
   * @return 0 on success, non-zero error code on failure.
   */
  int verify(int i, const char* dateTime, REVOCATION_INFO* pRevocationInfo);
};
