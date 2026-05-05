// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file content_type.h
 * @brief ASN.1 ContentType attribute for CMS/PKCS#7 structures.
 *
 * Represents the ContentType OID used to identify the type of content
 * in a CMS (Cryptographic Message Syntax) SignedData or EnvelopedData
 * structure, as defined in RFC 5652.
 */

#pragma once

#include "asn1_object_identifier.h"

/**
 * @brief CMS ContentType attribute wrapping an OBJECT IDENTIFIER.
 *
 * Encapsulates the OID that identifies the type of the encapsulated
 * content in a CMS structure (e.g., id-data, id-signedData,
 * id-envelopedData, id-digestedData, id-encryptedData, id-ct-TSTInfo).
 */
class CContentType : public CASN1ObjectIdentifier {
 public:
  /** @brief OID for CMS Data content type (1.2.840.113549.1.7.1). */
  static const char* OID_TYPE_DATA;
  /** @brief OID for CMS SignedData content type (1.2.840.113549.1.7.2). */
  static const char* OID_TYPE_SIGNED;
  /** @brief OID for CMS EnvelopedData content type (1.2.840.113549.1.7.3). */
  static const char* OID_TYPE_ENVELOPED;
  /** @brief OID for CMS SignedAndEnvelopedData content type. */
  static const char* OID_TYPE_SIGNED_ENVELOPED;
  /** @brief OID for CMS DigestedData content type (1.2.840.113549.1.7.5). */
  static const char* OID_TYPE_DIGEST;
  /** @brief OID for CMS EncryptedData content type (1.2.840.113549.1.7.6). */
  static const char* OID_TYPE_ENCRYPTED;
  /** @brief OID for RFC 3161 TSTInfo content type. */
  static const char* OID_TYPE_TSTINFO;

  /**
   * @brief Constructs a ContentType by decoding from a BufferedReader.
   * @param reader The reader positioned at the TLV-encoded OID.
   */
  explicit CContentType(BufferedReader& reader);

  /**
   * @brief Constructs a ContentType from a generic ASN.1 object.
   * @param contentType The ASN.1 object to interpret as a ContentType.
   */
  explicit CContentType(const CASN1Object& contentType);

  /**
   * @brief Constructs a ContentType from a dotted OID string (mutable).
   * @param lpszOId Null-terminated dotted OID string.
   */
  explicit CContentType(char* lpszOId);

  /**
   * @brief Constructs a ContentType from a dotted OID string (const).
   * @param timeStampDataOID Null-terminated dotted OID string.
   */
  explicit CContentType(const char* timeStampDataOID);

  /**
   * @brief Constructs a ContentType from an existing OBJECT IDENTIFIER.
   * @param algoId The OBJECT IDENTIFIER to copy.
   */
  explicit CContentType(const CASN1ObjectIdentifier& algoId);

  virtual ~CContentType() override;
};
