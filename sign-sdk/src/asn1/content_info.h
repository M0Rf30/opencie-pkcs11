// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file content_info.h
 * @brief CMS ContentInfo ASN.1 structure (RFC 5652 Section 3).
 *
 * ContentInfo is the top-level wrapper for all CMS content types
 * (SignedData, EnvelopedData, etc.), consisting of a ContentType OID
 * and an optional explicitly-tagged content field.
 */

#pragma once

#include "asn1/asn1_sequence.h"
#include "content_type.h"

/**
 * @brief CMS ContentInfo (RFC 5652 Section 3).
 *
 * @code
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * @endcode
 */
class CContentInfo : public CASN1Sequence {
 public:
  /**
   * @brief Constructs a ContentInfo with a content type and content.
   * @param contentType The ContentType OID.
   * @param content     The content payload.
   */
  CContentInfo(const CContentType& contentType, const CASN1Object& content);

  /**
   * @brief Constructs a ContentInfo with only a content type (no content).
   * @param contentType The ContentType OID.
   */
  CContentInfo(const CContentType& contentType);

  /**
   * @brief Parses a ContentInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the ContentInfo SEQUENCE.
   */
  CContentInfo(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param contentInfo Generic ASN.1 object containing ContentInfo encoding.
   */
  CContentInfo(const CASN1Object& contentInfo);

  virtual ~CContentInfo();

  /**
   * @brief Replaces the content field.
   * @param content The new content payload.
   */
  void setContent(const CASN1Object& content);

  /** @brief Returns the ContentType OID. */
  CContentType getContentType();

  /** @brief Returns the content payload object. */
  CASN1Object getContent();
};
