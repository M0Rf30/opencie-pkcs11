// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_object.h
 * @brief Base class for all ASN.1 TLV (Tag-Length-Value) objects.
 *
 * Provides the fundamental DER/BER encoding and decoding operations
 * shared by every ASN.1 type used in CMS/PKCS#7 signature handling.
 */

#pragma once

#include <string>

#include "buffered_reader.h"
#include "util/array.h"
#include "util/definitions.h"

/**
 * @brief Base class representing a single ASN.1 TLV element.
 *
 * Encapsulates the tag byte, encoded length, and value octets of an
 * ASN.1 object. Supports both DER and BER (indefinite-length) forms.
 * All concrete ASN.1 types in this library derive from CASN1Object.
 */
class CASN1Object {
 public:
  /** @brief Constructs an empty, uninitialized ASN.1 object. */
  CASN1Object();

  /**
   * @brief Copy constructor.
   * @param obj The object to copy.
   */
  // cppcheck-suppress noExplicitConstructor
  CASN1Object(const CASN1Object& obj);

  /**
   * @brief Constructs an ASN.1 object with the given tag and value.
   * @param btTag ASN.1 tag byte.
   * @param value DER-encoded value octets.
   */
  explicit CASN1Object(BYTE btTag, const ByteDynArray& value);

  /**
   * @brief Constructs an ASN.1 object with the given tag and no value.
   * @param btTag ASN.1 tag byte.
   */
  explicit CASN1Object(BYTE btTag);

  /**
   * @brief Constructs an ASN.1 object by reading TLV from a BufferedReader.
   * @param reader The reader positioned at the start of a TLV.
   */
  explicit CASN1Object(BufferedReader& reader);

  /**
   * @brief Constructs an ASN.1 object by decoding a DER byte array.
   * @param content DER-encoded TLV bytes.
   */
  // cppcheck-suppress noExplicitConstructor
  CASN1Object(const ByteDynArray& content);

  /**
   * @brief Constructs an ASN.1 object from a raw byte buffer.
   * @param value Pointer to DER-encoded data.
   * @param len   Length of the data in bytes.
   */
  CASN1Object(const BYTE* value, long len);

  virtual ~CASN1Object();

  /**
   * @brief Returns the ASN.1 tag byte for this object.
   * @return The tag byte (e.g. 0x30 for SEQUENCE, 0x02 for INTEGER).
   */
  virtual BYTE getTag() const;

  /**
   * @brief Returns the length of the value octets.
   * @return Number of value bytes.
   */
  UINT getLength() const;

  /**
   * @brief Returns a pointer to the value byte array.
   * @return Pointer to the internal value storage.
   */
  const ByteDynArray* getValue() const;

  /**
   * @brief Sets the value octets from a byte array.
   * @param value The new value octets.
   */
  void setValue(const ByteDynArray& value);

  /**
   * @brief Sets the value octets from a raw buffer.
   * @param value Pointer to value data.
   * @param len   Length in bytes.
   */
  void setValue(const BYTE* value, long len);

  /**
   * @brief Sets the ASN.1 tag byte.
   * @param tag The new tag byte.
   */
  void setTag(BYTE tag);

  /**
   * @brief Computes the total serialized (DER) length including tag and length
   * octets.
   * @return Total number of bytes when serialized.
   */
  int getSerializedLength();

  /**
   * @brief Computes the serialized length for a given value length.
   * @param nLen          Value length in bytes.
   * @param indefiniteLen True if using BER indefinite-length encoding.
   * @return Total number of bytes when serialized.
   */
  static int getSerializedLength(int nLen, bool indefiniteLen);

  /**
   * @brief Serializes this object to a DER byte array.
   * @param byteArray Output byte array receiving the DER encoding.
   */
  void toByteArray(ByteDynArray& byteArray) const;

  /**
   * @brief Decodes this object from a DER byte array.
   * @param content DER-encoded TLV bytes.
   */
  void fromByteArray(const ByteDynArray& content);

  /**
   * @brief Decodes this object from a raw DER buffer.
   * @param pContent Pointer to DER-encoded data.
   * @param iLen     Length of the data in bytes.
   */
  void fromByteArray(const BYTE* pContent, int iLen);

  /**
   * @brief Parses an ASN.1 TLV length field from a reader.
   * @param reader         The reader positioned at the TLV.
   * @param pbtTag         Output: parsed tag byte.
   * @param pValue         Output: parsed value octets.
   * @param pbtLenRead     Output: number of bytes used for the length field.
   * @param pbIndefiniteLen Output: true if indefinite-length encoding was used.
   * @return The parsed length value.
   */
  static int parseLen(BufferedReader& reader, BYTE* pbtTag,
                      ByteDynArray* pValue, BYTE* pbtLenRead,
                      bool* pbIndefiniteLen);

  /**
   * @brief Reads and decodes a TLV from a BufferedReader.
   * @param reader The reader positioned at the TLV.
   */
  void fromReader(BufferedReader& reader);

  /**
   * @brief Assignment operator.
   * @param obj The object to assign from.
   * @return A copy of this object.
   */
  CASN1Object operator=(const CASN1Object& obj);

  /**
   * @brief Equality comparison.
   * @param obj The object to compare against.
   * @return True if tag and value are identical.
   */
  bool operator==(const CASN1Object& obj) const;

  /**
   * @brief Inequality comparison.
   * @param obj The object to compare against.
   * @return True if tag or value differ.
   */
  bool operator!=(const CASN1Object& obj) const;

  /**
   * @brief Returns a hex string representation of the value octets.
   * @return Null-terminated hex string.
   */
  const char* toHexString();

  /**
   * @brief Returns the number of bytes used to encode the length field.
   * @return Length of the length encoding (1 for short form, 2+ for long form).
   */
  BYTE getOrigLenLen() const;

 protected:
  BYTE m_btTag;          ///< ASN.1 tag byte.
  ByteDynArray m_value;  ///< Value octets.

  /**
   * @brief Parses a BER-encoded TLV from a reader into a buffer.
   * @param reader The reader positioned at the TLV.
   * @param buffer Output buffer receiving the decoded data.
   * @return Number of bytes parsed.
   */
  static int parseBER(BufferedReader& reader, ByteDynArray& buffer);

  bool m_indefiniteLen;  ///< True if BER indefinite-length encoding is used.
  BYTE m_btLenRead;      ///< Number of bytes consumed by the length field.
  ByteDynArray m_der;    ///< Cached DER encoding of this object.
  std::string m_hexStr;  ///< Cached hex string returned by toHexString().
};
