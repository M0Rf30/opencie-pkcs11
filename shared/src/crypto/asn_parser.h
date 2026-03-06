// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn_parser.h
 * @brief ASN.1 DER/BER parser and encoder for CIE certificate handling.
 */

#pragma once
#include <memory>
#include <vector>

#include "util/array.h"

/**
 * @brief Reads the length field of an ASN.1 TLV structure.
 * @param data Byte array positioned at the start of the length field.
 * @return The decoded data length in bytes.
 */
size_t GetASN1DataLenght(ByteArray &data);

class CASNTag;

/** @brief Owning collection of ASN.1 tag nodes. */
using CASNTagArray = std::vector<std::unique_ptr<CASNTag>>;

/**
 * @brief Represents a single ASN.1 TLV (Tag-Length-Value) node.
 *
 * Supports recursive parsing of constructed types (SEQUENCE, SET, etc.)
 * and re-encoding back to DER format.
 */
class CASNTag {
 public:
  /** @brief Constructs an empty ASN.1 tag node. */
  CASNTag(void);

  std::vector<BYTE> tag;  ///< Raw tag bytes (may be multi-byte).
  ByteDynArray content;   ///< Value (content) bytes of this TLV.
  CASNTagArray tags;      ///< Child tags if this is a constructed type.

  /** @brief Returns true if this tag is a SEQUENCE or forced-sequence type. */
  bool isSequence();

  /**
   * @brief Encodes this tag and its children into a byte array.
   * @param data Output byte array to write the DER encoding into.
   * @param len Output total encoded length.
   */
  void Encode(ByteArray &data, size_t &len);

  /** @brief Returns the total DER-encoded length of this tag (including TLV
   * overhead). */
  size_t EncodeLen();

  /** @brief Returns the length of the content (value) portion only. */
  size_t ContentLen();

  /** @brief Re-parses the content bytes to discover child tags. */
  void Reparse();

  /** @brief Returns the tag as an integer value. */
  size_t tagInt();

  /**
   * @brief Accesses a child tag by index, verifying its tag value.
   * @param num Zero-based child index.
   * @param tag Expected tag byte value.
   * @return Reference to the matching child CASNTag.
   */
  CASNTag &Child(std::size_t num, uint8_t tag);

  /**
   * @brief Verifies that the tag content matches the expected bytes.
   * @param content Expected content bytes to compare against.
   */
  void Verify(ByteArray content);

  /**
   * @brief Checks that this tag matches the expected tag value.
   * @param tag Expected tag byte.
   * @return Reference to this CASNTag if the tag matches.
   */
  CASNTag &CheckTag(uint8_t tag);

  size_t startPos;  ///< Start byte position in the original parsed data.
  size_t endPos;    ///< End byte position in the original parsed data.

 private:
  bool forcedSequence;  ///< If true, this tag is treated as a constructed type.
};

/**
 * @brief ASN.1 DER parser and encoder.
 *
 * Parses raw DER-encoded byte data into a tree of CASNTag nodes and
 * can re-encode the tree back to DER format. Used for parsing CIE
 * certificates and APDU response structures.
 */
class CASNParser {
 public:
  /** @brief Constructs a new ASN.1 parser instance. */
  CASNParser(void);

  /**
   * @brief Encodes the given tag array into a byte array.
   * @param data Output byte array for the DER encoding.
   * @param tags Tag array to encode.
   */
  void Encode(ByteArray &data, CASNTagArray &tags);

  /**
   * @brief Encodes the internal tag tree into a dynamic byte array.
   * @param data Output dynamic byte array for the DER encoding.
   */
  void Encode(ByteDynArray &data);

  /**
   * @brief Parses DER-encoded data into the internal tag tree.
   * @param data Input byte array containing DER-encoded data.
   */
  void Parse(ByteArray &data);

  /**
   * @brief Parses DER-encoded data into the specified tag array.
   * @param data Input byte array containing DER-encoded data.
   * @param tags Output tag array to populate.
   * @param startseq Starting byte offset for position tracking.
   */
  void Parse(ByteArray &data, CASNTagArray &tags, size_t startseq);

  CASNTagArray tags;  ///< Parsed ASN.1 tag tree.

  /** @brief Calculates the total encoded length of all tags. */
  size_t CalcLen();
};
