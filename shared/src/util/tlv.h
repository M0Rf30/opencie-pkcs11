// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file tlv.h
 * @brief TLV (Tag-Length-Value) parser and builder for smart card APDUs.
 *
 * Provides classes for parsing TLV-encoded data structures commonly
 * found in smart card communication (ISO 7816 APDUs) and for
 * constructing new TLV-encoded buffers.
 */

#pragma once
#include <map>

#include "util/array.h"

/** @brief Map type for parsed TLV data (tag -> value reference). */
using tlvMap = std::map<uint8_t, ByteArray>;

/** @brief Map type for constructed TLV data (tag -> owned value). */
using tlvCreateMap = std::map<uint8_t, ByteDynArray>;

/**
 * @brief TLV parser for smart card data structures.
 *
 * Parses a byte array containing TLV-encoded data and provides
 * lookup of individual tag values by tag number.
 */
class CTLV {
  tlvMap map; /**< Parsed tag-to-value mappings. */

 public:
  /**
   * @brief Parse TLV data from a byte array.
   * @param data Byte array containing TLV-encoded data.
   */
  CTLV(ByteArray &data);

  /** @brief Destructor. */
  ~CTLV();

  /**
   * @brief Get the value associated with a tag.
   * @param Tag TLV tag identifier.
   * @return The value as a ByteArray.
   * @throws If the tag is not found.
   */
  ByteArray getValue(uint8_t Tag);

  /**
   * @brief Look up a tag and return a pointer to its value.
   * @param Tag TLV tag identifier.
   * @return Pointer to the ByteArray value, or nullptr if not found.
   */
  ByteArray *getTAG(uint8_t Tag);
};

/**
 * @brief TLV builder for constructing smart card data structures.
 *
 * Allows adding tag-value pairs and serializing them into a single
 * TLV-encoded byte buffer.
 */
class CTLVCreate {
 public:
  tlvCreateMap map; /**< Tag-to-value mappings being built. */

  /** @brief Default constructor. */
  CTLVCreate();

  /** @brief Destructor. */
  ~CTLVCreate();

  /**
   * @brief Add a new tag and return a pointer to its value buffer.
   * @param Tag TLV tag identifier to add.
   * @return Pointer to the newly created value buffer.
   */
  ByteDynArray *addValue(uint8_t Tag);

  /**
   * @brief Get the value buffer for an existing tag.
   * @param Tag TLV tag identifier.
   * @return Pointer to the value buffer, or nullptr if not found.
   */
  ByteDynArray *getValue(uint8_t Tag);

  /**
   * @brief Set the value for a tag.
   * @param Tag TLV tag identifier.
   * @param Value Byte array to assign to the tag.
   */
  void setValue(uint8_t Tag, ByteArray &Value);

  /**
   * @brief Serialize all tag-value pairs into a TLV-encoded buffer.
   * @return The serialized TLV byte buffer.
   */
  ByteDynArray getBuffer();
};
