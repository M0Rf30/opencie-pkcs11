// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file base64.h
 * @brief Base64 encoding and decoding utilities.
 */

#pragma once
#include <string>

#include "util/array.h"

/**
 * @brief Provides Base64 encoding and decoding operations.
 *
 * Used for converting binary data (e.g., certificates, keys) to and from
 * Base64-encoded text representation.
 */
class CBase64 {
 public:
  /** @brief Constructs a new CBase64 instance. */
  CBase64();

  /** @brief Destructor. */
  ~CBase64();

  /**
   * @brief Encodes binary data to a Base64 string.
   * @param data Input binary data to encode.
   * @param encodedData Output string receiving the Base64-encoded result.
   * @return Reference to the encoded output string.
   */
  std::string &Encode(ByteArray &data, std::string &encodedData);

  /**
   * @brief Decodes a Base64 string to binary data.
   * @param encodedData Null-terminated Base64-encoded input string.
   * @param data Output byte array receiving the decoded binary data.
   * @return Reference to the decoded output byte array.
   */
  ByteDynArray &Decode(const char *encodedData, ByteDynArray &data);
};
