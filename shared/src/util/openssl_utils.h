// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file openssl_utils.h
 * @brief OpenSSL-backed utility wrappers for encoding and UUID generation.
 *
 * Provides helper functions for Base64/hex encoding and UUID generation
 * using OpenSSL.
 */

#pragma once

#include <string>
#include <vector>

/** @brief Alias for a byte buffer (vector of unsigned char). */
using Buffer = std::vector<unsigned char>;

namespace lcp {

/**
 * @brief Collection of OpenSSL-backed utility functions.
 *
 * Provides static methods for Base64/hex encoding and UUID generation.
 */
class CryptoUtils {
 public:
  /**
   * @brief Decode a Base64 string into a byte vector.
   * @param base64 Base64-encoded input string.
   * @return Decoded byte vector.
   */
  static Buffer Base64ToVector(const std::string& base64);

  /**
   * @brief Convert raw bytes to a hexadecimal string.
   * @param key Raw byte buffer.
   * @return Hex-encoded string.
   */
  static std::string RawToHex(const Buffer& key);

  /**
   * @brief Convert a hexadecimal string to raw bytes.
   * @param hex Hex-encoded string.
   * @return Raw byte buffer.
   */
  static Buffer HexToRaw(const std::string& hex);

  /**
   * @brief Generate a random UUID string.
   * @return UUID in standard string format.
   */
  static std::string GenerateUuid();
};
}  // namespace lcp
