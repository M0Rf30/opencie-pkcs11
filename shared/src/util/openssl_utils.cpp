// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "openssl_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace lcp {

Buffer CryptoUtils::Base64ToVector(const std::string &base64) {
  if (base64.empty()) {
    throw std::runtime_error("base64 data is empty");
  }

  // EVP_DecodeBlock requires the input length to be a multiple of 4 and
  // does not tolerate embedded whitespace/newlines.
  std::string input(base64);
  input.erase(std::remove_if(input.begin(), input.end(),
                             [](unsigned char c) { return std::isspace(c); }),
              input.end());

  if (input.empty() || input.size() % 4 != 0) {
    throw std::runtime_error("result data is empty");
  }

  size_t padding = 0;
  if (input.back() == '=') padding++;
  if (input.size() >= 2 && input[input.size() - 2] == '=') padding++;

  Buffer result(input.size() / 4 * 3);
  int decodedLen = EVP_DecodeBlock(
      result.data(), reinterpret_cast<const unsigned char *>(input.data()),
      static_cast<int>(input.size()));
  if (decodedLen < 0 || static_cast<size_t>(decodedLen) < padding) {
    throw std::runtime_error("result data is empty");
  }
  result.resize(static_cast<size_t>(decodedLen) - padding);
  return result;
}

std::string CryptoUtils::RawToHex(const Buffer &key) {
  static const char digits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(key.size() * 2);
  for (unsigned char b : key) {
    hex.push_back(digits[b >> 4]);
    hex.push_back(digits[b & 0x0f]);
  }
  return hex;
}

Buffer CryptoUtils::HexToRaw(const std::string &hex) {
  Buffer value(hex.size() / 2);
  for (size_t i = 0; i < value.size(); ++i) {
    value[i] = static_cast<unsigned char>(
        std::stoul(hex.substr(i * 2, 2), nullptr, 16));
  }
  return value;
}

std::string CryptoUtils::GenerateUuid() {
  const static int UuidRawSize = 16;

  Buffer guid(UuidRawSize);
  if (RAND_bytes(guid.data(), static_cast<int>(guid.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }

  std::string guidHex = RawToHex(guid);
  return guidHex.insert(8, 1, '-')
      .insert(13, 1, '-')
      .insert(18, 1, '-')
      .insert(23, 1, '-');
}
}  // namespace lcp
