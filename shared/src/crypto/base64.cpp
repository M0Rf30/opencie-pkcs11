// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/base64.h"

#include <openssl/evp.h>

#include <climits>
#include <cstring>
#include <vector>

#include "util/definitions.h"

extern CLog Log;

CBase64::CBase64() {}

CBase64::~CBase64() {}

std::string &CBase64::Encode(const ByteArray &data, std::string &encodedData) {
  init_func
      // EVP_EncodeBlock output size: 4 * ceil(n/3) + 1
      size_t outLen = 4 * ((data.size() + 2) / 3) + 1;
  std::vector<unsigned char> buf(outLen);
  int len =
      EVP_EncodeBlock(buf.data(), data.data(), static_cast<int>(data.size()));
  encodedData.append(reinterpret_cast<char *>(buf.data()), len);
  return encodedData;
}

ByteDynArray &CBase64::Decode(const char *encodedData, ByteDynArray &data) {
  init_func auto isWs = [](char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
  };
  // Trim surrounding whitespace first: the padding count below must look at
  // the last real base64 character, not at trailing whitespace.
  const char *begin = encodedData;
  size_t inLen = strlen(encodedData);
  while (inLen > 0 && isWs(begin[0])) {
    ++begin;
    --inLen;
  }
  while (inLen > 0 && isWs(begin[inLen - 1])) --inLen;
  if (inLen > static_cast<size_t>(INT_MAX))
    throw logged_error("Base64 decode error");

  size_t pad = 0;
  while (pad < inLen && begin[inLen - 1 - pad] == '=') ++pad;
  if (pad > 2 || (inLen % 4) != 0 || memchr(begin, '=', inLen - pad) != nullptr)
    throw logged_error("Base64 decode error");

  // EVP_DecodeBlock output: 3 * (n/4), including the padding bytes
  std::vector<unsigned char> buf(3 * (inLen / 4) + 3);
  int len = EVP_DecodeBlock(buf.data(),
                            reinterpret_cast<const unsigned char *>(begin),
                            static_cast<int>(inLen));
  if (len < 0 || static_cast<size_t>(len) < pad)
    throw logged_error("Base64 decode error");
  len -= static_cast<int>(pad);
  ByteArray decodedBa(buf.data(), len);
  data.append(decodedBa);
  return data;
}
