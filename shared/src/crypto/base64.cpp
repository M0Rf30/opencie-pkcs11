// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/base64.h"

#include <openssl/evp.h>

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
  init_func size_t inLen = strlen(encodedData);
  // EVP_DecodeBlock output: 3 * (n/4), may overcount by 1-2 for padding
  std::vector<unsigned char> buf(3 * (inLen / 4) + 3);
  int len = EVP_DecodeBlock(
      buf.data(), reinterpret_cast<const unsigned char *>(encodedData),
      static_cast<int>(inLen));
  if (len < 0) throw logged_error("Base64 decode error");
  // Adjust for padding
  while (inLen > 0 && encodedData[inLen - 1] == '=') {
    --len;
    --inLen;
  }
  if (len < 0) throw logged_error("Base64 decode error");
  ByteArray decodedBa(buf.data(), len);
  data.append(decodedBa);
  return data;
}
