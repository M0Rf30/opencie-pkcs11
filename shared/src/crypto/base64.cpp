// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/base64.h"

#include <cryptopp/base64.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>

#include "util/definitions.h"

extern CLog Log;

CBase64::CBase64() {}

CBase64::~CBase64() {}

std::string &CBase64::Encode(const ByteArray &data, std::string &encodedData) {
  init_func std::string encoded;
  CryptoPP::StringSource(
      data.data(), data.size(), true,
      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
  encodedData.append(encoded);
  return encodedData;
}

ByteDynArray &CBase64::Decode(const char *encodedData, ByteDynArray &data) {
  init_func std::string decoded;
  CryptoPP::StringSource(
      reinterpret_cast<const BYTE *>(encodedData), strlen(encodedData), true,
      new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  ByteArray decodedBa(reinterpret_cast<BYTE *>(decoded.data()), decoded.size());
  data.append(decodedBa);
  return data;
}
