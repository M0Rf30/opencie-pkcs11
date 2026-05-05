// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/sha512.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

CSHA512::CSHA512() : isInit(false), ctx(nullptr) {}

CSHA512::~CSHA512() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

ByteDynArray CSHA512::Digest(const ByteArray& data) {
  const BYTE* pbData = static_cast<const BYTE*>(data.data());
  unsigned int nDataLen = data.size();
  BYTE abDigest[CryptoPP::SHA512::DIGESTSIZE];

  CryptoPP::SHA512().CalculateDigest(abDigest, pbData, nDataLen);

  ByteArray resp(abDigest, CryptoPP::SHA512::DIGESTSIZE);

  return ByteDynArray(resp);
}
