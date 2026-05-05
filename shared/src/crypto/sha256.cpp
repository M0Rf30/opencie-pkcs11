// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/sha256.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <openssl/evp.h>

CSHA256::CSHA256() : isInit(false), ctx(nullptr) {}

CSHA256::~CSHA256() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

void CSHA256::Init() {
  if (ctx) EVP_MD_CTX_free(ctx);
  ctx = EVP_MD_CTX_new();
  if (!ctx) throw logged_error("EVP_MD context allocation error");
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    throw logged_error("SHA-256 initialization error");
  isInit = true;
}
void CSHA256::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash not initialized");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CSHA256::Final() {
  if (!isInit) throw logged_error("Hash not initialized");
  ByteDynArray resp(SHA256_DIGEST_LENGTH);
  EVP_DigestFinal_ex(ctx, resp.data(), nullptr);
  isInit = false;

  return resp;
}
ByteDynArray CSHA256::Digest(const ByteArray& data) {
  const BYTE* pbData = static_cast<const BYTE*>(data.data());
  unsigned int nDataLen = data.size();
  BYTE abDigest[CryptoPP::SHA256::DIGESTSIZE];
  CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
  ByteArray resp(abDigest, CryptoPP::SHA256::DIGESTSIZE);

  return ByteDynArray(resp);
}
