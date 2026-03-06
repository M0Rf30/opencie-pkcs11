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

void CSHA512::Init() {
  if (ctx) EVP_MD_CTX_free(ctx);
  ctx = EVP_MD_CTX_new();
  if (!ctx) throw logged_error("Errore allocazione contesto EVP_MD");
  if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1)
    throw logged_error("Errore inizializzazione SHA512");
  isInit = true;
}
void CSHA512::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash non inizializzato");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CSHA512::Final() {
  if (!isInit) throw logged_error("Hash non inizializzato");
  ByteDynArray resp(SHA512_DIGEST_LENGTH);
  unsigned int len = 0;
  EVP_DigestFinal_ex(ctx, resp.data(), &len);
  resp.resize(len, true);
  isInit = false;

  return resp;
}

ByteDynArray CSHA512::Digest(ByteArray& data) {
  const BYTE* pbData = static_cast<BYTE*>(data.data());
  unsigned int nDataLen = data.size();
  BYTE abDigest[CryptoPP::SHA512::DIGESTSIZE];

  CryptoPP::SHA512().CalculateDigest(abDigest, pbData, nDataLen);

  ByteArray resp(abDigest, CryptoPP::SHA512::DIGESTSIZE);

  return resp;
}
