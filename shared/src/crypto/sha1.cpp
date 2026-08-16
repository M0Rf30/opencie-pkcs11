// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/sha1.h"

#include <openssl/evp.h>

CSHA1::CSHA1() : isInit(false), ctx(nullptr) {}

CSHA1::~CSHA1() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

void CSHA1::Init() {
  if (ctx) EVP_MD_CTX_free(ctx);
  ctx = EVP_MD_CTX_new();
  if (!ctx) throw logged_error("EVP_MD context allocation error");
  if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1)
    throw logged_error("SHA-1 initialization error");
  isInit = true;
}
void CSHA1::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash not initialized");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CSHA1::Final() {
  if (!isInit) throw logged_error("Hash not initialized");
  ByteDynArray resp(SHA_DIGEST_LENGTH);
  EVP_DigestFinal_ex(ctx, resp.data(), nullptr);
  isInit = false;

  return resp;
}

ByteDynArray CSHA1::Digest(ByteArray data) {
  Init();
  Update(data);
  return Final();
}
