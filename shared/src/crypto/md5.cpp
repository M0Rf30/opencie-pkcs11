// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/md5.h"

#include <openssl/evp.h>

CMD5::CMD5() : isInit(false), ctx {} {}

CMD5::~CMD5() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

void CMD5::Init() {
  if (ctx) EVP_MD_CTX_free(ctx);
  ctx = EVP_MD_CTX_new();
  if (!ctx) throw logged_error("EVP_MD context allocation error");
  if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1)
    throw logged_error("MD5 initialization error");
  isInit = true;
}
void CMD5::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash not initialized");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CMD5::Final() {
  if (!isInit) throw logged_error("Hash not initialized");
  ByteDynArray resp(MD5_DIGEST_LENGTH);
  EVP_DigestFinal_ex(ctx, resp.data(), nullptr);
  isInit = false;

  return resp;
}

ByteDynArray CMD5::Digest(ByteArray data) {
  Init();
  Update(data);
  return Final();
}
