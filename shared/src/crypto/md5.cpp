// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/md5.h"

#include <openssl/evp.h>

CMD5::CMD5() : isInit(false), ctx {} {}

CMD5::~CMD5() {}

void CMD5::Init() {
  // throw logged_error("A hash operation is already in progress");
  ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
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
