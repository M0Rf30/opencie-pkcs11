// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/md5.h"

#include <openssl/evp.h>

CMD5::CMD5() : isInit(false) {}

CMD5::~CMD5() {}

void CMD5::Init() {
  // throw logged_error("Un'operazione di hash � gi� in corso");
  ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
  isInit = true;
}
void CMD5::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash non inizializzato");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CMD5::Final() {
  if (!isInit) throw logged_error("Hash non inizializzato");
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
