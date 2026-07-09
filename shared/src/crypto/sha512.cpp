// SPDX-License-Identifier: LGPL-3.0-or-later
#include "crypto/sha512.h"

#include <openssl/evp.h>

CSHA512::CSHA512() : ctx(nullptr) {}

CSHA512::~CSHA512() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

ByteDynArray CSHA512::Digest(const ByteArray& data) {
  ByteDynArray resp(SHA512_DIGEST_LENGTH);
  unsigned int len = 0;
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) throw logged_error("EVP_MD_CTX_new failed");
  if (EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx, data.data(), data.size()) != 1 ||
      EVP_DigestFinal_ex(mdctx, resp.data(), &len) != 1) {
    EVP_MD_CTX_free(mdctx);
    throw logged_error("SHA-512 digest error");
  }
  EVP_MD_CTX_free(mdctx);
  return resp;
}
