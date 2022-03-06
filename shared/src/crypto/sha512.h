#pragma once

#include <openssl/evp.h>

#include "Util/array.h"

#define SHA512_DIGEST_LENGTH 64

class CSHA512 {
  bool isInit;
  EVP_MD_CTX *ctx;
  void Init();
  void Update(ByteArray data);
  ByteDynArray Final();

 public:
  CSHA512();
  ~CSHA512();
  ByteDynArray Digest(ByteArray &data);
};
