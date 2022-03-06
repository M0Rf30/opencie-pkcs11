#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "Util/array.h"


class CSHA256 {
 public:
  ByteDynArray Digest(ByteArray& data);
  void Init();
  void Update(ByteArray data);
  ByteDynArray Final();

  bool isInit;
  EVP_MD_CTX* ctx;
};
