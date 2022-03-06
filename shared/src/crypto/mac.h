#pragma once
#include <openssl/evp.h>

#include "Util/util_exception.h"
#include "Util/util.h"

class CMAC {
  ByteDynArray key;
  ByteDynArray iv;

 public:
  CMAC();
  CMAC(const ByteArray &key, const ByteArray &iv);
  ~CMAC(void);

  void Init(const ByteArray &key, const ByteArray &iv);
  ByteDynArray Mac(const ByteArray &data);
};
