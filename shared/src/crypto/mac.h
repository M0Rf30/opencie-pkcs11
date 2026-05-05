// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once
#include <openssl/evp.h>

#include "util/util.h"
#include "util/util_exception.h"

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
