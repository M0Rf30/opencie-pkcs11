#pragma once

#include <openssl/evp.h>

#include "Util/util_exception.h"
#include "Util/util.h"

#define DESKEY_LENGHT 8

class CDES3 {
  ByteDynArray Des3(const ByteArray &data, int encOp);
  ByteDynArray key;
  ByteDynArray iv;

 public:
  CDES3();
  CDES3(const ByteArray &key, const ByteArray &iv);
  ~CDES3(void);

  void Init(const ByteArray &key, const ByteArray &iv);
  ByteDynArray Encode(const ByteArray &data);
  ByteDynArray Decode(const ByteArray &data);
  ByteDynArray RawEncode(const ByteArray &data);
  ByteDynArray RawDecode(const ByteArray &data);
};
