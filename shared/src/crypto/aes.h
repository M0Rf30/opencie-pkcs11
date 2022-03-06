#pragma once

#include <openssl/evp.h>

#include "Util/util_exception.h"
#include "Util/util.h"

#define AESKEY_LENGHT 32
#define AES_BLOCK_SIZE 16
#define AES_ENCRYPT 1
#define AES_DECRYPT 0

class CAES {
  ByteDynArray key;
  ByteDynArray AES(const ByteArray &data, int encOp);
  ByteDynArray iv;

 public:
  CAES();
  CAES(const ByteArray &key, const ByteArray &iv);
  ~CAES(void);

  void Init(const ByteArray &key, const ByteArray &iv);
  ByteDynArray Encode(const ByteArray &data);
  ByteDynArray Decode(const ByteArray &data);
  ByteDynArray RawEncode(const ByteArray &data);
  ByteDynArray RawDecode(const ByteArray &data);
};
