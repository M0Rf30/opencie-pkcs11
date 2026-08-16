// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "cipher_base.h"

#include <memory>

namespace {
using EvpCipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
}

extern CLog Log;

ByteDynArray CipherBase::perform_cipher_operation(const ByteArray &data,
                                                  int encOp,
                                                  const EVP_CIPHER *cipher,
                                                  size_t block_size) {
  init_func

      ByteDynArray ivCopy = iv;

  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  ER_ASSERT(ctx != nullptr, "EVP context allocation error");

  // Allocate output buffer: round up to the next block boundary
  size_t AppSize = data.size() - 1;
  ByteDynArray resp(AppSize - (AppSize % block_size) + block_size);

  int outLen = 0;
  int finalLen = 0;
  int rc;

  if (encOp == 1) {  // Encrypt
    rc = EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(),
                            ivCopy.data());
    ER_ASSERT(rc == 1, "Encryption initialization error");
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    rc = EVP_EncryptUpdate(ctx.get(), resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Encryption error");
    EVP_EncryptFinal_ex(ctx.get(), resp.data() + outLen, &finalLen);
  } else {  // Decrypt
    rc = EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(),
                            ivCopy.data());
    ER_ASSERT(rc == 1, "Decryption initialization error");
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    rc = EVP_DecryptUpdate(ctx.get(), resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Decryption error");
    EVP_DecryptFinal_ex(ctx.get(), resp.data() + outLen, &finalLen);
  }

  return resp;
}
