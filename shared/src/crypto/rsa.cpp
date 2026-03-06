// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file rsa.cpp
 * @brief Implementation of RSA public-key operations for CIE authentication.
 */

#include "crypto/rsa.h"

#include <openssl/bn.h>

#include "util/func_call_info.h"
#include "util/log.h"

extern CLog Log;
#if (CRYPTOPP_VERSION >= 600) && (__cplusplus >= 201103L)
using byte = CryptoPP::byte;
#else
typedef unsigned char byte;
#endif

#include <cryptopp/pssr.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>

using CryptoPP::PSS;
using CryptoPP::RSASS;
using CryptoPP::SecByteBlock;
using CryptoPP::SHA512;

DWORD CRSA::GenerateKey(DWORD /*size*/, ByteDynArray & /*module*/,
                        ByteDynArray & /*pubexp*/, ByteDynArray & /*privexp*/) {
  init_func throw logged_error("Not supported");
}

ByteArray modulusBa;
ByteArray exponentBa;

CRSA::CRSA(ByteArray &mod, ByteArray &exp) {
  modulusBa = mod;
  exponentBa = exp;

  CryptoPP::Integer n(mod.data(), mod.size()), e(exp.data(), exp.size());
  pubKey.Initialize(n, e);
}

CRSA::~CRSA(void) {}

ByteDynArray CRSA::RSA_PURE(ByteArray &data) {
  CryptoPP::Integer m((const byte *)data.data(), data.size());
  CryptoPP::Integer c = pubKey.ApplyFunction(m);

  size_t len = c.MinEncodedSize();
  if (len == 0xff) len = 0x100;

  ByteDynArray resp(len);

  c.Encode(static_cast<byte *>(resp.data()), resp.size(),
           CryptoPP::Integer::UNSIGNED);

  return resp;
}

bool CRSA::RSA_PSS(ByteArray &signatureData, ByteArray &toSign) {
  RSASS<PSS, SHA512>::Verifier verifier(pubKey);
  SecByteBlock signatureBlock((const byte *)signatureData.data(),
                              signatureData.size());

  return verifier.VerifyMessage((const byte *)toSign.data(), toSign.size(),
                                signatureBlock, signatureBlock.size());
}
