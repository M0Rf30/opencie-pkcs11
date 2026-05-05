// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

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

ByteArray modulusBa;
ByteArray exponentBa;

CRSA::CRSA(const ByteArray &mod, const ByteArray &exp) {
  modulusBa = mod;
  exponentBa = exp;

  CryptoPP::Integer n(mod.data(), mod.size()), e(exp.data(), exp.size());
  pubKey.Initialize(n, e);
}

CRSA::~CRSA(void) {}

ByteDynArray CRSA::RSA_PURE(const ByteArray &data) {
  CryptoPP::Integer m(reinterpret_cast<const byte *>(data.data()), data.size());
  CryptoPP::Integer c = pubKey.ApplyFunction(m);

  size_t len = c.MinEncodedSize();
  if (len == 0xff) len = 0x100;

  ByteDynArray resp(len);

  c.Encode(reinterpret_cast<byte *>(resp.data()), resp.size(),
           CryptoPP::Integer::UNSIGNED);

  return resp;
}

bool CRSA::RSA_PSS(const ByteArray &signatureData, const ByteArray &toSign) {
  RSASS<PSS, SHA512>::Verifier verifier(pubKey);
  SecByteBlock signatureBlock(
      reinterpret_cast<const byte *>(signatureData.data()),
      signatureData.size());

  return verifier.VerifyMessage(reinterpret_cast<const byte *>(toSign.data()),
                                toSign.size(), signatureBlock,
                                signatureBlock.size());
}
