// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file rsa.cpp
 * @brief Implementation of RSA public-key operations for CIE authentication.
 */

#include "crypto/rsa.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>

#include "util/func_call_info.h"
#include "util/log.h"

extern CLog Log;

CRSA::CRSA(const ByteArray &mod, const ByteArray &exp) {
  BIGNUM *n = BN_bin2bn(mod.data(), static_cast<int>(mod.size()), nullptr);
  BIGNUM *e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
  if (!n || !e) {
    BN_free(n);
    BN_free(e);
    throw logged_error("BN_bin2bn failed");
  }

  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  if (!bld) {
    BN_free(n);
    BN_free(e);
    throw logged_error("OSSL_PARAM_BLD_new failed");
  }
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  BN_free(n);
  BN_free(e);
  if (!params) throw logged_error("OSSL_PARAM_BLD_to_param failed");

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
  if (!ctx) {
    OSSL_PARAM_free(params);
    throw logged_error("EVP_PKEY_CTX_new_from_name failed");
  }
  if (EVP_PKEY_fromdata_init(ctx) != 1 ||
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    throw logged_error("EVP_PKEY_fromdata failed");
  }
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
}

CRSA::~CRSA(void) {
  if (pkey) EVP_PKEY_free(pkey);
}

namespace {
struct BnClearDeleter {
  void operator()(BIGNUM *b) const { BN_clear_free(b); }
};
struct BnCtxDeleter {
  void operator()(BN_CTX *c) const { BN_CTX_free(c); }
};
using BnPtr = std::unique_ptr<BIGNUM, BnClearDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
}  // namespace

ByteDynArray CRSA::RSA_PURE(const ByteArray &data) {
  // RSA_PURE is also used for g^x mod p with a secret DH exponent x (passed
  // as @c exp to the constructor), so every BIGNUM is cleared on release and
  // the exponent is processed in constant time. RAII keeps this true on
  // every exit, including bad_alloc from the result buffer below.
  BIGNUM *rawN = nullptr;
  BIGNUM *rawE = nullptr;
  bool got = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &rawN) == 1 &&
             EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &rawE) == 1;
  BnPtr n(rawN), e(rawE);
  if (!got) throw std::runtime_error("EVP_PKEY_get_bn_param failed");

  BnPtr m(BN_bin2bn(data.data(), static_cast<int>(data.size()), nullptr));
  BnPtr c(BN_new());
  BnCtxPtr bnctx(BN_CTX_new());
  if (!m || !c || !bnctx)
    throw std::runtime_error("RSA_PURE: BIGNUM/BN_CTX allocation failed");

  // RFC 8017 RSAVP1: the signature representative must be in [0, n-1].
  if (BN_is_negative(m.get()) || BN_cmp(m.get(), n.get()) >= 0)
    throw std::runtime_error("RSA_PURE: representative out of range");

  BN_set_flags(e.get(), BN_FLG_CONSTTIME);
  if (BN_mod_exp(c.get(), m.get(), e.get(), n.get(), bnctx.get()) != 1)
    throw std::runtime_error("BN_mod_exp failed");

  size_t len = static_cast<size_t>(BN_num_bytes(n.get()));

  ByteDynArray resp(len);
  if (BN_bn2binpad(c.get(), resp.data(), static_cast<int>(len)) < 0)
    throw std::runtime_error("BN_bn2binpad failed");

  return resp;
}

bool CRSA::RSA_PSS(const ByteArray &signatureData, const ByteArray &toSign) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) return false;

  EVP_PKEY_CTX *pctx = nullptr;
  if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha512(), nullptr, pkey) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  if (EVP_DigestVerifyUpdate(mdctx, toSign.data(), toSign.size()) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  int rc =
      EVP_DigestVerifyFinal(mdctx, signatureData.data(), signatureData.size());
  EVP_MD_CTX_free(mdctx);
  return rc == 1;
}
