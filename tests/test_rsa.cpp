// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <vector>

#include "crypto/rsa.h"
#include "util/array.h"

namespace {

// Fixed RSA-2048 test key, pre-generated offline. Runtime RSA keygen was
// removed from this test because it can take an extremely long time (or
// trip CI watchdog timeouts) under QEMU user-mode emulation on linux-arm64
// runners; a static key keeps the test fast and deterministic everywhere.
constexpr char kFixedRsaTestKeyPem[] = R"PEMKEY(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0M10cx7eQTuIR
ufPcHe6BKZjWUVia99CqYUA6BCtz7tIzAXucFOaNV50BD1AlTozqMRuqhzWCStXA
yRIlkzysQM9SsdotgStPT+BwEfRp3woUqva2V99EjDIG6lz8kp0i6B4Q57g7QHCh
YqfwFz7FEr6QTC3ndRJdg76f8y46VTRkfSFFv8Onp7G66FW3S4AX4uhB6Wsr1Fdb
SylimwHxuZh2ZvAzpa/H9t5Gr7J1uSSa+EOLhPqrS3fmsQSlK3oJQatBun14hczb
Umr0htCFjZ4ubvEh8p0dXBV7BeR842L4ha3co/74RhE02bCLwHwwe1jWQ1ywRDRo
6iid8adNAgMBAAECggEAC3yIr2h1pX+5vlqFll7cEKSnpuWpibtJNEsdrnUMlge/
o1uxVuooJhNTITmqKK6god7+ffi/au49QNwwSW/gurQo4wMOPr9QlO4pBsvGMidy
+41IS6g/RZ3QJIu04K6x0INOQ1KZ9kDtzQO+Y7n/mM1Qk18fv/TA9nAK6yQzqqke
/bmZM3/5SDKlbo/g5d2fv3PHGPilSn0jGD3SU8FV5bJcevRhcUvDlvdTHQL/fuyt
w2v3emu1fC+gmEdndpRMU2YMi+Owz66FNJkSxvJbB4N/777dcCZ8y8FTn4TTXgA/
xcoJ/v9mJfYaQ7IwAvXXG1sK99/6Qi6D3DfX6HB0ewKBgQD86r7EKWp1H4Jq6Uxm
9S5CWk0g0NlpvCdKC9C68iUVPGqDezHiLAjsheB3eBbIGdsLrpHf0Ax8h6aBMMgK
cgRhH2O09An493tK5pm5qwjwAHkkzUJmGRnRUvNyR5bB7ctrviyGw7uzCdc1/XaA
rvZnoOBbCKngKIVGNOOylfrvtwKBgQC2ZbMIBDVklRSKABJMeNoSEstV17kvevyW
1OwKo5biYWZbloBAowHp2dLdjGBx4sQqA7vaAso3XdLQqTmbnTarHf5xuf0TU5TD
hN39TfUCFDrWwZx927fcadqBI2mQwJIU0vqzpGtWHM6fyVSPDYwXPsw16R4uesSo
XA9HGnqZGwKBgAwPUXtfEjF1iC165GbAaC1Hywe2jbdp/mGcgJ55b2U81UNhu3Yy
bVaB57sqocN24CgFcfU/IWlKupjMb6131FehPIrjXBpgCqP+rPPagPmYvC4SD4l4
xu9hSjR3z2t94EZJ8iuW57tYy8dKR71JGnzEgg41Mox6wigf23+ngSivAoGBAIDX
eg3Rmz2/qVCKGGL4g2J88DFlPyTxBXguU8Z4JF8pWjqcJ2CBRRrBiZiCTqZj/xmG
pa2shtdxaTeIMm9gMHvTpicDsGd0hQNP2dfSt52OWLnW7gphqJEEHRtXvnxH62jW
V82J+WBM3RA2EYszkJ/i9jGmyHEgu8YJsakSZUO9AoGBAIgs16Q3WmQeKIig80pE
NugTYGzLfrKYoXqihrUiy7putbm4JvlJxjjOUJ1wYO9JuyK8uiOM1aAsUuanmAjd
fNn4S7jyNnVFZU5SZfA48+YV0TIuJJMX9oe9PBWfJ4r9l9Gct9VfGd+ZQGDpn8Mf
lfIHs9HxVmuJRKPBeKrILrFM
-----END PRIVATE KEY-----
)PEMKEY";

// Wraps a fixed RSA-2048 keypair (parsed from kFixedRsaTestKeyPem) along
// with the raw big-endian modulus/exponent bytes needed to build a CRSA
// (public-key-only) instance.
struct GeneratedKey {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey {nullptr,
                                                            EVP_PKEY_free};
  std::vector<uint8_t> modulus;
  std::vector<uint8_t> exponent;
};

GeneratedKey GenerateRsaKey() {
  GeneratedKey gk;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_mem_buf(kFixedRsaTestKeyPem,
                      static_cast<int>(sizeof(kFixedRsaTestKeyPem) - 1)),
      BIO_free);
  REQUIRE(bio != nullptr);
  EVP_PKEY *raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  REQUIRE(raw != nullptr);
  gk.pkey.reset(raw);

  BIGNUM *n = nullptr;
  BIGNUM *e = nullptr;
  REQUIRE(EVP_PKEY_get_bn_param(gk.pkey.get(), OSSL_PKEY_PARAM_RSA_N, &n) == 1);
  REQUIRE(EVP_PKEY_get_bn_param(gk.pkey.get(), OSSL_PKEY_PARAM_RSA_E, &e) == 1);

  gk.modulus.resize(static_cast<size_t>(BN_num_bytes(n)));
  BN_bn2bin(n, gk.modulus.data());
  gk.exponent.resize(static_cast<size_t>(BN_num_bytes(e)));
  BN_bn2bin(e, gk.exponent.data());

  BN_free(n);
  BN_free(e);
  return gk;
}

}  // namespace

TEST_CASE("RSA_PURE public op matches private-key inverse", "[crypto][rsa]") {
  GeneratedKey gk = GenerateRsaKey();
  ByteArray mod(gk.modulus.data(), gk.modulus.size());
  ByteArray exp(gk.exponent.data(), gk.exponent.size());

  // A message smaller than the modulus (leading zero byte to guarantee it).
  std::vector<uint8_t> msg(gk.modulus.size(), 0);
  msg[0] = 0x00;
  msg[msg.size() - 1] = 0x2a;
  ByteArray msgArr(msg.data(), msg.size());

  CRSA rsa(mod, exp);
  ByteDynArray ct = rsa.RSA_PURE(msgArr);
  REQUIRE(ct.size() == gk.modulus.size());

  // Decrypt with the private key using raw (no-padding) RSA to recover msg.
  EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(gk.pkey.get(), nullptr);
  REQUIRE(dctx != nullptr);
  REQUIRE(EVP_PKEY_decrypt_init(dctx) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_NO_PADDING) == 1);

  size_t outlen = 0;
  REQUIRE(EVP_PKEY_decrypt(dctx, nullptr, &outlen, ct.data(), ct.size()) == 1);
  std::vector<uint8_t> recovered(outlen);
  REQUIRE(EVP_PKEY_decrypt(dctx, recovered.data(), &outlen, ct.data(),
                           ct.size()) == 1);
  EVP_PKEY_CTX_free(dctx);

  // recovered may be left-trimmed of leading zero bytes by OpenSSL.
  size_t skip = msg.size() - outlen;
  REQUIRE(skip <= msg.size());
  for (size_t i = 0; i < outlen; ++i) CHECK(recovered[i] == msg[skip + i]);
}

TEST_CASE("RSA_PSS verifies a valid SHA-512 PSS signature", "[crypto][rsa]") {
  GeneratedKey gk = GenerateRsaKey();
  ByteArray mod(gk.modulus.data(), gk.modulus.size());
  ByteArray exp(gk.exponent.data(), gk.exponent.size());

  const uint8_t message[] = {'h', 'e', 'l', 'l', 'o', ' ', 'c', 'i', 'e'};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  REQUIRE(mdctx != nullptr);
  EVP_PKEY_CTX *sctx = nullptr;
  REQUIRE(EVP_DigestSignInit(mdctx, &sctx, EVP_sha512(), nullptr,
                             gk.pkey.get()) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PSS_PADDING) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_AUTO) == 1);
  REQUIRE(EVP_DigestSignUpdate(mdctx, message, sizeof(message)) == 1);

  size_t sigLen = 0;
  REQUIRE(EVP_DigestSignFinal(mdctx, nullptr, &sigLen) == 1);
  std::vector<uint8_t> sig(sigLen);
  REQUIRE(EVP_DigestSignFinal(mdctx, sig.data(), &sigLen) == 1);
  sig.resize(sigLen);
  EVP_MD_CTX_free(mdctx);

  CRSA rsa(mod, exp);
  ByteArray sigArr(sig.data(), sig.size());
  ByteArray msgArr(message, sizeof(message));
  CHECK(rsa.RSA_PSS(sigArr, msgArr));

  // Tampering with the message must invalidate the signature.
  std::vector<uint8_t> tampered(message, message + sizeof(message));
  tampered[0] ^= 0xFF;
  ByteArray tamperedArr(tampered.data(), tampered.size());
  CHECK_FALSE(rsa.RSA_PSS(sigArr, tamperedArr));
}

TEST_CASE("RSA_PSS rejects corrupted signature bytes", "[crypto][rsa]") {
  GeneratedKey gk = GenerateRsaKey();
  ByteArray mod(gk.modulus.data(), gk.modulus.size());
  ByteArray exp(gk.exponent.data(), gk.exponent.size());

  const uint8_t message[] = {'t', 'e', 's', 't'};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  REQUIRE(mdctx != nullptr);
  EVP_PKEY_CTX *sctx = nullptr;
  REQUIRE(EVP_DigestSignInit(mdctx, &sctx, EVP_sha512(), nullptr,
                             gk.pkey.get()) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PSS_PADDING) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_AUTO) == 1);
  REQUIRE(EVP_DigestSignUpdate(mdctx, message, sizeof(message)) == 1);

  size_t sigLen = 0;
  REQUIRE(EVP_DigestSignFinal(mdctx, nullptr, &sigLen) == 1);
  std::vector<uint8_t> sig(sigLen);
  REQUIRE(EVP_DigestSignFinal(mdctx, sig.data(), &sigLen) == 1);
  sig.resize(sigLen);
  EVP_MD_CTX_free(mdctx);

  sig[sig.size() / 2] ^= 0xFF;

  CRSA rsa(mod, exp);
  ByteArray sigArr(sig.data(), sig.size());
  ByteArray msgArr(message, sizeof(message));
  CHECK_FALSE(rsa.RSA_PSS(sigArr, msgArr));
}
