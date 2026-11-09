// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Round trip: XML produced by CXAdESGenerator must be loadable and its
// signature verifiable by CXAdESVerifier (SDK-F21).
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "base_signer.h"
#include "sign/cie_sign_api.h"
#include "xades_generator.h"
#include "xades_verifier.h"

namespace {

class RoundTripSigner : public CBaseSigner {
 public:
  RoundTripSigner() {
    EVP_PKEY_CTX* kc = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kc);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kc, 2048);
    EVP_PKEY_keygen(kc, &m_key);
    EVP_PKEY_CTX_free(kc);
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1234567);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600 * 24);
    // Built separately: X509_get_subject_name() returns const in OpenSSL 4.
    // auto: wincrypt.h defines X509_NAME as a macro on Windows.
    auto* n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("RT"), -1,
                               -1, 0);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_NAME_free(n);
    X509_set_pubkey(x, m_key);
    X509_sign(x, m_key, EVP_sha256());
    unsigned char* der = nullptr;
    int len = i2d_X509(x, &der);
    m_cert = ByteDynArray(ByteArray(der, static_cast<size_t>(len)));
    OPENSSL_free(der);
    X509_free(x);
  }
  ~RoundTripSigner() override { EVP_PKEY_free(m_key); }

  long GetCertificate(const char*, CCertificate** pp,
                      ByteDynArray& id) override {
    id.push('1');
    *pp = new CCertificate(m_cert.data(), static_cast<long>(m_cert.size()));
    return 0;
  }
  long Sign(ByteDynArray& data, ByteDynArray&, int,
            ByteDynArray& signature) override {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(m_key, nullptr);
    EVP_PKEY_sign_init(c);
    EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PADDING);
    size_t sl = 0;
    EVP_PKEY_sign(c, nullptr, &sl, data.data(), data.size());
    std::string buf(sl, '\0');
    EVP_PKEY_sign(c, reinterpret_cast<unsigned char*>(buf.data()), &sl,
                  data.data(), data.size());
    EVP_PKEY_CTX_free(c);
    signature =
        ByteDynArray(ByteArray(reinterpret_cast<const BYTE*>(buf.data()), sl));
    return 0;
  }
  long Close() override { return 0; }

 private:
  EVP_PKEY* m_key = nullptr;
  ByteDynArray m_cert;
};

}  // namespace

TEST_CASE("XAdES generator output verifies with CXAdESVerifier",
          "[xades][SDK-F21]") {
  RoundTripSigner signer;
  CXAdESGenerator gen(&signer);
  gen.SetXAdES(true);
  const std::string doc = "<?xml version=\"1.0\"?><root><a>hello</a></root>";
  gen.SetData(ByteArray(reinterpret_cast<const BYTE*>(doc.data()), doc.size()));

  ByteDynArray out;
  REQUIRE(gen.Generate(out, FALSE, FALSE) == 0);
  std::string xml(reinterpret_cast<const char*>(out.data()), out.size());
  REQUIRE(xml.find("SignatureValue") != std::string::npos);
  REQUIRE(xml.find("X509Certificate") != std::string::npos);
  REQUIRE(xml.find("IssuerSerial") != std::string::npos);

  CXAdESVerifier v;
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "opencie_xades_roundtrip.xml";
  {
    std::ofstream f(path, std::ios::binary);
    f << xml;
  }
  std::string cpath = path.string();
  const long nSig = v.Load(cpath.data());
  std::filesystem::remove(path);
  REQUIRE(nSig == 1);
  REQUIRE(v.GetCertificate(0) != nullptr);
  const int res = v.verifySignature(0, nullptr, nullptr);
  CHECK((res & VERIFIED_SIGNATURE) != 0);
}
