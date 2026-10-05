// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "asn1/certificate.h"
#include "asn1/name.h"
#include "asn1/ocsp_request.h"
#include "cie_ca_certs_data.h"

namespace {

std::vector<uint8_t> readFile(const std::filesystem::path& path) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(f.good());
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

// Runs `cmd` (an OpenSSL CLI invocation), failing the test if it does not
// exit successfully. Used to generate synthetic, obviously-fake test
// certificates at runtime instead of checking in fixture data.
void run(const std::string& cmd) { REQUIRE(std::system(cmd.c_str()) == 0); }

// Generates a synthetic self-signed root CA and a leaf certificate it
// signs (both obviously-fake test data, fresh for each call), and returns
// the DER bytes of each plus the temp directory holding them (caller
// should remove_all() it when done).
struct SyntheticCertPair {
  std::filesystem::path dir;
  std::vector<uint8_t> rootDer;
  std::vector<uint8_t> leafDer;
};

SyntheticCertPair GenerateSyntheticRootAndLeaf() {
  auto uniq =
      std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path dir = std::filesystem::temp_directory_path() /
                              ("opencie_test_keyid_" + std::to_string(uniq));
  std::filesystem::create_directories(dir);

  std::string rootKey = (dir / "root.key").string();
  std::string rootPem = (dir / "root.pem").string();
  std::string rootDer = (dir / "root.der").string();
  std::string leafKey = (dir / "leaf.key").string();
  std::string leafCsr = (dir / "leaf.csr").string();
  std::string leafPem = (dir / "leaf.pem").string();
  std::string leafDer = (dir / "leaf.der").string();
  std::string leafExt = (dir / "leaf.ext").string();

  // Synthetic self-signed root: real (SHA-1 hash-of-key) Subject Key
  // Identifier and a self-referencing Authority Key Identifier. All values
  // below are obviously-fake test data generated fresh for this run.
  run("openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes "
      "-subj '/CN=OpenCIE Test Root/O=OpenCIE Test' "
      "-addext 'subjectKeyIdentifier=hash' "
      "-addext 'authorityKeyIdentifier=keyid:always' "
      "-keyout '" +
      rootKey + "' -out '" + rootPem + "' >/dev/null 2>&1");
  run("openssl x509 -in '" + rootPem + "' -outform DER -out '" + rootDer +
      "' >/dev/null 2>&1");

  // Leaf signed by the root, with its AKI derived from the root's actual
  // SKI (the real-world shape of the bug report: a leaf certificate whose
  // AuthorityKeyIdentifier keyIdentifier must resolve to the issuer's
  // SubjectKeyIdentifier for OCSP/CRL issuer lookup to work).
  run("openssl req -new -newkey rsa:2048 -nodes -subj '/CN=OpenCIE Test Leaf' "
      "-keyout '" +
      leafKey + "' -out '" + leafCsr + "' >/dev/null 2>&1");
  {
    std::ofstream ext(leafExt);
    REQUIRE(ext.good());
    ext << "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n";
  }
  run("openssl x509 -req -in '" + leafCsr + "' -CA '" + rootPem + "' -CAkey '" +
      rootKey + "' -CAcreateserial -days 1 -sha256 -extfile '" + leafExt +
      "' -out '" + leafPem + "' >/dev/null 2>&1");
  run("openssl x509 -in '" + leafPem + "' -outform DER -out '" + leafDer +
      "' >/dev/null 2>&1");

  SyntheticCertPair pair;
  pair.dir = dir;
  pair.rootDer = readFile(rootDer);
  pair.leafDer = readFile(leafDer);
  return pair;
}

}  // namespace

TEST_CASE(
    "Authority/Subject Key Identifier extraction returns the raw 20-byte "
    "key id, not a nested TLV",
    "[certificate][aki][ski]") {
  SyntheticCertPair pair = GenerateSyntheticRootAndLeaf();

  CCertificate rootCert(pair.rootDer.data(),
                        static_cast<long>(pair.rootDer.size()));
  CCertificate leafCert(pair.leafDer.data(),
                        static_cast<long>(pair.leafDer.size()));

  CASN1OctetString rootSki = rootCert.getSubjectKeyIdentifier();
  CASN1OctetString leafAki = leafCert.getAuthorithyKeyIdentifier();

  // A real key identifier is exactly 20 raw bytes (SHA-1 hash of the
  // public key) -- not the 22-byte nested TLV (an inner tag + length +
  // the 20 bytes) that the unfixed extractor used to return for both AKI
  // and SKI.
  REQUIRE(rootSki.getLength() == 20);
  REQUIRE(leafAki.getLength() == 20);

  // The leaf's AKI must equal the root's SKI byte-for-byte: this is what
  // CCertStore::GetCertificate() hashes and compares to find the issuer.
  REQUIRE(*rootSki.getValue() == *leafAki.getValue());

  std::error_code ec;
  std::filesystem::remove_all(pair.dir, ec);
}

TEST_CASE(
    "OCSP request CertID matches OpenSSL's OCSP_cert_to_id for the same "
    "cert pair",
    "[certificate][ocsp][certid]") {
  SyntheticCertPair pair = GenerateSyntheticRootAndLeaf();

  CCertificate leafCert(pair.leafDer.data(),
                        static_cast<long>(pair.leafDer.size()));

  // Build the request the same way CCertificate::verifyStatus() does, and
  // dig out the single CertID it contains:
  // OCSPRequest{ tbsRequest{ requestList{ Request{ CertID{...} } } } }.
  COCSPRequest req(leafCert);
  CASN1Sequence tbsRequest(req.elementAt(0));
  CASN1Sequence requestList(tbsRequest.elementAt(0));
  CASN1Sequence request(requestList.elementAt(0));
  CASN1Sequence certId(request.elementAt(0));

  CASN1OctetString issuerNameHash(certId.elementAt(1));
  CASN1OctetString issuerKeyHash(certId.elementAt(2));
  CASN1Integer serialNumber(certId.elementAt(3));

  // Independently compute the expected CertID with OpenSSL's own
  // OCSP_cert_to_id(), completely bypassing this SDK's ASN.1 code.
  const unsigned char* pLeaf = pair.leafDer.data();
  X509* leafX509 =
      d2i_X509(nullptr, &pLeaf, static_cast<long>(pair.leafDer.size()));
  REQUIRE(leafX509 != nullptr);

  const unsigned char* pRoot = pair.rootDer.data();
  X509* issuerX509 =
      d2i_X509(nullptr, &pRoot, static_cast<long>(pair.rootDer.size()));
  REQUIRE(issuerX509 != nullptr);

  OCSP_CERTID* expected = OCSP_cert_to_id(EVP_sha1(), leafX509, issuerX509);
  REQUIRE(expected != nullptr);

  ASN1_OCTET_STRING* expNameHash = nullptr;
  ASN1_OCTET_STRING* expKeyHash = nullptr;
  ASN1_INTEGER* expSerial = nullptr;
  REQUIRE(OCSP_id_get0_info(&expNameHash, nullptr, &expKeyHash, &expSerial,
                            expected) == 1);

  REQUIRE(issuerNameHash.getLength() ==
          static_cast<unsigned int>(ASN1_STRING_length(expNameHash)));
  REQUIRE(memcmp(issuerNameHash.getValue()->data(),
                 ASN1_STRING_get0_data(expNameHash),
                 issuerNameHash.getLength()) == 0);

  REQUIRE(issuerKeyHash.getLength() ==
          static_cast<unsigned int>(ASN1_STRING_length(expKeyHash)));
  REQUIRE(memcmp(issuerKeyHash.getValue()->data(),
                 ASN1_STRING_get0_data(expKeyHash),
                 issuerKeyHash.getLength()) == 0);

  // issuerKeyHash must equal the leaf's own raw Authority Key Identifier
  // (see COCSPRequest::ComputeCertID()'s comment): cross-check that too.
  CASN1OctetString leafAki = leafCert.getAuthorithyKeyIdentifier();
  REQUIRE(leafAki.getLength() == issuerKeyHash.getLength());
  REQUIRE(*leafAki.getValue() == *issuerKeyHash.getValue());

  // OpenSSL keeps an INTEGER's magnitude, while the DER content carries a
  // leading 0x00 when the top bit of the first magnitude byte is set. With
  // the 159-bit random serial from -CAcreateserial that happens about once
  // in 256 runs (the cause of an intermittent 20 == 19 failure).
  const uint8_t* serialData = serialNumber.getValue()->data();
  size_t serialLen = serialNumber.getLength();
  if (serialLen > 1 && serialData[0] == 0x00 && (serialData[1] & 0x80)) {
    ++serialData;
    --serialLen;
  }
  REQUIRE(serialLen == static_cast<size_t>(ASN1_STRING_length(expSerial)));
  REQUIRE(memcmp(serialData, ASN1_STRING_get0_data(expSerial), serialLen) == 0);

  OCSP_CERTID_free(expected);
  X509_free(leafX509);
  X509_free(issuerX509);

  std::error_code ec;
  std::filesystem::remove_all(pair.dir, ec);
}

TEST_CASE("Embedded CIE CA certificates parse and include SUBCA002",
          "[certificate][cie-ca]") {
  bool foundSubca002 = false;

  REQUIRE(std::size(CieCaCerts::kAll) == 5);

  for (const auto& entry : CieCaCerts::kAll) {
    REQUIRE(entry.der != nullptr);
    REQUIRE(entry.len > 0);

    CCertificate cert(entry.der, static_cast<long>(entry.len));

    std::string cn = cert.getSubject().getField(OID_COMMON_NAME);
    REQUIRE_FALSE(cn.empty());

    if (cn.find("SUBCA002") != std::string::npos) {
      foundSubca002 = true;

      // The SUBCA002 embedded cert must carry the same Subject Key
      // Identifier the real-world bug report's signer certificate names
      // as its Authority Key Identifier (F9:2E:E9:08...), confirming this
      // is the correct, currently-issuing CIE sub-CA.
      CASN1OctetString ski = cert.getSubjectKeyIdentifier();
      REQUIRE(ski.getLength() == 20);
      REQUIRE(ski.getValue()->data()[0] == 0xF9);
      REQUIRE(ski.getValue()->data()[1] == 0x2E);
      REQUIRE(ski.getValue()->data()[2] == 0xE9);
      REQUIRE(ski.getValue()->data()[3] == 0x08);
    }
  }

  REQUIRE(foundSubca002);
}
