// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "asn1/certificate.h"

namespace {

// Generates an obviously-fake self-signed certificate valid for one day
// from now and returns its DER bytes.
std::vector<uint8_t> GenerateSyntheticCert() {
  auto uniq =
      std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path dir = std::filesystem::temp_directory_path() /
                              ("opencie_test_validity_" + std::to_string(uniq));
  std::filesystem::create_directories(dir);
  const std::string key = (dir / "k.pem").string();
  const std::string der = (dir / "c.der").string();
  const std::string cmd =
      "openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes "
      "-subj '/CN=OpenCIE Validity Test' -keyout '" +
      key + "' -outform DER -out '" + der + "' >/dev/null 2>&1";
  REQUIRE(std::system(cmd.c_str()) == 0);

  std::ifstream f(der, std::ios::binary);
  REQUIRE(f.good());
  std::vector<uint8_t> out((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
  std::filesystem::remove_all(dir);
  return out;
}

}  // namespace

TEST_CASE("CCertificate::isValid compares real instants and fails closed",
          "[certificate][validity]") {
  auto bytes = GenerateSyntheticCert();
  ByteDynArray content(ByteArray(bytes.data(), bytes.size()));
  CCertificate* cert = CCertificate::createCertificate(content);
  REQUIRE(cert != nullptr);

  CHECK(cert->isValid());                       // inside the one-day window
  CHECK_FALSE(cert->isValid("200101000000Z"));  // long before notBefore
  CHECK_FALSE(cert->isValid("491231235959Z"));  // 2049, after notAfter
  CHECK_FALSE(cert->isValid("500101000000Z"));  // pivot: 1950, before
  CHECK_FALSE(cert->isValid("2501"));           // short buffer: no over-read
  CHECK_FALSE(cert->isValid("2501010000AAZ"));  // not digits
  delete cert;
}
