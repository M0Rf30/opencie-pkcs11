// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "util/cache_lib.h"

namespace {
// Redirects HOME to a fresh temp directory for the lifetime of the test so
// CacheSetData/CacheSetDer never touch the real user's ~/.CIEPKI/, and
// restores/removes everything afterward — even if a REQUIRE aborts the
// test case partway through.
class ScopedHomeOverride {
 public:
  explicit ScopedHomeOverride(std::string dir) : dir_(std::move(dir)) {
    if (const char *h = getenv("HOME")) {
      hadHome_ = true;
      oldHome_ = h;
    }
    setenv("HOME", dir_.c_str(), 1);
  }

  ~ScopedHomeOverride() {
    if (hadHome_)
      setenv("HOME", oldHome_.c_str(), 1);
    else
      unsetenv("HOME");
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);
  }

  const std::string &dir() const { return dir_; }

  ScopedHomeOverride(const ScopedHomeOverride &) = delete;
  ScopedHomeOverride &operator=(const ScopedHomeOverride &) = delete;

 private:
  std::string dir_;
  std::string oldHome_;
  bool hadHome_ = false;
};

std::string ReadFileBinary(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
}
}  // namespace

TEST_CASE("CacheSetData/CacheGetPIN/CacheGetCertificate round-trip via disk",
          "[cache]") {
  char tmpl[] = "/tmp/cie_cache_test_XXXXXX";
  char *dir = mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  ScopedHomeOverride homeGuard(dir);

  const char *PAN = "1234567890123456";
  std::string pin = "12345";
  std::string cert =
      "not-a-real-DER-certificate-but-long-enough-to-exercise-the-cache";

  CacheSetData(PAN, reinterpret_cast<uint8_t *>(cert.data()),
               static_cast<int>(cert.size()),
               reinterpret_cast<uint8_t *>(pin.data()),
               static_cast<int>(pin.size()));

  CHECK(CacheExists(PAN));

  std::vector<uint8_t> gotPin;
  CacheGetPIN(PAN, gotPin);
  REQUIRE(gotPin.size() == pin.size());
  CHECK(std::string(gotPin.begin(), gotPin.end()) == pin);

  std::vector<uint8_t> gotCert;
  CacheGetCertificate(PAN, gotCert);
  REQUIRE(gotCert.size() == cert.size());
  CHECK(std::string(gotCert.begin(), gotCert.end()) == cert);

  // The cache file on disk must be encrypted: neither secret shows up in
  // the raw bytes, and it must carry the random-IV "CIE1" format marker.
  std::string cachePath =
      homeGuard.dir() + "/.CIEPKI/" + std::string(PAN) + ".cache";
  std::string onDisk = ReadFileBinary(cachePath);
  REQUIRE_FALSE(onDisk.empty());
  CHECK(onDisk.find(pin) == std::string::npos);
  CHECK(onDisk.find(cert) == std::string::npos);
  REQUIRE(onDisk.size() >= 4);
  CHECK(onDisk.substr(0, 4) == "CIE1");

  CHECK(CacheRemove(PAN));
  CHECK_FALSE(CacheExists(PAN));
}

TEST_CASE("CacheSetDer/CacheGetDer round-trip via disk, encrypted at rest",
          "[cache]") {
  char tmpl[] = "/tmp/cie_cache_test_XXXXXX";
  char *dir = mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  ScopedHomeOverride homeGuard(dir);

  const char *PAN = "9999888877776666";
  std::string der = "not-a-real-DER-payload-but-nonzero-length-for-testing";

  CacheSetDer(PAN, reinterpret_cast<const uint8_t *>(der.data()), der.size());

  std::vector<uint8_t> gotDer;
  REQUIRE(CacheGetDer(PAN, gotDer));
  REQUIRE(gotDer.size() == der.size());
  CHECK(std::string(gotDer.begin(), gotDer.end()) == der);

  std::string derPath =
      homeGuard.dir() + "/.CIEPKI/" + std::string(PAN) + ".der";
  std::string onDisk = ReadFileBinary(derPath);
  CHECK(onDisk.find(der) == std::string::npos);
  REQUIRE(onDisk.size() >= 4);
  CHECK(onDisk.substr(0, 4) == "CIE1");
}

TEST_CASE("CacheGetDer returns false for a missing PAN", "[cache]") {
  char tmpl[] = "/tmp/cie_cache_test_XXXXXX";
  char *dir = mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  ScopedHomeOverride homeGuard(dir);

  std::vector<uint8_t> out;
  CHECK_FALSE(CacheGetDer("0000000000000000", out));
}
