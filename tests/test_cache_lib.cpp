// SPDX-License-Identifier: LGPL-3.0-or-later
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "keys.h"
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

// Encrypts `plaintext` the way the original CIE middleware this project was
// forked from (and the official IPZS "CIE ID" application, which still
// uses that container today) writes ~/.CIEPKI/<PAN>.cache: AES-128-CBC,
// key = SHA-1(ENCRYPTION_KEY), an all-zero IV, no magic header, no
// integrity tag. Used to simulate a cache written by that third-party
// software so CacheGetCertificate()'s fallback can be exercised without
// hardware.
std::string LegacyZeroIvEncrypt(const std::string &plaintext) {
  unsigned char key[16];
  unsigned char iv[16];
  memset(iv, 0x00, sizeof(iv));

  std::string enckey = ENCRYPTION_KEY;
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char *>(enckey.c_str()), enckey.length(),
       digest);
  memcpy(key, digest, sizeof(key));

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);

  int inLen = static_cast<int>(plaintext.size());
  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string ciphertext(inLen + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  EVP_EncryptUpdate(
      ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &outLen,
      reinterpret_cast<const unsigned char *>(plaintext.data()), inLen);
  EVP_EncryptFinal_ex(
      ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + outLen,
      &finalLen);
  EVP_CIPHER_CTX_free(ctx);
  ciphertext.resize(outLen + finalLen);
  return ciphertext;
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

TEST_CASE(
    "CacheGetCertificate reads a legacy zero-IV cache without modifying it",
    "[cache]") {
  char tmpl[] = "/tmp/cie_cache_test_XXXXXX";
  char *dir = mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  ScopedHomeOverride homeGuard(dir);

  const char *PAN = "1111222233334444";
  std::string pin = "1234";
  std::string cert = "legacy-cache-certificate-payload-from-a-third-party-app";

  // Build the same pinlen|pin|certlen|cert plaintext layout CacheSetData()
  // uses, then encrypt it with the legacy zero-IV container instead of the
  // authenticated one -- simulating a cache written by third-party CIE
  // software (e.g. the official CIE ID app) that predates this project's
  // hardening and that opencie-pkcs11 never wrote itself.
  uint32_t pinlen = static_cast<uint32_t>(pin.size());
  uint32_t certlen = static_cast<uint32_t>(cert.size());
  std::string plaintext;
  plaintext.append(reinterpret_cast<const char *>(&pinlen), sizeof(pinlen));
  plaintext.append(pin);
  plaintext.append(reinterpret_cast<const char *>(&certlen), sizeof(certlen));
  plaintext.append(cert);
  std::string legacyCiphertext = LegacyZeroIvEncrypt(plaintext);

  std::filesystem::create_directories(homeGuard.dir() + "/.CIEPKI");
  std::string cachePath =
      homeGuard.dir() + "/.CIEPKI/" + std::string(PAN) + ".cache";
  std::ofstream out(cachePath, std::ios::binary);
  out.write(legacyCiphertext.data(),
            static_cast<std::streamsize>(legacyCiphertext.size()));
  out.close();

  REQUIRE(CacheExists(PAN));

  std::vector<uint8_t> gotCert;
  CacheGetCertificate(PAN, gotCert);
  REQUIRE(gotCert.size() == cert.size());
  CHECK(std::string(gotCert.begin(), gotCert.end()) == cert);

  // The file belongs to the other app: it must be left byte-for-byte intact.
  CHECK(ReadFileBinary(cachePath) == legacyCiphertext);

  // A second read must still go through the legacy fallback.
  std::vector<uint8_t> gotCertAgain;
  CacheGetCertificate(PAN, gotCertAgain);
  REQUIRE(gotCertAgain.size() == cert.size());
  CHECK(std::string(gotCertAgain.begin(), gotCertAgain.end()) == cert);
}
