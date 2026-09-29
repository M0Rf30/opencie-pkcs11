// SPDX-License-Identifier: LGPL-3.0-or-later
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "keys.h"
#include "util/cache_lib.h"

#ifndef _WIN32
namespace {
// Redirects HOME to a fresh temp directory for the lifetime of the test so
// CacheSetData/CacheSetDer never touch the real user's ~/.CIEPKI/, and
// restores/removes everything afterward — even if a REQUIRE aborts the
// test case partway through.
//
// Windows is excluded: cache_lib's GetCardDir() resolves to
// %PROGRAMDATA%\CIEPKI there, so overriding HOME would have no effect on
// where the cache is written.
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

// Creates a fresh, unique temporary directory and returns its path. Portable
// replacement for POSIX mkdtemp(), which isn't available on Windows.
std::string MakeTempDir() {
  auto base = std::filesystem::temp_directory_path();
  for (int attempt = 0; attempt < 100; ++attempt) {
    auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    auto candidate = base / ("cie_cache_test_" + std::to_string(stamp) + "_" +
                             std::to_string(attempt));
    std::error_code ec;
    if (std::filesystem::create_directory(candidate, ec))
      return candidate.string();
  }
  throw std::runtime_error("MakeTempDir: could not create a unique dir");
}

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

// The tests in this file exercise CacheSetData/CacheSetDer's on-disk
// layout by overriding HOME to point at a scratch directory (see
// ScopedHomeOverride above); they don't apply on Windows since cache_lib
// resolves the cache directory from %PROGRAMDATA%, not HOME.
TEST_CASE("CacheSetData/CacheGetPIN/CacheGetCertificate round-trip via disk",
          "[cache]") {
  std::string dir = MakeTempDir();
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
  std::string dir = MakeTempDir();
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
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  std::vector<uint8_t> out;
  CHECK_FALSE(CacheGetDer("0000000000000000", out));
}

TEST_CASE("CacheGetDer reads a legacy zero-IV .der cache", "[cache]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  // .der caches written before the authenticated format hold certlen|cert
  // in the legacy zero-IV container (seen on a real CIE enrolled in May).
  const char *PAN = "1111222233334444";
  std::string cert = "legacy-der-cache-certificate-payload";
  uint32_t certlen = static_cast<uint32_t>(cert.size());
  std::string plaintext;
  plaintext.append(reinterpret_cast<const char *>(&certlen), sizeof(certlen));
  plaintext.append(cert);
  std::string legacyCiphertext = LegacyZeroIvEncrypt(plaintext);

  std::filesystem::create_directories(homeGuard.dir() + "/.CIEPKI");
  std::string derPath =
      homeGuard.dir() + "/.CIEPKI/" + std::string(PAN) + ".der";
  std::ofstream out(derPath, std::ios::binary);
  out.write(legacyCiphertext.data(),
            static_cast<std::streamsize>(legacyCiphertext.size()));
  out.close();

  std::vector<uint8_t> got;
  REQUIRE(CacheGetDer(PAN, got));
  CHECK(std::string(got.begin(), got.end()) == cert);
  // Read-only: the legacy file is left byte-for-byte intact.
  CHECK(ReadFileBinary(derPath) == legacyCiphertext);
}

TEST_CASE(
    "CacheGetCertificate reads a legacy zero-IV cache without modifying it",
    "[cache]") {
  std::string dir = MakeTempDir();
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

  // C_Login needs the cached first PIN half from the same legacy file.
  std::vector<uint8_t> gotPin;
  CacheGetPIN(PAN, gotPin);
  CHECK(std::string(gotPin.begin(), gotPin.end()) == pin);
  CHECK(ReadFileBinary(cachePath) == legacyCiphertext);
}

TEST_CASE("CacheSetData rejects a path-traversal PAN", "[cache]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  std::string cert = "cert";
  std::string pin = "1234";

  // A PAN containing path-traversal sequences must be rejected before it
  // is concatenated into a filesystem path (see finding CIE-CACHE-004),
  // instead of being allowed to write outside ~/.CIEPKI/.
  CHECK_THROWS(CacheSetData(
      "../../evil", reinterpret_cast<uint8_t *>(cert.data()),
      static_cast<int>(cert.size()), reinterpret_cast<uint8_t *>(pin.data()),
      static_cast<int>(pin.size())));

  CHECK(!std::filesystem::exists(std::filesystem::path(dir) / ".." / ".." /
                                 "evil.cache"));
}

TEST_CASE("CacheExists/CacheRemove/CacheGetDer reject non-hex PANs",
          "[cache]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  CHECK_THROWS(CacheExists("../etc/passwd"));
  CHECK_THROWS(CacheRemove("../etc/passwd"));
  std::vector<uint8_t> out;
  CHECK_THROWS(CacheGetDer("not hex!", out));
  // A plain, empty, or over-long PAN is likewise rejected.
  CHECK_THROWS(CacheExists(""));
  CHECK_THROWS(
      CacheExists("00000000000000000000000000000000000000000000000000"));
  // A valid hex PAN is still accepted (just reports "not found").
  CHECK_FALSE(CacheExists("abcdef0123456789"));
}

TEST_CASE(
    "CacheSetData writes cache and cache directory with owner-only "
    "permissions",
    "[cache]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  const char *PAN = "abcdef0123456789";
  std::string cert = "cert-bytes";
  std::string pin = "1234";

  CacheSetData(PAN, reinterpret_cast<uint8_t *>(cert.data()),
               static_cast<int>(cert.size()),
               reinterpret_cast<uint8_t *>(pin.data()),
               static_cast<int>(pin.size()));

  std::string cieDir = homeGuard.dir() + "/.CIEPKI";
  std::string cachePath = cieDir + "/" + std::string(PAN) + ".cache";

  struct stat dirSt {};
  REQUIRE(stat(cieDir.c_str(), &dirSt) == 0);
  CHECK((dirSt.st_mode & 0777) == 0700);

  struct stat fileSt {};
  REQUIRE(stat(cachePath.c_str(), &fileSt) == 0);
  CHECK((fileSt.st_mode & 0777) == 0600);

  // The atomic-write temp file must not be left behind.
  CHECK(!std::filesystem::exists(cachePath + ".tmp"));
}
#endif  // !_WIN32
