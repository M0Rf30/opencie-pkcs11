// SPDX-License-Identifier: LGPL-3.0-or-later
#include "cache_lib.h"

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <versionhelpers.h>
// clang-format on
#define CACHE_LOG(fmt, ...)
#elif defined(__ANDROID__)
#include <android/log.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#define CACHE_LOG(fmt, ...) \
  __android_log_print(ANDROID_LOG_DEBUG, "CIE-CACHE", fmt, ##__VA_ARGS__)

static std::string g_cie_data_dir;

extern "C" __attribute__((visibility("default"))) void cie_set_data_dir(
    const char *dir) {
  g_cie_data_dir = dir ? dir : "";
  CACHE_LOG("cie_set_data_dir: %s", g_cie_data_dir.c_str());
}
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#define CACHE_LOG(fmt, ...)
#endif

#include <cstring>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include "crypto/crypto_util.h"
#include "util/util.h"

/// This PIN and certificate cache implementation is provided for demonstration
/// purposes only. This version does NOT adequately protect the user's PIN,
/// which could be extracted by a malicious application. In production
/// environments, an implementation providing a high level of security is
/// strongly recommended.

#ifdef _WIN32
bool file_exists(const char *name) { return PathFileExists(name); }
#else
bool file_exists(const char *name) {
  struct stat buffer;
  return (stat(name, &buffer) == 0);
}
#endif

#ifdef _WIN32
std::string commonData;

std::string GetCardDir() {
  if (commonData.empty() || commonData[0] == 0) {
    char szPath[MAX_PATH];
    ExpandEnvironmentStrings("%PROGRAMDATA%\\CIEPKI", szPath, MAX_PATH);
    commonData = szPath;
  }
  return commonData;
}
#else
std::string GetCardDir() {
#ifdef __ANDROID__
  if (!g_cie_data_dir.empty()) {
    std::string path = g_cie_data_dir;
    path.append("/.CIEPKI/");
    CACHE_LOG("GetCardDir (explicit): %s", path.c_str());
    return path;
  }
#endif

  char *home = getenv("HOME");
  if (home == nullptr) {
    const struct passwd *pw = getpwuid(getuid());

    home = pw->pw_dir;
  }

  std::string path(home);

  path.append("/.CIEPKI/");

  CACHE_LOG("GetCardDir: %s", path.c_str());

  return path;
}
#endif

#ifdef _WIN32
void GetCardPath(const char *PAN, std::string &sPath) {
  auto Path = GetCardDir();

  if (Path[Path.length() - 1] != '\\') Path += '\\';

  Path += std::string(PAN);
  Path += ".cache";
  sPath = Path;
}
#else
void GetCardPath(const char *PAN, std::string &sPath) {
  auto Path = GetCardDir();

  Path += std::string(PAN);
  Path += ".cache";
  sPath = Path;
}
#endif

bool CacheExists(const char *PAN) {
  std::string sPath;
  GetCardPath(PAN, sPath);
  bool exists = file_exists(sPath.c_str());
  CACHE_LOG("CacheExists: path=%s exists=%d", sPath.c_str(), exists ? 1 : 0);
  return exists;
}

bool CacheRemove(const char *PAN) {
  std::string sPath;
  GetCardPath(PAN, sPath);
  int ret = remove(sPath.c_str());
  // Also remove the companion .der file if it exists.
  std::string derPath = sPath.substr(0, sPath.size() - 6) + ".der";
  remove(derPath.c_str());  // ignore error — file may not exist
  return ret == 0;
}

static void GetDerPath(const char *PAN, std::string &sPath) {
  auto Path = GetCardDir();
  Path += std::string(PAN);
  Path += ".der";
  sPath = Path;
}

void CacheSetDer(const char *PAN, const uint8_t *der, size_t len) {
  if (PAN == nullptr || der == nullptr || len == 0)
    throw logged_error("CacheSetDer: invalid arguments");

  auto szDir = GetCardDir();
#ifndef _WIN32
  struct stat st {};
  if (stat(szDir.c_str(), &st) == -1) {
    mkdir(szDir.c_str(), 0700);
  }
#endif

  std::string sPath;
  GetDerPath(PAN, sPath);

  // Encrypt with the same key/format used by CacheSetData so the
  // certificate is not stored in plaintext (consistent with existing cache).
  uint32_t certlen = static_cast<uint32_t>(len);
  std::string plaintext;
  plaintext.append(reinterpret_cast<const char *>(&certlen), sizeof(certlen));
  plaintext.append(reinterpret_cast<const char *>(der), len);

  std::string ciphertext;
  encrypt(plaintext, ciphertext);
  OPENSSL_cleanse(plaintext.data(), plaintext.size());

  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetDer: cannot open file for writing");
  file.write(ciphertext.c_str(), ciphertext.length());
  file.close();
}

bool CacheGetDer(const char *PAN, std::vector<uint8_t> &certificate) {
  if (PAN == nullptr) return false;

  std::string sPath;
  GetDerPath(PAN, sPath);

  if (!file_exists(sPath.c_str())) return false;

  try {
    ByteDynArray data;
    data.load(sPath.c_str());
    if (data.isEmpty()) return false;

    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;
    if (decrypt(ciphertext, plaintext) != 0) return false;

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
    uint32_t len;
    if (plaintext.size() < sizeof(len))
      throw logged_error("CacheGetDer: corrupted cache data");
    memcpy(&len, ptr, sizeof(len));
    ptr += sizeof(len);
    if (len > plaintext.size() - sizeof(len))
      throw logged_error("CacheGetDer: corrupted cache data (invalid length)");
    certificate.assign(ptr, ptr + len);
    return true;
  } catch (...) {
    return false;
  }
}

void CacheGetCertificate(const char *PAN, std::vector<uint8_t> &certificate) {
  if (PAN == nullptr) throw logged_error("PAN is required");

  std::string sPath;
  GetCardPath(PAN, sPath);

  if (file_exists(sPath.c_str())) {
    ByteDynArray data, Cert;
    data.load(sPath.c_str());

    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;
    if (decrypt(ciphertext, plaintext) != 0)
      throw logged_error("CacheGetCertificate: failed to decrypt cache");

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
    size_t remaining = plaintext.size();

    uint32_t len;
    if (remaining < sizeof(len))
      throw logged_error("CacheGetCertificate: corrupted cache data");
    memcpy(&len, ptr, sizeof(len));
    ptr += sizeof(len);
    remaining -= sizeof(len);
    if (len > remaining)
      throw logged_error(
          "CacheGetCertificate: corrupted cache data (invalid PIN length)");
    // salto il PIN
    ptr += len;
    remaining -= len;
    if (remaining < sizeof(len))
      throw logged_error("CacheGetCertificate: corrupted cache data");
    memcpy(&len, ptr, sizeof(len));
    ptr += sizeof(len);
    remaining -= sizeof(len);
    if (len > remaining)
      throw logged_error(
          "CacheGetCertificate: corrupted cache data (invalid certificate "
          "length)");
    Cert.resize(len);
    Cert.copy(ByteArray(ptr, len));

    certificate.resize(Cert.size());
    ByteArray(certificate.data(), certificate.size()).copy(Cert);
  } else {
    throw logged_error("CIE not enabled");
  }
}

void CacheGetPIN(const char *PAN, std::vector<uint8_t> &PIN) {
  if (PAN == nullptr) throw logged_error("PAN is required");

  std::string sPath;
  GetCardPath(PAN, sPath);

  if (file_exists(sPath.c_str())) {
    ByteDynArray data, ClearPIN;
    data.load(sPath.c_str());

    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;
    if (decrypt(ciphertext, plaintext) != 0)
      throw logged_error("CacheGetPIN: failed to decrypt cache");

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
    uint32_t len;
    if (plaintext.size() < sizeof(len))
      throw logged_error("CacheGetPIN: corrupted cache data");
    memcpy(&len, ptr, sizeof(len));
    ptr += sizeof(len);
    if (len > plaintext.size() - sizeof(len))
      throw logged_error("CacheGetPIN: corrupted cache data (invalid length)");
    ClearPIN.resize(len);
    ClearPIN.copy(ByteArray(ptr, len));

    PIN.resize(ClearPIN.size());
    ByteArray(PIN.data(), PIN.size()).copy(ClearPIN);

  } else
    throw logged_error("CIE not enabled");
}

void CacheSetData(const char *PAN, uint8_t *certificate, int certificateSize,
                  uint8_t *FirstPIN, int FirstPINSize) {
  if (PAN == nullptr) throw logged_error("PAN is required");

  auto szDir = GetCardDir();

#ifdef _WIN32
  char chDir[MAX_PATH];
  strcpy_s(chDir, szDir.c_str());

  if (!PathFileExists(chDir)) {
    CreateDirectory(chDir, nullptr);

    // Default ACL inherited from user profile is sufficient.
    // Do NOT widen access to WinBuiltinAnyPackageSid.
  }
#else
  struct stat st {};

  if (stat(szDir.c_str(), &st) == -1) {
    mkdir(szDir.c_str(), 0700);
  }
#endif

  std::string sPath;
  GetCardPath(PAN, sPath);

  ByteArray baCertificate(certificate, certificateSize);
  ByteArray baFirstPIN(FirstPIN, FirstPINSize);

  // Build plaintext as [pinlen][pin][certlen][cert] and encrypt the whole
  // buffer so the on-disk cache never holds the PIN or certificate in the
  // clear, on any platform.
  uint32_t pinlen = static_cast<uint32_t>(baFirstPIN.size());
  uint32_t certlen = static_cast<uint32_t>(baCertificate.size());

  std::string plaintext;
  plaintext.append(reinterpret_cast<const char *>(&pinlen), sizeof(pinlen));
  plaintext.append(reinterpret_cast<const char *>(baFirstPIN.data()), pinlen);
  plaintext.append(reinterpret_cast<const char *>(&certlen), sizeof(certlen));
  plaintext.append(reinterpret_cast<const char *>(baCertificate.data()),
                   certlen);

  std::string ciphertext;
  encrypt(plaintext, ciphertext);
  OPENSSL_cleanse(plaintext.data(), plaintext.size());

  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetData: cannot open file for writing");
  file.write(ciphertext.c_str(), ciphertext.length());
  file.close();
}
