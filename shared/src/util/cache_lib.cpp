// SPDX-License-Identifier: LGPL-3.0-or-later
#include "cache_lib.h"

#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <versionhelpers.h>
#define CACHE_LOG(fmt, ...)
#elif defined(__ANDROID__)
#include <android/log.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
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
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#define CACHE_LOG(fmt, ...)
#endif

#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include "util/util.h"

#ifndef _WIN32
#include "keys.h"
#endif

#ifndef _WIN32
using namespace CryptoPP;

int decrypt(const std::string &ciphertext, std::string &message);
#endif

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

#ifdef _WIN32
  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetDer: cannot open file for writing");
  uint32_t certlen = static_cast<uint32_t>(len);
  file.write(reinterpret_cast<const char *>(&certlen), sizeof(certlen));
  file.write(reinterpret_cast<const char *>(der),
             static_cast<std::streamsize>(len));
#else
  // Encrypt with the same static AES-CBC key used by CacheSetData so the
  // certificate is not stored in plaintext (consistent with existing cache).
  byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

  std::string enckey = ENCRYPTION_KEY;
  byte digest[SHA1::DIGESTSIZE];
  SHA1().CalculateDigest(digest, reinterpret_cast<const byte *>(enckey.c_str()),
                         enckey.length());
  memcpy(key, digest, CryptoPP::AES::DEFAULT_KEYLENGTH);

  uint32_t certlen = static_cast<uint32_t>(len);
  std::string ciphertext;
  CryptoPP::AES::Encryption aesEncryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
                                                              iv);
  CryptoPP::StreamTransformationFilter stfEncryptor(
      cbcEncryption, new CryptoPP::StringSink(ciphertext));
  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(&certlen),
                   sizeof(certlen));
  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(der),
                   static_cast<size_t>(len));
  stfEncryptor.MessageEnd();

  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetDer: cannot open file for writing");
  file.write(ciphertext.c_str(), ciphertext.length());
#endif
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

#ifdef _WIN32
    uint8_t *ptr = data.data();
    uint32_t len = *reinterpret_cast<uint32_t *>(ptr);
    ptr += sizeof(uint32_t);
    certificate.assign(ptr, ptr + len);
#else
    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;
    if (decrypt(ciphertext, plaintext) != 0) return false;

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
    uint32_t len = *reinterpret_cast<uint32_t *>(ptr);
    ptr += sizeof(uint32_t);
    certificate.assign(ptr, ptr + len);
#endif
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

#ifdef _WIN32
    uint8_t *ptr = data.data();
#else
    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;

    decrypt(ciphertext, plaintext);

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
#endif

    uint32_t len = *reinterpret_cast<uint32_t *>(ptr);
    ptr += sizeof(uint32_t);
    // salto il PIN
    ptr += len;
    len = *reinterpret_cast<uint32_t *>(ptr);
    ptr += sizeof(uint32_t);
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

#ifdef _WIN32
    uint8_t *ptr = data.data();
#else
    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;

    decrypt(ciphertext, plaintext);

    uint8_t *ptr =
        reinterpret_cast<uint8_t *>(const_cast<char *>(plaintext.c_str()));
#endif
    uint32_t len = *reinterpret_cast<uint32_t *>(ptr);
    ptr += sizeof(uint32_t);
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

    if (IsWindows8OrGreater()) {
      PACL pOldDACL = nullptr, pNewDACL = nullptr;
      PSECURITY_DESCRIPTOR pSD = nullptr;
      EXPLICIT_ACCESS ea;
      SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;

      DWORD dwRes =
          GetNamedSecurityInfo(chDir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                               nullptr, nullptr, &pOldDACL, nullptr, &pSD);
      if (dwRes != ERROR_SUCCESS)
        throw logged_error("Unable to activate CIE in the current process");

      PSID TheSID = nullptr;
      DWORD SidSize = SECURITY_MAX_SID_SIZE;
      if (!(TheSID = LocalAlloc(LMEM_FIXED, SidSize))) {
        if (pSD != nullptr) LocalFree((HLOCAL)pSD);
        throw logged_error("Unable to activate CIE in the current process");
      }

      if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, nullptr, TheSID,
                              &SidSize)) {
        if (TheSID != nullptr) LocalFree((HLOCAL)TheSID);
        if (pSD != nullptr) LocalFree((HLOCAL)pSD);
        throw logged_error("Unable to activate CIE in the current process");
      }

      ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
      ea.grfAccessPermissions = GENERIC_READ;
      ea.grfAccessMode = SET_ACCESS;
      ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
      ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
      ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
      ea.Trustee.ptstrName = (LPSTR)TheSID;

      if (SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS) {
        if (TheSID != nullptr) LocalFree((HLOCAL)TheSID);
        if (pSD != nullptr) LocalFree((HLOCAL)pSD);
        if (pNewDACL != nullptr) LocalFree((HLOCAL)pNewDACL);
        throw logged_error("Unable to activate CIE in the current process");
      }

      if (SetNamedSecurityInfo(chDir, SE_FILE_OBJECT, si, nullptr, nullptr,
                               pNewDACL, nullptr) != ERROR_SUCCESS) {
        if (pNewDACL != nullptr) LocalFree((HLOCAL)pNewDACL);
        if (TheSID != nullptr) LocalFree((HLOCAL)TheSID);
        if (pSD != nullptr) LocalFree((HLOCAL)pSD);
        throw logged_error("Unable to activate CIE in the current process");
      }
    }
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

#ifdef _WIN32
  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);

  uint32_t len = (uint32_t)baFirstPIN.size();
  file.write(reinterpret_cast<char *>(&len), sizeof(len));
  file.write(reinterpret_cast<char *>(baFirstPIN.data()), len);

  len = (uint32_t)baCertificate.size();
  file.write(reinterpret_cast<char *>(&len), sizeof(len));
  file.write(reinterpret_cast<char *>(baCertificate.data()), len);
#else
  uint32_t pinlen = static_cast<uint32_t>(baFirstPIN.size());
  uint32_t certlen = static_cast<uint32_t>(baCertificate.size());

  byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

  std::string ciphertext;
  std::string enckey = ENCRYPTION_KEY;

  byte digest[SHA1::DIGESTSIZE];
  SHA1().CalculateDigest(digest, reinterpret_cast<const byte *>(enckey.c_str()),
                         enckey.length());
  memcpy(key, digest, CryptoPP::AES::DEFAULT_KEYLENGTH);
  //
  // Create Cipher Text
  //
  CryptoPP::AES::Encryption aesEncryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
                                                              iv);

  CryptoPP::StreamTransformationFilter stfEncryptor(
      cbcEncryption, new CryptoPP::StringSink(ciphertext));
  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(&pinlen),
                   sizeof(pinlen));
  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(baFirstPIN.data()),
                   pinlen);

  stfEncryptor.Put(reinterpret_cast<const unsigned char *>(&certlen),
                   sizeof(certlen));
  stfEncryptor.Put(
      reinterpret_cast<const unsigned char *>(baCertificate.data()), certlen);

  stfEncryptor.MessageEnd();

  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  file.write(ciphertext.c_str(), ciphertext.length());
  file.close();
#endif
}
