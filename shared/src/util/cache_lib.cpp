// SPDX-FileCopyrightText: 2026 Gianluca Boiano
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
#include <fcntl.h>
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
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#define CACHE_LOG(fmt, ...)
#endif

#include <cerrno>
#include <cstring>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include "crypto/crypto_util.h"
#include "util/util.h"

/** @brief Global diagnostic logger, defined in the PKCS#11 module. */
extern CLog Log;

/// This PIN and certificate cache implementation is provided for demonstration
/// purposes only. This version does NOT adequately protect the user's PIN,
/// which could be extracted by a malicious application. In production
/// environments, an implementation providing a high level of security is
/// strongly recommended.

namespace {

/**
 * @brief Validate a PAN before it is used to build a cache file path.
 *
 * The PAN is normally a hex dump of card data, but IAS::IsEnrolled(),
 * IAS::Unenroll() and CacheGetDer() ultimately take it from the public
 * cie_* C API, so a caller-controlled value such as "../../foo" must be
 * rejected before it is concatenated into a path (see finding CIE-CACHE-004
 * / path traversal through the exported cie_* APIs).
 *
 * @param PAN Candidate PAN.
 * @return true if PAN is 1-32 characters of [0-9A-Fa-f].
 */
bool IsValidPAN(const char *PAN) {
  if (PAN == nullptr) return false;
  size_t len = strlen(PAN);
  if (len == 0 || len > 32) return false;
  for (size_t i = 0; i < len; i++) {
    char ch = PAN[i];
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
          (ch >= 'A' && ch <= 'F')))
      return false;
  }
  return true;
}

void RequireValidPAN(const char *PAN) {
  if (!IsValidPAN(PAN)) throw logged_error("Invalid PAN");
}

#ifndef _WIN32
/**
 * @brief Write @p data atomically and with owner-only permissions to
 * @p path.
 *
 * Writes to a uniquely named temporary file in the same directory
 * (mkostemp: O_CREAT|O_EXCL, mode 0600), fsyncs it, then renames it over
 * the destination. A unique name means two processes writing the same
 * cache file can never rename each other's partial file (finding SU-02),
 * and rename() replaces, rather than follows, a pre-existing symlink at
 * the target path (see finding CIE-CACHE-003).
 */
void WriteFileAtomic(const std::string &path, const char *data, size_t len) {
  std::string tmpPath = path + ".XXXXXX";
  int fd = mkostemp(tmpPath.data(), O_CLOEXEC);
  if (fd == -1) throw logged_error("Cannot create temporary cache file");

  size_t written = 0;
  bool ok = (fchmod(fd, 0600) == 0);
  while (ok && written < len) {
    ssize_t n = write(fd, data + written, len - written);
    if (n <= 0) {
      ok = false;
      break;
    }
    written += static_cast<size_t>(n);
  }
  if (ok) ok = (fsync(fd) == 0);
  close(fd);

  if (!ok) {
    unlink(tmpPath.c_str());
    throw logged_error("Failed to write cache file");
  }

  if (rename(tmpPath.c_str(), path.c_str()) != 0) {
    unlink(tmpPath.c_str());
    throw logged_error("Failed to finalize cache file");
  }
}

/**
 * @brief Verify (and optionally create/tighten) the cache directory.
 *
 * Fails closed: throws if @p dir is a symlink, is not a directory, or is
 * not owned by the effective uid (finding SU-01). The directory is opened
 * with O_DIRECTORY|O_NOFOLLOW and inspected via fstat() so the checks and
 * the chmod apply to the same object.
 *
 * ~/.CIEPKI may already exist, e.g. created by third-party CIE software
 * with looser permissions; when @p create is true this tightens it to
 * 0700 rather than trusting whatever is already there (see finding
 * CIE-CACHE-003).
 *
 * @param dir    Directory path (a trailing '/' is ignored).
 * @param create If true, create a missing directory and tighten the mode.
 *               If false, a missing directory is accepted.
 */
void CheckCacheDir(const std::string &dir, bool create) {
  std::string p = dir;
  while (p.size() > 1 && p.back() == '/') p.pop_back();

  if (create && mkdir(p.c_str(), 0700) != 0 && errno != EEXIST)
    throw logged_error("Cannot create cache directory");

  int fd = open(p.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd == -1) {
    if (!create && errno == ENOENT) return;
    throw logged_error(
        "Cache directory is not a real directory (symlink or wrong type)");
  }
  struct stat st {};
  if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid()) {
    close(fd);
    throw logged_error("Cache directory is not owned by the current user");
  }
  if (create && (st.st_mode & 07777) != 0700 && fchmod(fd, 0700) != 0) {
    close(fd);
    throw logged_error("Cannot restrict cache directory permissions");
  }
  close(fd);
}

void EnsureCacheDirSecure(const std::string &dir) { CheckCacheDir(dir, true); }
#endif

/** Cleanses a string's contents on every scope exit, including throws. */
struct ScopedStringWipe {
  explicit ScopedStringWipe(std::string &s) : s_(s) {}
  ~ScopedStringWipe() {
    if (!s_.empty()) OPENSSL_cleanse(s_.data(), s_.size());
  }
  ScopedStringWipe(const ScopedStringWipe &) = delete;
  ScopedStringWipe &operator=(const ScopedStringWipe &) = delete;
  std::string &s_;
};

}  // namespace

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
  std::string homeStorage;
  if (home == nullptr) {
    const struct passwd *pw = getpwuid(getuid());
    if (pw != nullptr && pw->pw_dir != nullptr) {
      homeStorage = pw->pw_dir;
      home = homeStorage.data();
    }
  }

  // No /tmp fallback: a world-writable directory must never hold the cache
  // (finding SU-01).
  if (home == nullptr || home[0] == '\0')
    throw logged_error("Cannot determine the home directory for the cache");

  std::string path(home);
  if (path.back() == '/') path.pop_back();

  path.append("/.CIEPKI/");

  CACHE_LOG("GetCardDir: %s", path.c_str());

  return path;
}
#endif

#ifdef _WIN32
void GetCardPath(const char *PAN, std::string &sPath) {
  RequireValidPAN(PAN);
  auto Path = GetCardDir();

  if (Path[Path.length() - 1] != '\\') Path += '\\';

  Path += std::string(PAN);
  Path += ".cache";
  sPath = Path;
}
#else
void GetCardPath(const char *PAN, std::string &sPath) {
  RequireValidPAN(PAN);
  auto Path = GetCardDir();
  CheckCacheDir(Path, false);

  Path += std::string(PAN);
  Path += ".cache";
  sPath = Path;
}
#endif

bool CacheExists(const char *PAN) {
  RequireValidPAN(PAN);
  std::string sPath;
  try {
    GetCardPath(PAN, sPath);
  } catch (const logged_error &) {
    // Invalid PAN or an untrustworthy cache directory: treat as no cache.
    return false;
  }
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
  RequireValidPAN(PAN);
  auto Path = GetCardDir();
#ifndef _WIN32
  CheckCacheDir(Path, false);
#endif
  Path += std::string(PAN);
  Path += ".der";
  sPath = Path;
}

void CacheSetDer(const char *PAN, const uint8_t *der, size_t len) {
  if (PAN == nullptr || der == nullptr || len == 0)
    throw logged_error("CacheSetDer: invalid arguments");

  auto szDir = GetCardDir();
#ifndef _WIN32
  EnsureCacheDirSecure(szDir);
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
  if (encrypt(plaintext, ciphertext) != 0) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    throw logged_error("CacheSetDer: failed to encrypt cache data");
  }
  OPENSSL_cleanse(plaintext.data(), plaintext.size());

#ifndef _WIN32
  WriteFileAtomic(sPath, ciphertext.data(), ciphertext.size());
#else
  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetDer: cannot open file for writing");
  file.write(ciphertext.c_str(), ciphertext.length());
  file.close();
#endif
}

bool CacheGetDer(const char *PAN, std::vector<uint8_t> &certificate) {
  if (PAN == nullptr) return false;

  RequireValidPAN(PAN);
  std::string sPath;
  try {
    GetDerPath(PAN, sPath);
  } catch (const logged_error &) {
    return false;
  }

  if (!file_exists(sPath.c_str())) return false;

  try {
    ByteDynArray data;
    data.load(sPath.c_str());
    if (data.isEmpty()) return false;

    std::string ciphertext(reinterpret_cast<const char *>(data.data()),
                           data.size());
    std::string plaintext;
    ScopedStringWipe plaintextWipe(plaintext);
    if (decrypt(ciphertext, plaintext) != 0) {
      // .der caches written before the authenticated format (and by
      // third-party CIE software) use the legacy zero-IV container. Without
      // this fallback cie_get_certificate() falls through to reading the card,
      // which fails with SW 6982, so apps never get notBefore/notAfter.
      plaintext.clear();
      if (decryptLegacyZeroIv(ciphertext, plaintext) != 0) return false;
    }

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
    ScopedStringWipe plaintextWipe(plaintext);
    if (decrypt(ciphertext, plaintext) != 0) {
      // Our own authenticated format didn't match. This is also exactly
      // what a cache written by third-party CIE software looks like: the
      // legacy AES-128-CBC/zero-IV container. Try that format before giving
      // up, so a card already enrolled with such software works here
      // without re-pairing.
      if (decryptLegacyZeroIv(ciphertext, plaintext) != 0)
        throw logged_error("CacheGetCertificate: failed to decrypt cache");
      Log.writePure(
          "CacheGetCertificate: cache for PAN is in the legacy "
          "unauthenticated format (likely written by third-party CIE "
          "software); read-only, leaving the file untouched");
    }

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
    ScopedStringWipe plaintextWipe(plaintext);
    // A file in the authenticated container that fails authentication is
    // treated as tampered: no legacy fallback (findings SU-09, CT-4, CT-7).
    // Only a file that is not in our format at all (written by third-party
    // CIE software, legacy zero-IV container) is accepted, and it is
    // immediately rewritten in the authenticated format so the unauthenticated
    // window closes after first use.
    if (decrypt(ciphertext, plaintext) != 0) {
      const bool hasMagic =
          ciphertext.compare(0, sizeof(kCacheCryptoMagic), kCacheCryptoMagic,
                             sizeof(kCacheCryptoMagic)) == 0;
      if (hasMagic)
        throw logged_error("CacheGetPIN: failed to authenticate cache");
      plaintext.clear();
      if (decryptLegacyZeroIv(ciphertext, plaintext) != 0)
        throw logged_error("CacheGetPIN: failed to decrypt cache");
      std::string upgraded;
      if (encrypt(plaintext, upgraded) != 0)
        throw logged_error("CacheGetPIN: failed to re-encrypt legacy cache");
#ifndef _WIN32
      CheckCacheDir(GetCardDir(), true);
      WriteFileAtomic(sPath, upgraded.data(), upgraded.size());
#else
      std::ofstream file(sPath.c_str(),
                         std::ofstream::out | std::ofstream::binary);
      if (!file) throw logged_error("CacheGetPIN: cannot rewrite cache");
      file.write(upgraded.c_str(), upgraded.length());
      file.close();
#endif
    }

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
    // %PROGRAMDATA%\CIEPKI inherits the ProgramData ACL by default, which
    // grants BUILTIN\Users Read&Execute on files and Create-files on the
    // folder -- so any local user could read another user's cache/log
    // files, and the first user to create this directory would own it.
    // Restrict the DACL to the current user (CREATOR OWNER) and SYSTEM
    // only. NOTE: this only applies to a directory we create ourselves;
    // if the directory was already created by another local installation
    // (e.g. an older build of this library, or third-party CIE software,
    // which uses this same well-known path for cache-format
    // compatibility) its existing ACL is left untouched here, since
    // narrowing an ACL that other CIE software also writes through risks
    // breaking interoperability with it. See finding CIE-CACHE-001.
    PSECURITY_DESCRIPTOR pSD = nullptr;
    SECURITY_ATTRIBUTES sa {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:PAI(A;OICI;GA;;;SY)(A;OICI;GA;;;CO)", SDDL_REVISION_1, &pSD,
            nullptr)) {
      sa.lpSecurityDescriptor = pSD;
      CreateDirectory(chDir, &sa);
      LocalFree(pSD);
    } else {
      CreateDirectory(chDir, nullptr);
    }
  }
#else
  EnsureCacheDirSecure(szDir);
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
  if (encrypt(plaintext, ciphertext) != 0) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    throw logged_error("CacheSetData: failed to encrypt cache data");
  }
  OPENSSL_cleanse(plaintext.data(), plaintext.size());

#ifndef _WIN32
  WriteFileAtomic(sPath, ciphertext.data(), ciphertext.size());
#else
  std::ofstream file(sPath.c_str(), std::ofstream::out | std::ofstream::binary);
  if (!file) throw logged_error("CacheSetData: cannot open file for writing");
  file.write(ciphertext.c_str(), ciphertext.length());
  file.close();
#endif
}
