// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <cstdlib>
#include <cstring>
#include <vector>

#include "logger/logger.h"
#include "pkcs11/pkcs11_functions.h"
#include "util/cache_lib.h"

using namespace CieIDLogger;

extern "C" {

/**
 * @brief Retrieve the DER-encoded X.509 certificate for an enrolled CIE card.
 *
 * Reads the certificate from the local AES-encrypted cache written by
 * cie_enable().  The caller is responsible for freeing *outDer with free().
 *
 * @param pan      NUL-terminated PAN string identifying the card.
 * @param outDer   On success, set to a malloc'd buffer containing the DER cert.
 * @param outLen   On success, set to the number of bytes in *outDer.
 * @return CKR_OK on success.
 *         CKR_ARGUMENTS_BAD if pan, outDer, or outLen is NULL.
 *         CKR_DEVICE_ERROR  if the card is not enrolled (cache missing).
 *         CKR_HOST_MEMORY   if malloc fails.
 *         CKR_FUNCTION_FAILED for any other error.
 */
CK_RV CK_ENTRY cie_get_certificate(const char *pan, unsigned char **outDer,
                                   unsigned long *outLen) {
  if (pan == nullptr || outDer == nullptr || outLen == nullptr)
    return CKR_ARGUMENTS_BAD;

  *outDer = nullptr;
  *outLen = 0;

  LOG_INFO("cie_get_certificate: looking up PAN='%s'", pan);

  if (!CacheExists(pan)) {
    LOG_ERROR("cie_get_certificate: card not enrolled (PAN not in cache)");
    return CKR_DEVICE_ERROR;
  }

  try {
    // Prefer the DER file written by cie_enable() — it contains the raw
    // X.509 cert encrypted with the static cache key and requires no live
    // PACE session to decrypt.
    std::vector<uint8_t> cert;
    if (!CacheGetDer(pan, cert) || cert.empty()) {
      LOG_ERROR("cie_get_certificate: DER cert not found in cache for PAN '%s'",
                pan);
      return CKR_FUNCTION_FAILED;
    }

    unsigned char *buf = static_cast<unsigned char *>(malloc(cert.size()));
    if (buf == nullptr) {
      LOG_ERROR("cie_get_certificate: malloc failed");
      return CKR_HOST_MEMORY;
    }

    memcpy(buf, cert.data(), cert.size());
    *outDer = buf;
    *outLen = static_cast<unsigned long>(cert.size());
    LOG_INFO("cie_get_certificate: OK, %zu bytes", cert.size());
    return CKR_OK;

  } catch (const std::exception &e) {
    LOG_ERROR("cie_get_certificate exception: %s", e.what());
    return CKR_FUNCTION_FAILED;
  } catch (...) {
    LOG_ERROR("cie_get_certificate: unknown exception");
    return CKR_FUNCTION_FAILED;
  }
}

/**
 * @brief Free a buffer libopencie-pkcs11 allocated and returned through an
 * out-parameter (currently only cie_get_certificate()'s *outDer).
 *
 * Always release such buffers through this function instead of the
 * caller's own free(): on Windows, the DLL and a statically-linked caller
 * can be bound to different CRT heaps, so freeing a cross-module
 * allocation with the wrong heap's free() is undefined behavior.
 *
 * @param ptr  Pointer previously returned via a libopencie-pkcs11
 *             out-parameter, or NULL (no-op).
 */
void CK_ENTRY cie_free(void *ptr) { free(ptr); }

}  // extern "C"
