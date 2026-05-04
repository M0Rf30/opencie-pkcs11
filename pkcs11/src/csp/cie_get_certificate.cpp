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
CK_RV CK_ENTRY cie_get_certificate(const char *pan,
                                    unsigned char **outDer,
                                    unsigned long *outLen) {
  if (pan == nullptr || outDer == nullptr || outLen == nullptr)
    return CKR_ARGUMENTS_BAD;

  *outDer = nullptr;
  *outLen = 0;

  if (!CacheExists(pan)) {
    LOG_ERROR("cie_get_certificate: card not enrolled (PAN not in cache)");
    return CKR_DEVICE_ERROR;
  }

  try {
    std::vector<uint8_t> cert;
    CacheGetCertificate(pan, cert);

    if (cert.empty()) {
      LOG_ERROR("cie_get_certificate: empty certificate in cache");
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
    return CKR_OK;

  } catch (const std::exception &e) {
    LOG_ERROR("cie_get_certificate exception: %s", e.what());
    return CKR_FUNCTION_FAILED;
  } catch (...) {
    LOG_ERROR("cie_get_certificate: unknown exception");
    return CKR_FUNCTION_FAILED;
  }
}

} // extern "C"
