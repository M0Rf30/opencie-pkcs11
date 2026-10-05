// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <cstdlib>
#include <cstring>
#include <vector>

#include "csp/cie_enable.h"
#include "logger/logger.h"
#include "pkcs11/pkcs11_functions.h"
#include "util/array.h"
#include "util/cache_lib.h"

using namespace CieIDLogger;

extern "C" {

/**
 * @brief Retrieve the DER-encoded X.509 certificate for an enrolled CIE card.
 *
 * Prefers the local AES-encrypted DER cache written by cie_enable(); if
 * that cache is missing or unusable (e.g. this PAN was never enrolled
 * through cie_enable(), or its cache was written by different CIE
 * software this build cannot read), falls back to a physically present
 * card with that PAN: the legacy CIE ID pairing cache (.cache) is decrypted
 * with the card-derived key. The certificate is NOT readable on-card
 * without a PIN, so a card never paired yields CKR_DEVICE_ERROR. See
 * github.com/M0Rf30/opencie-pkcs11/issues/25. The caller is responsible
 * for freeing *outDer with cie_free().
 *
 * @param pan      NUL-terminated PAN string identifying the card.
 * @param outDer   On success, set to a malloc'd buffer containing the DER cert.
 * @param outLen   On success, set to the number of bytes in *outDer.
 * @return CKR_OK on success.
 *         CKR_ARGUMENTS_BAD if pan, outDer, or outLen is NULL.
 *         CKR_DEVICE_ERROR  if the card is neither cached nor present.
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

  try {
    // Prefer the DER file written by cie_enable() — it contains the raw
    // X.509 cert encrypted with the static cache key and requires no live
    // PACE session to decrypt.
    std::vector<uint8_t> cert;
    bool haveCert = CacheGetDer(pan, cert) && !cert.empty();

    if (!haveCert) {
      LOG_INFO(
          "cie_get_certificate: no usable DER cache for PAN '%s', trying the "
          "legacy pairing cache with the card present",
          pan);
      ByteDynArray certRaw;
      if (CIE_FindCardByPAN(pan, &certRaw) && !certRaw.isEmpty()) {
        cert.assign(certRaw.data(), certRaw.data() + certRaw.size());
        haveCert = true;
        try {
          CacheSetDer(pan, cert.data(),
                      cert.size());  // best effort: next time needs no card
        } catch (...) {
        }
      }
    }

    if (!haveCert) {
      LOG_ERROR(
          "cie_get_certificate: no certificate for PAN '%s' (pair the card "
          "with CIE ID / cie_enable first, and keep it in the reader)",
          pan);
      return CKR_DEVICE_ERROR;
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
