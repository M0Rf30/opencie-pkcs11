// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cache_lib.h
 * @brief Certificate and PIN caching for CIE smart cards.
 *
 * Provides functions to cache and retrieve certificate and PIN data
 * keyed by the card's PAN (Personal Account Number), avoiding
 * redundant reads from the CIE smart card.
 */

#pragma once
#include <cstdint>
#include <vector>

/**
 * @brief Check whether cached data exists for a given PAN.
 * @param PAN Card Personal Account Number (identifier).
 * @return true if cached data exists, false otherwise.
 */
bool CacheExists(const char *PAN);

/**
 * @brief Retrieve the cached certificate for a given PAN.
 * @param PAN Card Personal Account Number.
 * @param[out] certificate Buffer to receive the certificate data.
 */
void CacheGetCertificate(const char *PAN, std::vector<uint8_t> &certificate);

/**
 * @brief Retrieve the cached PIN for a given PAN.
 * @param PAN Card Personal Account Number.
 * @param[out] PIN Buffer to receive the PIN data.
 */
void CacheGetPIN(const char *PAN, std::vector<uint8_t> &PIN);

/**
 * @brief Store certificate and PIN data in the cache.
 * @param PAN Card Personal Account Number (cache key).
 * @param certificate Pointer to the certificate data.
 * @param certificateSize Size of the certificate data in bytes.
 * @param FirstPIN Pointer to the PIN data.
 * @param FirstPINSize Size of the PIN data in bytes.
 */
void CacheSetData(const char *PAN, uint8_t *certificate, int certificateSize,
                  uint8_t *FirstPIN, int FirstPINSize);

/**
 * @brief Remove cached data for a given PAN.
 * @param PAN Card Personal Account Number.
 * @return true if data was removed, false if no data existed.
 */
bool CacheRemove(const char *PAN);

/**
 * @brief Store the DER-encoded X.509 certificate for a given PAN.
 *
 * The certificate is encrypted at rest the same way as CacheSetData(),
 * even though it is not secret itself, so the cache format stays
 * consistent and the file cannot be tampered with unnoticed.
 *
 * @param PAN  Card Personal Account Number (cache key).
 * @param der  Pointer to the DER certificate bytes.
 * @param len  Length of the DER certificate in bytes.
 */
void CacheSetDer(const char *PAN, const uint8_t *der, size_t len);

/**
 * @brief Retrieve the raw DER-encoded X.509 certificate for a given PAN.
 *
 * Reads the certificate written by CacheSetDer().
 *
 * @param PAN          Card Personal Account Number.
 * @param[out] certificate Buffer to receive the DER certificate bytes.
 * @return true if the file was found and read, false otherwise.
 */
bool CacheGetDer(const char *PAN, std::vector<uint8_t> &certificate);

#ifdef __ANDROID__
#ifdef __cplusplus
extern "C" {
#endif
void cie_set_data_dir(const char *dir);
#ifdef __cplusplus
}
#endif
#endif
