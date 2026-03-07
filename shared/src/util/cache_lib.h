// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

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

#ifdef __ANDROID__
#ifdef __cplusplus
extern "C" {
#endif
void cie_set_data_dir(const char *dir);
#ifdef __cplusplus
}
#endif
#endif
