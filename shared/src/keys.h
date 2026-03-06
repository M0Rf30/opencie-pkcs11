// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file keys.h
 * @brief Cryptographic key constants for local CIE data cache encryption.
 *
 * Defines the encryption key used to obfuscate cached CIE card data
 * (PIN and certificate) stored in ~/.CIEPKI/. This provides only basic
 * obfuscation, not cryptographic security.
 */

#pragma once

// WARNING: This key is used for local cache encryption (PIN + certificate
// caching in ~/.CIEPKI/). It provides only obfuscation, NOT real security.
// TODO: Replace with proper key derivation (e.g., PBKDF2 from a
// machine-specific secret) in a future release.
//
// Changing this key will invalidate all existing cached data, requiring
// users to re-register their CIE cards.
/** @brief Obfuscation key for local CIE data cache (~/.CIEPKI/).
 *  @warning This provides only basic obfuscation, NOT real security.
 *           Changing this value invalidates all existing cached data. */
inline constexpr const char* ENCRYPTION_KEY = "this is a fake key";
