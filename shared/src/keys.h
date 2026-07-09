// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file keys.h
 * @brief Cryptographic key constants for local CIE data cache encryption.
 *
 * Defines the encryption key used to obfuscate cached CIE card data
 * (PIN and certificate) stored in ~/.CIEPKI/. This provides only basic
 * obfuscation, not cryptographic security.
 */

#pragma once

// WARNING: This key provides obfuscation only, not real security.
// TODO: Replace with OS keyring (libsecret / Windows Credential Manager)
// or derive a per-user key via PBKDF2 from machine-ID + user-ID.
//
// This key is used for local cache encryption (PIN + certificate caching
// in ~/.CIEPKI/). Changing it will invalidate all existing cached data,
// requiring users to re-register their CIE cards.
/** @brief Obfuscation key for local CIE data cache (~/.CIEPKI/).
 *  @warning This provides only basic obfuscation, NOT real security.
 *           Changing this value invalidates all existing cached data. */
inline constexpr const char* ENCRYPTION_KEY = "this is a fake key";
