#pragma once

// WARNING: This key is used for local cache encryption (PIN + certificate
// caching in ~/.CIEPKI/). It provides only obfuscation, NOT real security.
// TODO: Replace with proper key derivation (e.g., PBKDF2 from a
// machine-specific secret) in a future release.
//
// Changing this key will invalidate all existing cached data, requiring
// users to re-register their CIE cards.
inline constexpr const char* ENCRYPTION_KEY = "this is a fake key";
