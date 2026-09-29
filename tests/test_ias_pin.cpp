// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Unit tests for IAS::IsValidPinLength()/ComposeFullPIN() — the shared PIN
// composition helper used by C_Login, C_InitPIN, C_SetPIN and cie_sign()
// (see OC-28: cie_sign_csp.cpp used to unconditionally prepend the cached
// first PIN half even when the caller already sent the full 8-digit PIN,
// silently mangling the PIN sent to the card).
//
// Constructing an IAS instance never touches a real card (see IAS::IAS()
// in ias.cpp: it only stores the ATR/AID bytes), so it is safe to build
// here. The 8-digit "full PIN" path never touches the on-disk cache
// either — ComposeFullPIN() skips GetFirstPIN() entirely for it — so it
// can be exercised end-to-end without hardware. The 4-digit "cached first
// half" path needs the card-derived AES key from a real PACE/DH session to
// decrypt the cache (IAS::InitEncKey(), unreachable outside a live
// session), so it is only proven indirectly here: an uncached synthetic
// PAN must make the 4-digit path fail loudly (it tries the cache) while
// leaving the 8-digit path unaffected (it never does) — exactly the
// distinction the OC-28 bug erased.
#ifndef _WIN32

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include "csp/ias.h"
#include "util/array.h"
#include "util/util_exception.h"

namespace {

// HOME override only works on non-Windows; cache_lib resolves
// %PROGRAMDATA% on Windows instead (see test_cache_lib.cpp).
class ScopedHomeOverride {
 public:
  explicit ScopedHomeOverride(std::string dir) : dir_(std::move(dir)) {
    if (const char *h = getenv("HOME")) {
      hadHome_ = true;
      oldHome_ = h;
    }
    setenv("HOME", dir_.c_str(), 1);
  }

  ~ScopedHomeOverride() {
    if (hadHome_)
      setenv("HOME", oldHome_.c_str(), 1);
    else
      unsetenv("HOME");
    std::filesystem::remove_all(dir_);
  }

  ScopedHomeOverride(const ScopedHomeOverride &) = delete;
  ScopedHomeOverride &operator=(const ScopedHomeOverride &) = delete;

 private:
  std::string dir_;
  std::string oldHome_;
  bool hadHome_ = false;
};

std::string MakeTempDir() {
  auto base = std::filesystem::temp_directory_path();
  for (int attempt = 0; attempt < 100; ++attempt) {
    auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    auto candidate = base / ("cie_ias_pin_test_" + std::to_string(stamp) + "_" +
                             std::to_string(attempt));
    std::error_code ec;
    if (std::filesystem::create_directory(candidate, ec))
      return candidate.string();
  }
  throw std::runtime_error("MakeTempDir: could not create a unique dir");
}

// IAS's constructor never transmits an APDU, and neither path under test
// does either; a callback that throws if invoked proves that holds.
HRESULT FailIfCalled(void * /*data*/, uint8_t * /*apdu*/, DWORD /*apduSize*/,
                     uint8_t * /*resp*/, DWORD * /*respSize*/) {
  throw std::runtime_error("unexpected APDU transmit in a PIN-helper test");
}

// Minimal ATR (same shape as AndroidNFCTransport::buildATR's own
// fallback) — IAS's constructor stores it verbatim, never parses it.
const uint8_t kDummyAtr[] = {0x3B, 0x80, 0x80, 0x01, 0x01};

// A synthetic, clearly-fake 11-byte PAN so IAS::PAN.mid(5, 6) resolves to
// a stable card identifier. Never a real PAN or tax code.
void SetSyntheticPan(IAS &ias) {
  const uint8_t pan[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xAB,
                         0xCD, 0xEF, 0x01, 0x23, 0x45};
  ias.PAN = ByteDynArray(ByteArray(pan, sizeof(pan)));
}

}  // namespace

TEST_CASE("IAS::IsValidPinLength accepts only 4 or 8 digits", "[ias][pin]") {
  CHECK(IAS::IsValidPinLength(8));
  CHECK(IAS::IsValidPinLength(4));
  CHECK_FALSE(IAS::IsValidPinLength(0));
  CHECK_FALSE(IAS::IsValidPinLength(3));
  CHECK_FALSE(IAS::IsValidPinLength(5));
  CHECK_FALSE(IAS::IsValidPinLength(7));
  CHECK_FALSE(IAS::IsValidPinLength(9));
  CHECK_FALSE(IAS::IsValidPinLength(12));
}

TEST_CASE(
    "IAS::ComposeFullPIN passes an 8-digit PIN through without touching "
    "the cache",
    "[ias][pin]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  IAS ias(FailIfCalled, ByteArray(kDummyAtr, sizeof(kDummyAtr)));
  SetSyntheticPan(ias);

  const uint8_t fullPin[] = {'1', '2', '3', '4', '5', '6', '7', '8'};
  ByteDynArray composed;

  // No cache file exists for this PAN at all: if ComposeFullPIN tried to
  // read it (the OC-28 bug — unconditional GetFirstPIN), this would throw
  // "CIE not enabled". It must not, because the input is already 8 digits.
  REQUIRE_NOTHROW(
      ias.ComposeFullPIN(ByteArray(fullPin, sizeof(fullPin)), composed));

  REQUIRE(composed.size() == 8);
  CHECK(std::memcmp(composed.data(), fullPin, 8) == 0);
}

TEST_CASE(
    "IAS::ComposeFullPIN looks up the cached first half for a 4-digit PIN",
    "[ias][pin]") {
  std::string dir = MakeTempDir();
  ScopedHomeOverride homeGuard(dir);

  IAS ias(FailIfCalled, ByteArray(kDummyAtr, sizeof(kDummyAtr)));
  SetSyntheticPan(ias);

  const uint8_t secondHalf[] = {'5', '6', '7', '8'};
  ByteDynArray composed;

  // Unlike the 8-digit case above, a 4-digit PIN must consult the local
  // cache for the first half. No cache was ever written for this PAN, so
  // this must fail loudly (logged_error) rather than silently composing a
  // wrong or truncated PIN.
  REQUIRE_THROWS_AS(
      ias.ComposeFullPIN(ByteArray(secondHalf, sizeof(secondHalf)), composed),
      logged_error);
}

#endif  // !_WIN32
