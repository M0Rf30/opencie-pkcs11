// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Hostile-card tests for the IAS protocol layer (shared/src/csp/ias.cpp).
//
// IAS talks to the card exclusively through the CToken transmit callback, so
// a fake card (a function from command APDU to response bytes) is enough to
// drive the file-read, GET RESPONSE and ASN.1 parsing paths with crafted
// answers. No hardware or secure-messaging session is needed: everything
// here runs on the plain (non-SM) channel.
#ifndef _WIN32

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <vector>

#include "csp/ias.h"
#include "util/array.h"
#include "util/util_exception.h"

namespace {

using Bytes = std::vector<uint8_t>;

// STM2 ATR: recognised by IAS::ReadCIEType(), so SelectAID_IAS() can set the
// card type (needed by InitDHParam) with a plain SELECT MF.
const uint8_t kStm2Atr[] = {0x3B, 0x80, 0x80, 0x01, 0x01};

Bytes Sw(uint16_t sw) {
  return {static_cast<uint8_t>(sw >> 8), static_cast<uint8_t>(sw & 0xFF)};
}

Bytes WithSw(Bytes body, uint16_t sw) {
  body.push_back(static_cast<uint8_t>(sw >> 8));
  body.push_back(static_cast<uint8_t>(sw & 0xFF));
  return body;
}

// A fake card: `handler` maps every command APDU to the full response
// (data + status word). Every command seen is recorded in `sent`.
class FakeCard {
 public:
  using Handler = std::function<Bytes(const Bytes &apdu)>;

  explicit FakeCard(Handler handler) : handler_(std::move(handler)) {}

  static HRESULT Transmit(void *data, uint8_t *apdu, DWORD apduSize,
                          uint8_t *resp, DWORD *respSize) {
    auto *self = static_cast<FakeCard *>(data);
    self->sent.emplace_back(apdu, apdu + apduSize);
    Bytes out = self->handler_(self->sent.back());
    if (out.size() > *respSize) return SCARD_E_INSUFFICIENT_BUFFER;
    std::memcpy(resp, out.data(), out.size());
    *respSize = static_cast<DWORD>(out.size());
    return SCARD_S_SUCCESS;
  }

  size_t Count(uint8_t ins) const {
    size_t n = 0;
    for (const auto &a : sent)
      if (a.size() >= 2 && a[1] == ins) ++n;
    return n;
  }

  std::vector<Bytes> sent;

 private:
  Handler handler_;
};

// A card holding a single transparent file: SELECT answers 9000, READ BINARY
// serves the file by offset and answers 6B00 past the end.
FakeCard::Handler FileCard(Bytes file) {
  return [file = std::move(file)](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xA4) return Sw(0x9000);
    if (apdu[1] == 0xB0) {
      size_t off = (static_cast<size_t>(apdu[2]) << 8) | apdu[3];
      size_t le = apdu.size() > 4 ? apdu[4] : 256;
      if (le == 0) le = 256;
      if (off >= file.size()) return Sw(0x6B00);
      size_t n = std::min(le, file.size() - off);
      return WithSw(Bytes(file.begin() + off, file.begin() + off + n), 0x9000);
    }
    return Sw(0x6D00);
  };
}

struct Rig {
  explicit Rig(FakeCard::Handler h)
      : card(std::move(h)),
        ias(FakeCard::Transmit, ByteArray(kStm2Atr, sizeof(kStm2Atr))) {
    ias.SetCardContext(&card);
  }
  FakeCard card;
  IAS ias;
};

}  // namespace

// CP-01: card-derived ASN.1 trees must be walked with checked accessors.

TEST_CASE("ReadDappPubKey rejects an empty EF instead of dereferencing it",
          "[ias][cp01]") {
  // First READ BINARY answers 6B00: the file content is empty, the parsed
  // tree has no root node.
  Rig rig(FileCard({}));
  ByteDynArray out;
  CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
}

TEST_CASE("ReadDappPubKey rejects a SEQUENCE missing its members",
          "[ias][cp01]") {
  ByteDynArray out;
  SECTION("no children at all") {
    Rig rig(FileCard({0x30, 0x00}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("modulus only, exponent missing") {
    Rig rig(FileCard({0x30, 0x04, 0x02, 0x02, 0x00, 0xC3}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("all-zero modulus") {
    Rig rig(
        FileCard({0x30, 0x08, 0x02, 0x02, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
}

TEST_CASE("ReadDappPubKey strips DER sign padding from a well-formed key",
          "[ias][cp01]") {
  Rig rig(
      FileCard({0x30, 0x08, 0x02, 0x02, 0x00, 0xC3, 0x02, 0x02, 0x01, 0x01}));
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.ias.ReadDappPubKey(out));
  REQUIRE(rig.ias.DappModule.size() == 1);
  CHECK(rig.ias.DappModule[0] == 0xC3);
  REQUIRE(rig.ias.DappPubKey.size() == 2);
  CHECK(rig.ias.DappPubKey[0] == 0x01);
  CHECK(rig.ias.DappPubKey[1] == 0x01);
}

TEST_CASE("InitDHParam and InitExtAuthKeyParam reject shallow ASN.1",
          "[ias][cp01]") {
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xCB) return WithSw({0x30, 0x00}, 0x9000);
    return Sw(0x9000);
  });
  rig.ias.SelectAID_IAS();  // sets the card type from the ATR
  CHECK_THROWS_AS(rig.ias.InitDHParam(), logged_error);
  CHECK_THROWS_AS(rig.ias.InitExtAuthKeyParam(), logged_error);
}

TEST_CASE("InitExtAuthKeyParam rejects a key template without its tags",
          "[ias][cp01]") {
  // Three nested SEQUENCEs, innermost empty: depth is right, tags are absent.
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xCB)
      return WithSw({0x30, 0x04, 0x30, 0x02, 0x30, 0x00}, 0x9000);
    return Sw(0x9000);
  });
  CHECK_THROWS_AS(rig.ias.InitExtAuthKeyParam(), logged_error);
}

TEST_CASE("SOD parsing rejects structurally empty input", "[ias][cp01]") {
  std::map<uint8_t, ByteDynArray> hashes;
  const uint8_t empty[] = {0x30, 0x00};
  CHECK_THROWS_AS(IAS::VerificaSOD(ByteArray(empty, sizeof(empty)), hashes),
                  logged_error);
  CHECK_THROWS_AS(IAS::VerificaSODPSS(ByteArray(empty, sizeof(empty)), hashes),
                  logged_error);
  CHECK_THROWS_AS(IAS::GetSODDigestAlg(ByteArray(empty, sizeof(empty))),
                  logged_error);
}

#endif  // _WIN32
