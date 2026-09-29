// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Unit tests for the contactless-retry work (native side): the
// card_link_error exception type that distinguishes an RF link
// drop/garbled response from an explicit card status word, and the
// RetryOnCardLinkError() bounded-retry policy built on top of it.
//
// A full PACE/DH/Secure-Messaging session cannot be faked cheaply here
// (it needs a real card-derived DH key exchange and AES/3DES session
// keys) -- per the ticket's own test guidance, this file instead:
//   1. Drives CToken::Transmit() directly through a fake
//      TokenTransmitCallback (CToken::setTransmitCallback) to prove the
//      exact classification CardAuthenticateEx()/IAS::* rely on: a
//      transport failure or a short/empty response throws
//      card_link_error, while a genuine card status word (including a
//      wrong-PIN word like 63C2) is returned as an ordinary StatusWord,
//      never as an exception.
//   2. Exercises RetryOnCardLinkError() (shared/src/util/retry.h) in
//      isolation with injected lambdas standing in for a full card read:
//      retries only on card_link_error, bounded to 3 attempts total, and
//      never retries a scard_error (e.g. a wrong-PIN status word).
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <vector>

#include "pcsc/token.h"
#include "util/retry.h"
#include "util/util_exception.h"

namespace {

// Simulates the RF link on a contactless reader: the first `failLink`
// calls to the transmit callback report an SCardTransmit()-level
// failure, the next `shortResp` calls report success but with fewer
// than 2 response bytes (a truncated/garbled frame), and every call
// after that returns `fixedResponse` verbatim.
struct FakeLink {
  int failLink = 0;
  int shortResp = 0;
  std::vector<uint8_t> fixedResponse;
  int callCount = 0;
};

HRESULT FakeTransmit(void *data, uint8_t * /*apdu*/, DWORD /*apduSize*/,
                     uint8_t *resp, DWORD *respSize) {
  auto *link = static_cast<FakeLink *>(data);
  ++link->callCount;

  if (link->failLink > 0) {
    --link->failLink;
    return SCARD_E_NOT_TRANSACTED;
  }
  if (link->shortResp > 0) {
    --link->shortResp;
    // A truncated frame: fewer than the mandatory 2-byte status word.
    *respSize = 1;
    resp[0] = 0x6C;
    return SCARD_S_SUCCESS;
  }
  std::memcpy(resp, link->fixedResponse.data(), link->fixedResponse.size());
  *respSize = static_cast<DWORD>(link->fixedResponse.size());
  return SCARD_S_SUCCESS;
}

// A bare "9000" (success) response: no data, just the status word.
std::vector<uint8_t> Sw9000() { return {0x90, 0x00}; }

// A wrong-PIN status word (2 attempts remaining): the card answering a
// VERIFY with its own explicit decision, not a link problem.
std::vector<uint8_t> Sw63C2() { return {0x63, 0xC2}; }

}  // namespace

TEST_CASE("CToken::Transmit throws card_link_error when SCardTransmit fails",
          "[retry][token]") {
  FakeLink link;
  link.failLink = 1;
  link.fixedResponse = Sw9000();

  CToken token;
  token.setTransmitCallback(FakeTransmit, &link);

  uint8_t apdu[] = {0x00, 0xA4, 0x04, 0x0C};
  REQUIRE_THROWS_AS(token.Transmit(ByteArray(apdu, sizeof(apdu)), nullptr),
                    card_link_error);
  CHECK(link.callCount == 1);
}

TEST_CASE("CToken::Transmit throws card_link_error on a short/garbled response",
          "[retry][token]") {
  FakeLink link;
  link.shortResp = 1;
  link.fixedResponse = Sw9000();

  CToken token;
  token.setTransmitCallback(FakeTransmit, &link);

  uint8_t apdu[] = {0x00, 0xA4, 0x04, 0x0C};
  REQUIRE_THROWS_AS(token.Transmit(ByteArray(apdu, sizeof(apdu)), nullptr),
                    card_link_error);
  CHECK(link.callCount == 1);
}

TEST_CASE(
    "CToken::Transmit returns a wrong-PIN status word normally -- never as "
    "an exception",
    "[retry][token]") {
  // This is the load-bearing distinction for PIN safety: a genuine 63C2
  // (wrong PIN, 2 attempts left) must come back as an ordinary return
  // value so callers can react to it (and MUST NOT retry), never get
  // funneled into the card_link_error retry path.
  FakeLink link;
  link.fixedResponse = Sw63C2();

  CToken token;
  token.setTransmitCallback(FakeTransmit, &link);

  uint8_t apdu[] = {0x00, 0x20, 0x00, 0x81};
  StatusWord sw = 0;
  REQUIRE_NOTHROW(sw = token.Transmit(ByteArray(apdu, sizeof(apdu)), nullptr));
  CHECK(sw == 0x63C2);
  CHECK(link.callCount == 1);
}

TEST_CASE(
    "RetryOnCardLinkError retries a card_link_error once and then "
    "succeeds",
    "[retry]") {
  int calls = 0;
  int result = RetryOnCardLinkError("test-op", 3, [&](int attempt) {
    ++calls;
    if (attempt == 1) throw card_link_error("simulated RF link drop");
    return 42;
  });

  CHECK(result == 42);
  CHECK(calls == 2);
}

TEST_CASE(
    "RetryOnCardLinkError is bounded to maxAttempts and rethrows "
    "card_link_error",
    "[retry]") {
  int calls = 0;
  REQUIRE_THROWS_AS(
      RetryOnCardLinkError("test-op", 3,
                           [&](int /*attempt*/) -> int {
                             ++calls;
                             throw card_link_error(
                                 "simulated persistent RF link drop");
                           }),
      card_link_error);
  CHECK(calls == 3);
}

TEST_CASE(
    "RetryOnCardLinkError never retries a scard_error (e.g. a PIN status "
    "word)",
    "[retry]") {
  int calls = 0;
  REQUIRE_THROWS_AS(RetryOnCardLinkError("test-op", 3,
                                         [&](int /*attempt*/) -> int {
                                           ++calls;
                                           throw scard_error(0x63C2);
                                         }),
                    scard_error);
  // Exactly one attempt: a card-reported status word is never retried,
  // regardless of maxAttempts.
  CHECK(calls == 1);
}
