// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <string>
#include <vector>

#include "csp/cie_error.h"
#include "opencie/cie_ext.h"
#include "pcsc/pcsc.h"
#include "pcsc/smart_card_transport.h"

namespace {

// Records the PC/SC calls of a reader field power-cycle.
class CycleTransport : public ISmartCardTransport {
 public:
  std::vector<std::string> calls;
  std::vector<DWORD> disconnectDispositions;
  bool fieldCycle = true;
  LONG connectResult = SCARD_S_SUCCESS;
  SCARDHANDLE nextHandle = 0x22;
  DWORD lastShareMode = 0;
  DWORD lastProtocols = 0;
  std::string lastReader;

  bool SupportsFieldPowerCycle() const override { return fieldCycle; }

  LONG EstablishContext(DWORD, LPSCARDCONTEXT phContext) override {
    *phContext = 1;
    return SCARD_S_SUCCESS;
  }
  LONG ReleaseContext(SCARDCONTEXT) override { return SCARD_S_SUCCESS; }
  LONG IsValidContext(SCARDCONTEXT) override { return SCARD_S_SUCCESS; }
  LONG ListReaders(SCARDCONTEXT, LPSTR, LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG GetStatusChange(SCARDCONTEXT, DWORD, SCARD_READERSTATE *,
                       DWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG Cancel(SCARDCONTEXT) override { return SCARD_S_SUCCESS; }

  LONG Connect(SCARDCONTEXT, LPCSTR szReader, DWORD dwShareMode,
               DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
               LPDWORD pdwActiveProtocol) override {
    calls.push_back("Connect");
    lastReader = szReader ? szReader : "";
    lastShareMode = dwShareMode;
    lastProtocols = dwPreferredProtocols;
    if (connectResult != SCARD_S_SUCCESS) return connectResult;
    *phCard = nextHandle;
    *pdwActiveProtocol = SCARD_PROTOCOL_T1;
    return SCARD_S_SUCCESS;
  }
  LONG Disconnect(SCARDHANDLE hCard, DWORD dwDisposition) override {
    calls.push_back("Disconnect:" + std::to_string(hCard));
    disconnectDispositions.push_back(dwDisposition);
    return SCARD_S_SUCCESS;
  }
  LONG Reconnect(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG Transmit(SCARDHANDLE, const SCARD_IO_REQUEST *, LPCBYTE, DWORD, LPBYTE,
                LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG BeginTransaction(SCARDHANDLE hCard) override {
    calls.push_back("Begin:" + std::to_string(hCard));
    return SCARD_S_SUCCESS;
  }
  LONG EndTransaction(SCARDHANDLE, DWORD) override { return SCARD_S_SUCCESS; }
  LONG GetAttrib(SCARDHANDLE, DWORD, LPBYTE, LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
};

constexpr std::chrono::milliseconds kNoWait {0};

}  // namespace

TEST_CASE("kFieldOffWait is long enough for a CCID field cycle",
          "[pcsc][field_cycle]") {
  CHECK(kFieldOffWait >= std::chrono::milliseconds(500));
}

TEST_CASE("powerCycleField unpowers, reconnects shared and re-begins",
          "[pcsc][field_cycle]") {
  CycleTransport t;
  {
    safeConnection conn(t, SCARDCONTEXT {1}, "Reader 0", SCARD_SHARE_SHARED);
    REQUIRE(conn.hCard == 0x22);
    t.calls.clear();
    t.nextHandle = 0x33;

    CHECK(conn.powerCycleField("Reader 0", kNoWait) == FieldCycleResult::Ok);

    CHECK(conn.hCard == 0x33);
    REQUIRE(t.calls.size() == 3);
    CHECK(t.calls[0] == "Disconnect:34");  // 0x22
    CHECK(t.calls[1] == "Connect");
    CHECK(t.calls[2] == "Begin:51");  // 0x33
    REQUIRE(t.disconnectDispositions.size() == 1);
    CHECK(t.disconnectDispositions[0] == SCARD_UNPOWER_CARD);
    CHECK(t.lastReader == "Reader 0");
    CHECK(t.lastShareMode == SCARD_SHARE_SHARED);
    CHECK(t.lastProtocols == SCARD_PROTOCOL_Tx);
    t.calls.clear();
    t.disconnectDispositions.clear();
  }
  // The destructor releases only the new handle, exactly once.
  REQUIRE(t.calls.size() == 1);
  CHECK(t.calls[0] == "Disconnect:51");
  CHECK(t.disconnectDispositions[0] == SCARD_RESET_CARD);
}

TEST_CASE("powerCycleField waits between power-off and reconnect",
          "[pcsc][field_cycle]") {
  CycleTransport t;
  safeConnection conn(t, SCARDCONTEXT {1}, "Reader 0", SCARD_SHARE_SHARED);
  const auto wait = std::chrono::milliseconds(60);
  const auto start = std::chrono::steady_clock::now();
  CHECK(conn.powerCycleField("Reader 0", wait) == FieldCycleResult::Ok);
  CHECK(std::chrono::steady_clock::now() - start >= wait);
}

TEST_CASE("powerCycleField reports a removed card without double disconnect",
          "[pcsc][field_cycle]") {
  CycleTransport t;
  {
    safeConnection conn(t, SCARDCONTEXT {1}, "Reader 0", SCARD_SHARE_SHARED);
    t.calls.clear();
    t.connectResult = static_cast<LONG>(SCARD_W_REMOVED_CARD);

    CHECK(conn.powerCycleField("Reader 0", kNoWait) ==
          FieldCycleResult::CardRemoved);
    CHECK(conn.hCard == 0);
    // Disconnect + failed Connect only: no transaction on a dead handle.
    REQUIRE(t.calls.size() == 2);
    CHECK(t.calls[0] == "Disconnect:34");
    CHECK(t.calls[1] == "Connect");
  }
  // The old handle was already released: the destructor does nothing.
  CHECK(t.calls.size() == 2);
}

TEST_CASE("powerCycleField maps other connect errors to Failed",
          "[pcsc][field_cycle]") {
  CycleTransport t;
  safeConnection conn(t, SCARDCONTEXT {1}, "Reader 0", SCARD_SHARE_SHARED);
  t.connectResult = static_cast<LONG>(SCARD_E_NOT_TRANSACTED);
  CHECK(conn.powerCycleField("Reader 0", kNoWait) == FieldCycleResult::Failed);
  CHECK(conn.hCard == 0);
}

TEST_CASE("powerCycleField is a no-op on transports without a field",
          "[pcsc][field_cycle]") {
  CycleTransport t;
  t.fieldCycle = false;  // NFC session transports
  safeConnection conn(t, SCARDCONTEXT {1}, "Reader 0", SCARD_SHARE_SHARED);
  t.calls.clear();

  CHECK(conn.powerCycleField("Reader 0", kNoWait) ==
        FieldCycleResult::Unsupported);
  CHECK(conn.hCard == 0x22);
  CHECK(t.calls.empty());
}

TEST_CASE("a card needing re-presentation is reported as kind 12 / sw 6A82",
          "[pcsc][field_cycle][cie_error]") {
  // Same recording the CAN reader performs after the field cycle failed.
  cie_clear_error();
  cie_record_card_reset_required(0x6A82);

  cie_error_kind kind = CIE_ERR_NONE;
  uint16_t sw = 0;
  REQUIRE(cie_last_error(&kind, &sw) == CKR_OK);
  CHECK(kind == CIE_ERR_CARD_RESET_REQUIRED);
  CHECK(static_cast<int>(kind) == 12);
  CHECK(sw == 0x6A82);
  cie_clear_error();
}
