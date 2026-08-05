// SPDX-License-Identifier: LGPL-3.0-or-later
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "pcsc/pcsc.h"
#include "pcsc/smart_card_transport.h"

namespace {

class MockTransport : public ISmartCardTransport {
 public:
  explicit MockTransport(bool present) : present_(present) {}

  LONG EstablishContext(DWORD, LPSCARDCONTEXT phContext) override {
    *phContext = 1;
    return SCARD_S_SUCCESS;
  }

  LONG ReleaseContext(SCARDCONTEXT) override { return SCARD_S_SUCCESS; }
  LONG IsValidContext(SCARDCONTEXT) override { return SCARD_S_SUCCESS; }

  LONG ListReaders(SCARDCONTEXT, LPSTR mszReaders,
                   LPDWORD pcchReaders) override {
    if (listReadersError_ != SCARD_S_SUCCESS) return listReadersError_;
    static const char kName[] = "Mock Reader 0";
    DWORD needed = sizeof(kName) + 1;
    if (mszReaders == nullptr) {
      *pcchReaders = needed;
      return SCARD_S_SUCCESS;
    }
    std::memcpy(mszReaders, kName, sizeof(kName));
    mszReaders[sizeof(kName)] = 0;
    *pcchReaders = needed;
    return SCARD_S_SUCCESS;
  }

  LONG GetStatusChange(SCARDCONTEXT, DWORD dwTimeout,
                       SCARD_READERSTATE *rgReaderStates,
                       DWORD cReaders) override {
    std::unique_lock<std::mutex> lock(mutex_);
    auto apply = [&]() {
      for (DWORD i = 0; i < cReaders; i++) {
        auto &rs = rgReaderStates[i];
        if (rs.pvUserData != nullptr) {
          rs.dwEventState = rs.dwCurrentState;
          continue;
        }
        DWORD event = present_ ? SCARD_STATE_PRESENT : SCARD_STATE_EMPTY;
        if (event != rs.dwCurrentState) event |= SCARD_STATE_CHANGED;
        rs.dwEventState = event;
      }
    };
    if (dwTimeout == 0) {
      apply();
      return SCARD_S_SUCCESS;
    }
    cv_.wait(lock, [&] { return cancelled_ || changed_; });
    if (cancelled_) return SCARD_E_CANCELLED;
    changed_ = false;
    apply();
    return SCARD_S_SUCCESS;
  }

  LONG Cancel(SCARDCONTEXT) override {
    std::lock_guard<std::mutex> lock(mutex_);
    cancelled_ = true;
    cv_.notify_all();
    return SCARD_S_SUCCESS;
  }

  LONG Connect(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE,
               LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG Disconnect(SCARDHANDLE, DWORD) override { return SCARD_S_SUCCESS; }
  LONG Reconnect(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG Transmit(SCARDHANDLE, const SCARD_IO_REQUEST *, LPCBYTE, DWORD, LPBYTE,
                LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }
  LONG BeginTransaction(SCARDHANDLE) override { return SCARD_S_SUCCESS; }
  LONG EndTransaction(SCARDHANDLE, DWORD) override { return SCARD_S_SUCCESS; }
  LONG GetAttrib(SCARDHANDLE, DWORD, LPBYTE, LPDWORD) override {
    return SCARD_E_INVALID_PARAMETER;
  }

  void setListReadersError(LONG code) { listReadersError_ = code; }

  void setPresent(bool present) {
    std::lock_guard<std::mutex> lock(mutex_);
    present_ = present;
    changed_ = true;
    cv_.notify_all();
  }

 private:
  std::atomic<bool> present_;
  LONG listReadersError_ = SCARD_S_SUCCESS;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool cancelled_ = false;
  bool changed_ = false;
};

struct EventLog {
  std::mutex mutex;
  std::condition_variable cv;
  std::vector<std::pair<std::string, bool>> events;

  void record(const std::string &reader, bool insert) {
    std::lock_guard<std::mutex> lock(mutex);
    events.emplace_back(reader, insert);
    cv.notify_all();
  }

  bool waitFor(size_t count) {
    std::unique_lock<std::mutex> lock(mutex);
    return cv.wait_for(lock, std::chrono::seconds(2),
                       [&] { return events.size() >= count; });
  }
};

void onReaderEvent(std::string &reader, bool insert, void *appData) {
  static_cast<EventLog *>(appData)->record(reader, insert);
}

}  // namespace

TEST_CASE("readerMonitor fires exactly one insert for a card present at start",
          "[pcsc][readerMonitor]") {
  MockTransport transport(true);
  EventLog log;
  {
    readerMonitor monitor(transport, onReaderEvent, &log);
    REQUIRE(log.waitFor(1));
  }
  std::lock_guard<std::mutex> lock(log.mutex);
  REQUIRE(log.events.size() == 1);
  CHECK(log.events[0].first == "Mock Reader 0");
  CHECK(log.events[0].second == true);
}

TEST_CASE("readerMonitor still detects removal and reinsertion afterward",
          "[pcsc][readerMonitor]") {
  MockTransport transport(true);
  EventLog log;
  readerMonitor monitor(transport, onReaderEvent, &log);
  REQUIRE(log.waitFor(1));

  transport.setPresent(false);
  REQUIRE(log.waitFor(2));
  transport.setPresent(true);
  REQUIRE(log.waitFor(3));

  std::lock_guard<std::mutex> lock(log.mutex);
  REQUIRE(log.events.size() == 3);
  CHECK(log.events[0].second == true);
  CHECK(log.events[1].second == false);
  CHECK(log.events[2].second == true);
}

TEST_CASE("readerMonitor handles no readers available without crashing",
          "[pcsc][readerMonitor]") {
  MockTransport transport(false);
  transport.setListReadersError(SCARD_E_NO_READERS_AVAILABLE);
  EventLog log;
  {
    readerMonitor monitor(transport, onReaderEvent, &log);
  }
  std::lock_guard<std::mutex> lock(log.mutex);
  CHECK(log.events.empty());
}

TEST_CASE("readerMonitor handles no PC/SC service without crashing",
          "[pcsc][readerMonitor]") {
  MockTransport transport(false);
  transport.setListReadersError(SCARD_E_NO_SERVICE);
  EventLog log;
  {
    readerMonitor monitor(transport, onReaderEvent, &log);
  }
  std::lock_guard<std::mutex> lock(log.mutex);
  CHECK(log.events.empty());
}
