// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <thread>

#include "csp/cie_error.h"
#include "opencie/cie_ext.h"

TEST_CASE("cie_classify_sw maps every documented status word", "[cie_error]") {
  CHECK(cie_classify_sw(0x9000) == CIE_ERR_NONE);
  CHECK(cie_classify_sw(0x6300) == CIE_ERR_WRONG_PIN);
  CHECK(cie_classify_sw(0x6700) == CIE_ERR_WRONG_PIN);
  CHECK(cie_classify_sw(0x6983) == CIE_ERR_PIN_BLOCKED);
  CHECK(cie_classify_sw(0x6984) == CIE_ERR_PIN_NOT_SET);
  CHECK(cie_classify_sw(0x6982) == CIE_ERR_SECURITY_NOT_SATISFIED);
  CHECK(cie_classify_sw(0x6A82) == CIE_ERR_FILE_NOT_FOUND);
  CHECK(cie_classify_sw(0x6A80) == CIE_ERR_WRONG_PARAMS);
  CHECK(cie_classify_sw(0x6A86) == CIE_ERR_WRONG_PARAMS);
  CHECK(cie_classify_sw(0x6A88) == CIE_ERR_WRONG_PARAMS);
  CHECK(cie_classify_sw(0x6B00) == CIE_ERR_WRONG_PARAMS);
  CHECK(cie_classify_sw(0x6D00) == CIE_ERR_INS_NOT_SUPPORTED);
  CHECK(cie_classify_sw(0x6E00) == CIE_ERR_INS_NOT_SUPPORTED);
}

TEST_CASE("cie_classify_sw maps the whole 0x63C0-0x63CF range to WRONG_PIN",
          "[cie_error]") {
  for (uint16_t sw = 0x63C0; sw <= 0x63CF; ++sw)
    CHECK(cie_classify_sw(sw) == CIE_ERR_WRONG_PIN);
}

TEST_CASE("cie_classify_sw defaults unmapped words to CIE_ERR_UNKNOWN",
          "[cie_error]") {
  CHECK(cie_classify_sw(0x1234) == CIE_ERR_UNKNOWN);
}

TEST_CASE("cie_record_sw_error / cie_last_error / cie_clear_error round-trip",
          "[cie_error]") {
  cie_error_kind kind = CIE_ERR_UNKNOWN;
  uint16_t sw = 0;

  cie_record_sw_error(0x6983);
  REQUIRE(cie_last_error(&kind, &sw) == CKR_OK);
  CHECK(kind == CIE_ERR_PIN_BLOCKED);
  CHECK(sw == 0x6983);

  cie_clear_error();
  REQUIRE(cie_last_error(&kind, &sw) == CKR_OK);
  CHECK(kind == CIE_ERR_NONE);
  CHECK(sw == 0);

  cie_record_transport_error();
  REQUIRE(cie_last_error(&kind, &sw) == CKR_OK);
  CHECK(kind == CIE_ERR_CARD_COMMUNICATION);
  CHECK(sw == 0);

  cie_clear_error();
}

TEST_CASE("cie_last_error accepts NULL out-params without crashing",
          "[cie_error]") {
  cie_record_sw_error(0x6982);
  CHECK(cie_last_error(nullptr, nullptr) == CKR_OK);
  cie_clear_error();
}

TEST_CASE("the last-error record is thread-local", "[cie_error]") {
  cie_clear_error();
  cie_record_sw_error(0x6983);  // main thread: PIN_BLOCKED / 0x6983

  std::thread other([] {
    cie_record_sw_error(0x6A82);  // other thread: FILE_NOT_FOUND / 0x6A82
    cie_error_kind kind = CIE_ERR_UNKNOWN;
    uint16_t sw = 0;
    cie_last_error(&kind, &sw);
    CHECK(kind == CIE_ERR_FILE_NOT_FOUND);
    CHECK(sw == 0x6A82);
  });
  other.join();

  cie_error_kind kind = CIE_ERR_UNKNOWN;
  uint16_t sw = 0;
  REQUIRE(cie_last_error(&kind, &sw) == CKR_OK);
  CHECK(kind == CIE_ERR_PIN_BLOCKED);
  CHECK(sw == 0x6983);

  cie_clear_error();
}
