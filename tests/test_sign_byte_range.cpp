// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "pdf_byte_range.h"

namespace {
// "AAAA<hex>BBBB": 4 + (2+hex) + 4 bytes.
std::string makeDoc(size_t hexLen) {
  return "AAAA<" + std::string(hexLen, '0') + ">BBBB";
}
PdfByteRange rangeFor(size_t hexLen) {
  return {0, 4, static_cast<long long>(4 + hexLen + 2), 4};
}
PdfByteRangeStatus check(const std::string& doc, const PdfByteRange& r,
                         size_t hexLen) {
  return ValidatePdfByteRange(reinterpret_cast<const uint8_t*>(doc.data()),
                              doc.size(), r, hexLen);
}
}  // namespace

TEST_CASE("ParsePdfByteRange accepts exactly four non-negative ints") {
  PdfByteRange r;
  REQUIRE(ParsePdfByteRange("[ 0 10 20 30 ]", r));
  CHECK(r.len0 == 10);
  CHECK(r.start1 == 20);
  CHECK(r.len1 == 30);
  CHECK_FALSE(ParsePdfByteRange("[ 0 10 20 ]", r));
  CHECK_FALSE(ParsePdfByteRange("[ 0 10 20 30 40 ]", r));
  CHECK_FALSE(ParsePdfByteRange("[ 0 -10 20 30 ]", r));
  CHECK_FALSE(ParsePdfByteRange("[ 0 a 20 30 ]", r));
}

TEST_CASE("ValidatePdfByteRange accepts a well-formed full-coverage range") {
  CHECK(check(makeDoc(8), rangeFor(8), 8) == PdfByteRangeStatus::Ok);
}

TEST_CASE("ValidatePdfByteRange rejects bad ranges") {
  const auto doc = makeDoc(8);
  auto r = rangeFor(8);

  auto bad = r;
  bad.start0 = 1;
  CHECK(check(doc, bad, 8) == PdfByteRangeStatus::OutOfBounds);

  bad = r;
  bad.len1 = 1000;
  CHECK(check(doc, bad, 8) == PdfByteRangeStatus::OutOfBounds);

  bad = r;  // unordered / overlapping
  bad.start1 = 2;
  CHECK(check(doc, bad, 8) == PdfByteRangeStatus::OutOfBounds);

  bad = r;
  bad.len0 = -1;
  CHECK(check(doc, bad, 8) == PdfByteRangeStatus::OutOfBounds);

  // gap larger than the /Contents string (hidden unsigned bytes)
  bad = r;
  bad.start1 += 2;
  bad.len1 -= 2;
  CHECK(check(doc, bad, 8) == PdfByteRangeStatus::GapMismatch);

  // declared hex length disagrees with the gap
  CHECK(check(doc, r, 6) == PdfByteRangeStatus::GapMismatch);
}

TEST_CASE("ValidatePdfByteRange flags partial coverage") {
  const auto doc = makeDoc(8) + "TRAILING";
  CHECK(check(doc, rangeFor(8), 8) == PdfByteRangeStatus::PartialCoverage);
}

TEST_CASE("VerifyResultToBitmask never turns error codes into all-bits") {
  CHECK(VerifyResultToBitmask(-1) == 0);
  CHECK(VerifyResultToBitmask(-5) == 0);
  CHECK(VerifyResultToBitmask(0x1000) == 0x1000);
}
