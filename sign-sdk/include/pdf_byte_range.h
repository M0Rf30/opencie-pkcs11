// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file pdf_byte_range.h
 * @brief Strict /ByteRange parsing and validation for PDF signatures.
 *
 * Header-only and independent of PoDoFo so it can be unit tested on crafted
 * buffers.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

/** Parsed /ByteRange [start0 len0 start1 len1]. */
struct PdfByteRange {
  long long start0 = 0;
  long long len0 = 0;
  long long start1 = 0;
  long long len1 = 0;
};

/** Outcome of ValidatePdfByteRange(). */
enum class PdfByteRangeStatus {
  Ok,                ///< Fully valid and covering the whole file.
  OutOfBounds,       ///< Negative, unordered, overlapping or past EOF.
  GapMismatch,       ///< Gap is not exactly the /Contents hex string.
  PartialCoverage,   ///< Valid, but bytes follow the signed range.
};

/**
 * Parse the textual form of a /ByteRange array. Requires exactly four
 * non-negative integers.
 * @return false if malformed.
 */
inline bool ParsePdfByteRange(const std::string& text, PdfByteRange& out) {
  std::string clean = text;
  std::replace(clean.begin(), clean.end(), '[', ' ');
  std::replace(clean.begin(), clean.end(), ']', ' ');
  std::istringstream ss(clean);
  long long v[4];
  for (auto& x : v) {
    if (!(ss >> x) || x < 0) return false;
  }
  char extra;
  if (ss >> extra) return false;  // more than four elements
  out.start0 = v[0];
  out.len0 = v[1];
  out.start1 = v[2];
  out.len1 = v[3];
  return true;
}

/**
 * Validate a parsed /ByteRange against the file bytes.
 *
 * Requires start0 == 0, ordered in-bounds non-overlapping ranges, and the gap
 * between them to be exactly "<" + @p contentsHexLen hex digits + ">" as it
 * appears in the file.
 *
 * @param buf             Whole PDF file.
 * @param size            Size of @p buf.
 * @param contentsHexLen  Number of hex digits in the parsed /Contents string.
 */
inline PdfByteRangeStatus ValidatePdfByteRange(const uint8_t* buf, size_t size,
                                               const PdfByteRange& r,
                                               size_t contentsHexLen) {
  const long long fileLen = static_cast<long long>(size);
  if (r.start0 != 0 || r.len0 < 0 || r.start1 < 0 || r.len1 < 0)
    return PdfByteRangeStatus::OutOfBounds;
  if (r.len0 > fileLen || r.start1 > fileLen || r.len1 > fileLen ||
      r.start1 < r.len0 || r.start1 + r.len1 > fileLen)
    return PdfByteRangeStatus::OutOfBounds;

  const long long gap = r.start1 - r.len0;
  if (gap < 2 || static_cast<unsigned long long>(gap) != contentsHexLen + 2 ||
      buf[r.len0] != '<' || buf[r.start1 - 1] != '>')
    return PdfByteRangeStatus::GapMismatch;

  if (r.start1 + r.len1 != fileLen) return PdfByteRangeStatus::PartialCoverage;
  return PdfByteRangeStatus::Ok;
}

/**
 * Map a verifier return code to a VERIFIED_* bitmask. Negative values are
 * error codes, not bitmasks: they must never be stored as flags (an error code
 * such as -1 would otherwise set every bit).
 */
inline long VerifyResultToBitmask(long result) {
  return result < 0 ? 0 : result;
}
