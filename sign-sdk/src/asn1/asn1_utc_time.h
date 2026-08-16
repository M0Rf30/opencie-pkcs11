// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_utc_time.h
 * @brief ASN.1 UTCTime primitive type.
 *
 * Represents an ASN.1 UTCTime value (ITU-T X.680) used in X.509
 * certificates for validity dates and in CMS for signing times.
 * The two-digit year is interpreted per RFC 5280: values 00-49 map to
 * 2000-2049, values 50-99 map to 1950-1999.
 */

#pragma once

#include <ctime>

#include "asn1_object.h"

/**
 * @brief Formats @p t as a UTCTime string ("YYMMDDHHMMSSZ") in UTC.
 *
 * The trailing 'Z' asserts UTC, so the broken-down time must come from
 * gmtime, not localtime — using local time here shifts every comparison
 * against a certificate or CRL by the local UTC offset. Wraps the
 * reentrant conversion, which is spelled gmtime_r on POSIX and gmtime_s
 * (with reversed arguments) on Windows.
 *
 * @param t     Time to format.
 * @param szOut Output buffer.
 * @param nOut  Size of @p szOut in bytes.
 * @return true on success; false if the conversion or formatting failed.
 */
bool FormatUtcTime(time_t t, char* szOut, size_t nOut);

/**
 * @brief ASN.1 UTCTime (tag 0x17).
 *
 * Stores a date/time in the format "YYMMDDHHMMSSZ". Provides parsing
 * from DER encoding, construction from a string, and extraction of
 * the time value into a caller-supplied buffer.
 */
class CASN1UTCTime : public CASN1Object {
 private:
  /** @brief DER tag byte for UTCTime (0x17). */
  static const BYTE TAG;

 public:
  /**
   * @brief Parses a UTCTime from a DER-encoded stream.
   * @param reader Buffered reader positioned at the UTCTime TLV.
   */
  explicit CASN1UTCTime(BufferedReader& reader);

  /**
   * @brief Constructs a UTCTime from a string representation.
   * @param szUTCTime UTC time string (e.g. "YYMMDDHHMMSSZ").
   */
  explicit CASN1UTCTime(const char* szUTCTime);

  /**
   * @brief Constructs a UTCTime from an already-parsed ASN.1 object.
   * @param obj Generic ASN.1 object containing UTCTime encoding.
   */
  explicit CASN1UTCTime(const CASN1Object& obj);

  virtual ~CASN1UTCTime() override;

  /**
   * @brief Extracts the time value as a null-terminated string.
   * @param szTime Output buffer receiving the UTC time string.
   */
  void getUTCTime(char* szTime);
};
