// SPDX-License-Identifier: LGPL-3.0-or-later
// ASN1UTCTime.cpp: implementation of the CASN1UTCTime class.
//
#include "asn1/asn1_utc_time.h"

#include "asn1_exception.h"

const BYTE CASN1UTCTime::TAG = 0x17;

bool FormatUtcTime(time_t t, char* szOut, size_t nOut) {
  if (szOut == nullptr || nOut == 0) return false;

  struct tm tmUtc;
#ifdef _WIN32
  // Microsoft's gmtime_s takes the output first and returns errno_t.
  if (gmtime_s(&tmUtc, &t) != 0) return false;
#else
  if (gmtime_r(&t, &tmUtc) == nullptr) return false;
#endif

  return strftime(szOut, nOut, "%y%m%d%H%M%SZ", &tmUtc) != 0;
}

CASN1UTCTime::~CASN1UTCTime() {}

CASN1UTCTime::CASN1UTCTime(BufferedReader& reader) : CASN1Object(reader) {}

CASN1UTCTime::CASN1UTCTime(const char* szUTCTime) : CASN1Object(TAG) {
  ByteDynArray utcTime(
      ByteArray(reinterpret_cast<const BYTE*>(szUTCTime), strlen(szUTCTime)));
  setValue(utcTime);
}

CASN1UTCTime::CASN1UTCTime(const CASN1Object& utcTime) : CASN1Object(utcTime) {}

void CASN1UTCTime::getUTCTime(char* szTime) {
  // Every known caller passes a fixed buffer; the smallest is
  // REVOCATION_INFO::szThisUpdate/szExpiration/szRevocationDate, char[60]
  // (shared/src/sign/cie_sign_api.h). A UTCTime/GeneralizedTime value has no
  // legitimate reason to exceed a couple dozen ASCII digits
  // ("YYYYMMDDHHMMSS.ffffZ" and similar); cap well below the smallest
  // destination buffer and reject anything longer instead of trusting the
  // attacker-controlled DER length.
  constexpr size_t kMaxUTCTimeLen = 31;
  if (m_value.size() > kMaxUTCTimeLen) {
    throw CASN1ParsingException();
  }
  memcpy(szTime, reinterpret_cast<const char*>(m_value.data()), m_value.size());
  szTime[m_value.size()] = 0;
}
