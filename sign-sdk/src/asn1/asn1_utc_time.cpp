// ASN1UTCTime.cpp: implementation of the CASN1UTCTime class.
//
#include "asn1/asn1_utc_time.h"

const BYTE CASN1UTCTime::TAG = 0x17;

CASN1UTCTime::~CASN1UTCTime() {}

CASN1UTCTime::CASN1UTCTime(BufferedReader& reader) : CASN1Object(reader) {}

CASN1UTCTime::CASN1UTCTime(const char* szUTCTime) : CASN1Object(TAG) {
  ByteDynArray utcTime(
      ByteArray(reinterpret_cast<const BYTE*>(szUTCTime), strlen(szUTCTime)));
  setValue(utcTime);
}

CASN1UTCTime::CASN1UTCTime(const CASN1Object& utcTime) : CASN1Object(utcTime) {}

void CASN1UTCTime::getUTCTime(char* szTime) {
  memcpy(szTime, reinterpret_cast<const char*>(m_value.data()), m_value.size());
  szTime[m_value.size()] = 0;
}
