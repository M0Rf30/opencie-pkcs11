// ASN1UTCTime.cpp: implementation of the CASN1UTCTime class.
//
#include "asn1/asn1_utc_time.h"

// Construction/Destruction

const BYTE CASN1UTCTime::TAG = 0x17;

// distruttori
CASN1UTCTime::~CASN1UTCTime() {}

// costruttori
CASN1UTCTime::CASN1UTCTime(UUCBufferedReader& reader) : CASN1Object(reader) {}

CASN1UTCTime::CASN1UTCTime(const char* szUTCTime) : CASN1Object(TAG) {
  UUCByteArray utcTime(reinterpret_cast<const BYTE*>(szUTCTime), strlen(szUTCTime));
  setValue(utcTime);
}

CASN1UTCTime::CASN1UTCTime(const CASN1Object& utcTime) : CASN1Object(utcTime) {}

void CASN1UTCTime::getUTCTime(char* szTime) {
  memcpy(szTime, reinterpret_cast<const char*>(m_value.getContent()), m_value.getLength());
  szTime[m_value.getLength()] = 0;
}
