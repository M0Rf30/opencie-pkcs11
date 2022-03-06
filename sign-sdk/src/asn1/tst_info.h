// TSTInfo.h: interface for the CTSTInfo class.
//
#pragma once


#if _MSC_VER > 1000
#pragma once
#endif  // _MSC_VER > 1000

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/algorithm_identifier.h"
#include "name.h"

class CTSTInfo : public CASN1Sequence {
 public:
  CTSTInfo(UUCBufferedReader& reader);

  CTSTInfo(const CASN1Object& tstInfo);

  virtual ~CTSTInfo();

  CASN1UTCTime getUTCTime();

  CASN1Integer getSerialNumber();

  CAlgorithmIdentifier getDigestAlgorithn();

  CASN1Sequence getMessageImprint();

  // N.B. il campo TSAName è opzionale. se non presente nel tstoken torna
  // eccezione
  CName getTSAName();
};

