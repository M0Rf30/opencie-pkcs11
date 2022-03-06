// Name.h: interface for the CName class.
//

#pragma once

#include <string>

#include "asn1/asn1_sequence.h"

#define OID_EMAIL_ADDRESS "1.2.840.113549.1.9.1"
#define OID_UNSTRUCTURED_NAME "1.2.840.113549.1.9.2"
#define OID_CONTENT_TYPE "1.2.840.113549.1.9.3"
#define OID_MESSAGE_DIGEST "1.2.840.113549.1.9.4"
#define OID_SIGNING_TIME "1.2.840.113549.1.9.5"
#define OID_COUNTERSIGNATURE "1.2.840.113549.1.9.6"
#define OID_CHALLENGE_PASSWORD "1.2.840.113549.1.9.7"
#define OID_UNSTRUCTURED_ADDRESS "1.2.840.113549.1.9.8"
#define OID_EXTENDED_CERTIFICATE_ATTRIBUTES "2.5.4.3"
#define OID_COMMON_NAME "2.5.4.3"
#define OID_SURNAME "2.5.4.4"
#define OID_COUNTRY_NAME "2.5.4.6"
#define OID_LOCALITY_NAME "2.5.4.7"
#define OID_STATE_OR_PROVINCE_NAME "2.5.4.8"
#define OID_ORGANIZATION_NAME "2.5.4.10"
#define OID_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define OID_TITLE "2.5.4.12"
#define OID_NAME "2.5.4.41"
#define OID_GIVEN_NAME "2.5.4.42"
#define OID_INITIALS "2.5.4.43"
#define OID_GENERATION_QUALIFIER "2.5.4.44"
#define OID_DN_QUALIFIER "2.5.4.46"
#define OID_SERIALNUMBER "2.5.4.5"


class CName : public CASN1Sequence {
 public:
  CName(UUCBufferedReader& reader);

  CName(const CASN1Object& name);

  std::string getField(const char* fieldOID);

  void getNameAsString(UUCByteArray& objId);

  virtual ~CName();
};


