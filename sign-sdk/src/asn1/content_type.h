#pragma once

#include "asn1_object_identifier.h"

class CContentType : public CASN1ObjectIdentifier {
 public:
  static const char* OID_TYPE_DATA;
  static const char* OID_TYPE_SIGNED;
  static const char* OID_TYPE_ENVELOPED;
  static const char* OID_TYPE_SIGNED_ENVELOPED;
  static const char* OID_TYPE_DIGEST;
  static const char* OID_TYPE_ENCRYPTED;
  static const char* OID_TYPE_TSTINFO;

  CContentType(UUCBufferedReader& reader);

  CContentType(const CASN1Object& contentType);

  CContentType(char* lpszOId);
  CContentType(const char* timeStampDataOID);

  CContentType(const CASN1ObjectIdentifier& algoId);

  virtual ~CContentType();
};

