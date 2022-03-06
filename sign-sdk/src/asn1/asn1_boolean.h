#pragma once

#include "asn1/asn1_object.h"
#include "asn1/buffered_reader.h"
class CASN1Boolean : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  // costruttori

  CASN1Boolean(bool val);

  CASN1Boolean(const CASN1Object&);

  CASN1Boolean(UUCBufferedReader& reader);
  // distruttori

  ~CASN1Boolean();

  bool getBoolValue() const;
};

