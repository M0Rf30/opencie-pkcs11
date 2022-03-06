#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1/algorithm_identifier.h"
#include "asn1_octet_string.h"

class CDigestInfo : public CASN1Sequence {
  // Defined as
  // DigestInfo ::= SEQUENCE {
  // 		digestAlgorithm DigestAlgorithmIdentifier,
  //		digest Digest}

 public:
  CDigestInfo(UUCBufferedReader& reader);

  CDigestInfo(const CAlgorithmIdentifier& algoId,
              const CASN1OctetString& digest);

  CDigestInfo(const CASN1Object& digestInfo);

  CAlgorithmIdentifier getDigestAlgorithm();

  CASN1OctetString getDigest();
};

