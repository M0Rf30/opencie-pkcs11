// SPDX-License-Identifier: LGPL-3.0-or-later

#include "digest_info.h"

CDigestInfo::CDigestInfo(BufferedReader& reader) : CASN1Sequence(reader) {}

CDigestInfo::CDigestInfo(const CAlgorithmIdentifier& algoId,
                         const CASN1OctetString& digest) {
  addElement(algoId);
  addElement(digest);
}

CDigestInfo::CDigestInfo(const CASN1Object& digestInfo)
    : CASN1Sequence(digestInfo) {}

CAlgorithmIdentifier CDigestInfo::getDigestAlgorithm() {
  return CAlgorithmIdentifier(elementAt(0));
}

CASN1OctetString CDigestInfo::getDigest() {
  return CASN1OctetString(elementAt(1));
}
