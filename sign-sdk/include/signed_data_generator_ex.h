// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

// #include "asn1/utiltypes.h"
#include <vector>

#include "asn1/asn1_set_of.h"
#include "asn1/signer_info.h"
#include "asn1/time_stamp_response.h"
#include "signed_document.h"
#include "Util/byte_array.h"

class SignedDataGeneratorEx {
 public:
  SignedDataGeneratorEx(CSignedDocument& sd);

  virtual ~SignedDataGeneratorEx();

  bool isDetached();

  void setContent(const BYTE* content, int len);

  void addSigners(CSignedDocument& sd);

  void addCounterSignature(CSignerInfo& signerInfoRef,
                           CSignedDocument& countersignature);

  void addCounterSignature(CSignerInfo& signerInfoRef,
                           CSignedDocument& counterSignature,
                           CTimeStampResponse& tsr);

  void setTimestamp(CTimeStampResponse& tsr, int signerInfoIndex);

  void toByteArray(UUCByteArray& pkcs7SignedData);

 private:
  UUCByteArray m_content;

  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
  CASN1SetOf m_digestAlgos;

  bool addCounterSignature(CSignerInfo& signerInfo, CSignerInfo& signerInfoRef,
                           CSignerInfo& counterSignature);
};
