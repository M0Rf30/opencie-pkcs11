// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include <map>
#include <memory>

#include "asn1/content_info.h"
#include "asn1/signed_data.h"
#include "asn1/signer_info.h"
#include "Util/definitions.h"
#include "sign/disigonsdk.h"
#include "Util/byte_array.h"

class CSignedDocument {
 public:
  CSignedDocument(const BYTE* content, int len);
  CSignedDocument(const CSignedDocument& signedDocument);

  virtual ~CSignedDocument();

  int verify();
  int verify(const char* dateTime);
  int verify(int index, REVOCATION_INFO* pRevocationInfo);
  int verify(int index, const char* dateTime, REVOCATION_INFO* pRevocationInfo);

  int getSignerCount();
  CASN1SetOf getSignerInfos();
  CASN1SetOf getCertificates();
  CASN1SetOf getDigestAlgos();

  CSignerInfo getSignerInfo(int index);
  CCertificate getSignerCertificate(int index);
  void getContent(UUCByteArray& content);

  // static void init(map<string, CCertificate*> certMap);

  void makeDetached();

  void toByteArray(UUCByteArray& signedData);

  CSignedData getSignedData();

  bool isDetached();
  void setContent(UUCByteArray& content);

  // 0 successivo al 30 Giugno 2011, 1 successivo al 30 agosto 2010, 2
  // precedente al 30 agosto 2010
  static int get452009Range(char* szDateTime);

 private:
  std::unique_ptr<CContentInfo> m_pCMSSignedData;
  std::unique_ptr<CSignedData> m_pSignedData;
  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
};
