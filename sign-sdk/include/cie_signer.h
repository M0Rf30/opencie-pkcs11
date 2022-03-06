#pragma once

#include "asn1/certificate.h"
#include "asn1/rsa_private_key.h"
#include "base_signer.h"
#include "csp/ias.h"
#include <memory>

class CCIESigner : public CBaseSigner {
 public:
  CCIESigner(IAS* pIAS);
  virtual ~CCIESigner(void);

  long Init(const char* szPIN);

  virtual long GetCertificate(const char* alias, CCertificate** ppCertificate,
                              UUCByteArray& id);

  virtual long Sign(UUCByteArray& data, UUCByteArray& id, int algo,
                    UUCByteArray& signature);

  virtual long Close();

 private:
  IAS* m_pIAS;
  char m_szPIN[9];
  std::unique_ptr<CCertificate> m_pCertificate;
};
