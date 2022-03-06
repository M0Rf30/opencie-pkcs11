#pragma once

#include "asn1/time_stamp_token.h"

class CTSAClient {
 public:
  CTSAClient(void);
  virtual ~CTSAClient(void);

  void SetTSAUrl(const char* szUrl);
  void SetCredential(const char* szUsername, const char* szPassword);
  void SetUsername(const char* szUsername);
  void SetPassword(const char* szPassword);
  long GetTimeStampToken(UUCByteArray& digest, const char* szPolicyID,
                         CTimeStampToken** ppTimeStampToken);

 private:
  char m_szTSAUrl[256];
  char m_szTSAUsername[256];
  char m_szTSAPassword[256];
};
