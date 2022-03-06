#pragma once

#include <map>

#include "asn1/certificate.h"


class CCertStore {
 public:
  static void AddCertificate(CCertificate& caCertificate);

  static CCertificate* GetCertificate(CCertificate& certificate);

  static void CleanUp();

 private:
  static std::map<unsigned long, CCertificate*> m_certMap;
};
