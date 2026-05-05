// SPDX-License-Identifier: LGPL-3.0-or-later
#include "cert_store.h"

#include <cstdio>
#include <map>

#include "util/util.h"

unsigned long getHash(const char* szKey);

#ifdef WIN32

#else
#include <dirent.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

std::map<unsigned long, CCertificate*> CCertStore::m_certMap;

void CCertStore::AddCertificate(CCertificate& certificate) {
  // LOG_DBG((0, "--> CertStore::AddCertificate", ""));

  try {
    unsigned long nHash;
    CASN1OctetString subjectKeyIdentifier =
        certificate.getSubjectKeyIdentifier();

    if (subjectKeyIdentifier.getLength() > 0) {
      const ByteDynArray* pValue = subjectKeyIdentifier.getValue();
      std::string skiHex = dumpHexData(*pValue);
      const char* szSki = skiHex.c_str();

      // LOG_DBG((0, "AddCertificate", "szSki: %s", szSki));

      nHash = getHash(szSki);
    } else {
      ByteDynArray baSubject;
      certificate.getSubject().getNameAsString(baSubject);
      nHash = getHash(reinterpret_cast<const char*>(baSubject.data()));
    }

    CCertificate* pCert = new CCertificate(certificate);

    m_certMap[nHash] = pCert;
  } catch (...) {
    LOG_ERR((0, "CertStore::AddCertificate Exception", ""));
  }

  // LOG_DBG((0, "<-- CertStore::AddCertificate", ""));
}

CCertificate* CCertStore::GetCertificate(CCertificate& certificate) {
  try {
    unsigned long nHash;
    CASN1OctetString autorityKeyIdentifier =
        certificate.getAuthorithyKeyIdentifier();

    if (autorityKeyIdentifier.getLength() > 0) {
      ByteDynArray* pValue =
          const_cast<ByteDynArray*>(autorityKeyIdentifier.getValue());
      pValue->set(0, 0x04);

      std::string akiHex = dumpHexData(*pValue);
      const char* szAki = akiHex.c_str();

      LOG_DBG((0, "GetCertificate", "szAki: %s", szAki));

      nHash = getHash(szAki);
    } else {
      ByteDynArray baIssuer;
      certificate.getIssuer().getNameAsString(baIssuer);
      nHash = getHash(reinterpret_cast<const char*>(baIssuer.data()));
    }

    CCertificate* pCert = m_certMap[nHash];
    if (pCert != nullptr &&
        pCert->getSerialNumber() == certificate.getSerialNumber())
      return nullptr;

    return pCert;
  } catch (...) {
    LOG_ERR((0, "CertStore::AddCertificate Exception", ""));
  }

  return nullptr;
}

void CCertStore::CleanUp() {
  for (std::map<unsigned long, CCertificate*>::iterator it = m_certMap.begin();
       it != m_certMap.end(); ++it) {
    CCertificate* pCert = static_cast<CCertificate*>(it->second);
    SAFEDELETE(pCert)
  }
}

unsigned long getHash(const char* szKey) {
  int h = 0;
  int off = 0;
  const char* val = szKey;
  int len = strlen(szKey);

  if (len < 16) {
    for (int i = len; i > 0; i--) {
      h = (h * 37) + val[off++];
    }
  } else {
    // only sample some characters
    int skip = len / 8;
    for (int i = len; i > 0; i -= skip, off += skip) {
      h = (h * 39) + val[off];
    }
  }

  return h;
}
