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

    std::map<unsigned long, CCertificate*>::iterator it = m_certMap.find(nHash);
    if (it != m_certMap.end()) {
      // A different certificate previously occupied this hash bucket
      // (the hash is a weak 32-bit value, so collisions happen) or this
      // same certificate is being re-added; free the old entry so it is
      // not leaked.
      CCertificate* pOld = it->second;
      SAFEDELETE(pOld)
      it->second = pCert;
    } else {
      m_certMap[nHash] = pCert;
    }
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

    bool haveAki = autorityKeyIdentifier.getLength() > 0;
    if (haveAki) {
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

    std::map<unsigned long, CCertificate*>::iterator it = m_certMap.find(nHash);
    if (it == m_certMap.end() || it->second == nullptr) return nullptr;

    CCertificate* pCert = it->second;
    if (pCert->getSerialNumber() == certificate.getSerialNumber())
      return nullptr;

    // The map is keyed by a weak 32-bit hash, so a bucket hit only means
    // the candidate hashed the same as the issuer we are looking for, not
    // that it actually is that issuer. Confirm it before trusting it:
    // the candidate's subject DN must equal the DER-encoded issuer DN of
    // the certificate under test, and -- when both sides carry one -- its
    // Subject Key Identifier must equal the Authority Key Identifier we
    // looked up with.
    if (pCert->getSubject() != certificate.getIssuer()) return nullptr;

    if (haveAki) {
      CASN1OctetString candidateSki = pCert->getSubjectKeyIdentifier();
      if (candidateSki.getLength() == 0 ||
          *candidateSki.getValue() != *autorityKeyIdentifier.getValue())
        return nullptr;
    }

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
