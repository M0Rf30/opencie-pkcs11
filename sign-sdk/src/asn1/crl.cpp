// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "asn1/crl.h"

#include <ctime>

#include "asn1/asn1_utc_time.h"
#include "asn1/certificate.h"
#include "asn1_exception.h"
#include "asn1_octet_string.h"

CCrl::CCrl(BufferedReader& reader) : CASN1Sequence(reader) {}

CCrl::CCrl(const CASN1Object& contentInfo) : CASN1Sequence(contentInfo) {}

bool CCrl::isRevoked(const CASN1Integer& serialNumber, const char* szDateTime,
                     int* pReason, REVOCATION_INFO* pRevocationInfo) {
  LOG_MSG((0, "CCrl::isRevoked", "enter"));

  CASN1Sequence tbsCertList(elementAt(0));

  if (pRevocationInfo) {
    CASN1UTCTime thisUpdate = CASN1UTCTime(tbsCertList.elementAt(3));
    thisUpdate.getUTCTime(pRevocationInfo->szThisUpdate);
  }

  CASN1Sequence revokedCertificates(tbsCertList.elementAt(5));
  int count = revokedCertificates.size();
  if (count > 0) {
    for (int i = 0; i < count; i++) {
      CASN1Sequence revokedCertificate =
          CASN1Sequence(revokedCertificates.elementAt(i));

      CASN1Integer sn(revokedCertificate.elementAt(0));

      if (serialNumber == sn) {
        CASN1Object revocationDate(revokedCertificate.elementAt(1));

        BYTE* btRevocationDate;

        if (revocationDate.getValue()->size() > 13) {
          btRevocationDate =
              const_cast<BYTE*>(revocationDate.getValue()->data()) +
              revocationDate.getValue()->size() - 13;
        } else {
          btRevocationDate =
              const_cast<BYTE*>(revocationDate.getValue()->data());
        }

        if (pRevocationInfo) {
          pRevocationInfo->nType = TYPE_CRL;
          memcpy(pRevocationInfo->szRevocationDate, btRevocationDate, 13);
          pRevocationInfo->szRevocationDate[13] = 0;
        }

        if (szDateTime != nullptr) {
          if (memcmp(szDateTime, btRevocationDate, 13) < 0) {
            if (pRevocationInfo)
              pRevocationInfo->nRevocationStatus = REVOCATION_STATUS_GOOD;
            *pReason = REVOCATION_STATUS_GOOD;
            return false;
          }
        }

        if (revokedCertificate.size() > 2) {
          CASN1Sequence extension(revokedCertificate.elementAt(2));

          CASN1Sequence crlReason(extension.elementAt(0));

          CASN1OctetString reasonCode(crlReason.elementAt(1));
          const ByteDynArray* pVal = reasonCode.getValue();

          BYTE reason = pVal->data()[2];  // reasonCode.getTag() & 0x0F;
          if (reason == 6)                // Certificate HOLD
            *pReason = REVOCATION_STATUS_SUSPENDED;
          else
            *pReason = REVOCATION_STATUS_REVOKED;
        } else {
          // reason non presente
          *pReason = REVOCATION_STATUS_REVOKED;
        }

        if (pRevocationInfo) pRevocationInfo->nRevocationStatus = *pReason;

        LOG_MSG((0, "CCrl::isRevoked", "YES: %d", *pReason));

        return true;
      }
    }
  }

  *pReason = REVOCATION_STATUS_GOOD;
  LOG_MSG((0, "CCrl::isRevoked", "NO: %d", *pReason));
  if (pRevocationInfo) pRevocationInfo->nRevocationStatus = *pReason;

  LOG_MSG((0, "CCrl::isRevoked", "exit with false"));

  return false;
}

bool CCrl::verifySignature(CCertificate& issuer) {
  // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
  // signatureValue BIT STRING } has the same shape as Certificate, so the
  // existing certificate-signature verifier can be reused directly.
  try {
    CCertificate crlAsCert(*this);
    return crlAsCert.verifySignature(issuer);
  } catch (const CASN1Exception&) {
    return false;
  } catch (...) {
    return false;
  }
}

bool CCrl::isCurrent(const char* szDateTime) {
  char szNow[20];
  const char* szRef = szDateTime;
  if (!szRef) {
    time_t now = time(nullptr);
    struct tm tmNow;
    strftime(szNow, sizeof(szNow), "%y%m%d%H%M%SZ", gmtime_r(&now, &tmNow));
    szRef = szNow;
  }

  try {
    CASN1Sequence tbsCertList(elementAt(0));

    CASN1UTCTime thisUpdate(tbsCertList.elementAt(3));
    const ByteDynArray* pThisUpdate = thisUpdate.getValue();
    if (!pThisUpdate || pThisUpdate->size() < 13) return false;

    const BYTE* btThisUpdate = pThisUpdate->data() + (pThisUpdate->size() - 13);
    if (memcmp(szRef, btThisUpdate, 13) < 0) return false;  // not yet valid

    if (tbsCertList.isPresent(4)) {
      CASN1Object nextUpdateObj(tbsCertList.elementAt(4));
      if (nextUpdateObj.getTag() == 0x17) {  // UTCTime
        CASN1UTCTime nextUpdate(nextUpdateObj);
        const ByteDynArray* pNextUpdate = nextUpdate.getValue();
        if (!pNextUpdate || pNextUpdate->size() < 13) return false;

        const BYTE* btNextUpdate =
            pNextUpdate->data() + (pNextUpdate->size() - 13);
        if (memcmp(szRef, btNextUpdate, 13) > 0) return false;  // expired
      }
    }

    return true;
  } catch (const CASN1Exception&) {
    return false;
  } catch (...) {
    return false;
  }
}
