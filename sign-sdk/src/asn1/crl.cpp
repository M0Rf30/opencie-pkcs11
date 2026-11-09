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

  // TBSCertList ::= SEQUENCE { version INTEGER OPTIONAL, signature,
  // issuer, thisUpdate, nextUpdate Time OPTIONAL, revokedCertificates
  // SEQUENCE OPTIONAL, crlExtensions [0] OPTIONAL }: locate the fields
  // instead of assuming a v2 CRL that carries nextUpdate.
  size_t idx = 0;
  if (tbsCertList.size() > 0 && tbsCertList.elementAt(0).getTag() == 0x02)
    idx++;
  const size_t thisUpdateIdx = idx + 2;
  if (tbsCertList.size() <= thisUpdateIdx)
    throw logged_error("CCrl::isRevoked: malformed TBSCertList");

  if (pRevocationInfo) {
    CASN1UTCTime thisUpdate = CASN1UTCTime(tbsCertList.elementAt(thisUpdateIdx));
    thisUpdate.getUTCTime(pRevocationInfo->szThisUpdate);
  }

  size_t nextIdx = thisUpdateIdx + 1;
  if (nextIdx < tbsCertList.size()) {
    const BYTE tag = tbsCertList.elementAt(nextIdx).getTag();
    if (tag == 0x17 || tag == 0x18) nextIdx++;
  }

  CASN1Sequence revokedCertificates;
  if (nextIdx < tbsCertList.size() &&
      tbsCertList.elementAt(nextIdx).getTag() == 0x30)
    revokedCertificates = CASN1Sequence(tbsCertList.elementAt(nextIdx));
  int count = revokedCertificates.size();
  if (count > 0) {
    for (int i = 0; i < count; i++) {
      CASN1Sequence revokedCertificate =
          CASN1Sequence(revokedCertificates.elementAt(i));

      CASN1Integer sn(revokedCertificate.elementAt(0));

      if (serialNumber == sn) {
        CASN1Object revocationDate(revokedCertificate.elementAt(1));

        BYTE* btRevocationDate;

        if (revocationDate.getValue()->size() < 13)
          throw logged_error("CCrl::isRevoked: malformed revocationDate");

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
          if (pVal->size() < 3)
            throw logged_error("CCrl::isRevoked: malformed reasonCode");

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
    if (!FormatUtcTime(now, szNow, sizeof(szNow))) return false;
    szRef = szNow;
  }

  try {
    CASN1Sequence tbsCertList(elementAt(0));

    // Skip the optional version, then signature and issuer.
    size_t idx = 0;
    if (tbsCertList.size() > 0 && tbsCertList.elementAt(0).getTag() == 0x02)
      idx++;
    if (tbsCertList.size() <= idx + 2) return false;

    CASN1UTCTime thisUpdate(tbsCertList.elementAt(idx + 2));
    const ByteDynArray* pThisUpdate = thisUpdate.getValue();
    if (!pThisUpdate || pThisUpdate->size() < 13) return false;

    const BYTE* btThisUpdate = pThisUpdate->data() + (pThisUpdate->size() - 13);
    if (memcmp(szRef, btThisUpdate, 13) < 0) return false;  // not yet valid

    if (tbsCertList.isPresent(idx + 3)) {
      CASN1Object nextUpdateObj(tbsCertList.elementAt(idx + 3));
      const BYTE nextTag = nextUpdateObj.getTag();
      if (nextTag == 0x17 || nextTag == 0x18) {  // UTCTime / GeneralizedTime
        // The last 13 bytes of both forms are YYMMDDHHMMSSZ.
        const ByteDynArray* pNextUpdate = nextUpdateObj.getValue();
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
