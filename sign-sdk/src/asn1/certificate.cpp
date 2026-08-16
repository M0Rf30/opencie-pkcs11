// SPDX-License-Identifier: LGPL-3.0-or-later
// Certificate.cpp: implementation of the CCertificate class.
#include "asn1/certificate.h"

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sys/types.h>

#include <algorithm>
#include <ctime>
#include <vector>

#include "asn1/crl.h"
#include "asn1_exception.h"
#include "asn1_octet_string.h"
#include "cert_store.h"
#include "crypto/base64.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "digest_info.h"
#include "ldap_crl.h"
#include "ocsp_request.h"

#define MAX_RSA_MODULUS_LEN 512
#define PROXY_AUTHENTICATION_REQUIRED 407

char g_szResolveList[4096] = {0};

static size_t WriteCallback(void* contents, size_t size, size_t nmemb,
                            void* userp);
long HTTPRequest(const ByteDynArray& data, const char* szUrl,
                 const char* szContentType, ByteDynArray& response);

extern char g_szVerifyProxy[MAX_PATH];
extern char* g_szVerifyProxyUsrPass;
extern int g_nVerifyProxyPort;

CCertificate* CCertificate::createCertificate(ByteDynArray& contentArray) {
  const BYTE* content = contentArray.data();
  int len = contentArray.size();

  if (content[0] != 0x30) {  // base64
    std::string encoded(reinterpret_cast<const char*>(content),
                        static_cast<size_t>(len));

    // strip PEM header/footer if present
    auto dash = encoded.find("--");
    if (dash != std::string::npos) {
      auto start = encoded.find('\n', dash);
      auto end = encoded.rfind("\n--");
      if (start != std::string::npos)
        encoded = encoded.substr(start + 1, end != std::string::npos
                                                ? end - (start + 1)
                                                : std::string::npos);
    }

    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                                 [](char c) { return c == '\r' || c == '\n'; }),
                  encoded.end());

    ByteDynArray decoded;
    CBase64().Decode(encoded.c_str(), decoded);

    if (!(decoded.data()[0] == 0x30 && (decoded.data()[1] & 0x80))) {
      throw -6;
    }

    BufferedReader reader(decoded.data(), decoded.size());

    CCertificate* pCert = new CCertificate(reader);

    return pCert;

    return pCert;

  } else {
    BufferedReader reader(const_cast<BYTE*>(content), len);

    return new CCertificate(reader);
  }
}

CCertificate::CCertificate(const BYTE* value, long len)
    : CASN1Sequence(value, len) {}

CCertificate::CCertificate(BufferedReader& reader) : CASN1Sequence(reader) {}

CCertificate::CCertificate(const CASN1Object& cert) : CASN1Sequence(cert) {}

CCertificate::~CCertificate() {}

CCertificateInfo CCertificate::getCertificateInfo() {
  return CCertificateInfo(elementAt(0));
}

CAlgorithmIdentifier CCertificate::getAlgorithmIdentifier() {
  return CAlgorithmIdentifier(elementAt(1));
}

CName CCertificate::getIssuer() { return getCertificateInfo().getIssuer(); }

CName CCertificate::getSubject() { return getCertificateInfo().getSubject(); }

CASN1Integer CCertificate::getSerialNumber() {
  return getCertificateInfo().getSerialNumber();
}

CASN1UTCTime CCertificate::getExpiration() {
  return getCertificateInfo().getExpiration();
}

CASN1UTCTime CCertificate::getFrom() { return getCertificateInfo().getFrom(); }

CASN1Sequence CCertificate::getExtensions() {
  return getCertificateInfo().getExtensions();
}

CASN1Sequence CCertificate::getQCStatements() {
  return getExtension(CASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3"));
}

bool CCertificate::isNonRepudiation() {
  CASN1Sequence keyUsage(getExtension(CASN1ObjectIdentifier("2.5.29.15")));
  int n = keyUsage.size();
  if (n == 0)  // not found
    return false;

  CASN1OctetString octetString(keyUsage.elementAt(n - 1));

  ByteDynArray content;

  // content
  if (octetString.getTag() == 0x24) {  // contructed octet string
    CASN1Sequence contentArray(octetString);
    int size = contentArray.size();
    for (int i = 0; i < size; i++) {
      CASN1OctetString part(contentArray.elementAt(i));
      content.append(ByteArray(part.getValue()->data(), part.getLength()));
    }
  } else {
    content.append(
        ByteArray(octetString.getValue()->data(), octetString.getLength()));
  }

  BufferedReader reader(content);
  CASN1BitString val(reader);

  const ByteDynArray* pVal = val.getValue();
  if (!pVal || pVal->size() < 2) return false;

  const BYTE* pKeyUsageFlags = pVal->data();
  BYTE unusedbits = pKeyUsageFlags[0];
  {
    BYTE flags = pKeyUsageFlags[1];
    if (unusedbits < 7) {
      if ((flags & 0x40) == 0x40)  // non repudiation and digital signature
        return true;
    }
  }

  return false;
}

bool CCertificate::isQualified() {
  if (!isNonRepudiation()) return false;

  CASN1Sequence qcStatement(
      getExtension(CASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3")));
  if (qcStatement.size() == 0)  // not found
    return false;

  return true;
}

bool CCertificate::isSHA256() {
  CAlgorithmIdentifier sha256Algo(szSHA256OID);
  CAlgorithmIdentifier digestAlgo(elementAt(1));
  if (!(digestAlgo.elementAt(0) == sha256Algo.elementAt(0))) return false;

  return true;
}
bool CCertificate::isValid() {
  char szTime[20];
  time_t now = time(nullptr);
  struct tm tmNow;
  strftime(szTime, sizeof(szTime), "%y%m%d%H%M%SZ", gmtime_r(&now, &tmNow));

  return isValid(szTime);
}

bool CCertificate::isValid(const char* szDateTime) {
  if (!szDateTime) return isValid();

  CASN1UTCTime utcnow(szDateTime);

  CASN1UTCTime expiration(getExpiration());

  BYTE* btExpiration;

  if (expiration.getValue()->size() > 13) {
    btExpiration = const_cast<BYTE*>(expiration.getValue()->data()) +
                   expiration.getValue()->size() - 13;
  } else {
    btExpiration = const_cast<BYTE*>(expiration.getValue()->data());
  }

  if (memcmp(utcnow.getValue()->data(), btExpiration, 13) > 0) return false;

  CASN1UTCTime from(getFrom());

  BYTE* btFrom;

  if (from.getValue()->size() > 13) {
    btFrom = const_cast<BYTE*>(from.getValue()->data()) +
             from.getValue()->size() - 13;
  } else {
    btFrom = const_cast<BYTE*>(from.getValue()->data());
  }

  if (memcmp(utcnow.getValue()->data(), btFrom, 13) < 0) return false;

  return true;
}

CASN1Sequence CCertificate::getExtension(const CASN1ObjectIdentifier& oid) {
  CASN1Sequence certExtensions = getExtensions();
  CASN1Sequence extensions(certExtensions.elementAt(0));
  CASN1Sequence requestedExtension;
  int count = extensions.size();
  for (int i = 0; i < count; i++) {
    CASN1Sequence extension(extensions.elementAt(i));
    CASN1ObjectIdentifier extoid(extension.elementAt(0));
    if (extoid.equals(oid)) {
      return extension;
    }
  }

  return requestedExtension;
}

CASN1Sequence CCertificate::getCertificatePolicies() {
  CASN1Sequence certPolicies(
      getExtension(CASN1ObjectIdentifier(szCertificatePolicies)));

  if (certPolicies.size() > 0) {
    CASN1OctetString val(certPolicies.elementAt(1));

    BufferedReader reader(*val.getValue());
    return CASN1Sequence(reader);
  } else {
    return CASN1Sequence();
  }
}

CASN1OctetString CCertificate::getAuthorithyKeyIdentifier() {
  CASN1Sequence keyIdentifier(
      getExtension(CASN1ObjectIdentifier(szAuthorityKeyIdentifier)));

  CASN1OctetString val(keyIdentifier.elementAt(1));

  BufferedReader reader(*val.getValue());
  return CASN1OctetString(reader);
}

CASN1OctetString CCertificate::getSubjectKeyIdentifier() {
  CASN1Sequence keyIdentifier(
      getExtension(CASN1ObjectIdentifier(szSubjectKeyIdentifier)));

  if (keyIdentifier.size() > 0) {
    CASN1OctetString val(keyIdentifier.elementAt(1));
    return val;
  } else {
    CASN1OctetString val("");
    return val;
  }
}

// A.1 OCSP over HTTP
//
// This section describes the formatting that will be done to the
// request and response to support HTTP.
//
// A.1.1 Request
// HTTP based OCSP requests can use either the GET or the POST method to
// submit their requests. To enable HTTP caching, small requests (that
// after encoding are less than 255 bytes), MAY be submitted using GET.
// If HTTP caching is not important, or the request is greater than 255
// bytes, the request SHOULD be submitted using POST.  Where privacy is
// a requirement, OCSP transactions exchanged using HTTP MAY be
// protected using either TLS/SSL or some other lower layer protocol.
//
// An OCSP request using the GET method is constructed as follows:
//
// GET {url}/{url-encoding of base-64 encoding of the DER encoding of
// the OCSPRequest}
//
// where {url} may be derived from the value of AuthorityInfoAccess or
// other local configuration of the OCSP client.
//
// An OCSP request using the POST method is constructed as follows: The
// Content-Type header has the value "application/ocsp-request" while
// the body of the message is the binary value of the DER encoding of
// the OCSPRequest.
//
// A.1.2 Response
// An HTTP-based OCSP response is composed of the appropriate HTTP
// headers, followed by the binary value of the DER encoding of the
// OCSPResponse. The Content-Type header has the value
// "application/ocsp-response". The Content-Length header SHOULD specify
// the length of the response. Other HTTP headers MAY be present and MAY
// be ignored if not understood by the requestor.

namespace {

// Extended Key Usage extension OID (2.5.29.37) and the id-kp-OCSPSigning
// purpose OID (RFC 6960 SS4.2.2.2) that a delegated OCSP responder
// certificate must carry.
constexpr const char* szExtKeyUsageOID = "2.5.29.37";
constexpr const char* szOCSPSigningOID = "1.3.6.1.5.5.7.3.9";

// Returns true if `cert` carries the given Extended Key Usage OID. Mirrors
// the OCTET STRING unwrapping already used by CCertificate::isNonRepudiation.
bool HasExtendedKeyUsage(CCertificate& cert, const char* szOid) {
  CASN1Sequence eku(cert.getExtension(CASN1ObjectIdentifier(szExtKeyUsageOID)));
  int n = eku.size();
  if (n == 0) return false;

  CASN1OctetString octetString(eku.elementAt(n - 1));

  ByteDynArray content;
  if (octetString.getTag() == 0x24) {  // constructed octet string
    CASN1Sequence contentArray(octetString);
    int size = contentArray.size();
    for (int i = 0; i < size; i++) {
      CASN1OctetString part(contentArray.elementAt(i));
      content.append(ByteArray(part.getValue()->data(), part.getLength()));
    }
  } else {
    content.append(
        ByteArray(octetString.getValue()->data(), octetString.getLength()));
  }

  try {
    BufferedReader reader(content);
    CASN1Sequence purposes(reader);
    CASN1ObjectIdentifier target(szOid);
    int count = purposes.size();
    for (int i = 0; i < count; i++) {
      CASN1ObjectIdentifier purpose(purposes.elementAt(i));
      if (purpose.equals(target)) return true;
    }
  } catch (const CASN1Exception&) {
    return false;
  }

  return false;
}

// Verifies that `basicOCSPResponse` (BasicOCSPResponse SEQUENCE, which has
// the same { content, signatureAlgorithm, signature } shape as Certificate)
// is signed either directly by `subject`'s issuer, or by a delegated
// responder certificate embedded in the response that is itself signed by
// the issuer and carries the id-kp-OCSPSigning EKU. Fails closed: a missing
// issuer or any parsing problem yields false.
bool VerifyOCSPResponderSignature(CCertificate& subject,
                                  CASN1Sequence& basicOCSPResponse) {
  CCertificate* pIssuer = CCertStore::GetCertificate(subject);
  if (!pIssuer) return false;

  CCertificate responseAsCert(basicOCSPResponse);
  if (responseAsCert.verifySignature(*pIssuer)) return true;

  if (!basicOCSPResponse.isPresent(3)) return false;

  try {
    CASN1Object certsObj(basicOCSPResponse.elementAt(3));
    if (certsObj.getTag() != 0xA0) return false;  // certs [0] EXPLICIT

    CASN1Sequence certsWrapper(certsObj);
    CASN1Sequence certsSeq(certsWrapper.elementAt(0));

    int nCerts = certsSeq.size();
    for (int i = 0; i < nCerts; i++) {
      CCertificate responderCert(certsSeq.elementAt(i));
      if (responderCert.verifySignature(*pIssuer) &&
          HasExtendedKeyUsage(responderCert, szOCSPSigningOID) &&
          responseAsCert.verifySignature(responderCert)) {
        return true;
      }
    }
  } catch (const CASN1Exception&) {
    return false;
  }

  return false;
}

// Verifies that `certIDObj` (the CertID SEQUENCE from a SingleResponse)
// identifies `subject`: same issuerNameHash/issuerKeyHash/serialNumber this
// SDK would have placed in the OCSP request for it. Only SHA-1 CertIDs are
// supported, matching the only hash algorithm this SDK ever requests with.
bool MatchesCertID(CCertificate& subject, const CASN1Object& certIDObj) {
  try {
    CASN1Sequence certID(certIDObj);
    if (certID.size() < 4) return false;

    CAlgorithmIdentifier hashAlgo(certID.elementAt(0));
    if (!hashAlgo.getOID().equals(CASN1ObjectIdentifier(szSHA1OID)))
      return false;

    ByteDynArray expectedIssuerNameHash;
    ByteDynArray expectedIssuerKeyHash;
    COCSPRequest::ComputeCertID(subject, expectedIssuerNameHash,
                                expectedIssuerKeyHash);

    CASN1OctetString issuerNameHash(certID.elementAt(1));
    CASN1OctetString issuerKeyHash(certID.elementAt(2));
    CASN1Integer serial(certID.elementAt(3));

    const ByteDynArray* pIssuerNameHash = issuerNameHash.getValue();
    if (!pIssuerNameHash ||
        pIssuerNameHash->size() != expectedIssuerNameHash.size() ||
        CRYPTO_memcmp(pIssuerNameHash->data(), expectedIssuerNameHash.data(),
                      expectedIssuerNameHash.size()) != 0)
      return false;

    const ByteDynArray* pIssuerKeyHash = issuerKeyHash.getValue();
    if (!pIssuerKeyHash ||
        pIssuerKeyHash->size() != expectedIssuerKeyHash.size() ||
        CRYPTO_memcmp(pIssuerKeyHash->data(), expectedIssuerKeyHash.data(),
                      expectedIssuerKeyHash.size()) != 0)
      return false;

    if (!(serial == subject.getSerialNumber())) return false;

    return true;
  } catch (const CASN1Exception&) {
    return false;
  }
}

}  // namespace

int CCertificate::verifyStatus(REVOCATION_INFO* pRevocationInfo) {
  return verifyStatus(nullptr, pRevocationInfo);
}

int CCertificate::verifyStatus(const char* szTime,
                               REVOCATION_INFO* pRevocationInfo) {
  LOG_DBG((0, "--> CCertificate::verifyStatus", "Time: %s", szTime));

  int status = REVOCATION_STATUS_UNKNOWN;

  CASN1Integer serialNumber(getSerialNumber());

  try {
    // check for OCSP presence
    CASN1Sequence ocsp(
        getExtension(CASN1ObjectIdentifier(szAuthorityInfoAccess)));
    if (ocsp.size() == 0) throw 1L;

    CASN1OctetString val(ocsp.elementAt(1));
    ByteDynArray* pbaVal = const_cast<ByteDynArray*>(val.getValue());
    BufferedReader reader(*pbaVal);

    CASN1Sequence authorityInfoAccess(reader);

    // AuthorityInfoAccessSyntax  ::=
    // SEQUENCE SIZE (1..MAX) OF AccessDescription
    //
    // AccessDescription  ::=  SEQUENCE {
    // accessMethod          OBJECT IDENTIFIER,
    // accessLocation        GeneralName  }

    // find the OCSP method
    CASN1ObjectIdentifier oid(szMethodOCSP);
    int size = authorityInfoAccess.size();
    for (int i = 0; i < size; i++) {
      CASN1Sequence accessDescription(authorityInfoAccess.elementAt(i));

      if (oid.equals(CASN1ObjectIdentifier(accessDescription.elementAt(0)))) {
        LOG_DBG((0, "CCertificate::verifyStatus", "createOCSP request"));

        CASN1Object accessLocation(accessDescription.elementAt(1));
        ByteDynArray* pValue =
            const_cast<ByteDynArray*>(accessLocation.getValue());
        pValue->push(static_cast<BYTE>('\0'));

        LOG_DBG((0, "CCertificate::verifyStatus", "OCSP Url: %s",
                 reinterpret_cast<const char*>(pValue->data())));

        // prepare the OCSP request
        COCSPRequest ocspRequest(*this);
        ByteDynArray baOcspRequest;
        ocspRequest.toByteArray(baOcspRequest);
        LOG_DBG((0, "CCertificate::verifyStatus", "POST OCSP Request"));

        ByteDynArray response;
        long nRet = HTTPRequest(baOcspRequest,
                                reinterpret_cast<const char*>(pValue->data()),
                                "application/ocsp-request", response);
        if (nRet) {
          LOG_ERR((0, "CCertificate::verifyStatus",
                   "OCSP not available. Error: %x", nRet));
        }

        if (response.size() == 0) {
          LOG_ERR((0, "CCertificate::verifyStatus", "Empty OCSP response"));
          throw -1;
        }

        LOG_DBG((0, "CCertificate::verifyStatus", "OCSP OK"));

        // response data goes into an OCSPResponse object
        {
          BufferedReader reader2(response);
          CASN1Sequence ocspResponse(reader2);

          CASN1Integer responseStatus(ocspResponse.elementAt(0));

          int inner_status = responseStatus.getIntValue();
          LOG_DBG((0, "CCertificate::verifyStatus", "OCSP responseStatus: %d",
                   inner_status));
          if (inner_status == 0) {  // successfull
            CASN1Sequence responseBytes1(ocspResponse.elementAt(1));
            CASN1Sequence responseBytes(responseBytes1.elementAt(0));

            CASN1ObjectIdentifier responseType(responseBytes.elementAt(0));
            CASN1OctetString inner_response(responseBytes.elementAt(1));

            const ByteDynArray* pVal = inner_response.getValue();

            BufferedReader reader3(*pVal);
            CASN1Sequence basicOCSPResponse(reader3);

            CASN1Sequence responseData(basicOCSPResponse.elementAt(0));

            CASN1Sequence responses(responseData.elementAt(2));

            CASN1Sequence singleResponse(responses.elementAt(0));

            // Fail closed: never consult certStatus before the responder's
            // signature and the CertID binding have been verified.
            if (!VerifyOCSPResponderSignature(*this, basicOCSPResponse)) {
              LOG_ERR((0, "CCertificate::verifyStatus",
                       "OCSP response signature could not be verified "
                       "against the issuer or a delegated responder; "
                       "ignoring response"));
              throw CASN1BadObjectIdException(
                  "OCSP responder signature invalid");
            }

            if (!MatchesCertID(*this, singleResponse.elementAt(0))) {
              LOG_ERR((0, "CCertificate::verifyStatus",
                       "OCSP response CertID does not match the certificate "
                       "under test; ignoring response"));
              throw CASN1BadObjectIdException("OCSP response CertID mismatch");
            }

            CASN1Object certStatus(singleResponse.elementAt(1));
            CASN1UTCTime thisUpdate(singleResponse.elementAt(2));

            if (pRevocationInfo) {
              pRevocationInfo->nType = TYPE_OCSP;
              thisUpdate.getUTCTime(pRevocationInfo->szThisUpdate);
            }

            BYTE tag = certStatus.getTag();

            LOG_DBG((0, "CCertificate::verifyStatus", "certStatus: %d", tag));

            switch (tag & 0x0F) {
              case 0:
                // good
                LOG_DBG((0, "CCertificate::verifyStatus", "Status GOOD"));
                inner_status = REVOCATION_STATUS_GOOD;
                if (pRevocationInfo)
                  pRevocationInfo->nRevocationStatus = REVOCATION_STATUS_GOOD;
                break;

              case 1:
                // revoked

                // check CRLReason
                {
                  CASN1Sequence clrReason(certStatus);

                  try {
                    // check date against revocation time
                    CASN1Object revocationTime(clrReason.elementAt(0));

                    BYTE* btRevocationTime;

                    if (revocationTime.getValue()->size() > 13) {
                      btRevocationTime =
                          const_cast<BYTE*>(revocationTime.getValue()->data()) +
                          revocationTime.getValue()->size() - 13;
                    } else if (revocationTime.getValue()->size() == 13) {
                      btRevocationTime =
                          const_cast<BYTE*>(revocationTime.getValue()->data());
                    } else {
                      throw CASN1ParsingException();
                    }

                    if (pRevocationInfo) {
                      memcpy(pRevocationInfo->szRevocationDate,
                             btRevocationTime, 13);
                      pRevocationInfo->szRevocationDate[13] = 0;
                    }

                    if (szTime != nullptr)
                      if (memcmp(szTime, btRevocationTime, 13) < 0) {
                        if (pRevocationInfo)
                          pRevocationInfo->nRevocationStatus =
                              REVOCATION_STATUS_GOOD;
                        return REVOCATION_STATUS_GOOD;
                      }

                    CASN1OctetString reasonCode(clrReason.elementAt(1));
                    const ByteDynArray* pVal2 = reasonCode.getValue();
                    if (!pVal2 || pVal2->size() < 3) {
                      throw CASN1ParsingException();
                    }

                    BYTE reason =
                        pVal2->data()[2];  // reasonCode.getTag() & 0x0F;
                    if (reason == 6) {     // Certificate HOLD
                      LOG_DBG((0, "CCertificate::verifyStatus",
                               "Status SUSPENDED"));
                      inner_status = REVOCATION_STATUS_SUSPENDED;
                    } else {
                      LOG_DBG(
                          (0, "CCertificate::verifyStatus", "Status REVOKED"));
                      inner_status = REVOCATION_STATUS_REVOKED;
                    }
                    if (pRevocationInfo)
                      pRevocationInfo->nRevocationStatus = inner_status;
                  } catch (const CASN1Exception&) {
                    LOG_DBG((0, "CCertificate::verifyStatus",
                             "Unexpected Exception"));
                    inner_status = REVOCATION_STATUS_REVOKED;
                  }
                }
                break;

              case 2:
                // unknown
                LOG_DBG((0, "CCertificate::verifyStatus", "Status UNKNONWN"));
                inner_status = REVOCATION_STATUS_UNKNOWN;
                break;

              default:
                break;
            }

            if (inner_status != REVOCATION_STATUS_UNKNOWN) return inner_status;
          }
        }
      }
    }
  } catch (const CASN1Exception&) {
    LOG_ERR((0, "CCertificate::verifyStatus", "Unexpected ASN1 Exception"));
  } catch (long r) {
    LOG_MSG((0, "CCertificate::verifyStatus",
             "authorityInfoAccess OCSP not present. Error: %x", r));
  } catch (...) {
    LOG_ERR((0, "CCertificate::verifyStatus", "Unexpected Exception"));
  }

  try {
    // char* sz;

    LOG_DBG((0, "CCertificate::verifyStatus", "Try CRL"));

    // verify the CRL
    CASN1Sequence crlDP1(
        getExtension(CASN1ObjectIdentifier(szCrlDistributionPointsOID)));
    CASN1OctetString crlDPValue(crlDP1.elementAt(1));

    BufferedReader reader(*(crlDPValue.getValue()));

    CASN1Sequence crlDP(reader);

    int size = crlDP.size();
    if (size > 0) {
      for (int i = 0; i < size; i++) {
        CASN1Sequence dp(crlDP.elementAt(i));

        CASN1Sequence distributionPointName(dp.elementAt(0));

        CASN1Sequence fullName(distributionPointName.elementAt(0));

        CASN1Object name3(fullName.elementAt(0));

        ByteDynArray* pValue = const_cast<ByteDynArray*>(name3.getValue());

        pValue->push(static_cast<BYTE>('\0'));

        const char* szcrlurl = reinterpret_cast<const char*>(pValue->data());

        LOG_DBG((0, "CCertificate::verifyStatus", "CRL Url: %s", szcrlurl));

        ByteDynArray response;
        ByteDynArray data;
        long nRet = HTTPRequest(data, szcrlurl, nullptr, response);
        if (nRet) {
          LOG_ERR((0, "CCertificate::verifyStatus",
                   "CRL not available. Error: %x", nRet));
          return REVOCATION_STATUS_NOTLOADED;
        } else {
          LOG_DBG((0, "CCertificate::verifyStatus", "CRL OK, nRet: %d", nRet));
        }

        if (response.size() > 0) {
          BufferedReader reader4(response.data(), response.size());
          CCrl crl(reader4);

          // Fail closed: never consult revokedCertificates before the CRL
          // is confirmed to be signed by the issuing CA and current.
          CCertificate* pCRLIssuer = CCertStore::GetCertificate(*this);
          if (!pCRLIssuer) {
            LOG_ERR((0, "CCertificate::verifyStatus",
                     "CRL issuer certificate not found; cannot verify CRL"));
            return REVOCATION_STATUS_NOTLOADED;
          }

          if (!crl.verifySignature(*pCRLIssuer)) {
            LOG_ERR((0, "CCertificate::verifyStatus",
                     "CRL signature verification failed; rejecting CRL"));
            return REVOCATION_STATUS_NOTLOADED;
          }

          if (!crl.isCurrent(szTime)) {
            LOG_ERR((0, "CCertificate::verifyStatus",
                     "CRL is not current (expired or not yet valid); "
                     "rejecting CRL"));
            return REVOCATION_STATUS_NOTLOADED;
          }

          int revstatus = 0;
          if (!crl.isRevoked(serialNumber, szTime, &revstatus,
                             pRevocationInfo)) {
            LOG_MSG((0, "CCertificate::verifyStatus", "Cert Status: GOOD: %d",
                     revstatus));
            status = REVOCATION_STATUS_GOOD;
          } else {
            LOG_MSG((0, "CCertificate::verifyStatus",
                     "Cert Status: REVOKED: %d", revstatus));
            status = REVOCATION_STATUS_REVOKED;
          }
        } else {
          LOG_ERR((0, "CCertificate::verifyStatus", "CRL Empty"));
          return REVOCATION_STATUS_NOTLOADED;
        }
      }
    }
  } catch (const CASN1Exception&) {
    LOG_ERR((0, "CCertificate::verifyStatus", "Unexpected ASN1 Exception"));
  } catch (...) {
    LOG_ERR((0, "CCertificate::verifyStatus", "Unexpected Exception"));
  }

  LOG_DBG((0, "<-- CCertificate::verifyStatus", "exit"));

  return status;
}

int CCertificate::verify() {
  int bitmask = 0;

  // verify the certificate chain
  CCertificate* pCert = this;
  CCertificate* pCACert = CCertStore::GetCertificate(*pCert);
  while (pCACert && pCert->verifySignature(*pCACert)) {
    bitmask |= VERIFIED_CACERT_FOUND;
    pCert = pCACert;
    pCACert = CCertStore::GetCertificate(*pCACert);
  }

  // pCACert becomes null both when a self-signed trust anchor matched
  // itself in the store and when the issuer of pCert simply could not be
  // found. Only the former is a validated chain; fail closed otherwise.
  if (!pCACert && (bitmask & VERIFIED_CACERT_FOUND) &&
      pCert->getIssuer() == pCert->getSubject() &&
      pCert->verifySignature(*pCert)) {
    bitmask |= VERIFIED_CERT_CHAIN;
  }

  return bitmask;
}

bool CCertificate::verifySignature(CCertificate& cert) {
  // OpenSSL
  ByteDynArray baCert;
  cert.toByteArray(baCert);

  X509* x509 = nullptr;

  const BYTE* content = baCert.data();
  x509 = d2i_X509(nullptr, &content, baCert.size());

  EVP_PKEY* evp_pubkey;

  evp_pubkey = X509_get_pubkey(x509);

  CASN1BitString encryptedDigest(elementAt(2));
  const ByteDynArray* pEncryptedDigest = encryptedDigest.getValue();
  if (!pEncryptedDigest || pEncryptedDigest->size() < 2 ||
      pEncryptedDigest->data()[0] != 0) {
    EVP_PKEY_free(evp_pubkey);
    X509_free(x509);
    return false;
  }
  ByteDynArray encDigest(pEncryptedDigest->mid(1));

  BYTE decrypted[MAX_RSA_MODULUS_LEN];
  unsigned int len = MAX_RSA_MODULUS_LEN;

  {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(evp_pubkey, nullptr);
    if (pctx && EVP_PKEY_verify_recover_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) > 0) {
      const BYTE* encrypted = encDigest.data();
      const int encrypted_len = static_cast<int>(encDigest.size());
      size_t outlen = MAX_RSA_MODULUS_LEN;
      if (EVP_PKEY_verify_recover(pctx, decrypted, &outlen, encrypted,
                                  encrypted_len) > 0) {
        len = static_cast<unsigned int>(outlen);
      } else {
        len = 0;
      }
    } else {
      len = 0;
    }
    EVP_PKEY_CTX_free(pctx);
  }

  EVP_PKEY_free(evp_pubkey);
  X509_free(x509);

  if (len) {
    try {
      BufferedReader reader(decrypted, len);
      CDigestInfo digestInfo(reader);

      // EVP_PKEY_verify_recover only strips the PKCS#1 v1.5 padding
      // (00 01 FF..FF 00); nothing otherwise checks that the DigestInfo
      // SEQUENCE consumed the whole recovered block. An attacker could
      // shorten the FF run and append arbitrary trailing bytes after a
      // valid DigestInfo, so require exact consumption here.
      if (reader.getPosition() != len) {
        return false;
      }

      // Cross-check the recovered signature's digest algorithm against
      // the algorithm declared in the certificate's own signatureAlgorithm
      // field; without this a signature computed with one hash could be
      // reinterpreted under a different declared algorithm.
      CAlgorithmIdentifier digestAlgo(digestInfo.getDigestAlgorithm());
      CAlgorithmIdentifier declaredSigAlgo(elementAt(1));
      if (digestAlgo.elementAt(0) != declaredSigAlgo.elementAt(0)) {
        return false;
      }

      CASN1OctetString digest = digestInfo.getDigest();
      ByteDynArray* pDigestValue = const_cast<ByteDynArray*>(digest.getValue());

      // content
      ByteDynArray content2;
      getCertificateInfo().toByteArray(content2);

      BYTE* buff;
      int bufflen = 0;

      buff = const_cast<BYTE*>(content2.data());
      bufflen = content2.size();

      CAlgorithmIdentifier sha256Algo(szSHA256OID);
      CAlgorithmIdentifier sha1Algo(szSHA1OID);
      if (digestAlgo.elementAt(0) == sha256Algo.elementAt(0)) {
        ByteDynArray hash = CSHA256::Digest(ByteArray(buff, bufflen));

        if (hash.size() == SHA256_DIGEST_LENGTH &&
            pDigestValue->size() == SHA256_DIGEST_LENGTH &&
            CRYPTO_memcmp(hash.data(), pDigestValue->data(),
                          SHA256_DIGEST_LENGTH) == 0) {
          return true;
        }

      } else if (digestAlgo.elementAt(0) == sha1Algo.elementAt(0)) {
        ByteDynArray hash = CSHA1().Digest(ByteArray(buff, bufflen));

        if (hash.size() == SHA_DIGEST_LENGTH &&
            pDigestValue->size() == SHA_DIGEST_LENGTH &&
            CRYPTO_memcmp(hash.data(), pDigestValue->data(),
                          SHA_DIGEST_LENGTH) == 0) {
          return true;
        }
      }
    } catch (const CASN1Exception&) {
      return false;
    } catch (...) {
      return false;
    }
  }

  return false;
}

long HTTPRequest(const ByteDynArray& data, const char* szUrl,
                 const char* szContentType, ByteDynArray& response) {
#ifdef __ANDROID__
  if (!g_szResolveList[0]) {
    snprintf(g_szResolveList, sizeof(g_szResolveList),
             "ocsp.cie.interno.gov.it:443:2.42.225.135"
             ",ldap.cie.interno.gov.it:80:2.42.225.136");
  }
#endif
  // general initilization
  curl_global_init(CURL_GLOBAL_DEFAULT);

  CURL* ctx = curl_easy_init();

  // set URL
  curl_easy_setopt(ctx, CURLOPT_URL, szUrl);

  // TLS server certificate verification is intentionally left at libcurl's
  // secure defaults (CURLOPT_SSL_VERIFYPEER/VERIFYHOST enabled).

#ifdef __ANDROID__
  curl_easy_setopt(ctx, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(ctx, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
  // vcpkg-built curl+OpenSSL has no baked-in CA bundle on Android: point it
  // at the system CA store (OpenSSL hashed-dir format) so verification works.
  curl_easy_setopt(ctx, CURLOPT_CAPATH, "/system/etc/security/cacerts");
#endif

  struct curl_slist* resolve_list = nullptr;
  if (g_szResolveList[0]) {
    const char* p = strstr(szUrl, "://");
    if (p) {
      p += 3;
      const char* end = p;
      while (*end && *end != '/' && *end != ':') ++end;
      size_t hlen = static_cast<size_t>(end - p);
      if (hlen > 0 && hlen < 256) {
        char hostname[256];
        memcpy(hostname, p, hlen);
        hostname[hlen] = '\0';
        int port = (strncmp(szUrl, "https://", 8) == 0) ? 443 : 80;
        if (*end == ':') port = static_cast<int>(strtol(end + 1, nullptr, 10));
        const char* entry = g_szResolveList;
        while (*entry) {
          const char* comma = strchr(entry, ',');
          size_t elen =
              comma ? static_cast<size_t>(comma - entry) : strlen(entry);
          const char* colon1 =
              static_cast<const char*>(memchr(entry, ':', elen));
          if (colon1) {
            size_t ehost_len = static_cast<size_t>(colon1 - entry);
            if (ehost_len == hlen && strncmp(entry, hostname, hlen) == 0) {
              const char* colon2 = strchr(colon1 + 1, ':');
              if (colon2) {
                int eport = static_cast<int>(strtol(colon1 + 1, nullptr, 10));
                if (eport == port) {
                  char buf[512];
                  snprintf(buf, sizeof(buf), "%.*s", static_cast<int>(elen),
                           entry);
                  LOG_ERR((0, "HTTPRequest", "using resolve: %s", buf));
                  resolve_list = curl_slist_append(resolve_list, buf);
                }
              }
            }
          }
          if (!comma) break;
          entry = comma + 1;
        }
        if (resolve_list)
          curl_easy_setopt(ctx, CURLOPT_RESOLVE, resolve_list);
        else
          LOG_ERR(
              (0, "HTTPRequest", "no resolve entry for %s:%d", hostname, port));
      }
    }
  }

  if (data.size() > 0) {
    // set POST method
    curl_easy_setopt(ctx, CURLOPT_POST, 1);

    // give the data you want to post
    curl_easy_setopt(ctx, CURLOPT_POSTFIELDS, data.data());
    LOG_ERR((0, "HTTPRequest", "POST data content: %s", data.data()));
    // give the data lenght
    curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE, data.size());
  }

  if (g_nVerifyProxyPort != -1) {
    LOG_MSG((0, "HTTPRequest", "Proxy: %s, %d", g_szVerifyProxy,
             g_nVerifyProxyPort));

    // set the proxy
    curl_easy_setopt(ctx, CURLOPT_PROXY, g_szVerifyProxy);

    // set the proxy type
    curl_easy_setopt(ctx, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);

    if (g_nVerifyProxyPort != 0) {
      LOG_MSG((0, "HTTPRequest", "Proxy Port: %d", g_nVerifyProxyPort));

      curl_easy_setopt(ctx, CURLOPT_PROXYPORT, g_nVerifyProxyPort);
    }

    if (g_szVerifyProxyUsrPass != nullptr) {
      LOG_MSG((0, "HTTPRequest", "Proxy UserPass: %s", g_szVerifyProxyUsrPass));
      curl_easy_setopt(ctx, CURLOPT_PROXYUSERPWD, g_szVerifyProxyUsrPass);
    }
  }

  // set the callback function that handle the data return from server
  // if you don't set this, the return data just show up on the screen
  // size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
  curl_easy_setopt(ctx, CURLOPT_WRITEFUNCTION, WriteCallback);

  // we pass our 'chunk' struct to the callback function
  curl_easy_setopt(ctx, CURLOPT_WRITEDATA, static_cast<void*>(&response));

  struct curl_slist* headers = nullptr;

  if (szContentType) {
    char szAux[256];
    snprintf(szAux, sizeof(szAux), "Content-Type: %s", szContentType);

    headers = curl_slist_append(headers, szAux);

    curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers);
  }

  // let's do it...
  CURLcode ret = curl_easy_perform(ctx);

  LONG responseCode;

  /* Check for errors */
  if (ret != CURLE_OK) {
    LOG_ERR((0, "HTTPRequest", "Unable to connect to: %s", szUrl));
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(ctx);
    return ret;
  }

  curl_easy_getinfo(ctx, CURLINFO_RESPONSE_CODE, &responseCode);

  LOG_ERR((0, "HTTPRequest", "HttpCode: %d", responseCode));

  if (responseCode == PROXY_AUTHENTICATION_REQUIRED) {
    LOG_ERR((0, "HTTPRequest",
             "Unable to connect to: %s. Proxy authentication required", szUrl));
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(ctx);
    return responseCode;
  }

  LOG_ERR((0, "HTTPRequest", "connect to: %s OK", szUrl));

  // clean up
  if (headers) curl_slist_free_all(headers);
  if (resolve_list) curl_slist_free_all(resolve_list);
  curl_easy_cleanup(ctx);

  if (response.size() == 0) {
    LOG_ERR((0, "<-- HTTPRequest", "empty response"));
    return -1;
  }

  return 0;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb,
                            void* userp) {
  ByteDynArray* pResponse = static_cast<ByteDynArray*>(userp);
  size_t realsize = size * nmemb;
  pResponse->append(ByteArray(static_cast<BYTE*>(contents), realsize));

  return realsize;
}
