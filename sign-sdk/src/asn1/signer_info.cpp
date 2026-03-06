#include "signer_info.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/types.h>

#include <cstdio>

#include "asn1/asn1_set_of.h"
#include "asn1/certificate.h"
#include "asn1_optional_field.h"
#include "cert_store.h"
#include "digest_info.h"
#include "util/util.h"

CSignerInfo::~CSignerInfo() {}

CSignerInfo::CSignerInfo(BufferedReader& reader) : CASN1Sequence(reader) {}

CSignerInfo::CSignerInfo(const CASN1Object& signerInfo)
    : CASN1Sequence(signerInfo) {}

CSignerInfo::CSignerInfo(const CIssuerAndSerialNumber& issuer,
                         const CAlgorithmIdentifier& digestAlgo,
                         const CAlgorithmIdentifier& encAlgo,
                         const CASN1OctetString& encDigest) {
  addElement(CASN1Integer(1));
  addElement(issuer);
  addElement(digestAlgo);
  addElement(encAlgo);
  addElement(encDigest);
}

void CSignerInfo::addAuthenticatedAttributes(const CASN1SetOf& attributes) {
  addElementAt(CASN1OptionalField(attributes, 0x00), 3);
}

void CSignerInfo::addUnauthenticatedAttributes(const CASN1SetOf& attributes) {
  if (size() < 7)
    addElement(CASN1OptionalField(attributes, 0x01));
  else
    setElementAt(CASN1OptionalField(attributes, 0x01), 6);
}

CASN1OctetString CSignerInfo::getEncryptedDigest() {
  CASN1Object obj(elementAt(3));

  if (obj.getTag() == 0xA0) {  // optional auth attributes present
    return CASN1OctetString(elementAt(5));
  } else {
    return CASN1OctetString(elementAt(4));
  }
}

CAlgorithmIdentifier CSignerInfo::getDigestAlgorithn() {
  return CAlgorithmIdentifier(elementAt(2));
}

CIssuerAndSerialNumber CSignerInfo::getIssuerAndSerialNumber() {
  return CIssuerAndSerialNumber(elementAt(1));
}

CASN1SetOf CSignerInfo::getAuthenticatedAttributes() {
  CASN1Object obj(elementAt(3));

  if (obj.getTag() == 0xA0) {  // optional auth attributes present
    return obj;
  } else {
    CASN1SetOf empty;
    return empty;
  }
}

CASN1SetOf CSignerInfo::getUnauthenticatedAttributes() {
  if (size() > 6) {
    CASN1Object obj(elementAt(3));

    if (obj.getTag() == 0xA0)  // optional auth attributes present
      return elementAt(6);
    else
      return elementAt(5);
  } else {
    return CASN1SetOf();
  }
}

CASN1UTCTime CSignerInfo::getSigningTime() {
  CASN1SetOf attrs = getAuthenticatedAttributes();

  int size = attrs.size();
  for (int j = 0; j < size; j++) {
    CASN1Sequence attr = attrs.elementAt(j);
    CASN1ObjectIdentifier objId(attr.elementAt(0));
    if (objId.equals(CASN1ObjectIdentifier(szSigningTimeOID)))
      return (CASN1SetOf(attr.elementAt(1))).elementAt(0);
  }

  throw -1L;
}

CASN1OctetString CSignerInfo::getContentHash() {
  CASN1SetOf attrs = getAuthenticatedAttributes();
  int size = attrs.size();
  for (int j = 0; j < size; j++) {
    CASN1Sequence attr = attrs.elementAt(j);
    CASN1ObjectIdentifier objId(attr.elementAt(0));
    if (objId.equals(CASN1ObjectIdentifier(szMessageDigestOID)))
      return (CASN1SetOf(attr.elementAt(1))).elementAt(0);
  }

  throw -1L;
}

CTimeStampToken CSignerInfo::getTimeStampToken() {
  CASN1SetOf attributes = getUnauthenticatedAttributes();
  CASN1ObjectIdentifier oidTimestampToken(szTimestampTokenOID);

  // search for timestamp oid
  int nSize = attributes.size();
  for (int i = 0; i < nSize; i++) {
    CASN1Sequence attribute = attributes.elementAt(i);
    CASN1ObjectIdentifier oid = attribute.elementAt(0);

    if (oid.equals(oidTimestampToken)) {
      CASN1SetOf values(attribute.elementAt(1));
      return values.elementAt(0);
    }
  }

  return CTimeStampToken(CASN1Sequence());
}

bool CSignerInfo::hasTimeStampToken() {
  CASN1SetOf tst = getTimeStampToken();
  return tst.size() > 0;
}

CASN1SetOf CSignerInfo::getCountersignatures() {
  CASN1SetOf counterSignatures;
  CASN1SetOf attributes = getUnauthenticatedAttributes();
  CASN1ObjectIdentifier oid(szCounterSignatureOID);

  // search for countersignature oid
  int nSize = attributes.size();
  for (int i = 0; i < nSize; i++) {
    CASN1Sequence attribute = attributes.elementAt(i);
    CASN1ObjectIdentifier oid1 = attribute.elementAt(0);

    if (oid.equals(oid1)) {
      CASN1SetOf set(attribute.elementAt(1));
      counterSignatures.addElement(set.elementAt(0));
    }
  }

  return counterSignatures;
}

void CSignerInfo::setCountersignatures(int index,
                                       CSignerInfo& countersignature) {
  CASN1SetOf attributes = getUnauthenticatedAttributes();
  CASN1ObjectIdentifier oid(szCounterSignatureOID);
  int counter = 0;
  // search for countersignature oid
  int nSize = attributes.size();
  for (int i = 0; i < nSize; i++) {
    CASN1Sequence attribute = attributes.elementAt(i);
    CASN1ObjectIdentifier oid1 = attribute.elementAt(0);

    if (oid.equals(oid1)) {
      if (counter == index) {
        CASN1Sequence v;
        v.addElement(oid);
        CASN1SetOf cs;
        cs.addElement(countersignature);
        v.addElement(cs);

        attributes.setElementAt(v, i);

        addUnauthenticatedAttributes(attributes);
        return;
      }

      counter++;
    }
  }
}

void CSignerInfo::addCountersignatures(CSignerInfo& countersignature) {
  CASN1SetOf attributes = getUnauthenticatedAttributes();
  CASN1ObjectIdentifier oid(szCounterSignatureOID);

  CASN1Sequence v;
  v.addElement(oid);
  CASN1SetOf cs;
  cs.addElement(countersignature);
  v.addElement(cs);
  attributes.addElement(v);

  addUnauthenticatedAttributes(attributes);
}

void CSignerInfo::setTimeStampToken(CTimeStampToken& tst) {
  CASN1SetOf attributes = getUnauthenticatedAttributes();
  CASN1ObjectIdentifier oid(szTimestampTokenOID);

  CASN1Sequence v;
  v.addElement(oid);
  CASN1SetOf cs;
  cs.addElement(tst);
  v.addElement(cs);
  attributes.addElement(v);

  addUnauthenticatedAttributes(attributes);
}

int CSignerInfo::getCountersignatureCount() {
  CASN1SetOf countersignatures(getCountersignatures());
  return countersignatures.size();
}

int CSignerInfo::verifyCountersignature(int i, CASN1SetOf& certificates) {
  return verifyCountersignature(i, certificates, nullptr, nullptr);
}

int CSignerInfo::verifyCountersignature(int i, CASN1SetOf& certificates,
                                        const char* szDateTime,
                                        REVOCATION_INFO* pRevocationInfo) {
  CASN1SetOf countersignatures(getCountersignatures());
  CSignerInfo countersignature(countersignatures.elementAt(i));
  CASN1OctetString source(getEncryptedDigest());
  return verifySignature(source, countersignature, certificates, szDateTime,
                         pRevocationInfo);
}

int CSignerInfo::verifySignature(CASN1OctetString& source,
                                 CSignerInfo& signerInfo,
                                 CASN1SetOf& certificates,
                                 const char* szDateTime,
                                 REVOCATION_INFO* pRevocationInfo) {
  LOG_DBG((0, "--> CSignerInfo::verifySignature", "Verify Revocation: %d",
           (pRevocationInfo != nullptr)));

  CCertificate cert = getSignatureCertificate(signerInfo, certificates);

  int bitmask = 0;

  // verifica il certificato
  if (cert.isValid(szDateTime)) {
    bitmask |= VERIFIED_CERT_VALIDITY;
  }

  if (cert.isQualified()) {
    bitmask |= VERIFIED_CERT_QUALIFIED;
  }

  if (cert.isNonRepudiation()) {
    bitmask |= VERIFIED_KEY_USAGE;
  }

  if (cert.isSHA256()) {
    bitmask |= VERIFIED_CERT_SHA256;
  }

  if (pRevocationInfo) {
    pRevocationInfo->nRevocationStatus = REVOCATION_STATUS_UNKNOWN;

    // verify revocation status only if the certificate is valid
    if (bitmask & VERIFIED_CERT_VALIDITY) {
      int verifyStatus = cert.verifyStatus(szDateTime, pRevocationInfo);

      switch (verifyStatus) {
        case REVOCATION_STATUS_GOOD:
          bitmask |= VERIFIED_CERT_GOOD;
          bitmask |= VERIFIED_CRL_LOADED;
          break;

        case REVOCATION_STATUS_REVOKED:
          bitmask |= VERIFIED_CRL_LOADED;
          bitmask |= VERIFIED_CERT_REVOKED;
          break;

        case REVOCATION_STATUS_SUSPENDED:
          bitmask |= VERIFIED_CERT_SUSPENDED;
          bitmask |= VERIFIED_CRL_LOADED;
          break;

        case REVOCATION_STATUS_UNKNOWN:
          bitmask |= VERIFIED_CRL_LOADED;
          break;

        default:
          break;
      }
    }
  }

  // verifica la cert chain
  //	CName issuerName(cert.getIssuer());
  //	ByteDynArray issuer;
  //	issuerName.getNameAsString(issuer);//getField(OID_COMMON_NAME);
  //
  CCertificate* pCert = &cert;
  CCertificate* pCACert = CCertStore::GetCertificate(cert);
  while (pCACert && pCert->verifySignature(*pCACert)) {
    bitmask |= VERIFIED_CACERT_FOUND;

    if (pCACert->isValid(szDateTime)) {
      bitmask |= VERIFIED_CACERT_VALIDITY;
      if (pRevocationInfo) {
        int verifyStatus = pCACert->verifyStatus(szDateTime, nullptr);

        switch (verifyStatus) {
          case REVOCATION_STATUS_GOOD:
            bitmask |= VERIFIED_CACERT_GOOD;
            bitmask |= VERIFIED_CACRL_LOADED;
            break;

          case REVOCATION_STATUS_REVOKED:
            bitmask |= VERIFIED_CACRL_LOADED;
            bitmask |= VERIFIED_CACERT_REVOKED;
            break;

          case REVOCATION_STATUS_SUSPENDED:
            bitmask |= VERIFIED_CACERT_SUSPENDED;
            bitmask |= VERIFIED_CACRL_LOADED;
            break;

          case REVOCATION_STATUS_UNKNOWN:
            break;
        }
      }
    }

    pCert = pCACert;
    pCACert = CCertStore::GetCertificate(*pCACert);
  }

  if (!pCACert) {
    bitmask |= VERIFIED_CERT_CHAIN;
  }

  // verifica la firma

  // OpenSSL
  ByteDynArray baCert;
  cert.toByteArray(baCert);
  X509* x509 = nullptr;

  const BYTE* content = baCert.data();
  x509 = d2i_X509(nullptr, &content, baCert.size());

  EVP_PKEY* evp_pubkey;

  evp_pubkey = X509_get_pubkey(x509);

  CASN1OctetString encryptedDigest(signerInfo.getEncryptedDigest());
  const ByteDynArray* pEncDigest = encryptedDigest.getValue();

  try {
    BYTE decrypted[MAX_RSA_MODULUS_LEN];
    unsigned int len = MAX_RSA_MODULUS_LEN;

    const BYTE* encrypted = pEncDigest->data();
    const int encrypted_len = static_cast<int>(pEncDigest->size());

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(evp_pubkey, nullptr);
    if (pctx && EVP_PKEY_verify_recover_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) > 0) {
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

    EVP_PKEY_free(evp_pubkey);
    X509_free(x509);

    if (len) {
      LOG_DBG((0, "CSignerInfo::verifySignature", "RSAPublicDecrypt OK"));

      char szAux[100];

      ByteDynArray dec(ByteArray(decrypted, len));
      BufferedReader reader(dec);
      CDigestInfo digestInfo(reader);
      CASN1OctetString digest = digestInfo.getDigest();
      ByteDynArray* pDigestValue = const_cast<ByteDynArray*>(digest.getValue());

      // content
      ByteDynArray content;
      CASN1OctetString octetString(source);

      if (octetString.getTag() == 0x24) {  // contructed octet string
        CASN1Sequence contentArray(octetString);
        int size = contentArray.size();
        for (int i = 0; i < size; i++) {
          content.append(ByteArray(contentArray.elementAt(i).getValue()->data(),
                                   contentArray.elementAt(i).getLength()));
        }
      } else {
        content.append(
            ByteArray(octetString.getValue()->data(), octetString.getLength()));
      }

      BYTE* buff;
      int bufflen = 0;

      ByteDynArray messageDigest;

      // estra i signedattributes
      ByteDynArray signedAttr;
      CASN1SetOf authAttr(signerInfo.getAuthenticatedAttributes());
      int authAttrSize = authAttr.size();

      LOG_DBG(
          (0, "CSignerInfo::verifySignature", "Attrsize: %d", authAttrSize));

      if (authAttrSize > 0) {
        CASN1ObjectIdentifier oid(szMessageDigestOID);
        CASN1ObjectIdentifier oid1(szContentTypeOID);
        CASN1ObjectIdentifier oid2(szIdAASigningCertificateV2OID);
        for (int i = 0; i < authAttrSize; i++) {
          CASN1Sequence attr(authAttr.elementAt(i));

          if (oid.equals(attr.elementAt(0))) {
            bitmask |= VERIFIED_SIGNED_ATTRIBUTE_MD;
            CASN1SetOf values(attr.elementAt(1));
            CASN1OctetString val(values.elementAt(0));
            const ByteDynArray* pval = val.getValue();
            messageDigest.append(*pval);
          } else if (oid1.equals(attr.elementAt(0))) {
            bitmask |= VERIFIED_SIGNED_ATTRIBUTE_CT;
          } else if (oid2.equals(attr.elementAt(0))) {
            bitmask |= VERIFIED_SIGNED_ATTRIBUTE_SC;
          }
        }

        authAttr.toByteArray(signedAttr);
        buff = const_cast<BYTE*>(signedAttr.data());
        bufflen = signedAttr.size();
      } else {
        // se non ci sono signedattributes l'hash va fatto sul content
        buff = const_cast<BYTE*>(content.data());
        bufflen = content.size();
      }

      CAlgorithmIdentifier digestAlgo(digestInfo.getDigestAlgorithm());
      CAlgorithmIdentifier sha256Algo(szSHA256OID);
      CAlgorithmIdentifier sha1Algo(szSHA1OID);
      if (digestAlgo.elementAt(0) == sha256Algo.elementAt(0)) {
        LOG_DBG((0, "CSignerInfo::verifySignature", "SHA256 OK"));

        bitmask |= VERIFIED_SHA256;

        BYTE hash[32];
        BYTE hash2[32];

        EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(sha256_ctx, EVP_sha256());
        EVP_DigestUpdate(sha256_ctx, buff, bufflen);
        EVP_DigestFinal(sha256_ctx, hash, nullptr);
        EVP_MD_CTX_free(sha256_ctx);

        EVP_MD_CTX* sha256_1_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(sha256_1_ctx, EVP_sha256());
        EVP_DigestUpdate(sha256_1_ctx, content.data(), content.size());
        EVP_DigestFinal(sha256_1_ctx, hash2, nullptr);
        EVP_MD_CTX_free(sha256_1_ctx);

        ByteDynArray bahash(ByteArray(hash, 32));
        LOG_DBG((0, "CSignerInfo::verifySignature", "DigestValue: %s, %s",
                 dumpHexData(*pDigestValue).c_str(),
                 dumpHexData(bahash).c_str()));

        if (CRYPTO_memcmp(hash, pDigestValue->data(), 32) == 0) {
          LOG_DBG((0, "CSignerInfo::verifySignature", "SHA256 Len OK"));

          // verifica l'hash del content
          if (messageDigest.size() > 0) {
            if (CRYPTO_memcmp(hash2, messageDigest.data(), 32) == 0) {
              bitmask |= VERIFIED_SIGNATURE;
              LOG_DBG(
                  (0, "CSignerInfo::verifySignature", "VERIFIED: %x", bitmask));
            } else {
              LOG_DBG((0, "CSignerInfo::verifySignature", "Not verified"));
            }
          } else {
            if (CRYPTO_memcmp(hash2, hash, 32) == 0) {
              bitmask |= VERIFIED_SIGNATURE;
              LOG_DBG((0, "CSignerInfo::verifySignature", "VERIFIED 2: %x",
                       bitmask));
            } else {
              LOG_DBG((0, "CSignerInfo::verifySignature", "Not verified 2"));
            }
          }
        } else {
          LOG_DBG((0, "CSignerInfo::verifySignature", "Not verified 3"));
        }
      } else if (digestAlgo.elementAt(0) ==
                 sha1Algo.elementAt(
                     0)) {  // if(digestAlgo == CAlgorithmIdentifier(szSHA1OID))
        LOG_DBG((0, "CSignerInfo::verifySignature", "SHA1"));
        unsigned char hash[SHA_DIGEST_LENGTH];
        EVP_MD_CTX* sha1_ctx = nullptr;

        // calcola l'hash SHA1
        sha1_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(sha1_ctx, EVP_sha1());
        EVP_DigestUpdate(sha1_ctx, buff, bufflen);
        EVP_DigestFinal(sha1_ctx, hash, nullptr);
        EVP_MD_CTX_free(sha1_ctx);

        // Reinterpret the hash as five unsigned 32-bit words.
        unsigned* word = reinterpret_cast<unsigned*>(hash);

        snprintf(szAux, sizeof(szAux), "%08X%08X%08X%08X%08X ",
                 __builtin_bswap32(word[0]), __builtin_bswap32(word[1]),
                 __builtin_bswap32(word[2]), __builtin_bswap32(word[3]),
                 __builtin_bswap32(word[4]));

        ByteDynArray hashaux(szAux);

        sha1_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(sha1_ctx, EVP_sha1());
        EVP_DigestUpdate(sha1_ctx, content.data(), content.size());
        EVP_DigestFinal(sha1_ctx, hash, nullptr);
        EVP_MD_CTX_free(sha1_ctx);

        snprintf(szAux, sizeof(szAux), "%08X%08X%08X%08X%08X ",
                 __builtin_bswap32(word[0]), __builtin_bswap32(word[1]),
                 __builtin_bswap32(word[2]), __builtin_bswap32(word[3]),
                 __builtin_bswap32(word[4]));

        ByteDynArray contentHash(szAux);

        if (CRYPTO_memcmp(hashaux.data(), pDigestValue->data(),
                          hashaux.size()) == 0) {
          LOG_DBG((0, "CSignerInfo::verifySignature", "length 1"));

          // verifica l'hash del content
          if (messageDigest.size() > 0) {
            LOG_DBG((0, "CSignerInfo::verifySignature", "length 2"));
            if (CRYPTO_memcmp(contentHash.data(), messageDigest.data(),
                              contentHash.size()) == 0) {
              bitmask |= VERIFIED_SIGNATURE;
            } else {
              LOG_DBG((0, "CSignerInfo::verifySignature", "Not verified 2"));
            }
          } else {
            if (CRYPTO_memcmp(contentHash.data(), hashaux.data(),
                              contentHash.size()) == 0) {
              bitmask |= VERIFIED_SIGNATURE;
            } else {
              LOG_DBG((0, "CSignerInfo::verifySignature", "Not verified 3"));
            }
          }
        }
      }
    } else {
      LOG_ERR(
          (0, "CSignerInfo::verifySignature", "RSA Signature not verified"));
    }
  } catch (...) {
    LOG_ERR((0, "CSignerInfo::verifySignature", "Unexpected Exception"));
  }

  return bitmask;
}

CCertificate CSignerInfo::getSignatureCertificate(CSignerInfo& signature,
                                                  CASN1SetOf& certificates) {
  CIssuerAndSerialNumber issuerAndSerialNumber =
      signature.getIssuerAndSerialNumber();

  for (size_t i = 0; i < certificates.size(); i++) {
    CCertificate cert = certificates.elementAt(i);
    CName issuer = cert.getIssuer();
    CASN1Integer serialNumber = cert.getSerialNumber();

    CIssuerAndSerialNumber issuerAndSerial(issuer, serialNumber, false);

    if (issuerAndSerial == issuerAndSerialNumber) {
      return cert;
    }
  }

  throw -1;
}
