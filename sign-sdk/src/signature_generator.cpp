// SPDX-License-Identifier: LGPL-3.0-or-later

#include "signature_generator.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstddef>
#include <ctime>
#include <vector>

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_object_identifier.h"
#include "asn1/asn1_octet_string.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_set_of.h"
#include "asn1/certificate.h"
#include "asn1/digest_info.h"
#include "cert_store.h"
#include "crypto/sha256.h"
#include "util/array.h"
#include "util/definitions.h"

CSignatureGeneratorBase::CSignatureGeneratorBase(CBaseSigner* pSigner)
    : m_pSigner(pSigner),
      m_nHashAlgo(CKM_SHA1_RSA_PKCS),
      m_pTSAClient(nullptr) {
  m_szAlias[0] = 0;
}

CSignatureGeneratorBase::CSignatureGeneratorBase(
    CSignatureGeneratorBase* pGenerator) {
  m_pSigner = pGenerator->m_pSigner;
  m_pTSAClient = pGenerator->m_pTSAClient;
  snprintf(m_szAlias, sizeof(m_szAlias), "%s", pGenerator->m_szAlias);
  m_nHashAlgo = pGenerator->m_nHashAlgo;
}

CSignatureGeneratorBase::~CSignatureGeneratorBase(void) {}

void CSignatureGeneratorBase::SetData(const ByteArray& data) {
  m_data.append(data);
}

void CSignatureGeneratorBase::SetAlias(char* alias) {
  snprintf(m_szAlias, sizeof(m_szAlias), "%s", alias);
}

void CSignatureGeneratorBase::SetHashAlgo(int hashAlgo) {
  m_nHashAlgo = hashAlgo;
}

void CSignatureGeneratorBase::SetTSA(char* szUrl, char* szUsername = nullptr,
                                     char* szPassword = nullptr) {
  m_pTSAClient = new CTSAClient();
  m_pTSAClient->SetTSAUrl(szUrl);
  if (szUsername) {
    m_pTSAClient->SetCredential(szUsername, szPassword);
  }
}

void CSignatureGeneratorBase::SetTSAUsername(char* szUsername) {
  m_pTSAClient->SetUsername(szUsername);
}

void CSignatureGeneratorBase::SetTSAPassword(char* szPassword) {
  m_pTSAClient->SetPassword(szPassword);
}

// CSignatureGenerator
CSignatureGenerator::CSignatureGenerator(CBaseSigner* pSigner, bool bRemote)
    : CSignatureGeneratorBase(pSigner), m_bCAdES(false), m_bRemote(bRemote) {}

CSignatureGenerator::~CSignatureGenerator(void) {}

void CSignatureGenerator::SetPKCS7Data(const ByteArray& pkcs7data) {
  try {
    CSignedDocument sd(const_cast<BYTE*>(pkcs7data.data()), pkcs7data.size());

    if (!sd.isDetached()) {
      sd.getContent(m_data);
    }

    m_signerInfos = sd.getSignerInfos();
    m_certificates = sd.getCertificates();
    m_digestAlgos = sd.getDigestAlgos();
  } catch (...) {
  }
}

void CSignatureGenerator::SetCAdES(bool cades) { m_bCAdES = cades; }

bool CSignatureGenerator::GetCAdES() { return m_bCAdES; }

long CSignatureGenerator::GetCertificate(CCertificate** ppCertificate) {
  ByteDynArray id;
  long nRes = m_pSigner->GetCertificate(m_szAlias, ppCertificate, id);
  if (nRes) {
    LOG_ERR(
        (0, "CSignatureGenerator::Generate", "GetCertificate error: %x", nRes));
    return nRes;
  }

  return 0;
}

long CSignatureGenerator::Generate(ByteDynArray& pkcs7SignedData,
                                   BOOL bDetached, BOOL bVerifyCertificate) {
  // get the certificate based on alias
  LOG_DBG((0, "CSignatureGenerator::Generate", ""));

  ByteDynArray id;
  CCertificate* pSignerCertificate;
  long nRes = m_pSigner->GetCertificate(m_szAlias, &pSignerCertificate, id);
  if (nRes) {
    LOG_ERR(
        (0, "CSignatureGenerator::Generate", "GetCertificate error: %x", nRes));
    m_pSigner->Close();
    return nRes;
  }

  LOG_DBG((0, "CSignatureGenerator::Generate", "bVerifyCertificate: %d",
           bVerifyCertificate));

  if (bVerifyCertificate) {
    if (!pSignerCertificate->isValid()) {
      SAFEDELETE(pSignerCertificate);
      m_pSigner->Close();
      return CIE_SIGN_ERROR_CERT_EXPIRED;
    }

    int bitmask = pSignerCertificate->verify();

    if ((bitmask & VERIFIED_CACERT_FOUND) == 0) {
      SAFEDELETE(pSignerCertificate);
      m_pSigner->Close();
      return CIE_SIGN_ERROR_CACERT_NOTFOUND;
    }

    if ((bitmask & VERIFIED_CERT_CHAIN) == 0) {
      SAFEDELETE(pSignerCertificate);
      m_pSigner->Close();
      return CIE_SIGN_ERROR_CERT_INVALID;
    }

    if (pSignerCertificate->verifyStatus(nullptr) != REVOCATION_STATUS_GOOD) {
      SAFEDELETE(pSignerCertificate);
      m_pSigner->Close();
      return CIE_SIGN_ERROR_CERT_REVOKED;
    }
  }

  // extract the cert value
  ByteDynArray certval;
  pSignerCertificate->toByteArray(certval);

  // hash certificate
  ByteArray baCert(certval.data(), certval.size());
  ByteDynArray certHashBuf = CSHA256().Digest(baCert);
  LOG_DBG((0, "CSignatureGenerator::Generate", "setSigningCertificate"));

  m_signerInfoGenerator.setSigningCertificate(certval.data(), certval.size(),
                                              certHashBuf.data(), 32);

  // hash algo
  int mech = m_bCAdES ? CKM_SHA256_RSA_PKCS : m_nHashAlgo;
  CAlgorithmIdentifier hashOID(mech == CKM_SHA256_RSA_PKCS ? szSHA256OID
                                                           : szSHA1OID);
  size_t i = 0;
  for (i = 0; i < m_digestAlgos.size(); i++) {
    if (m_digestAlgos.elementAt(i) == hashOID) break;
  }

  if (i == m_digestAlgos.size()) m_digestAlgos.addElement(hashOID);

  // content hashing
  LOG_DBG((0, "CSignatureGenerator::Generate", "CertificateHash"));

  std::vector<BYTE> hashBuf;
  int hashlen;

  switch (mech) {
    case CKM_SHA256_RSA_PKCS: {
      LOG_DBG((0, "CSignatureGenerator::Generate",
               "CertificateHash: CKM_SHA256_RSA_PKCS"));

      hashBuf.resize(32);
      hashlen = 32;
      // sha2((BYTE*)m_data.data(), m_data.size(), hash, 0);
      {
        ByteArray baData(m_data.data(), m_data.size());
        ByteDynArray h = CSHA256().Digest(baData);
        memcpy(hashBuf.data(), h.data(), 32);
      }
      m_signerInfoGenerator.setContentHash(hashBuf.data(), hashlen);

      ByteDynArray signedAttributes;
      m_signerInfoGenerator.getSignedAttributes(signedAttributes, false,
                                                !bDetached);
      {
        ByteArray baSA(signedAttributes.data(), signedAttributes.size());
        ByteDynArray h = CSHA256().Digest(baSA);
        memcpy(hashBuf.data(), h.data(), 32);
      }
      // sha2(signedAttributes.data(), signedAttributes.size(), hash,
      //      0);
    } break;

    case CKM_SHA1_RSA_PKCS: {
      LOG_DBG((0, "CSignatureGenerator::Generate",
               "CertificateHash: CKM_SHA1_RSA_PKCS"));

      hashBuf.resize(24);
      hashlen = 24;

      char szAux[50];

      EVP_MD_CTX* sha1_ctx = EVP_MD_CTX_new();
      EVP_DigestInit(sha1_ctx, EVP_sha1());
      EVP_DigestUpdate(sha1_ctx, const_cast<BYTE*>(m_data.data()),
                       m_data.size());
      EVP_DigestFinal(sha1_ctx, hashBuf.data(), nullptr);
      EVP_MD_CTX_free(sha1_ctx);

      // Reinterpret the hash as five unsigned 32-bit words.
      unsigned* word = reinterpret_cast<unsigned*>(hashBuf.data());

      snprintf(szAux, sizeof(szAux), "%08X%08X%08X%08X%08X ",
               __builtin_bswap32(word[0]), __builtin_bswap32(word[1]),
               __builtin_bswap32(word[2]), __builtin_bswap32(word[3]),
               __builtin_bswap32(word[4]));

      ByteDynArray hashaux(szAux);

      memcpy(hashBuf.data(), hashaux.data(), hashlen);

      m_signerInfoGenerator.setContentHash(hashBuf.data(), hashlen);

      ByteDynArray signedAttributes;
      m_signerInfoGenerator.getSignedAttributes(signedAttributes, false,
                                                !bDetached);

      // compute total digest
      EVP_MD_CTX* sha1_1_ctx = EVP_MD_CTX_new();
      EVP_DigestInit(sha1_1_ctx, EVP_sha1());
      EVP_DigestUpdate(sha1_1_ctx, signedAttributes.data(),
                       signedAttributes.size());
      EVP_DigestFinal(sha1_1_ctx, hashBuf.data(), nullptr);
      EVP_MD_CTX_free(sha1_1_ctx);

      snprintf(szAux, sizeof(szAux), "%08X%08X%08X%08X%08X ",
               __builtin_bswap32(word[0]), __builtin_bswap32(word[1]),
               __builtin_bswap32(word[2]), __builtin_bswap32(word[3]),
               __builtin_bswap32(word[4]));

      ByteDynArray hashaux1(szAux);

      memcpy(hashBuf.data(), hashaux1.data(), hashlen);
    } break;
  }

  ByteDynArray digest;

  if (m_bRemote) {
    digest.append(ByteArray(hashBuf.data(), hashlen));
  } else {
    CASN1OctetString digestString(hashBuf.data(), hashlen);
    CDigestInfo digestInfo(hashOID, digestString);

    digestInfo.toByteArray(digest);
  }

  ByteDynArray signature;

  LOG_DBG((0, "CSignatureGenerator::Generate", "Sign"));

  // make signature on the digest info
  CK_RV rv = m_pSigner->Sign(digest, id, CKM_RSA_PKCS, signature);
  if (rv) {
    LOG_DBG((0, "CSignatureGenerator::Generate", "Sign error: %x", rv));
    m_pSigner->Close();
    return rv;
  }

  m_signerInfoGenerator.setSignature(const_cast<BYTE*>(signature.data()),
                                     signature.size());

  // TSA
  if (m_pTSAClient != nullptr) {
    CSignerInfo signerInfo = m_signerInfoGenerator.getSignerInfo();

    CASN1OctetString octetString = signerInfo.getEncryptedDigest();
    ByteDynArray content;
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

    hashBuf.resize(32);
    hashlen = 32;

    // sha2((BYTE*)content.data(), content.size(), hash, 0);
    {
      ByteArray baContent(content.data(), content.size());
      ByteDynArray h = CSHA256().Digest(baContent);
      memcpy(hashBuf.data(), h.data(), 32);
    }

    ByteDynArray hashaux(ByteArray(hashBuf.data(), hashlen));

    CTimeStampToken* ptst = nullptr;
    nRes = m_pTSAClient->GetTimeStampToken(hashaux, nullptr, &ptst);
    if (ptst) {
      m_signerInfoGenerator.setTimestampToken(ptst);
    } else {
      LOG_DBG((0, "CSignatureGenerator::Generate", "TSA error: %x", nRes));
      delete pSignerCertificate;
      delete ptst;
      return CIE_SIGN_ERROR_TSA;
    }

    delete ptst;
  }

  CSignerInfo signerInfo = m_signerInfoGenerator.getSignerInfo();
  m_signerInfos.addElement(signerInfo);

  // aggiunge i certificati di CA
  CCertificate* pCACert = CCertStore::GetCertificate(*pSignerCertificate);
  while (pCACert) {
    m_certificates.addElement(*pCACert);
    pCACert = CCertStore::GetCertificate(*pCACert);
  }

  m_certificates.addElement(*pSignerCertificate);
  delete pSignerCertificate;

  // Crea signedData
  CSignedData* pSignedData;
  if (m_data.size() == 0 || bDetached) {  // detached
    const char* dataOID = szDataOID;
    CContentType contentType(dataOID);
    pSignedData = new CSignedData(m_digestAlgos, CContentInfo(contentType),
                                  m_signerInfos, m_certificates);
  } else {
    // Crea signedData
    CASN1ObjectIdentifier dataOID(szDataOID);
    CASN1OctetString data(m_data);
    CContentInfo ci(dataOID, data);
    pSignedData =
        new CSignedData(m_digestAlgos, ci, m_signerInfos, m_certificates);
  }

  LOG_DBG((0, "CSignatureGenerator::Generate", "ContentInfo"));

  // Infine crea ContentInfo
  CContentInfo contentInfo(szSignedDataOID, *pSignedData);

  pkcs7SignedData.clear();
  contentInfo.toByteArray(pkcs7SignedData);

  delete pSignedData;

  m_pSigner->Close();

  LOG_DBG((0, "<-- CSignatureGenerator::Generate", "OK"));

  return CKR_OK;
}
