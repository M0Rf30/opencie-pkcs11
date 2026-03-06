// SPDX-License-Identifier: LGPL-3.0-or-later
#include "xades_generator.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ctime>
#include <map>

#include "asn1/digest_info.h"
#include "big_integer_library.h"
#include "crypto/base64.h"
#include "crypto/sha256.h"
#include "util/array.h"

#define DIGEST_METHOD_SHA1 "http://www.w3.org/2000/09/xmldsig#sha1"
#define DIGEST_METHOD_RSASHA256 \
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define DIGEST_METHOD_SHA256 "http://www.w3.org/2001/04/xmlenc#sha256"
#define NAMESPACE_XML_DSIG "http://www.w3.org/2000/09/xmldsig#"
#define NAMESPACE_XADES_111 "http://uri.etsi.org/01903/v1.1.1#"
#define NAMESPACE_XADES_132 "http://uri.etsi.org/01903/v1.3.2#"
#define NAMESPACE_XADES_1410 "http://uri.etsi.org/01903/v1.4.1"
#define NAMESPACE_XADES "http://uri.etsi.org/01903#"

#define REFTYPE_CONTENT 1
#define REFTYPE_URI 2

using uint32 = unsigned long;
char* Bin128ToDec(const uint32 N[4]);

void printBigInt(const BYTE* buffer, int buflen, std::string& sDecimalValue);

CXAdESGenerator::CXAdESGenerator(CBaseSigner* pCryptoki)
    : CSignatureGeneratorBase(pCryptoki), m_bXAdES(false) {}

CXAdESGenerator::CXAdESGenerator(CSignatureGeneratorBase* pGenerator)
    : CSignatureGeneratorBase(pGenerator), m_bXAdES(false) {}

CXAdESGenerator::~CXAdESGenerator(void) {}

void CXAdESGenerator::SetXAdES(bool xades) { m_bXAdES = xades; }

void CXAdESGenerator::SetFileName(char* szFileName) {
  snprintf(m_szFileName, sizeof(m_szFileName), "%s", szFileName);
}

static void extractNs(xmlDocPtr pDoc, xmlNode* a_node,
                      std::map<const xmlChar*, xmlNsPtr*>* pNsPtrMap) {
  xmlNode* cur_node = nullptr;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      xmlNsPtr* nsPtr = xmlGetNsList(pDoc, cur_node);
      if (nsPtr) {
        pNsPtrMap->insert(
            std::pair<const xmlChar*, xmlNsPtr*>(nsPtr[0]->href, nsPtr));
      }
    }

    extractNs(pDoc, cur_node->children, pNsPtrMap);
  }
}

long CXAdESGenerator::Generate(ByteDynArray& xadesData, BOOL bDetached,
                               BOOL bVerifyCertificate) {
  // get the certificate based on alias
  ByteDynArray id;
  CCertificate* pSignerCertificate;
  m_pSigner->GetCertificate(m_szAlias, &pSignerCertificate, id);

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

  xmlDocPtr pDoc;
  xmlNodePtr root;

  // Build an XML tree from the file;
  pDoc = xmlParseMemory(reinterpret_cast<const char*>(m_data.data()),
                        m_data.size());

  if (pDoc == nullptr) return CIE_SIGN_ERROR_INVALID_FILE;

  // Check the document is of the right kind

  root = xmlDocGetRootElement(pDoc);
  if (root == nullptr) {
    // fprintf(stderr,"empty document\n");
    xmlFreeDoc(pDoc);
    return CIE_SIGN_ERROR_INVALID_FILE;
  }

  std::map<const xmlChar*, xmlNsPtr*> nsPtrMap;

  extractNs(pDoc, root, &nsPtrMap);

  // generate ID
  time_t t = time(nullptr);
  snprintf(m_szID, sizeof(m_szID), "signature_%ld", static_cast<long>(t));

  // hash del documento
  // string strDocHashB64;
  // string strDocCanonicalForm;

  // CanonicalizeAndHashBase64(pDoc, strDocHashB64, strDocCanonicalForm);

  // QualifyingProperties
  xmlDocPtr docQualifyingProperties = nullptr;
  std::string strQualifPropsHashB64;
  std::string strCanonicalForm;

  if (m_bXAdES) {
    docQualifyingProperties =
        CreateQualifyingProperties(pDoc, pSignerCertificate);

    xmlDocPtr doc0 = xmlCopyDoc(docQualifyingProperties, TRUE);
    xmlDocPtr doc1 = xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"));
    xmlNodePtr rootNode = &(doc0->children[0].children[0]);

    xmlDocSetRootElement(doc1, rootNode);

    for (const auto& [key, val] : nsPtrMap) {
      xmlNsPtr* nsPtr = val;
      while (nsPtr) {
        nsPtr = nsPtr[0]->next ? &(nsPtr[0]->next) : nullptr;
      }
    }

    CanonicalizeAndHashBase64(doc1, strQualifPropsHashB64, strCanonicalForm);

    xmlFreeDoc(doc0);
    xmlFreeDoc(doc1);
  }

  // SignedInfo
  xmlDocPtr docSignedInfo =
      CreateSignedInfo(pDoc, strQualifPropsHashB64, bDetached, m_szFileName);

  for (const auto& [key, val] : nsPtrMap) {
    xmlNsPtr* nsPtr = val;
    while (nsPtr) {
      nsPtr = nsPtr[0]->next ? &(nsPtr[0]->next) : nullptr;
    }
  }

  std::string strSignedInfoHashB64;
  std::string strSigInfoCanonicalForm;
  xmlDocPtr doc0 = xmlCopyDoc(docSignedInfo, TRUE);

  xmlDocPtr doc1 = xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"));
  xmlNodePtr rootNode = &(doc0->children[0].children[0]);

  xmlDocSetRootElement(doc1, rootNode);

  for (const auto& [key, val] : nsPtrMap) {
    xmlNsPtr* nsPtr = val;
    while (nsPtr) {
      nsPtr = nsPtr[0]->next ? &(nsPtr[0]->next) : nullptr;
    }
  }

  CanonicalizeAndHashBase64(doc1, strSignedInfoHashB64,
                            strSigInfoCanonicalForm);

  // compute signature
  ByteDynArray signature;
  ByteDynArray data(
      ByteArray(reinterpret_cast<const BYTE*>(strSigInfoCanonicalForm.c_str()),
                strSigInfoCanonicalForm.length()));

  ByteDynArray hashauxDyn;
  CBase64().Decode(strSignedInfoHashB64.c_str(), hashauxDyn);
  ByteDynArray hashaux(ByteArray(
      hashauxDyn.data(), static_cast<unsigned long>(hashauxDyn.size())));

  CAlgorithmIdentifier hashOID(szSHA256OID);
  ByteDynArray digest;

  CASN1OctetString digestString(hashaux);
  CDigestInfo digestInfo(hashOID, digestString);

  digestInfo.toByteArray(digest);

  // make signature on the digest info
  CK_RV rv = m_pSigner->Sign(digest, id, CKM_RSA_PKCS, signature);
  if (rv) return rv;

  // static xmlChar nl[] = "\n";

  std::string strSignatureB64;
  {
    ByteArray baSig(signature.data(), signature.size());
    CBase64().Encode(baSig, strSignatureB64);
  }

  xmlNodePtr pSignatureRoot;

  pSignatureRoot = xmlDocGetRootElement(docSignedInfo);

  // KeyInfo
  xmlNewChild(pSignatureRoot, nullptr, BAD_CAST "ds:KeyInfo", nullptr);

  // certificate in B64
  ByteDynArray baCert;
  pSignerCertificate->toByteArray(baCert);

  std::string strCertB64;
  {
    ByteArray baCertArg(baCert.data(), baCert.size());
    CBase64().Encode(baCertArg, strCertB64);
  }

  if (docQualifyingProperties) {
    // Object
    xmlNodePtr pObject =
        xmlNewChild(pSignatureRoot, nullptr, BAD_CAST "ds:Object", nullptr);

    // QualifyingProperties
    xmlNodePtr rootQualifyingProperties =
        xmlDocGetRootElement(docQualifyingProperties);
    xmlAddChild(pObject, rootQualifyingProperties);
  }

  xmlChar* membuf;
  int nSize;

  if (bDetached) {
    xmlDocPtr newdoc = xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"));
    xmlDocSetRootElement(newdoc, pSignatureRoot);
    xmlKeepBlanksDefault(0);
    xmlDocDumpFormatMemory(newdoc, &membuf, &nSize, 1);
  } else {
    // signature
    xmlAddChild(root, pSignatureRoot);
    xmlKeepBlanksDefault(0);
    xmlDocDumpFormatMemory(pDoc, &membuf, &nSize, 1);
  }

  xadesData.append(ByteArray(membuf, nSize));

  xmlFree(membuf);
  xmlFreeDoc(pDoc);

  return CKR_OK;
}

void CXAdESGenerator::CanonicalizeAndHashBase64(xmlDocPtr pDoc,
                                                std::string& strDocHashB64,
                                                std::string& strCanonical) {
  // hash del documento
  xmlChar* pCanonicalDoc = nullptr;
  int docLen = xmlC14NDocDumpMemory(pDoc, nullptr, XML_C14N_1_0, nullptr, 0,
                                    &pCanonicalDoc);
  if (docLen > 0) pCanonicalDoc[docLen] = 0;

  strCanonical.append(reinterpret_cast<char*>(pCanonicalDoc));

  ByteDynArray hashaux;
  if (m_bXAdES) {
    ByteArray baCan(reinterpret_cast<const uint8_t*>(pCanonicalDoc),
                    static_cast<size_t>(docLen));
    ByteDynArray sha256res = CSHA256().Digest(baCan);
    hashaux.append(ByteArray(sha256res.data(), 32));
  } else {
    // calcola l'hash SHA1
    unsigned char hash[SHA_DIGEST_LENGTH];

    EVP_MD_CTX* sha1_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(sha1_ctx, EVP_sha1());
    EVP_DigestUpdate(sha1_ctx, pCanonicalDoc, docLen);
    EVP_DigestFinal(sha1_ctx, hash, nullptr);
    EVP_MD_CTX_free(sha1_ctx);

    char szAux[100];

    // Reinterpret the hash as five unsigned 32-bit words.
    unsigned* word = reinterpret_cast<unsigned*>(hash);

    snprintf(szAux, sizeof(szAux), "%08X%08X%08X%08X%08X ",
             __builtin_bswap32(word[0]), __builtin_bswap32(word[1]),
             __builtin_bswap32(word[2]), __builtin_bswap32(word[3]),
             __builtin_bswap32(word[4]));

    hashaux.load(szAux);
  }

  strDocHashB64.clear();
  ByteArray baHash(hashaux.data(), hashaux.size());
  CBase64().Encode(baHash, strDocHashB64);
}

xmlDocPtr CXAdESGenerator::CreateSignedInfo(
    xmlDocPtr pDocument, std::string& strQualifyingPropertiesB64Hash,
    bool bDetached, char* szFileName) {
  // XML doc
  xmlDocPtr doc = xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"));
  doc->children = xmlNewDocNode(doc, nullptr, BAD_CAST "ds:Signature", nullptr);

  xmlNodePtr pSignatureNode = doc->children;
  xmlNewProp(pSignatureNode, BAD_CAST "Id", BAD_CAST m_szID);

  // <SignedInfo>
  xmlNodePtr pSignedInfo =
      xmlNewChild(pSignatureNode, nullptr,
                  reinterpret_cast<const xmlChar*>("ds:SignedInfo"), nullptr);

  // in ver 1.1 we need this namespace def
  // xmlNewNs(pSignedInfo, (const xmlChar*)NAMESPACE_XML_DSIG, nullptr);

  // <CanonicalizationMethod>
  xmlNodePtr pN1 = xmlNewChild(
      pSignedInfo, nullptr,
      reinterpret_cast<const xmlChar*>("ds:CanonicalizationMethod"), nullptr);
  xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("Algorithm"),
             reinterpret_cast<const xmlChar*>(
                 "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"));

  // <SignatureMethod>
  pN1 = xmlNewChild(pSignedInfo, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:SignatureMethod"),
                    nullptr);
  if (m_bXAdES) {
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
  } else {
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/2000/09/xmldsig#rsa-sha1"));
  }

  // <Reference>
  pN1 = xmlNewChild(pSignedInfo, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Reference"), nullptr);
  if (bDetached) {
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("URI"),
               reinterpret_cast<const xmlChar*>(szFileName));
  } else {
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("URI"),
               reinterpret_cast<const xmlChar*>(""));
  }

  if (!bDetached) {
    // Transformation
    xmlNodePtr pN2 =
        xmlNewChild(pN1, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Transforms"), nullptr);
    xmlNodePtr pN3 =
        xmlNewChild(pN2, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Transform"), nullptr);

    // filter xpath
    xmlSetProp(pN3, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/2002/06/xmldsig-filter2"));

    xmlNodePtr pN31 = xmlNewChild(
        pN3, nullptr, reinterpret_cast<const xmlChar*>("dsig-xpath:XPath"),
        reinterpret_cast<const xmlChar*>("/descendant::ds:Signature"));
    xmlSetProp(pN31, reinterpret_cast<const xmlChar*>("Filter"),
               reinterpret_cast<const xmlChar*>("subtract"));

    // c14N
    xmlNodePtr pN4 =
        xmlNewChild(pN2, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Transform"), nullptr);
    xmlSetProp(pN4, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"));
  }

  // documents digest
  xmlNodePtr pN2 =
      xmlNewChild(pN1, nullptr,
                  reinterpret_cast<const xmlChar*>("ds:DigestMethod"), nullptr);
  xmlSetProp(pN2, reinterpret_cast<const xmlChar*>("Algorithm"),
             reinterpret_cast<const xmlChar*>(
                 "http://www.w3.org/2001/04/xmlenc#sha256"));

  // digest value
  // hash del documento
  std::string strDocHashB64;
  std::string strCanonicalDoc;

  CanonicalizeAndHashBase64(pDocument, strDocHashB64, strCanonicalDoc);

  pN2 = xmlNewChild(pN1, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:DigestValue"),
                    reinterpret_cast<const xmlChar*>(strDocHashB64.c_str()));

  if (!strQualifyingPropertiesB64Hash.empty()) {
    // XAdES xadesSignedProperties
    // Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties
    // <Reference>
    pN1 =
        xmlNewChild(pSignedInfo, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Reference"), nullptr);
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("URI"),
               reinterpret_cast<const xmlChar*>("#xadesSignedProperties"));
    xmlSetProp(pN1, reinterpret_cast<const xmlChar*>("Type"),
               reinterpret_cast<const xmlChar*>(
                   "http://uri.etsi.org/01903#SignedProperties"));

    // Transformation
    xmlNodePtr pN02 =
        xmlNewChild(pN1, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Transforms"), nullptr);
    // c14N
    xmlNodePtr pN04 =
        xmlNewChild(pN02, nullptr,
                    reinterpret_cast<const xmlChar*>("ds:Transform"), nullptr);
    xmlSetProp(pN04, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"));

    // documents digest
    pN2 = xmlNewChild(pN1, nullptr,
                      reinterpret_cast<const xmlChar*>("ds:DigestMethod"),
                      nullptr);
    xmlSetProp(pN2, reinterpret_cast<const xmlChar*>("Algorithm"),
               reinterpret_cast<const xmlChar*>(
                   "http://www.w3.org/2001/04/xmlenc#sha256"));
    pN2 = xmlNewChild(pN1, nullptr,
                      reinterpret_cast<const xmlChar*>("ds:DigestValue"),
                      reinterpret_cast<const xmlChar*>(
                          strQualifyingPropertiesB64Hash.c_str()));
  }

  return doc;
}

xmlDocPtr CXAdESGenerator::CreateQualifyingProperties(
    xmlDocPtr /*pDocument*/, CCertificate* pCertificate) {
  // XML doc
  xmlDocPtr doc = xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"));
  doc->children = xmlNewDocNode(doc, nullptr,
                                BAD_CAST "xades:QualifyingProperties", nullptr);

  // QualifyingProperties
  xmlNodePtr pQualifyingProperties = doc->children;
  xmlNewProp(pQualifyingProperties, BAD_CAST "Target", BAD_CAST m_szID);

  // <SignedProperties>
  xmlNodePtr pSignedProperties = xmlNewChild(
      pQualifyingProperties, nullptr,
      reinterpret_cast<const xmlChar*>("xades:SignedProperties"), nullptr);
  xmlNewProp(pSignedProperties, BAD_CAST "Id",
             BAD_CAST "xadesSignedProperties");

  // <SignedSignatureProperties>
  xmlNodePtr pSignedSignatureProperties = xmlNewChild(
      pSignedProperties, nullptr,
      reinterpret_cast<const xmlChar*>("xades:SignedSignatureProperties"),
      nullptr);

  // <SigningTime>
  /* Get UNIX-style time and display as number and string. */
  time_t ltime;
  time(&ltime);
  tm* pCurTime = gmtime(&ltime);  // localtime(&ltime);

  char szTime[100];

  strftime(szTime, 100, "%Y-%m-%dT%H:%M:%SZ", pCurTime);

  // SigningCertificate
  xmlNodePtr pSigningCertificate = xmlNewChild(
      pSignedSignatureProperties, nullptr,
      reinterpret_cast<const xmlChar*>("xades:SigningCertificate"), nullptr);

  // Cert
  xmlNodePtr pCert =
      xmlNewChild(pSigningCertificate, nullptr,
                  reinterpret_cast<const xmlChar*>("xades:Cert"), nullptr);

  // CertDigest
  xmlNodePtr pCertDigest = xmlNewChild(
      pCert, nullptr, reinterpret_cast<const xmlChar*>("xades:CertDigest"),
      nullptr);

  // DigestMethod
  xmlNodePtr pDigestMethod =
      xmlNewChild(pCertDigest, nullptr,
                  reinterpret_cast<const xmlChar*>("ds:DigestMethod"), nullptr);
  xmlNewProp(pDigestMethod, BAD_CAST "Algorithm",
             BAD_CAST DIGEST_METHOD_SHA256);
  // xmlNodeAddContent(pCertDigest, nl);

  // DigestValue
  // extract the cert value
  ByteDynArray certval;
  pCertificate->toByteArray(certval);

  ByteArray baCert2(certval.data(), certval.size());
  ByteDynArray sha256cert = CSHA256().Digest(baCert2);
  ByteDynArray hashaux(ByteArray(sha256cert.data(), 32));

  std::string strHashB64;
  {
    ByteArray baHashArg(hashaux.data(), hashaux.size());
    CBase64().Encode(baHashArg, strHashB64);
  }

  // X509IssuerName
  ByteDynArray strIssuerName;
  pCertificate->getIssuer().getNameAsString(strIssuerName);

  // X509SerialNumber
  CASN1Integer serialNumber(pCertificate->getSerialNumber());
  ByteDynArray* pSerialNumber =
      const_cast<ByteDynArray*>(serialNumber.getValue());

  BigInteger sernum = dataToBigInteger<const BYTE>(
      pSerialNumber->data(), pSerialNumber->size(), BigInteger::positive);

  std::string strSerNum = bigIntegerToString(sernum);

  return doc;
}

/* N[0] - contains least significant bits, N[3] - most significant */
char* Bin128ToDec(const uint32 N[4]) {
  // log10(x) = log2(x) / log2(10) ~= log2(x) / 3.322
  static char s[128 / 3 + 1 + 1];
  uint32 n[4];
  char* p = s;
  int i;

  memset(s, '0', sizeof(s) - 1);
  s[sizeof(s) - 1] = '\0';

  memcpy(n, N, sizeof(n));

  for (i = 0; i < 128; i++) {
    int j, carry;

    carry = (n[3] >= 0x80000000);
    // Shift n[] left, doubling it
    n[3] = ((n[3] << 1) & 0xFFFFFFFF) + (n[2] >= 0x80000000);
    n[2] = ((n[2] << 1) & 0xFFFFFFFF) + (n[1] >= 0x80000000);
    n[1] = ((n[1] << 1) & 0xFFFFFFFF) + (n[0] >= 0x80000000);
    n[0] = ((n[0] << 1) & 0xFFFFFFFF);

    // Add s[] to itself in decimal, doubling it
    for (j = sizeof(s) - 2; j >= 0; j--) {
      s[j] += s[j] - '0' + carry;

      carry = (s[j] > '9');

      if (carry) {
        s[j] -= 10;
      }
    }
  }

  while ((p[0] == '0') && (p < &s[sizeof(s) - 2])) {
    p++;
  }

  return p;
}

void printBigInt(const BYTE* buffer, int buflen, std::string& sDecimalValue) {
  for (int i = 0; i < buflen; i++) {
    unsigned x = buffer[i];
    char buf[(sizeof(x) * CHAR_BIT) / 3 + 2];  // slightly oversize buffer
    char* result = buf + sizeof(buf) - 1;      // index of next output digit

    // add digits to result, starting at
    // the end (least significant digit)

    *result = '\0';  // terminating null
    do {
      *--result = '0' + (x % 10);  // remainder gives the next digit
      x /= 10;
    } while (x);  // keep going until x reaches zero

    sDecimalValue.append(result);
  }
}
