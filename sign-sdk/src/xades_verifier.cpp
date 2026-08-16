// SPDX-License-Identifier: LGPL-3.0-or-later
#include "xades_verifier.h"

#include <libxml/c14n.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstring>
#include <string>
#include <vector>

#include "cert_store.h"
#include "crypto/base64.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#define MAX_FILENAME 250

xmlXPathObjectPtr getRequestedNode(xmlChar* path, xmlXPathContextPtr xpathCtx);
xmlNodeSetPtr getRequestedNodes(xmlChar* path, xmlXPathContextPtr xpathCtx);

namespace {

// Supported algorithm URIs. Anything else is treated as unsupported and
// makes the corresponding check (and therefore the whole signature) fail
// closed rather than silently succeed.
constexpr const char* kC14N10 =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
constexpr const char* kEnvelopedSignatureTransform =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char* kFilter2Transform =
    "http://www.w3.org/2002/06/xmldsig-filter2";
constexpr const char* kSignatureRsaSha1 =
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
constexpr const char* kSignatureRsaSha256 =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
constexpr const char* kDigestSha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
constexpr const char* kDigestSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
constexpr const char* kTypeSignedProperties =
    "http://uri.etsi.org/01903#SignedProperties";

std::string Trim(const std::string& s) {
  size_t begin = s.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) return std::string();
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(begin, end - begin + 1);
}

bool IsSafeXPathLiteral(const std::string& s) {
  return !s.empty() && s.find('\'') == std::string::npos;
}

std::string GetAttr(xmlNodePtr node, const char* name) {
  xmlChar* value = xmlGetProp(node, BAD_CAST name);
  if (!value) return std::string();
  std::string result(reinterpret_cast<char*>(value));
  xmlFree(value);
  return result;
}

// Evaluates @p expr against @p ctx and returns the text content of the
// single matched node. Fails unless exactly one node matches, so callers
// never silently pick an arbitrary candidate out of an ambiguous or empty
// result.
bool EvalSingleString(xmlXPathContextPtr ctx, const char* expr,
                      std::string& out) {
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
  if (!obj) return false;

  bool ok = false;
  if (obj->type == XPATH_NODESET && obj->nodesetval &&
      obj->nodesetval->nodeNr == 1) {
    xmlChar* content = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);
    if (content) {
      out.assign(reinterpret_cast<char*>(content));
      xmlFree(content);
      ok = true;
    }
  }

  xmlXPathFreeObject(obj);
  return ok;
}

xmlXPathContextPtr NewXAdESXPathContext(xmlDocPtr doc) {
  xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
  if (!ctx) return nullptr;

  xmlXPathRegisterNs(ctx, BAD_CAST "ds",
                     BAD_CAST "http://www.w3.org/2000/09/xmldsig#");
  xmlXPathRegisterNs(ctx, BAD_CAST "xades",
                     BAD_CAST "http://uri.etsi.org/01903/v1.3.2#");
  return ctx;
}

// Canonicalizes (Canonical XML 1.0, no comments) the node-set matched by
// @p expr. Used both for whole-subtree canonicalization (ds:SignedInfo, a
// ds:Reference target) and for the document-minus-signature form required
// by the enveloped-signature / filter2 transforms.
bool CanonicalizeXPathNodeSet(xmlXPathContextPtr ctx, const char* expr,
                              std::string& out) {
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
  if (!obj) return false;

  if (obj->type != XPATH_NODESET || !obj->nodesetval ||
      obj->nodesetval->nodeNr == 0) {
    xmlXPathFreeObject(obj);
    return false;
  }

  xmlChar* canonical = nullptr;
  int len = xmlC14NDocDumpMemory(ctx->doc, obj->nodesetval, XML_C14N_1_0,
                                 nullptr, 0, &canonical);
  xmlXPathFreeObject(obj);

  if (len <= 0 || !canonical) {
    if (canonical) xmlFree(canonical);
    return false;
  }

  out.assign(reinterpret_cast<char*>(canonical), static_cast<size_t>(len));
  xmlFree(canonical);
  return true;
}

bool DigestSupported(const std::string& algoUri) {
  return algoUri == kDigestSha256 || algoUri == kDigestSha1;
}

ByteDynArray ComputeDigest(const std::string& algoUri, const ByteArray& data) {
  if (algoUri == kDigestSha256) return CSHA256::Digest(data);
  if (algoUri == kDigestSha1) return CSHA1().Digest(data);
  return ByteDynArray();
}

// CBase64::Decode throws on malformed input; input here is attacker
// controlled (an XML file being verified), so it must never escape as an
// uncaught exception.
bool Base64DecodeSafe(const std::string& b64, ByteDynArray& out) {
  try {
    CBase64::Decode(b64.c_str(), out);
    return true;
  } catch (...) {
    return false;
  }
}

// Returns the sole XML_ELEMENT_NODE child of @p parent, or nullptr if there
// is none or more than one (an ambiguous/unexpected shape is unsupported).
xmlNodePtr SoleElementChild(xmlNodePtr parent) {
  xmlNodePtr found = nullptr;
  for (xmlNodePtr child = parent->children; child; child = child->next) {
    if (child->type != XML_ELEMENT_NODE) continue;
    if (found) return nullptr;
    found = child;
  }
  return found;
}

// This codebase's own generator (xades_generator.cpp CreateSignedInfo)
// emits an xmldsig-filter2 Transform with a single XPath child,
// Filter="subtract", selecting exactly "/descendant::ds:Signature" to
// exclude the (not-yet-present) signature element from the whole-document
// digest. That is the only filter2 shape this verifier accepts.
bool IsSubtractSignatureFilter2(xmlNodePtr transformNode) {
  xmlNodePtr xpathNode = SoleElementChild(transformNode);
  if (!xpathNode || !xmlStrEqual(xpathNode->name, BAD_CAST "XPath")) {
    return false;
  }

  if (GetAttr(xpathNode, "Filter") != "subtract") return false;

  xmlChar* content = xmlNodeGetContent(xpathNode);
  std::string expr = content ? reinterpret_cast<char*>(content) : "";
  if (content) xmlFree(content);

  return Trim(expr) == "/descendant::ds:Signature";
}

// Verifies a single ds:Reference: resolves its target per its Transforms,
// canonicalizes it, and compares the digest to ds:DigestValue.
//
// Supported:
//  - URI="" (whole document) with Transforms exactly
//    [enveloped-signature | filter2 "subtract /descendant::ds:Signature"],
//    then C14N 1.0. Every ds:Signature element in the document is excluded
//    (this codebase never co-signs an already-signed document, so that is
//    equivalent to, and reproduces, the state the document was digested in
//    at signing time).
//  - URI="#id" (same-document fragment) with Transforms exactly [C14N 1.0].
// Anything else (external/detached URIs, XSLT/Base64/XPath transforms,
// unrecognized filter2 expressions, unsupported digest algorithms) is
// unsupported and fails the reference closed.
bool VerifyReference(xmlXPathContextPtr ctx, xmlNodePtr referenceNode,
                     bool* pIsSignedPropertiesReference) {
  *pIsSignedPropertiesReference =
      GetAttr(referenceNode, "Type") == kTypeSignedProperties;

  std::string uri = GetAttr(referenceNode, "URI");

  ctx->node = referenceNode;
  std::string digestAlgo;
  if (!EvalSingleString(ctx, "./ds:DigestMethod/@Algorithm", digestAlgo) ||
      !DigestSupported(digestAlgo)) {
    return false;
  }

  std::string digestValueB64;
  if (!EvalSingleString(ctx, "./ds:DigestValue", digestValueB64)) {
    return false;
  }

  xmlXPathObjectPtr transformsObj =
      xmlXPathEvalExpression(BAD_CAST "./ds:Transforms/ds:Transform", ctx);
  std::vector<xmlNodePtr> transforms;
  if (transformsObj) {
    if (transformsObj->nodesetval) {
      for (int i = 0; i < transformsObj->nodesetval->nodeNr; i++) {
        transforms.push_back(transformsObj->nodesetval->nodeTab[i]);
      }
    }
    xmlXPathFreeObject(transformsObj);
  }

  std::string canonical;

  if (uri.empty()) {
    if (transforms.size() != 2) return false;

    std::string algo0 = GetAttr(transforms[0], "Algorithm");
    bool structural = (algo0 == kEnvelopedSignatureTransform) ||
                      (algo0 == kFilter2Transform &&
                       IsSubtractSignatureFilter2(transforms[0]));
    if (!structural || GetAttr(transforms[1], "Algorithm") != kC14N10) {
      return false;
    }

    if (!CanonicalizeXPathNodeSet(ctx,
                                  "(//. | //@* | //namespace::*)"
                                  "[not(ancestor-or-self::ds:Signature)]",
                                  canonical)) {
      return false;
    }
  } else if (uri.size() > 1 && uri[0] == '#') {
    std::string id = uri.substr(1);
    if (!IsSafeXPathLiteral(id)) return false;

    if (transforms.size() != 1 ||
        GetAttr(transforms[0], "Algorithm") != kC14N10) {
      return false;
    }

    std::string base = "//*[@Id='" + id + "']";

    xmlXPathObjectPtr idObj =
        xmlXPathEvalExpression(BAD_CAST base.c_str(), ctx);
    bool uniqueTarget =
        idObj && idObj->nodesetval && idObj->nodesetval->nodeNr == 1;
    if (idObj) xmlXPathFreeObject(idObj);
    if (!uniqueTarget) return false;

    std::string expr = "(" + base + " | " + base + "//node() | " + base +
                       "//@* | " + base + "//namespace::*)";
    if (!CanonicalizeXPathNodeSet(ctx, expr.c_str(), canonical)) {
      return false;
    }
  } else {
    // External/detached reference: this verifier only ever has the signed
    // XML file itself, never a separately supplied original payload, so
    // such a reference can never be resolved and must fail closed.
    return false;
  }

  ByteDynArray computed = ComputeDigest(
      digestAlgo, ByteArray(reinterpret_cast<const uint8_t*>(canonical.data()),
                            canonical.size()));

  ByteDynArray expected;
  if (!Base64DecodeSafe(digestValueB64, expected)) return false;

  if (computed.size() == 0 || expected.size() != computed.size()) {
    return false;
  }

  return CRYPTO_memcmp(computed.data(), expected.data(), computed.size()) == 0;
}

// Verifies the RSA signature over the canonicalized ds:SignedInfo and every
// ds:Reference it lists. Supported ds:SignatureMethod: rsa-sha1, rsa-sha256.
// Supported ds:CanonicalizationMethod: Canonical XML 1.0 (no comments) — the
// only method this codebase's generator ever emits. Anything else is
// unsupported and returns false without setting VERIFIED_SIGNATURE.
bool VerifyXmlDSigSignature(xmlXPathContextPtr ctx, xmlNodePtr signatureNode,
                            CCertificate* pCert, const ByteArray& sigValueB64,
                            bool& outSignedPropertiesVerified) {
  outSignedPropertiesVerified = false;
  if (!pCert || sigValueB64.isEmpty()) return false;

  ctx->node = signatureNode;
  xmlXPathObjectPtr siObj =
      xmlXPathEvalExpression(BAD_CAST "./ds:SignedInfo", ctx);
  if (!siObj || !siObj->nodesetval || siObj->nodesetval->nodeNr != 1) {
    if (siObj) xmlXPathFreeObject(siObj);
    return false;
  }
  xmlNodePtr signedInfoNode = siObj->nodesetval->nodeTab[0];
  xmlXPathFreeObject(siObj);

  ctx->node = signedInfoNode;
  std::string c14nAlgo;
  if (!EvalSingleString(ctx, "./ds:CanonicalizationMethod/@Algorithm",
                        c14nAlgo) ||
      c14nAlgo != kC14N10) {
    return false;
  }

  std::string sigMethod;
  if (!EvalSingleString(ctx, "./ds:SignatureMethod/@Algorithm", sigMethod)) {
    return false;
  }

  const EVP_MD* md = nullptr;
  if (sigMethod == kSignatureRsaSha1) {
    md = EVP_sha1();
  } else if (sigMethod == kSignatureRsaSha256) {
    md = EVP_sha256();
  } else {
    return false;
  }

  std::string canonicalSignedInfo;
  if (!CanonicalizeXPathNodeSet(
          ctx, "(. | @* | namespace::* | .//node() | .//@* | .//namespace::*)",
          canonicalSignedInfo)) {
    return false;
  }

  xmlXPathObjectPtr refsObj =
      xmlXPathEvalExpression(BAD_CAST "./ds:Reference", ctx);
  if (!refsObj || !refsObj->nodesetval || refsObj->nodesetval->nodeNr == 0) {
    if (refsObj) xmlXPathFreeObject(refsObj);
    return false;
  }
  std::vector<xmlNodePtr> references(
      refsObj->nodesetval->nodeTab,
      refsObj->nodesetval->nodeTab + refsObj->nodesetval->nodeNr);
  xmlXPathFreeObject(refsObj);

  for (xmlNodePtr referenceNode : references) {
    bool isSignedProperties = false;
    if (!VerifyReference(ctx, referenceNode, &isSignedProperties)) {
      return false;
    }
    if (isSignedProperties) outSignedPropertiesVerified = true;
  }

  std::string sigB64(reinterpret_cast<const char*>(sigValueB64.data()),
                     sigValueB64.size());
  ByteDynArray signature;
  if (!Base64DecodeSafe(sigB64, signature) || signature.isEmpty()) {
    return false;
  }

  ByteDynArray certBytes;
  pCert->toByteArray(certBytes);
  const BYTE* p = certBytes.data();
  X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(certBytes.size()));
  if (!x509) return false;

  EVP_PKEY* pkey = X509_get_pubkey(x509);
  X509_free(x509);
  if (!pkey) return false;

  bool signatureOk = false;
  EVP_MD_CTX* mctx = EVP_MD_CTX_new();
  if (mctx) {
    if (EVP_DigestVerifyInit(mctx, nullptr, md, nullptr, pkey) == 1 &&
        EVP_DigestVerifyUpdate(mctx, canonicalSignedInfo.data(),
                               canonicalSignedInfo.size()) == 1) {
      signatureOk =
          EVP_DigestVerifyFinal(mctx, signature.data(), signature.size()) == 1;
    }
    EVP_MD_CTX_free(mctx);
  }
  EVP_PKEY_free(pkey);

  return signatureOk;
}

// Verifies xades:SigningCertificate/xades:Cert[1]/xades:CertDigest against
// the actual signer certificate, as ETSI TS 101 903 requires. Supported
// digest algorithms: sha1, sha256 (same set as ds:Reference digests).
bool VerifySigningCertificateDigest(xmlXPathContextPtr ctx,
                                    xmlNodePtr signatureNode,
                                    CCertificate* pCert) {
  if (!pCert) return false;

  ctx->node = signatureNode;
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(
      BAD_CAST
      "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/"
      "xades:SignedSignatureProperties/xades:SigningCertificate/"
      "xades:Cert[1]/xades:CertDigest",
      ctx);
  if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr != 1) {
    if (obj) xmlXPathFreeObject(obj);
    return false;
  }
  xmlNodePtr certDigestNode = obj->nodesetval->nodeTab[0];
  xmlXPathFreeObject(obj);

  ctx->node = certDigestNode;
  std::string algo;
  if (!EvalSingleString(ctx, "./ds:DigestMethod/@Algorithm", algo) ||
      !DigestSupported(algo)) {
    return false;
  }

  std::string valueB64;
  if (!EvalSingleString(ctx, "./ds:DigestValue", valueB64)) return false;

  ByteDynArray certBytes;
  pCert->toByteArray(certBytes);
  ByteDynArray computed =
      ComputeDigest(algo, ByteArray(certBytes.data(), certBytes.size()));

  ByteDynArray expected;
  if (!Base64DecodeSafe(valueB64, expected)) return false;

  if (computed.size() == 0 || expected.size() != computed.size()) {
    return false;
  }

  return CRYPTO_memcmp(computed.data(), expected.data(), computed.size()) == 0;
}

}  // namespace

bool CXAdESVerifier::m_bLibXmlInitialized = false;

CXAdESVerifier::CXAdESVerifier(void) : m_pXAdESDoc(nullptr) {
  if (!m_bLibXmlInitialized) {
    m_bLibXmlInitialized = true;
    /* Init libxml */
    xmlInitParser();
    // cppcheck-suppress unknownMacro
    LIBXML_TEST_VERSION
  }
}

CXAdESVerifier::~CXAdESVerifier(void) {
  if (m_pXAdESDoc) {
    if (m_pXAdESDoc->ppSignatures) {
      int count = m_pXAdESDoc->nSignatures;
      for (int i = 0; i < count; i++) {
        SAFEDELETE(m_pXAdESDoc->ppSignatures[i]->pX509Cert);
        SAFEDELETE(m_pXAdESDoc->ppSignatures[i]);
      }

      SAFEDELETE(*(m_pXAdESDoc->ppSignatures));
      SAFEDELETE(m_pXAdESDoc->ppSignatures);
    }

    if (m_pXAdESDoc->pXmlDoc) xmlFreeDoc(m_pXAdESDoc->pXmlDoc);

    SAFEDELETE(m_pXAdESDoc);
  }
}

CCertificate* CXAdESVerifier::GetCertificate(int index) {
  const SignatureInfo* pSignatureInfo = m_pXAdESDoc->ppSignatures[index];
  return pSignatureInfo->pX509Cert;
}

CASN1ObjectIdentifier CXAdESVerifier::GetDigestAlgorithm(int index) {
  const SignatureInfo* pSignatureInfo = m_pXAdESDoc->ppSignatures[index];

  switch (pSignatureInfo->nDigestAlgo) {
    case CIE_SIGN_ALGO_SHA256:
      return CASN1ObjectIdentifier(szSHA256OID);

    case CIE_SIGN_ALGO_SHA512:
      return CASN1ObjectIdentifier(szSHA512OID);

    default:
      return CASN1ObjectIdentifier(szSHA1OID);
  }
}

int CXAdESVerifier::verifySignature(int index, const char* szDateTime,
                                    REVOCATION_INFO* pRevocationInfo) {
  if (!m_pXAdESDoc) return -1;

  int bitmask = 0;

  SignatureInfo* pSignatureInfo = m_pXAdESDoc->ppSignatures[index];

  // Verify the certificate
  if (pSignatureInfo->pX509Cert->isValid(szDateTime)) {
    bitmask |= VERIFIED_CERT_VALIDITY;
  }

  if (pSignatureInfo->pX509Cert->isQualified()) {
    bitmask |= VERIFIED_CERT_QUALIFIED;
  }

  if (pSignatureInfo->pX509Cert->isSHA256()) {
    bitmask |= VERIFIED_CERT_SHA256;
  }

  if (pSignatureInfo->nDigestAlgo == CIE_SIGN_ALGO_SHA256) {
    bitmask |= VERIFIED_SHA256;
  }

  if (pRevocationInfo) {
    pRevocationInfo->nRevocationStatus = REVOCATION_STATUS_UNKNOWN;
    // verify revocation status only if the certificate is valid
    if (bitmask & VERIFIED_CERT_VALIDITY) {
      int verifyStatus =
          pSignatureInfo->pX509Cert->verifyStatus(szDateTime, pRevocationInfo);

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
          break;
      }
    }
  }

  // verifica la cert chain

  CCertificate* pCert = pSignatureInfo->pX509Cert;
  CCertificate* pCACert =
      CCertStore::GetCertificate(*pSignatureInfo->pX509Cert);
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

  // pCACert becomes null both when a self-signed trust anchor matched
  // itself in the store and when the issuer of pCert simply could not be
  // found. Only the former is a validated chain; fail closed otherwise.
  if (!pCACert && (bitmask & VERIFIED_CACERT_FOUND) &&
      pCert->getIssuer() == pCert->getSubject() &&
      pCert->verifySignature(*pCert)) {
    bitmask |= VERIFIED_CERT_CHAIN;
  }

  // Verify the actual XML signature: the ds:SignedInfo signature value and
  // every ds:Reference digest. VERIFIED_SIGNATURE and the XAdES
  // signed-attribute bits below are only set when every check genuinely
  // passes; any parse error, missing element, or unsupported algorithm
  // leaves them unset. VERIFIED_SIGNED_ATTRIBUTE_CT is never set: this
  // format has no content-type signed property to verify it against.
  if (pSignatureInfo->pSignatureNode && m_pXAdESDoc->pXmlDoc) {
    xmlXPathContextPtr xpathCtx = NewXAdESXPathContext(m_pXAdESDoc->pXmlDoc);
    if (xpathCtx) {
      bool bSignedPropertiesVerified = false;
      if (VerifyXmlDSigSignature(xpathCtx, pSignatureInfo->pSignatureNode,
                                 pSignatureInfo->pX509Cert,
                                 pSignatureInfo->sigValue,
                                 bSignedPropertiesVerified)) {
        bitmask |= VERIFIED_SIGNATURE;
      }

      if (bSignedPropertiesVerified) {
        bitmask |= VERIFIED_SIGNED_ATTRIBUTE_MD;
      }

      if (pSignatureInfo->bCAdES &&
          VerifySigningCertificateDigest(xpathCtx,
                                         pSignatureInfo->pSignatureNode,
                                         pSignatureInfo->pX509Cert)) {
        bitmask |= VERIFIED_SIGNED_ATTRIBUTE_SC;
      }

      xmlXPathFreeContext(xpathCtx);
    }
  }

  return bitmask;
}

long CXAdESVerifier::Load(char* szFilename) {
  m_pXAdESDoc = parseXAdESFile(szFilename);
  if (!m_pXAdESDoc)
    return CIE_SIGN_ERROR_INVALID_FILE;
  else
    return m_pXAdESDoc->nSignatures;
}

XAdESDoc* CXAdESVerifier::parseXAdESFile(char* szFilename) {
  LOG_DBG(
      (0, "parseXAdESFile", "Opening: %s", szFilename ? szFilename : "(null)"));

  xmlDocPtr doc = xmlParseFile(szFilename);

  LOG_DBG((0, "parseXAdESFile", "xmlParseFile result: %p", doc));

  XAdESDoc* pXAdESDoc = nullptr;
  xmlNodePtr curNode;

  // Check the document is of the right kind

  curNode = xmlDocGetRootElement(doc);
  if (curNode == nullptr) {
    LOG_ERR((0, "parseXAdESFile", "Empty or unparseable document: %s",
             szFilename ? szFilename : "(null)"));
    xmlFreeDoc(doc);
    return (nullptr);
  }

  // get signature node by XPath
  xmlXPathContextPtr xpathCtx;
  xmlXPathObjectPtr xpathObj;

  // Create xpath evaluation context
  xpathCtx = xmlXPathNewContext(doc);
  if (xpathCtx == nullptr) {
    // fprintf(stderr,"Error: unable to create new XPath context\n");
    xmlFreeDoc(doc);
    return nullptr;
  }

  xmlXPathRegisterNs(xpathCtx, BAD_CAST "ds",
                     BAD_CAST "http://www.w3.org/2000/09/xmldsig#");

  xmlXPathRegisterNs(xpathCtx, BAD_CAST "xs",
                     BAD_CAST "http://uri.etsi.org/01903/v1.3.2#");

  xmlXPathRegisterNs(xpathCtx, BAD_CAST "xades",
                     BAD_CAST "http://uri.etsi.org/01903/v1.3.2#");

  xmlChar* path = BAD_CAST "//ds:Signature";
  // Evaluate xpath expression
  xpathObj = xmlXPathEvalExpression(path, xpathCtx);
  if (xpathObj == nullptr) {
    // Unable to evaluate xpath expression
    LOG_ERR((0, "parseXAdESFile", "XPath evaluation failed"));
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    return nullptr;
  }

  int nodeNr =
      (xpathObj->nodesetval != nullptr) ? xpathObj->nodesetval->nodeNr : 0;
  LOG_DBG((0, "parseXAdESFile", "Found %d ds:Signature node(s)", nodeNr));

  if (nodeNr > 0) {
    // gets the first node
    pXAdESDoc = new XAdESDoc;
    pXAdESDoc->pXmlDoc = doc;

    curNode = xpathObj->nodesetval->nodeTab[0];
    parseSignatureNode(xpathCtx, xpathObj->nodesetval, pXAdESDoc);
  }

  // Cleanup of XPath data
  xmlXPathFreeObject(xpathObj);
  xmlXPathFreeContext(xpathCtx);

  // doc now lives inside pXAdESDoc->pXmlDoc (freed by ~CXAdESVerifier) so
  // every pSignatureNode stored in a SignatureInfo stays valid for later
  // verifySignature() calls. Only free it here if no XAdESDoc claimed it.
  if (!pXAdESDoc) {
    xmlFreeDoc(doc);
  }

  return pXAdESDoc;
}

void CXAdESVerifier::parseSignatureNode(xmlXPathContextPtr xpathCtx,
                                        xmlNodeSetPtr signatureNodes,
                                        XAdESDoc* pXAdESDoc) {
  pXAdESDoc->nSignatures = signatureNodes->nodeNr;
  pXAdESDoc->ppSignatures = new SignatureInfo*;
  *pXAdESDoc->ppSignatures = new SignatureInfo[pXAdESDoc->nSignatures];

  xmlXPathObjectPtr xpathObj;
  xmlNodePtr signatureMethodNode;
  xmlNodePtr curNode;
  xmlNodePtr signatureValueNode;
  xmlNodeSetPtr certificateNodeSet;

  char szPath[BUFFERSIZE];

  for (int i = 0; i < signatureNodes->nodeNr; i++) {
    pXAdESDoc->ppSignatures[i] = new SignatureInfo;

    curNode = signatureNodes->nodeTab[i];
    pXAdESDoc->ppSignatures[i]->pSignatureNode = curNode;

    const xmlChar* id = xmlGetProp(curNode, BAD_CAST "Id");

    // Canonicalization method
    snprintf(szPath, sizeof(szPath),
             "//ds:Signature[@Id='%s']/ds:SignedInfo/ds:CanonicalizationMethod",
             id);
    xmlChar* path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      xmlXPathFreeObject(xpathObj);
    }

    // SignatureMethod
    snprintf(szPath, sizeof(szPath),
             "//ds:Signature[@Id='%s']/ds:SignedInfo/ds:SignatureMethod", id);
    path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      if (xpathObj->nodesetval->nodeNr > 0) {
        signatureMethodNode = xpathObj->nodesetval->nodeTab[0];
        char* szContent = reinterpret_cast<char*>(
            signatureMethodNode->properties[0]
                .children[0]
                .content);  // xmlNodeContent(signatureMethodNode);

        if (strstr(szContent, "sha256")) {
          (*pXAdESDoc->ppSignatures[i]).nDigestAlgo = CIE_SIGN_ALGO_SHA256;
        } else if (strstr(szContent, "sha512")) {
          (*pXAdESDoc->ppSignatures[i]).nDigestAlgo = CIE_SIGN_ALGO_SHA512;
        } else if (strstr(szContent, "sha1")) {
          (*pXAdESDoc->ppSignatures[i]).nDigestAlgo = CIE_SIGN_ALGO_SHA1;
        }
      }

      xmlXPathFreeObject(xpathObj);
    }

    // References
    snprintf(szPath, sizeof(szPath),
             "//ds:Signature[@Id='%s']/ds:SignedInfo/ds:Reference", id);
    path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      xmlXPathFreeObject(xpathObj);
    }

    // SignatureValue
    snprintf(szPath, sizeof(szPath),
             "//ds:Signature[@Id='%s']/ds:SignatureValue", id);
    path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      if (xpathObj->nodesetval->nodeNr > 0) {
        signatureValueNode = xpathObj->nodesetval->nodeTab[0];

        char* szContent =
            reinterpret_cast<char*>(xmlNodeGetContent(signatureValueNode));
        (*pXAdESDoc->ppSignatures[i])
            .sigValue.append(ByteArray(reinterpret_cast<BYTE*>(szContent),
                                       strlen(szContent)));
      }

      xmlXPathFreeObject(xpathObj);
    }

    // X509Certificates
    snprintf(
        szPath, sizeof(szPath),
        "//ds:Signature[@Id='%s']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
        id);
    path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      if (xpathObj->nodesetval->nodeNr > 0) {
        certificateNodeSet = xpathObj->nodesetval;
        char* szContent = reinterpret_cast<char*>(
            xmlNodeGetContent(certificateNodeSet->nodeTab[0]));
        ByteDynArray content(
            ByteArray(reinterpret_cast<BYTE*>(szContent), strlen(szContent)));
        (*pXAdESDoc->ppSignatures[i]).pX509Cert =
            CCertificate::createCertificate(content);
      }

      xmlXPathFreeObject(xpathObj);
    }

    // QualifyingProperties
    snprintf(szPath, sizeof(szPath),
             "//ds:Signature[@Id='%s']/ds:Object/xades:QualifyingProperties",
             id);
    path = BAD_CAST szPath;

    // Evaluate xpath expression
    xpathObj = xmlXPathEvalExpression(path, xpathCtx);
    if (xpathObj) {
      (*pXAdESDoc->ppSignatures[i]).bCAdES = false;
      if (xpathObj->nodesetval->nodeNr > 0) {
        (*pXAdESDoc->ppSignatures[i]).bCAdES = true;
      }

      xmlXPathFreeObject(xpathObj);
    }
  }
}
