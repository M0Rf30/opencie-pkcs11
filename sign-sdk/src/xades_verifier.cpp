// SPDX-FileCopyrightText: 2026 Gianluca Boiano
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

std::string GetAttr(xmlNodePtr node, const char* name) {
  xmlChar* value = xmlGetProp(node, BAD_CAST name);
  if (!value) return std::string();
  std::string result(reinterpret_cast<char*>(value));
  xmlFree(value);
  return result;
}

// Returns the one element of @p doc whose unqualified "Id" attribute equals
// @p id, or nullptr when there is none or more than one. The Id comes from
// an untrusted URI="#..." attribute, so it is compared against the tree
// instead of being spliced into an XPath expression; duplicates are an
// ambiguity an attacker can use to redirect a reference, hence rejected.
xmlNodePtr FindUniqueElementById(xmlDocPtr doc, const std::string& id) {
  xmlNodePtr root = xmlDocGetRootElement(doc);
  xmlNodePtr found = nullptr;

  xmlNodePtr node = root;
  while (node) {
    if (node->type == XML_ELEMENT_NODE) {
      xmlChar* value = xmlGetNoNsProp(node, BAD_CAST "Id");
      if (value) {
        bool match = id == reinterpret_cast<const char*>(value);
        xmlFree(value);
        if (match) {
          if (found) return nullptr;
          found = node;
        }
      }
    }

    // Pre-order walk without recursion.
    if (node->children && node->type == XML_ELEMENT_NODE) {
      node = node->children;
    } else {
      while (node && !node->next) {
        node = node->parent == reinterpret_cast<xmlNodePtr>(doc) ? nullptr
                                                                 : node->parent;
      }
      if (node) node = node->next;
    }
  }
  return found;
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

// Like EvalSingleString, but takes the first matched node (document order)
// when several match. Used for ds:X509Certificate, where the signer
// certificate may be followed by issuer certificates.
bool EvalFirstString(xmlXPathContextPtr ctx, const char* expr,
                     std::string& out) {
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
  if (!obj) return false;

  bool ok = false;
  if (obj->type == XPATH_NODESET && obj->nodesetval &&
      obj->nodesetval->nodeNr >= 1) {
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

// Returns true if @p node is @p ancestor or lies inside its subtree.
bool IsSelfOrDescendant(xmlNodePtr node, xmlNodePtr ancestor) {
  for (; node; node = node->parent) {
    if (node == ancestor) return true;
  }
  return false;
}

// Verifies a single ds:Reference: resolves its target per its Transforms,
// canonicalizes it, and compares the digest to ds:DigestValue.
//
// Supported:
//  - URI="" (whole document) with Transforms exactly
//    [enveloped-signature | filter2 "subtract /descendant::ds:Signature"],
//    then C14N 1.0. enveloped-signature removes only @p signatureNode (the
//    signature being verified), as XML-DSig defines it; the filter2
//    expression removes every ds:Signature, as the expression says (that is
//    the form this codebase's generator emits).
//  - URI="#id" (same-document fragment) with Transforms exactly [C14N 1.0];
//    the Id must identify exactly one element in the document.
// Anything else (external/detached URIs, XSLT/Base64/XPath transforms,
// unrecognized filter2 expressions, unsupported digest algorithms) is
// unsupported and fails the reference closed.
//
// Reports, from where the reference actually resolves (never from its
// Type attribute alone): *pCoversSignedProperties when the target is the
// signature's own @p signedPropertiesNode, *pIsDataReference when it covers
// anything other than that node. A reference that claims
// Type=SignedProperties but resolves elsewhere fails.
bool VerifyReference(xmlXPathContextPtr ctx, xmlNodePtr referenceNode,
                     xmlNodePtr signatureNode, xmlNodePtr signedPropertiesNode,
                     bool* pCoversSignedProperties, bool* pIsDataReference) {
  *pCoversSignedProperties = false;
  *pIsDataReference = false;
  const bool claimsSignedProperties =
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

    // The whole document is never the signed properties element.
    if (claimsSignedProperties) return false;

    const char* expr = nullptr;
    if (algo0 == kEnvelopedSignatureTransform) {
      xmlXPathObjectPtr self = xmlXPathNewNodeSet(signatureNode);
      if (!self ||
          xmlXPathRegisterVariable(ctx, BAD_CAST "signature", self) != 0) {
        if (self) xmlXPathFreeObject(self);
        return false;
      }
      // count(. | $signature) = 1 is the XPath node-identity test.
      expr =
          "(//. | //@* | //namespace::*)"
          "[not(ancestor-or-self::node()[count(. | $signature) = 1])]";
    } else {
      expr =
          "(//. | //@* | //namespace::*)"
          "[not(ancestor-or-self::ds:Signature)]";
    }

    ctx->node = referenceNode;
    if (!CanonicalizeXPathNodeSet(ctx, expr, canonical)) return false;
    *pIsDataReference = true;
  } else if (uri.size() > 1 && uri[0] == '#') {
    xmlNodePtr target = FindUniqueElementById(ctx->doc, uri.substr(1));
    if (!target) return false;

    if (signedPropertiesNode && target == signedPropertiesNode) {
      *pCoversSignedProperties = true;
    } else if (claimsSignedProperties) {
      return false;
    }
    *pIsDataReference = !signedPropertiesNode ||
                        !IsSelfOrDescendant(target, signedPropertiesNode);

    if (transforms.size() != 1 ||
        GetAttr(transforms[0], "Algorithm") != kC14N10) {
      return false;
    }

    ctx->node = target;
    if (!CanonicalizeXPathNodeSet(
            ctx, "(. | .//node() | .//@* | .//namespace::*)", canonical)) {
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
//
// Besides each digest matching, at least one ds:Reference must cover signed
// data other than the XAdES SignedProperties (otherwise the signature only
// protects its own metadata). @p signedPropertiesNode is this signature's
// own xades:SignedProperties (or null); outSignedPropertiesVerified is set
// only when a reference resolves to exactly that node and the whole
// signature verifies.
bool VerifyXmlDSigSignature(xmlXPathContextPtr ctx, xmlNodePtr signatureNode,
                            xmlNodePtr signedPropertiesNode,
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

  bool coversSignedProperties = false;
  bool coversData = false;
  for (xmlNodePtr referenceNode : references) {
    bool refCoversSignedProperties = false;
    bool refIsData = false;
    if (!VerifyReference(ctx, referenceNode, signatureNode,
                         signedPropertiesNode, &refCoversSignedProperties,
                         &refIsData)) {
      return false;
    }
    coversSignedProperties |= refCoversSignedProperties;
    coversData |= refIsData;
  }
  if (!coversData) return false;

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

  outSignedPropertiesVerified = signatureOk && coversSignedProperties;
  return signatureOk;
}

// Locates this signature's own xades:SignedProperties: the only one under
// ds:Signature/ds:Object/xades:QualifyingProperties. Null unless there is
// exactly one, so a second, attacker-added copy can never be picked up.
xmlNodePtr FindSignedProperties(xmlXPathContextPtr ctx,
                                xmlNodePtr signatureNode) {
  ctx->node = signatureNode;
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(
      BAD_CAST "./ds:Object/xades:QualifyingProperties/xades:SignedProperties",
      ctx);
  xmlNodePtr found = nullptr;
  if (obj && obj->type == XPATH_NODESET && obj->nodesetval &&
      obj->nodesetval->nodeNr == 1) {
    found = obj->nodesetval->nodeTab[0];
  }
  if (obj) xmlXPathFreeObject(obj);
  return found;
}

// Verifies xades:SigningCertificate/xades:Cert[1]/xades:CertDigest inside
// @p signedPropertiesNode against the actual signer certificate, as ETSI TS
// 101 903 requires. Supported digest algorithms: sha1, sha256 (same set as
// ds:Reference digests). Only meaningful once a signed ds:Reference covers
// @p signedPropertiesNode.
bool VerifySigningCertificateDigest(xmlXPathContextPtr ctx,
                                    xmlNodePtr signedPropertiesNode,
                                    CCertificate* pCert) {
  if (!pCert || !signedPropertiesNode) return false;

  ctx->node = signedPropertiesNode;
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(
      BAD_CAST
      "./xades:SignedSignatureProperties/xades:SigningCertificate/"
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

XAdESDoc::~XAdESDoc() {
  if (ppSignatures) {
    // ppSignatures is an array of nSignatures pointers; entries not yet
    // created (parse aborted part-way) are null.
    for (int i = 0; i < nSignatures; i++) {
      if (!ppSignatures[i]) continue;
      SAFEDELETE(ppSignatures[i]->pX509Cert);
      SAFEDELETE(ppSignatures[i]);
    }
    delete[] ppSignatures;
    ppSignatures = nullptr;
  }

  if (pXmlDoc) {
    xmlFreeDoc(pXmlDoc);
    pXmlDoc = nullptr;
  }
}

CXAdESVerifier::~CXAdESVerifier(void) { SAFEDELETE(m_pXAdESDoc); }

const SignatureInfo* CXAdESVerifier::GetSignatureInfo(int index) const {
  if (!m_pXAdESDoc || !m_pXAdESDoc->ppSignatures || index < 0 ||
      index >= m_pXAdESDoc->nSignatures) {
    return nullptr;
  }
  return m_pXAdESDoc->ppSignatures[index];
}

CCertificate* CXAdESVerifier::GetCertificate(int index) {
  const SignatureInfo* pSignatureInfo = GetSignatureInfo(index);
  return pSignatureInfo ? pSignatureInfo->pX509Cert : nullptr;
}

CASN1ObjectIdentifier CXAdESVerifier::GetDigestAlgorithm(int index) {
  const SignatureInfo* pSignatureInfo = GetSignatureInfo(index);
  if (!pSignatureInfo) return CASN1ObjectIdentifier(szSHA1OID);

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

  // Fail closed: a signature without a signer certificate (or an index that
  // does not name a signature) verifies nothing.
  const SignatureInfo* pSignatureInfo = GetSignatureInfo(index);
  if (!pSignatureInfo || !pSignatureInfo->pX509Cert) return 0;

  int bitmask = 0;

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

  // verify the certificate chain

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
      xmlNodePtr signedPropertiesNode =
          FindSignedProperties(xpathCtx, pSignatureInfo->pSignatureNode);
      if (VerifyXmlDSigSignature(
              xpathCtx, pSignatureInfo->pSignatureNode, signedPropertiesNode,
              pSignatureInfo->pX509Cert, pSignatureInfo->sigValue,
              bSignedPropertiesVerified)) {
        bitmask |= VERIFIED_SIGNATURE;
      }

      if (bSignedPropertiesVerified) {
        bitmask |= VERIFIED_SIGNED_ATTRIBUTE_MD;
      }

      // The certificate digest is only trustworthy if a verified reference
      // covers the SignedProperties element it was read from.
      if (pSignatureInfo->bCAdES && bSignedPropertiesVerified &&
          VerifySigningCertificateDigest(xpathCtx, signedPropertiesNode,
                                         pSignatureInfo->pX509Cert)) {
        bitmask |= VERIFIED_SIGNED_ATTRIBUTE_SC;
      }

      xmlXPathFreeContext(xpathCtx);
    }
  }

  return bitmask;
}

long CXAdESVerifier::Load(char* szFilename) {
  SAFEDELETE(m_pXAdESDoc);
  m_pXAdESDoc = parseXAdESFile(szFilename);
  if (!m_pXAdESDoc) return CIE_SIGN_ERROR_INVALID_FILE;

  // A ds:Signature that yielded no signer certificate cannot be reported or
  // verified; refuse the whole file rather than expose a half-parsed entry.
  for (int i = 0; i < m_pXAdESDoc->nSignatures; i++) {
    const SignatureInfo* pSignatureInfo = GetSignatureInfo(i);
    if (!pSignatureInfo || !pSignatureInfo->pX509Cert) {
      SAFEDELETE(m_pXAdESDoc);
      return CIE_SIGN_ERROR_INVALID_FILE;
    }
  }
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
    // A false return (a signature without a usable certificate) is picked
    // up by Load(), which checks every entry.
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

bool CXAdESVerifier::parseSignatureNode(xmlXPathContextPtr xpathCtx,
                                        xmlNodeSetPtr signatureNodes,
                                        XAdESDoc* pXAdESDoc) {
  // One pointer per signature, null-initialised so the destructor can run
  // even if parsing of a later signature throws.
  pXAdESDoc->ppSignatures = new SignatureInfo*[signatureNodes->nodeNr]();
  pXAdESDoc->nSignatures = signatureNodes->nodeNr;

  bool allParsed = true;

  for (int i = 0; i < signatureNodes->nodeNr; i++) {
    SignatureInfo* pInfo = new SignatureInfo();
    pXAdESDoc->ppSignatures[i] = pInfo;

    xmlNodePtr signatureNode = signatureNodes->nodeTab[i];
    pInfo->pSignatureNode = signatureNode;

    // Every lookup is relative to this ds:Signature node. The document's
    // Id attributes are attacker controlled (duplicates, quotes), so they
    // are never used to locate a signature's children.
    xpathCtx->node = signatureNode;

    // SignatureMethod
    std::string sigMethod;
    if (EvalSingleString(xpathCtx,
                         "./ds:SignedInfo/ds:SignatureMethod/@Algorithm",
                         sigMethod)) {
      if (sigMethod.find("sha256") != std::string::npos) {
        pInfo->nDigestAlgo = CIE_SIGN_ALGO_SHA256;
      } else if (sigMethod.find("sha512") != std::string::npos) {
        pInfo->nDigestAlgo = CIE_SIGN_ALGO_SHA512;
      } else if (sigMethod.find("sha1") != std::string::npos) {
        pInfo->nDigestAlgo = CIE_SIGN_ALGO_SHA1;
      }
    }

    // SignatureValue
    std::string sigValue;
    if (EvalSingleString(xpathCtx, "./ds:SignatureValue", sigValue)) {
      pInfo->sigValue.append(ByteArray(
          reinterpret_cast<const BYTE*>(sigValue.data()), sigValue.size()));
    }

    // X509Certificate
    std::string certB64;
    if (EvalFirstString(xpathCtx, "./ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                        certB64) &&
        !certB64.empty()) {
      try {
        ByteDynArray content(ByteArray(
            reinterpret_cast<const BYTE*>(certB64.data()), certB64.size()));
        pInfo->pX509Cert = CCertificate::createCertificate(content);
      } catch (...) {
        pInfo->pX509Cert = nullptr;
      }
    }
    if (!pInfo->pX509Cert) allParsed = false;

    // QualifyingProperties
    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(
        BAD_CAST "./ds:Object/xades:QualifyingProperties", xpathCtx);
    if (xpathObj) {
      pInfo->bCAdES = xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0;
      xmlXPathFreeObject(xpathObj);
    }
  }

  return allParsed;
}
