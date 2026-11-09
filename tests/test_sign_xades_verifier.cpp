// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Regression tests for CXAdESVerifier on crafted XML (SDK-F4/F5/F7/F8):
// multiple ds:Signature elements, missing/hostile @Id, malformed
// SignatureMethod, duplicate Ids and reference coverage. Signed documents
// are built in-process with a throwaway RSA key, so no fixtures or hardware
// are needed.
#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "sign/cie_sign_api.h"
#include "xades_verifier.h"

namespace {

constexpr const char* kNsDs = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char* kC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
constexpr const char* kEnveloped =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char* kSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
constexpr const char* kRsaSha256 =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
constexpr const char* kTypeSignedProperties =
    "http://uri.etsi.org/01903#SignedProperties";

std::string B64(const unsigned char* data, size_t len) {
  std::string out(4 * ((len + 2) / 3) + 1, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                          static_cast<int>(len));
  out.resize(static_cast<size_t>(n));
  return out;
}

std::string Sha256B64(const std::string& data) {
  unsigned char md[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
  return B64(md, sizeof(md));
}

// Throwaway signer: self-signed certificate + RSA key, generated once.
struct TestSigner {
  EVP_PKEY* key = nullptr;
  std::string certB64;
  std::string certDigestB64;

  TestSigner() {
    key = EVP_RSA_gen(2048);
    REQUIRE(key);
    X509* x = X509_new();
    REQUIRE(x);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    // Built separately: X509_get_subject_name() returns const in OpenSSL 4.
    // auto: wincrypt.h defines X509_NAME as a macro on Windows.
    auto* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("OpenCIE XAdES Test"), -1, -1,
        0);
    X509_set_subject_name(x, name);
    X509_set_issuer_name(x, name);
    X509_NAME_free(name);
    REQUIRE(X509_sign(x, key, EVP_sha256()) > 0);

    unsigned char* der = nullptr;
    int len = i2d_X509(x, &der);
    REQUIRE(len > 0);
    certB64 = B64(der, static_cast<size_t>(len));
    certDigestB64 =
        Sha256B64(std::string(reinterpret_cast<char*>(der), size_t(len)));
    OPENSSL_free(der);
    X509_free(x);
  }
  ~TestSigner() { EVP_PKEY_free(key); }

  std::string Sign(const std::string& data) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    REQUIRE(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);
    size_t siglen = 0;
    REQUIRE(EVP_DigestSign(ctx, nullptr, &siglen,
                           reinterpret_cast<const unsigned char*>(data.data()),
                           data.size()) == 1);
    std::vector<unsigned char> sig(siglen);
    REQUIRE(EVP_DigestSign(ctx, sig.data(), &siglen,
                           reinterpret_cast<const unsigned char*>(data.data()),
                           data.size()) == 1);
    EVP_MD_CTX_free(ctx);
    return B64(sig.data(), siglen);
  }
};

const TestSigner& Signer() {
  static TestSigner signer;
  return signer;
}

struct XmlDoc {
  xmlDocPtr doc = nullptr;
  explicit XmlDoc(const std::string& xml) {
    doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), "t.xml",
                        nullptr, 0);
  }
  ~XmlDoc() {
    if (doc) xmlFreeDoc(doc);
  }
};

// Canonical XML 1.0 of the node-set selected by `expr` evaluated with
// `node` as the context node.
std::string C14N(xmlDocPtr doc, xmlNodePtr node, const char* expr) {
  xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
  REQUIRE(ctx);
  xmlXPathRegisterNs(ctx, BAD_CAST "ds", BAD_CAST kNsDs);
  ctx->node = node;
  xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
  REQUIRE(obj);
  REQUIRE(obj->nodesetval);
  xmlChar* out = nullptr;
  int len = xmlC14NDocDumpMemory(doc, obj->nodesetval, XML_C14N_1_0, nullptr, 0,
                                 &out);
  REQUIRE(len > 0);
  std::string s(reinterpret_cast<char*>(out), static_cast<size_t>(len));
  xmlFree(out);
  xmlXPathFreeObject(obj);
  xmlXPathFreeContext(ctx);
  return s;
}

xmlNodePtr FindById(xmlNodePtr n, const std::string& id) {
  for (; n; n = n->next) {
    if (n->type != XML_ELEMENT_NODE) continue;
    xmlChar* v = xmlGetNoNsProp(n, BAD_CAST "Id");
    bool hit = v && id == reinterpret_cast<char*>(v);
    if (v) xmlFree(v);
    if (hit) return n;
    if (xmlNodePtr r = FindById(n->children, id)) return r;
  }
  return nullptr;
}

constexpr const char* kSubtreeExpr =
    "(. | .//node() | .//@* | .//namespace::*)";

struct RefSpec {
  std::string uri;
  std::string type;
};

struct SigSpec {
  std::string id = "sig1";
  std::string spId = "sp1";
  // Empty means: the data element plus this signature's own SignedProperties.
  std::vector<RefSpec> refs;
  bool keyInfo = true;
  std::string signatureMethodAttrs =
      std::string("Algorithm=\"") + kRsaSha256 + "\"";
};

const char* kDocHead =
    "<Root xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "
    "xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
    "<Data Id=\"data1\">hello</Data>";
const char* kDocTail = "</Root>";

std::vector<RefSpec> EffectiveRefs(const SigSpec& s) {
  if (!s.refs.empty()) return s.refs;
  return {{"#data1", ""}, {"#" + s.spId, kTypeSignedProperties}};
}

std::string SigBlock(const SigSpec& s) {
  std::string b = "<ds:Signature";
  if (!s.id.empty()) b += " Id=\"" + s.id + "\"";
  b += "><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"";
  b += kC14N;
  b += "\"/><ds:SignatureMethod " + s.signatureMethodAttrs + "/>";
  int n = 0;
  for (const RefSpec& r : EffectiveRefs(s)) {
    b += "<ds:Reference URI=\"" + r.uri + "\"";
    if (!r.type.empty()) b += " Type=\"" + r.type + "\"";
    b += "><ds:Transforms>";
    if (r.uri.empty()) {
      b += std::string("<ds:Transform Algorithm=\"") + kEnveloped + "\"/>";
    }
    b += std::string("<ds:Transform Algorithm=\"") + kC14N + "\"/>";
    b += std::string("</ds:Transforms><ds:DigestMethod Algorithm=\"") +
         kSha256 + "\"/><ds:DigestValue>@@D" + std::to_string(n++) +
         "@@</ds:DigestValue></ds:Reference>";
  }
  b += "</ds:SignedInfo><ds:SignatureValue>@@SIG@@</ds:SignatureValue>";
  if (s.keyInfo) {
    b += "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + Signer().certB64 +
         "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
  }
  b += "<ds:Object><xades:QualifyingProperties><xades:SignedProperties Id=\"" +
       s.spId +
       "\"><xades:SignedSignatureProperties><xades:SigningCertificate>"
       "<xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"";
  b += kSha256;
  b += "\"/><ds:DigestValue>" + Signer().certDigestB64 +
       "</ds:DigestValue></xades:CertDigest></xades:Cert>"
       "</xades:SigningCertificate></xades:SignedSignatureProperties>"
       "</xades:SignedProperties></xades:QualifyingProperties></ds:Object>"
       "</ds:Signature>";
  return b;
}

void ReplaceAll(std::string& s, const std::string& from,
                const std::string& to) {
  for (size_t p = s.find(from); p != std::string::npos;
       p = s.find(from, p + to.size())) {
    s.replace(p, from.size(), to);
  }
}

// Appends a correctly digested and signed ds:Signature described by `spec`
// to `body` (the children of Root so far) and returns the new body. Digests
// are computed over whatever the references really resolve to in the
// document at that point.
std::string AddSignature(const std::string& body, const SigSpec& spec) {
  std::string block = SigBlock(spec);
  std::string full = kDocHead + body + block + kDocTail;
  // kDocHead already contains the first child; body holds the remainder.

  {
    XmlDoc d(full);
    REQUIRE(d.doc);
    xmlNodePtr root = xmlDocGetRootElement(d.doc);
    int n = 0;
    for (const RefSpec& r : EffectiveRefs(spec)) {
      std::string canon;
      if (r.uri.empty()) {
        // Whole document minus this signature (enveloped-signature).
        std::string sigId = spec.id;
        std::string expr =
            "(//. | //@* | //namespace::*)"
            "[not(ancestor-or-self::ds:Signature[@Id='" +
            sigId + "'])]";
        canon = C14N(d.doc, root, expr.c_str());
      } else {
        xmlNodePtr target = FindById(root, r.uri.substr(1));
        REQUIRE(target);
        canon = C14N(d.doc, target, kSubtreeExpr);
      }
      ReplaceAll(full, "@@D" + std::to_string(n++) + "@@", Sha256B64(canon));
    }
  }

  {
    XmlDoc d(full);
    REQUIRE(d.doc);
    xmlNodePtr root = xmlDocGetRootElement(d.doc);
    xmlNodePtr sig = nullptr;
    for (xmlNodePtr c = root->children; c; c = c->next) {
      if (c->type == XML_ELEMENT_NODE &&
          xmlStrEqual(c->name, BAD_CAST "Signature")) {
        sig = c;  // last one is the new signature
      }
    }
    REQUIRE(sig);
    xmlNodePtr si = sig->children;
    REQUIRE(si);
    std::string canonSi =
        C14N(d.doc, si,
             "(. | @* | namespace::* | .//node() | .//@* | .//namespace::*)");
    ReplaceAll(full, "@@SIG@@", Signer().Sign(canonSi));
  }

  // Strip the head/tail again so further signatures can be appended.
  std::string head = kDocHead;
  return full.substr(head.size(),
                     full.size() - head.size() - std::string(kDocTail).size());
}

std::string WrapDoc(const std::string& body) {
  return std::string(kDocHead) + body + kDocTail;
}

struct TempFile {
  std::filesystem::path path;
  explicit TempFile(const std::string& content) {
    auto uniq =
        std::chrono::high_resolution_clock::now().time_since_epoch().count();
    path = std::filesystem::temp_directory_path() /
           ("opencie_xades_" + std::to_string(uniq) + ".xml");
    std::ofstream f(path, std::ios::binary);
    f << content;
  }
  ~TempFile() {
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }
  char* cpath() {
    str = path.string();
    return str.data();
  }
  std::string str;
};

constexpr int kFullOk = VERIFIED_SIGNATURE | VERIFIED_SIGNED_ATTRIBUTE_MD |
                        VERIFIED_SIGNED_ATTRIBUTE_SC;

// The CIE_SIGN_ERROR_* macros are unsigned long; Load() returns long.
constexpr long kInvalidFile = static_cast<long>(CIE_SIGN_ERROR_INVALID_FILE);

long LoadXml(CXAdESVerifier& v, const std::string& xml) {
  TempFile f(xml);
  return v.Load(f.cpath());
}

int Verify(CXAdESVerifier& v, int i) {
  return v.verifySignature(i, nullptr, nullptr);
}

}  // namespace

TEST_CASE("XAdES verifier accepts a well-formed signed document",
          "[xades][sanity]") {
  std::string xml = WrapDoc(AddSignature("", SigSpec {}));
  CXAdESVerifier v;
  REQUIRE(LoadXml(v, xml) == 1);
  REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
  REQUIRE(v.GetCertificate(0) != nullptr);
}

TEST_CASE("XAdES verifier handles two or more ds:Signature elements",
          "[xades][SDK-F4]") {
  SigSpec a;
  SigSpec b;
  b.id = "sig2";
  b.spId = "sp2";
  SigSpec c;
  c.id = "sig3";
  c.spId = "sp3";
  std::string body = AddSignature("", a);
  body = AddSignature(body, b);
  body = AddSignature(body, c);

  CXAdESVerifier v;
  REQUIRE(LoadXml(v, WrapDoc(body)) == 3);
  for (int i = 0; i < 3; i++) {
    REQUIRE(v.GetCertificate(i) != nullptr);
    INFO("signature " << i << " bits " << std::hex << Verify(v, i));
    REQUIRE((Verify(v, i) & kFullOk) == kFullOk);
  }
  // Out-of-range indexes are refused, not dereferenced.
  REQUIRE(v.GetCertificate(3) == nullptr);
  REQUIRE(v.GetCertificate(-1) == nullptr);
  REQUIRE(Verify(v, 3) == 0);

  // Loading again on the same verifier releases the previous document.
  REQUIRE(LoadXml(v, WrapDoc(AddSignature("", a))) == 1);
}

TEST_CASE("XAdES verifier survives crafted signature metadata",
          "[xades][SDK-F5]") {
  SECTION("SignatureMethod without attributes") {
    SigSpec s;
    s.signatureMethodAttrs = "";
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("SignatureMethod with an empty attribute") {
    SigSpec s;
    s.signatureMethodAttrs = "Algorithm=\"\"";
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("SignatureMethod attribute is an entity reference") {
    SigSpec s;
    s.signatureMethodAttrs = "Algorithm=\"&amp;\"";
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("signature without Id is still parsed from its own node") {
    SigSpec s;
    s.id = "";
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
  }

  SECTION("signature without a certificate fails to load, cleanly") {
    SigSpec s;
    s.keyInfo = false;
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == kInvalidFile);
    REQUIRE(v.GetCertificate(0) == nullptr);
    REQUIRE(Verify(v, 0) == -1);
  }

  SECTION("unparseable certificate text fails to load, cleanly") {
    std::string xml = WrapDoc(AddSignature("", SigSpec {}));
    ReplaceAll(xml, Signer().certB64, "!!!not-base64-or-der!!!");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == kInvalidFile);
  }

  SECTION("empty X509Certificate and missing SignedInfo") {
    std::string xml = WrapDoc(
        "<ds:Signature Id=\"s\"><ds:KeyInfo><ds:X509Data>"
        "<ds:X509Certificate/></ds:X509Data></ds:KeyInfo>"
        "</ds:Signature>");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == kInvalidFile);
  }
}

TEST_CASE("XAdES verifier does not build XPath from Id values",
          "[xades][SDK-F7]") {
  SECTION("quote in a signature Id") {
    SigSpec s;
    s.id = "a&apos; or &apos;1&apos;=&apos;1";
    // The reference digests do not depend on the signature Id here.
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
  }

  SECTION("very long signature Id") {
    SigSpec s;
    s.id = std::string(5000, 'x');
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
  }

  SECTION("duplicate signature Ids do not make signatures share material") {
    SigSpec a;
    a.id = "dup";
    SigSpec b;
    b.id = "dup";
    b.spId = "sp2";
    std::string body = AddSignature("", a);
    // The second block has its own SignedInfo, SignatureValue, certificate
    // and QualifyingProperties; tamper its SignatureValue so any
    // cross-signature mixing would be visible.
    body = AddSignature(body, b);
    std::string xml = WrapDoc(body);
    size_t second = xml.rfind("<ds:SignatureValue>");
    REQUIRE(second != std::string::npos);
    xml.insert(second + std::string("<ds:SignatureValue>").size(), "AAAA");

    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == 2);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) != 0);
    REQUIRE((Verify(v, 1) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("reference URI with a quote does not break out") {
    // The digest oracle cannot resolve such a URI, so sign a normal
    // document and rewrite the data reference afterwards.
    std::string xml = WrapDoc(AddSignature("", SigSpec {}));
    ReplaceAll(xml, "<ds:Reference URI=\"#data1\"",
               "<ds:Reference URI=\"#x&apos;]|//*|//*[@Id=&apos;\"");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }
}

TEST_CASE("XAdES verifier enforces reference coverage", "[xades][SDK-F8]") {
  SECTION("duplicate Id on the referenced data element is rejected") {
    std::string xml = WrapDoc(AddSignature("", SigSpec {}));
    ReplaceAll(xml, "</Data>", "</Data><Data Id=\"data1\">evil</Data>");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("tampered signed content is detected") {
    std::string xml = WrapDoc(AddSignature("", SigSpec {}));
    ReplaceAll(xml, ">hello<", ">HELLO<");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == 1);
    REQUIRE((Verify(v, 0) & VERIFIED_SIGNATURE) == 0);
  }

  SECTION("a signature that only covers its SignedProperties is not valid") {
    SigSpec s;
    s.refs = {{"#sp1", kTypeSignedProperties}};
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    int bits = Verify(v, 0);
    REQUIRE((bits & VERIFIED_SIGNATURE) == 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_MD) == 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_SC) == 0);
  }

  SECTION("Type=SignedProperties pointing at other data is not accepted") {
    SigSpec s;
    s.refs = {{"#data1", kTypeSignedProperties}};
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    int bits = Verify(v, 0);
    REQUIRE((bits & VERIFIED_SIGNATURE) == 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_MD) == 0);
  }

  SECTION("SignedProperties digest is by resolved node, not by Type") {
    SigSpec s;
    s.refs = {{"#data1", ""}, {"#sp1", ""}};  // no Type attribute
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
  }

  SECTION(
      "without a covering reference the signing-certificate digest is "
      "not trusted") {
    // Reference only the data: signature is valid, but SignedProperties is
    // unsigned, so neither XAdES attribute bit may be set.
    SigSpec s;
    s.refs = {{"#data1", ""}};
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, WrapDoc(AddSignature("", s))) == 1);
    int bits = Verify(v, 0);
    REQUIRE((bits & VERIFIED_SIGNATURE) != 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_MD) == 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_SC) == 0);
  }

  SECTION("a second SignedProperties copy is never the one that is trusted") {
    // Attacker adds a second QualifyingProperties with its own
    // SignedProperties to the signature: ambiguous, so none is used.
    std::string xml = WrapDoc(AddSignature("", SigSpec {}));
    ReplaceAll(
        xml, "</ds:Object>",
        "<xades:QualifyingProperties><xades:SignedProperties Id=\"sp9\"/>"
        "</xades:QualifyingProperties></ds:Object>");
    CXAdESVerifier v;
    REQUIRE(LoadXml(v, xml) == 1);
    int bits = Verify(v, 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_MD) == 0);
    REQUIRE((bits & VERIFIED_SIGNED_ATTRIBUTE_SC) == 0);
  }

  SECTION("enveloped URI=\"\" excludes only the signature being verified") {
    SigSpec s;
    s.refs = {{"", ""}, {"#sp1", kTypeSignedProperties}};
    std::string body = AddSignature("", s);

    {
      CXAdESVerifier v;
      REQUIRE(LoadXml(v, WrapDoc(body)) == 1);
      REQUIRE((Verify(v, 0) & kFullOk) == kFullOk);
    }

    // Hide extra content inside an additional ds:Signature: it is part of
    // the document as far as the first signature is concerned, so its
    // digest must no longer match.
    SigSpec other;
    other.id = "sig2";
    other.spId = "sp2";
    std::string two = AddSignature(body, other);
    CXAdESVerifier v2;
    REQUIRE(LoadXml(v2, WrapDoc(two)) == 2);
    REQUIRE((Verify(v2, 0) & VERIFIED_SIGNATURE) == 0);
    REQUIRE((Verify(v2, 1) & kFullOk) == kFullOk);
  }
}
