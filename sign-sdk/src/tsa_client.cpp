// SPDX-License-Identifier: LGPL-3.0-or-later
#include "tsa_client.h"

#include <openssl/crypto.h>

#include <cstdio>
#include <cstring>

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_octet_string.h"
#include "asn1/time_stamp_request.h"
#include "asn1/time_stamp_response.h"
#include "asn1/time_stamp_token.h"
#include "curl/curl.h"

extern char g_szResolveList[4096];

static size_t WriteCallback(void* contents, size_t size, size_t nmemb,
                            void* userp);

// RFC 3161 Section 2.4.2: TSTInfo ::= SEQUENCE { version, policy,
// messageImprint, serialNumber, genTime, accuracy OPTIONAL,
// ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL,
// extensions [1] OPTIONAL }. version/policy/messageImprint/serialNumber/
// genTime always occupy elements 0..4 (CTSTInfo::getUTCTime() already
// relies on genTime being element 4); nonce, when present, is the first
// plain INTEGER (tag 0x02) after that, before the context-tagged tsa/
// extensions fields -- the same scanning approach CTSTInfo::getTSAName()
// already uses for the tsa field.
static bool TSTInfoNonceMatches(CTSTInfo& tstInfo,
                                const CASN1Integer& sentNonce) {
  unsigned int siz = tstInfo.size();
  for (unsigned int i = 5; i < siz; i++) {
    CASN1Object obj = tstInfo.elementAt(i);
    BYTE tag = obj.getTag();
    if (tag == 0x02) return CASN1Integer(obj) == sentNonce;
    if (tag == 0xA0 || tag == 0xA1) break;  // reached tsa/extensions: no nonce
  }
  // We always send a nonce (see GetTimeStampToken below); RFC 3161 requires
  // a compliant TSA to echo it back, so a response without one is rejected.
  return false;
}

// Confirms the token's MessageImprint (hash algorithm + hashed message)
// matches what we actually asked to be timestamped, so a TSA cannot bind
// its timestamp to a different digest than the caller requested.
static bool TSTInfoMessageImprintMatches(CTSTInfo& tstInfo,
                                         const ByteDynArray& expectedDigest) {
  if (expectedDigest.size() == 0) return false;

  CASN1Sequence messageImprint = tstInfo.getMessageImprint();
  CAlgorithmIdentifier expectedAlgo(szSHA256OID);
  if (!(messageImprint.elementAt(0) == expectedAlgo.elementAt(0))) return false;

  CASN1OctetString hashedMessage(messageImprint.elementAt(1));
  const ByteDynArray* pDigest = hashedMessage.getValue();
  return pDigest != nullptr && pDigest->size() == expectedDigest.size() &&
         CRYPTO_memcmp(pDigest->data(), expectedDigest.data(),
                       expectedDigest.size()) == 0;
}

CTSAClient::CTSAClient(void) : m_szTSAUrl(""), m_szTSAPassword("") {
  m_szTSAUsername[0] = '\0';
}

CTSAClient::~CTSAClient(void) {}

void CTSAClient::SetTSAUrl(const char* szUrl) {
  snprintf(m_szTSAUrl, sizeof(m_szTSAUrl), "%s", szUrl);
}

void CTSAClient::SetCredential(const char* szUsername, const char* szPassword) {
  snprintf(m_szTSAUsername, sizeof(m_szTSAUsername), "%s", szUsername);
  snprintf(m_szTSAPassword, sizeof(m_szTSAPassword), "%s", szPassword);
}

void CTSAClient::SetUsername(const char* szUsername) {
  snprintf(m_szTSAUsername, sizeof(m_szTSAUsername), "%s", szUsername);
}

void CTSAClient::SetPassword(const char* szPassword) {
  snprintf(m_szTSAPassword, sizeof(m_szTSAPassword), "%s", szPassword);
}

long CTSAClient::GetTimeStampToken(ByteDynArray& digest, const char* szPolicyID,
                                   CTimeStampToken** ppTimeStampToken) {
  // RFC 3161 nonce: random 64-bit value so each request is unique and the
  // response can be bound to it (replay protection). Constrain the first
  // byte to [0x01, 0x7f] to keep the DER INTEGER positive and minimal.
  ByteDynArray nonceBytes(8);
  nonceBytes.random();
  nonceBytes[0] = (nonceBytes[0] & 0x7f) | 0x01;
  CASN1Integer nounce(nonceBytes.data(),
                      static_cast<unsigned int>(nonceBytes.size()));
  CTimeStampRequest request(szSHA256OID, digest, szPolicyID, nounce);

  ByteDynArray tsaRequest;
  request.toByteArray(tsaRequest);

  ByteDynArray tsdata;

  // general initilization
  CURL* ctx = curl_easy_init();

  // set URL
  curl_easy_setopt(ctx, CURLOPT_URL, m_szTSAUrl);

  // set POST method
  curl_easy_setopt(ctx, CURLOPT_POST, 1);

  // give the data you want to post
  curl_easy_setopt(ctx, CURLOPT_POSTFIELDS, tsaRequest.data());

  // give the data lenght
  curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE, tsaRequest.size());

  // show messages for debugging
  // curl_easy_setopt(ctx, CURLOPT_VERBOSE);

  // set the callback function that handle the data return from server
  // if you don't set this, the return data just show up on the screen
  // size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
  curl_easy_setopt(ctx, CURLOPT_WRITEFUNCTION, WriteCallback);

  // we pass our 'chunk' struct to the callback function
  curl_easy_setopt(ctx, CURLOPT_WRITEDATA, static_cast<void*>(&tsdata));

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
    const char* szUrl = m_szTSAUrl;
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
                  resolve_list = curl_slist_append(resolve_list, buf);
                }
              }
            }
          }
          if (!comma) break;
          entry = comma + 1;
        }
        if (resolve_list) curl_easy_setopt(ctx, CURLOPT_RESOLVE, resolve_list);
      }
    }
  }

  struct curl_slist* headers = nullptr;
  headers =
      curl_slist_append(headers, "Content-Type: application/timestamp-query");

  // talor the header to application/binary
  if (m_szTSAUsername[0]) {
    curl_easy_setopt(ctx, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

    curl_easy_setopt(ctx, CURLOPT_USERNAME, m_szTSAUsername);

    curl_easy_setopt(ctx, CURLOPT_PASSWORD, m_szTSAPassword);
  }

  curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers);

  // let's do it...
  CURLcode ret = curl_easy_perform(ctx);

  // Check for errors
  if (ret != CURLE_OK) {
    LOG_MSG((0, "HTTPRequest", "error: %x", ret));
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(ret));
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_slist_free_all(headers);
    curl_easy_cleanup(ctx);
    return ret;
  }

  // clean up
  curl_slist_free_all(headers);
  if (resolve_list) curl_slist_free_all(resolve_list);
  curl_easy_cleanup(ctx);

  try {
    CTimeStampResponse tsResponse(const_cast<BYTE*>(tsdata.data()),
                                  static_cast<int>(tsdata.size()));

    CPKIStatusInfo statusInfo(tsResponse.getPKIStatusInfo());

    if (statusInfo.getStatus().getIntValue() == 0) {
      CTimeStampToken token(tsResponse.getTimeStampToken());
      CTSTInfo tstInfo = token.getTSTInfo();

      if (!TSTInfoNonceMatches(tstInfo, nounce)) {
        LOG_ERR((0, "TSACLient",
                 "GetTimeStampToken: nonce mismatch, rejecting response"));
        *ppTimeStampToken = nullptr;
      } else if (!TSTInfoMessageImprintMatches(tstInfo, digest)) {
        LOG_ERR((0, "TSACLient",
                 "GetTimeStampToken: messageImprint does not match the "
                 "requested digest, rejecting response"));
        *ppTimeStampToken = nullptr;
      } else {
        *ppTimeStampToken = new CTimeStampToken(token);
      }
    } else {
      LOG_ERR((0, "TSACLient", "CPKIStatusInfo error: %x",
               statusInfo.getStatus().getIntValue()));

      *ppTimeStampToken = nullptr;
    }
  } catch (...) {
    *ppTimeStampToken = nullptr;
  }

  if (*ppTimeStampToken == nullptr) return -1;

  return 0;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb,
                            void* userp) {
  ByteDynArray* pData = static_cast<ByteDynArray*>(userp);

  size_t realsize = size * nmemb;
  pData->append(ByteArray(static_cast<BYTE*>(contents), realsize));

  return realsize;
}
