#include "tsa_client.h"

#include <cstdio>
#include <cstring>

#include "asn1/time_stamp_request.h"
#include "asn1/time_stamp_response.h"
#include "asn1/time_stamp_token.h"


#include "curl/curl.h"

static size_t WriteCallback(void* contents, size_t size, size_t nmemb,
                            void* userp);

CTSAClient::CTSAClient(void) { m_szTSAUsername[0] = '\0'; }

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
  CASN1Integer nounce(1);
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

  curl_easy_setopt(ctx, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(ctx, CURLOPT_SSL_VERIFYHOST, false);

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

    return ret;
  }

  // clean up
  curl_slist_free_all(headers);
  curl_easy_cleanup(ctx);

  try {
    CTimeStampResponse tsResponse(const_cast<BYTE*>(tsdata.data()),
                                  static_cast<int>(tsdata.size()));

    CPKIStatusInfo statusInfo(tsResponse.getPKIStatusInfo());

    if (statusInfo.getStatus().getIntValue() == 0) {
      *ppTimeStampToken = new CTimeStampToken(tsResponse.getTimeStampToken());
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
