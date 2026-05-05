// SPDX-License-Identifier: LGPL-3.0-or-later

#include "cie_signer.h"

#include <openssl/obj_mac.h>

#include <cstring>

#include "pkcs11/cryptoki.h"
extern "C" {
void make_digest_info(int algid, unsigned char* pbtDigest, size_t btDigestLen,
                      unsigned char* pbtDigestInfo, size_t* pbtDigestInfoLen);
}

CCIESigner::CCIESigner(IAS* pIAS) : m_pIAS(pIAS), m_szPIN("") {}

CCIESigner::~CCIESigner(void) = default;

long CCIESigner::Init(const char* szPIN) {
  snprintf(m_szPIN, sizeof(m_szPIN), "%s", szPIN);

  LOG_DBG((0, "Init CIESigner\n", ""));

  try {
    m_pIAS->SelectAID_IAS();
    m_pIAS->SelectAID_CIE();
    m_pIAS->InitDHParam();

    ByteDynArray data;
    m_pIAS->ReadDappPubKey(data);
    m_pIAS->InitExtAuthKeyParam();
    m_pIAS->DHKeyExchange();
    m_pIAS->DAPP();

    ByteArray baPIN(reinterpret_cast<const uint8_t*>(szPIN), strlen(szPIN));
    StatusWord sw = m_pIAS->VerifyPIN(baPIN);

    if (sw != 0x9000) {
      LOG_ERR((0, "<-- CCIESigner::Init", "VerifyPIN failed: %x", sw));
      return sw;
    }

    LOG_DBG((0, "<-- CCIESigner::Init", "OK"));

    return 0;
  } catch (const scard_error& err) {
    LOG_ERR((0, "<-- CCIESigner::Init", "failed: %x", err.sw));

    return err.sw;
  } catch (...) {
    LOG_ERR((0, "<-- CCIESigner::Init", "unexpected failure"));
    return -1;
  }

  return 0;
}

long CCIESigner::GetCertificate(const char* /*szAlias*/,
                                CCertificate** ppCertificate,
                                ByteDynArray& id) {
  id.push(static_cast<BYTE>('1'));

  LOG_DBG((0, "--> CCIESigner::GetCertificate", "Called"));

  ByteDynArray c;
  m_pIAS->ReadCertCIE(c);

  *ppCertificate = new CCertificate(c.data(), c.size());  // caller owns

  LOG_DBG((0, "<-- CCIESigner::GetCertificate", "OK"));

  return CKR_OK;
}

long CCIESigner::Sign(ByteDynArray& data, ByteDynArray& /*id*/, int algo,
                      ByteDynArray& signature) {
  LOG_DBG((0, "--> CCIESigner::Sign", "algo: %d", algo));

  try {
    // DigestInfo
    unsigned char digestinfo[256];
    size_t digestinfolen = 256;
    // TODO digest info
    switch (algo) {
      case CKM_SHA256_RSA_PKCS:
        make_digest_info(NID_sha256, const_cast<unsigned char*>(data.data()),
                         static_cast<size_t>(data.size()), digestinfo,
                         &digestinfolen);

        break;

      case CKM_SHA1_RSA_PKCS:
        make_digest_info(NID_sha1, const_cast<unsigned char*>(data.data()),
                         static_cast<size_t>(data.size()), digestinfo,
                         &digestinfolen);
        break;

      case CKM_RSA_PKCS:
        digestinfolen = data.size();
        memcpy(digestinfo, data.data(), digestinfolen);
        break;
    }

    ByteArray baDigestInfo(digestinfo, digestinfolen);
    ByteDynArray baSignature;

    m_pIAS->Sign(baDigestInfo, baSignature);

    signature.append(
        ByteArray(baSignature.data(), static_cast<int>(baSignature.size())));
  } catch (const scard_error& err) {
    return err.sw;
  } catch (...) {
    return -1;
  }

  return CKR_OK;
}

long CCIESigner::Close() { return 0; }
