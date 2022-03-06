#include "crypto/sha256.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <openssl/evp.h>

void CSHA256::Init() {
  ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  isInit = true;
}
void CSHA256::Update(ByteArray data) {
  if (!isInit) throw logged_error("Hash non inizializzato");
  EVP_DigestUpdate(ctx, data.data(), data.size());
}
ByteDynArray CSHA256::Final() {
  if (!isInit) throw logged_error("Hash non inizializzato");
  ByteDynArray resp(SHA256_DIGEST_LENGTH);
  EVP_DigestFinal_ex(ctx, resp.data(), nullptr);
  isInit = false;

  return resp;
}
ByteDynArray CSHA256::Digest(ByteArray& data) {
  const BYTE* pbData = static_cast<BYTE*>(data.data());
  unsigned int nDataLen = data.size();
  BYTE abDigest[CryptoPP::SHA256::DIGESTSIZE];
  CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
  ByteArray resp(abDigest, CryptoPP::SHA256::DIGESTSIZE);

  return resp;
}
