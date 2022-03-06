#include "crypto/aes.h"

#include <openssl/evp.h>

extern CLog Log;

static const EVP_CIPHER *aes_cbc_cipher(size_t keyLen) {
  switch (keyLen) {
    case 16:
      return EVP_aes_128_cbc();
    case 24:
      return EVP_aes_192_cbc();
    case 32:
      return EVP_aes_256_cbc();
    default:
      return nullptr;
  }
}

ByteDynArray CAES::AES(const ByteArray &data, int encOp) {
  init_func

      ByteDynArray iv2 = iv;

  const EVP_CIPHER *cipher = aes_cbc_cipher(key.size());
  ER_ASSERT(cipher != nullptr, "Dimensione chiave AES non valida");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ER_ASSERT(ctx != nullptr, "Errore allocazione contesto EVP");

  size_t AppSize = data.size() - 1;
  ByteDynArray resp(AppSize - (AppSize % 16) + 16);

  int outLen = 0;
  int finalLen = 0;
  int rc;

  if (encOp == AES_ENCRYPT) {
    rc = EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv2.data());
    ER_ASSERT(rc == 1, "Errore inizializzazione cifratura AES");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    rc = EVP_EncryptUpdate(ctx, resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Errore cifratura AES");
    EVP_EncryptFinal_ex(ctx, resp.data() + outLen, &finalLen);
  } else {
    rc = EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv2.data());
    ER_ASSERT(rc == 1, "Errore inizializzazione decifratura AES");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    rc = EVP_DecryptUpdate(ctx, resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Errore decifratura AES");
    EVP_DecryptFinal_ex(ctx, resp.data() + outLen, &finalLen);
  }

  EVP_CIPHER_CTX_free(ctx);

  return resp;
}
void CAES::Init(const ByteArray &key, const ByteArray &iv) {
  init_func this->iv = iv;
  this->key = key;

  exit_func
}

CAES::CAES() {}

CAES::~CAES(void) {}

CAES::CAES(const ByteArray &key, const ByteArray &iv) { Init(key, iv); }

ByteDynArray CAES::Encode(const ByteArray &data) {
  init_func return AES(ISOPad16(data), AES_ENCRYPT);
}

ByteDynArray CAES::RawEncode(const ByteArray &data) {
  init_func ER_ASSERT(
      (data.size() % AES_BLOCK_SIZE) == 0,
      "La dimensione dei dati da cifrare deve essere multipla di 16");
  return AES(data, AES_ENCRYPT);
}

ByteDynArray CAES::Decode(const ByteArray &data) {
  init_func ByteDynArray result = AES(data, AES_DECRYPT);
  result.resize(RemoveISOPad(result), true);
  return result;
}

ByteDynArray CAES::RawDecode(const ByteArray &data) {
  init_func ER_ASSERT(
      (data.size() % AES_BLOCK_SIZE) == 0,
      "La dimensione dei dati da cifrare deve essere multipla di 16");
  return AES(data, AES_DECRYPT);
}
