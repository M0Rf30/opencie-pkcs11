#include "crypto/des3.h"

#include <cryptopp/misc.h>
#include <openssl/evp.h>

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

extern CLog Log;

void CDES3::Init(const ByteArray &key, const ByteArray &iv) {
  init_func long KeySize = key.size();

  switch (KeySize) {
    case 8:
      throw logged_error("Chiave 3DES 8 byte non supportata");
      break;
    case 16:
    case 24:
      this->key = key;
      break;
    default:
      throw logged_error("Dimensione chiave 3DES non valida");
  }
  this->iv = iv;

  exit_func
}

CDES3::~CDES3(void) {}

CDES3::CDES3() {}

ByteDynArray CDES3::Des3(const ByteArray &data, int encOp) {
  init_func

      ByteDynArray ivCopy = iv;

  // For 16-byte keys: EVP_des_ede_cbc uses k1|k2 with k3=k1 internally
  // For 24-byte keys: EVP_des_ede3_cbc uses k1|k2|k3
  // Both are available in OpenSSL 3.x default provider (no legacy needed)
  const EVP_CIPHER *cipher;
  if (key.size() == 16)
    cipher = EVP_des_ede_cbc();
  else
    cipher = EVP_des_ede3_cbc();

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ER_ASSERT(ctx != nullptr, "Errore allocazione contesto EVP");

  size_t AppSize = data.size() - 1;
  ByteDynArray resp(AppSize - (AppSize % 8) + 8);

  int outLen = 0;
  int finalLen = 0;
  int rc;

  if (encOp == DES_ENCRYPT) {
    rc = EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), ivCopy.data());
    ER_ASSERT(rc == 1, "Errore inizializzazione cifratura 3DES");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    rc = EVP_EncryptUpdate(ctx, resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Errore cifratura 3DES");
    EVP_EncryptFinal_ex(ctx, resp.data() + outLen, &finalLen);
  } else {
    rc = EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), ivCopy.data());
    ER_ASSERT(rc == 1, "Errore inizializzazione decifratura 3DES");
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    rc = EVP_DecryptUpdate(ctx, resp.data(), &outLen, data.data(),
                           static_cast<int>(data.size()));
    ER_ASSERT(rc == 1, "Errore decifratura 3DES");
    EVP_DecryptFinal_ex(ctx, resp.data() + outLen, &finalLen);
  }

  EVP_CIPHER_CTX_free(ctx);

  return resp;
}

CDES3::CDES3(const ByteArray &key, const ByteArray &iv) { Init(key, iv); }

ByteDynArray CDES3::Encode(const ByteArray &data) {
  init_func return Des3(ISOPad(data), DES_ENCRYPT);
}

ByteDynArray CDES3::RawEncode(const ByteArray &data) {
  init_func ByteDynArray result;
  ER_ASSERT((data.size() % 8) == 0,
            "La dimensione dei dati da cifrare deve essere multipla di 8");

  return Des3(data, DES_ENCRYPT);
}

ByteDynArray CDES3::Decode(const ByteArray &data) {
  init_func auto result = Des3(data, DES_DECRYPT);
  result.resize(RemoveISOPad(result), true);
  return result;
}

ByteDynArray CDES3::RawDecode(const ByteArray &data) {
  init_func ByteDynArray result;
  ER_ASSERT((data.size() % 8) == 0,
            "La dimensione dei dati da cifrare deve essere multipla di 8");

  return Des3(data, DES_DECRYPT);
}
