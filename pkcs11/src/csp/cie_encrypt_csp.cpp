// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// cie_encrypt_csp.cpp — RSA-OAEP encryption using the CIE card's public key.
//
// Does NOT require the card to be present. Reads the enrolled certificate
// from the local cache (via cie_get_certificate), extracts the RSA public
// key, and encrypts the input file with RSA-OAEP (SHA-256).
// For large files, generates a random AES-256 key, encrypts the file with
// AES-256-GCM, then RSA-OAEP encrypts the AES key. Output format:
//   [4 bytes big-endian:
//   encrypted_key_len][encrypted_key][iv(12)][tag(16)][ciphertext]

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "logger/logger.h"
#include "opencie/cie_ext.h"
#include "pkcs11/pkcs11_functions.h"
#include "util/util_exception.h"

using namespace CieIDLogger;

extern "C" CK_RV CK_ENTRY cie_encrypt(const char* pan, const char* inFilePath,
                                      const char* outFilePath,
                                      PROGRESS_CALLBACK progressCallBack) {
  LOG_INFO("****** Starting cie_encrypt ******");

  if (pan == nullptr || inFilePath == nullptr || outFilePath == nullptr) {
    LOG_ERROR("cie_encrypt - NULL argument");
    return CKR_ARGUMENTS_BAD;
  }

  std::unique_ptr<unsigned char, decltype(&free)> derBuf(nullptr, free);
  X509* cert = nullptr;
  EVP_PKEY* pkey = nullptr;

  try {
    // Step 1: Load certificate
    progressCallBack(10, "Loading certificate...");
    unsigned char* derBufRaw = nullptr;
    unsigned long derLen = 0;
    CK_RV ret = cie_get_certificate(pan, &derBufRaw, &derLen);
    if (ret != CKR_OK) {
      LOG_ERROR("cie_encrypt - Failed to get certificate");
      return ret;
    }
    derBuf.reset(derBufRaw);

    // Parse certificate with OpenSSL
    const unsigned char* p = derBufRaw;
    cert = d2i_X509(nullptr, &p, derLen);
    if (cert == nullptr) {
      LOG_ERROR("cie_encrypt - Failed to parse X.509 certificate");
      return CKR_FUNCTION_FAILED;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == nullptr) {
      LOG_ERROR("cie_encrypt - Failed to extract public key from certificate");
      X509_free(cert);
      return CKR_FUNCTION_FAILED;
    }

    // Step 2: Read input file
    progressCallBack(30, "Reading file...");
    FILE* fp = fopen(inFilePath, "rb");
    if (fp == nullptr) {
      LOG_ERROR("cie_encrypt - Failed to open input file: %s", inFilePath);
      EVP_PKEY_free(pkey);
      X509_free(cert);
      return CKR_DEVICE_ERROR;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize < 0) {
      LOG_ERROR("cie_encrypt - Failed to get file size");
      fclose(fp);
      EVP_PKEY_free(pkey);
      X509_free(cert);
      return CKR_DEVICE_ERROR;
    }

    std::vector<unsigned char> fileData;
    if (fileSize > 0) {
      fileData.resize(static_cast<size_t>(fileSize));
      size_t bytesRead = fread(fileData.data(), 1, fileSize, fp);
      if (bytesRead != static_cast<size_t>(fileSize)) {
        LOG_ERROR("cie_encrypt - Failed to read file");
        fclose(fp);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_DEVICE_ERROR;
      }
    }
    fclose(fp);

    progressCallBack(50, "Encrypting...");
    int rsaSize = EVP_PKEY_get_size(pkey);
    std::vector<unsigned char> outData;

    // Check if we can do direct RSA-OAEP encryption
    // RSA-OAEP with SHA-256 needs at least 2*32 + 2 = 66 bytes overhead
    if (static_cast<int>(fileData.size()) <= (rsaSize - 42)) {
      // Direct RSA-OAEP encryption
      EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
      if (pctx == nullptr || EVP_PKEY_encrypt_init(pctx) != 1 ||
          EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1) {
        LOG_ERROR("cie_encrypt - EVP_PKEY_CTX initialization failed");
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      std::vector<unsigned char> encrypted(rsaSize);
      size_t encLen = static_cast<size_t>(rsaSize);
      if (EVP_PKEY_encrypt(pctx, encrypted.data(), &encLen, fileData.data(),
                           fileData.size()) != 1) {
        LOG_ERROR("cie_encrypt - EVP_PKEY_encrypt failed");
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      EVP_PKEY_CTX_free(pctx);
      outData.insert(outData.end(), encrypted.begin(),
                     encrypted.begin() + encLen);
    } else {
      // Hybrid AES-256-GCM + RSA-OAEP
      unsigned char aesKey[32];
      unsigned char iv[12];
      unsigned char tag[16];

      // Generate random AES key and IV
      if (RAND_bytes(aesKey, 32) != 1 || RAND_bytes(iv, 12) != 1) {
        LOG_ERROR("cie_encrypt - RAND_bytes failed");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }

      // Encrypt file with AES-256-GCM
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (ctx == nullptr) {
        LOG_ERROR("cie_encrypt - EVP_CIPHER_CTX_new failed");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }

      std::vector<unsigned char> ciphertext(fileData.size() + 16);
      int cipherLen = 0;
      int tmpLen = 0;

      if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aesKey, iv) !=
          1) {
        LOG_ERROR("cie_encrypt - EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }

      if (EVP_EncryptUpdate(ctx, ciphertext.data(), &tmpLen, fileData.data(),
                            fileData.size()) != 1) {
        LOG_ERROR("cie_encrypt - EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      cipherLen = tmpLen;

      if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + cipherLen, &tmpLen) !=
          1) {
        LOG_ERROR("cie_encrypt - EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      cipherLen += tmpLen;

      // Get the authentication tag
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        LOG_ERROR("cie_encrypt - EVP_CIPHER_CTX_ctrl GET_TAG failed");
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      EVP_CIPHER_CTX_free(ctx);

      // RSA-OAEP encrypt the AES key
      EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
      if (pctx == nullptr || EVP_PKEY_encrypt_init(pctx) != 1 ||
          EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1) {
        LOG_ERROR(
            "cie_encrypt - EVP_PKEY_CTX initialization for AES key failed");
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      std::vector<unsigned char> encryptedKey(rsaSize);
      size_t encKeyLen = static_cast<size_t>(rsaSize);
      if (EVP_PKEY_encrypt(pctx, encryptedKey.data(), &encKeyLen, aesKey, 32) !=
          1) {
        LOG_ERROR("cie_encrypt - EVP_PKEY_encrypt for AES key failed");
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }
      EVP_PKEY_CTX_free(pctx);

      // Build output: [4 bytes BE
      // len][encrypted_key][iv(12)][tag(16)][ciphertext]
      uint32_t keyLenBE = htonl(encKeyLen);
      outData.insert(outData.end(), reinterpret_cast<unsigned char*>(&keyLenBE),
                     reinterpret_cast<unsigned char*>(&keyLenBE) + 4);
      outData.insert(outData.end(), encryptedKey.begin(),
                     encryptedKey.begin() + encKeyLen);
      outData.insert(outData.end(), iv, iv + 12);
      outData.insert(outData.end(), tag, tag + 16);
      outData.insert(outData.end(), ciphertext.begin(),
                     ciphertext.begin() + cipherLen);
    }

    // Step 3: Write output file
    progressCallBack(80, "Writing encrypted file...");
    FILE* outFp = fopen(outFilePath, "wb");
    if (outFp == nullptr) {
      LOG_ERROR("cie_encrypt - Failed to open output file: %s", outFilePath);
      EVP_PKEY_free(pkey);
      X509_free(cert);
      return CKR_DEVICE_ERROR;
    }

    size_t bytesWritten = fwrite(outData.data(), 1, outData.size(), outFp);
    fclose(outFp);

    if (bytesWritten != outData.size()) {
      LOG_ERROR("cie_encrypt - Failed to write encrypted file");
      EVP_PKEY_free(pkey);
      X509_free(cert);
      return CKR_DEVICE_ERROR;
    }

    progressCallBack(100, "OK!");
    LOG_INFO("cie_encrypt - completed successfully");

    EVP_PKEY_free(pkey);
    X509_free(cert);
    return SCARD_S_SUCCESS;

  } catch (const std::exception& ex) {
    LOG_ERROR("cie_encrypt - Exception: %s", ex.what());
    if (pkey != nullptr) EVP_PKEY_free(pkey);
    if (cert != nullptr) X509_free(cert);
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("cie_encrypt - Unknown exception");
    if (pkey != nullptr) EVP_PKEY_free(pkey);
    if (cert != nullptr) X509_free(cert);
    return CKR_GENERAL_ERROR;
  }
}
