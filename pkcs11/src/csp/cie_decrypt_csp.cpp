// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// cie_decrypt_csp.cpp — RSA-OAEP decryption using the CIE card's private key.
//
// Requires the physical card. Uses the same PC/SC + IAS setup as
// cie_sign_csp.cpp. Sends the (possibly AES-key) ciphertext to the card
// as a raw RSA operation, then removes OAEP padding in software.
// Handles both direct RSA-OAEP and hybrid AES-256-GCM+RSA-OAEP formats
// (same format as cie_encrypt output).

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
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "csp/cie_enable.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "opencie/cie_ext.h"
#include "pcsc/pcsc.h"
#include "pkcs11/pkcs11_functions.h"
#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif
#include "util/array.h"
#include "util/util_exception.h"

using namespace CieIDLogger;

#define CARD_PAN_MISMATCH (int)(0x000000F1)

extern "C" {
CK_RV CK_ENTRY cie_decrypt(const char* inFilePath, const char* pin,
                           const char* pan, const char* outFilePath,
                           PROGRESS_CALLBACK progressCallBack);
}

CK_RV CK_ENTRY cie_decrypt(const char* inFilePath, const char* pin,
                           const char* pan, const char* outFilePath,
                           PROGRESS_CALLBACK progressCallBack) {
  LOG_INFO("****** Starting cie_decrypt ******");

  if (inFilePath == nullptr || pin == nullptr || pan == nullptr ||
      outFilePath == nullptr) {
    LOG_ERROR("cie_decrypt - NULL argument");
    return CKR_ARGUMENTS_BAD;
  }

  std::unique_ptr<char, decltype(&free)> readers(nullptr, free);
  std::unique_ptr<char, decltype(&free)> ATR(nullptr, free);
  std::unique_ptr<unsigned char, decltype(&free)> derBuf(nullptr, free);
  bool panMismatch = false;

  try {
    DWORD len = 0;
    SCARDCONTEXT hSC;

#if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_decrypt - EstablishContext error: %d\n", nRet);
      return CKR_DEVICE_ERROR;
    }
    LOG_INFO("cie_decrypt - Establish Context ok\n");

    nRet = transport->ListReaders(hSC, nullptr, &len);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_decrypt - List readers error: %d\n", nRet);
      return CKR_TOKEN_NOT_PRESENT;
    }

    if (len == 1) return CKR_TOKEN_NOT_PRESENT;

    readers.reset(static_cast<char*>(malloc(len)));

    if (transport->ListReaders(hSC, readers.get(), &len) != SCARD_S_SUCCESS) {
      return CKR_TOKEN_NOT_PRESENT;
    }

    char* curreader = readers.get();
    bool foundCIE = false;

    progressCallBack(25, "Looking for CIE...");

    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR.get()),
                               &atrLen) != SCARD_S_SUCCESS) {
        return CKR_DEVICE_ERROR;
      }

      ATR.reset(static_cast<char*>(malloc(atrLen)));

      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR.get()),
                               &atrLen) != SCARD_S_SUCCESS) {
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR.get()), atrLen);

      auto ias = std::make_unique<IAS>(TokenTransmitCallback, atrBa);
      ias->SetCardContext(&conn);

      ias->token.Reset();
      // Continue looking for a CIE if the token is unrecognised
      try {
        ias->SelectAID_IAS();
      } catch (logged_error& err) {
        ATR.reset();
        continue;
      }
      ias->ReadPAN();

      foundCIE = true;
      ByteDynArray IntAuth;
      ias->SelectAID_CIE();
      ias->ReadDappPubKey(IntAuth);
      ias->SelectAID_CIE();
      ias->InitEncKey();

      ByteDynArray IdServizi;
      ias->ReadIdServizi(IdServizi);
      ByteArray baPan =
          ByteArray(reinterpret_cast<const uint8_t*>(pan), strlen(pan));

      if (baPan.size() > 0 &&
          memcmp(baPan.data(), IdServizi.data(), IdServizi.size()) != 0) {
        panMismatch = true;
        ATR.reset();
        continue;
      }

      progressCallBack(50, "Authenticating with card...");

      ByteDynArray FullPIN;
      ByteArray LastPIN =
          ByteArray(reinterpret_cast<const uint8_t*>(pin), strlen(pin));
      ias->GetFirstPIN(FullPIN);
      FullPIN.append(LastPIN);
      ias->token.Reset();

      progressCallBack(60, "Reading encrypted file...");

      // Read encrypted file
      FILE* fp = fopen(inFilePath, "rb");
      if (fp == nullptr) {
        LOG_ERROR("cie_decrypt - Failed to open input file: %s", inFilePath);
        return CKR_DEVICE_ERROR;
      }

      fseek(fp, 0, SEEK_END);
      long fileSize = ftell(fp);
      fseek(fp, 0, SEEK_SET);

      if (fileSize < 0) {
        LOG_ERROR("cie_decrypt - Failed to get file size");
        fclose(fp);
        return CKR_DEVICE_ERROR;
      }

      std::vector<unsigned char> encryptedData;
      if (fileSize > 0) {
        encryptedData.resize(static_cast<size_t>(fileSize));
        size_t bytesRead = fread(encryptedData.data(), 1, fileSize, fp);
        if (bytesRead != static_cast<size_t>(fileSize)) {
          LOG_ERROR("cie_decrypt - Failed to read file");
          fclose(fp);
          return CKR_DEVICE_ERROR;
        }
      }
      fclose(fp);

      // Get RSA modulus size from certificate
      unsigned char* derBufRaw = nullptr;
      unsigned long derLen = 0;
      CK_RV ret = cie_get_certificate(pan, &derBufRaw, &derLen);
      if (ret != CKR_OK) {
        LOG_ERROR("cie_decrypt - Failed to get certificate");
        return ret;
      }
      derBuf.reset(derBufRaw);

      const unsigned char* p = derBufRaw;
      X509* cert = d2i_X509(nullptr, &p, derLen);
      if (cert == nullptr) {
        LOG_ERROR("cie_decrypt - Failed to parse X.509 certificate");
        return CKR_FUNCTION_FAILED;
      }

      EVP_PKEY* pkey = X509_get_pubkey(cert);
      if (pkey == nullptr) {
        LOG_ERROR("cie_decrypt - Failed to extract public key");
        X509_free(cert);
        return CKR_FUNCTION_FAILED;
      }

      int rsaSize = EVP_PKEY_get_size(pkey);

      progressCallBack(70, "Decrypting...");

      std::vector<unsigned char> plaintext;

      // Detect format: check if first 4 bytes look like a length prefix
      bool isHybrid = false;
      if (encryptedData.size() >= 4) {
        uint32_t keyLenBE;
        memcpy(&keyLenBE, encryptedData.data(), 4);
        uint32_t keyLen = ntohl(keyLenBE);
        // If keyLen is reasonable (between 128 and 512 bytes) and the file is
        // large enough, treat as hybrid
        if (keyLen >= 128 && keyLen <= 512 &&
            encryptedData.size() >= 4 + keyLen + 12 + 16) {
          isHybrid = true;
        }
      }

      if (!isHybrid) {
        // Direct RSA-OAEP decryption
        ByteDynArray rawResult;
        ias->Sign(ByteArray(encryptedData.data(), encryptedData.size()),
                  rawResult);

        // Remove OAEP padding
        std::vector<unsigned char> decrypted(rsaSize);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        int decLen = RSA_padding_check_PKCS1_OAEP_mgf1(
            decrypted.data(), rsaSize, rawResult.data(), rawResult.size(),
            rsaSize, nullptr, 0, nullptr, nullptr);
#pragma GCC diagnostic pop

        if (decLen <= 0) {
          LOG_ERROR("cie_decrypt - OAEP padding check failed");
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }

        plaintext.insert(plaintext.end(), decrypted.begin(),
                         decrypted.begin() + decLen);
      } else {
        // Hybrid AES-256-GCM + RSA-OAEP decryption
        uint32_t keyLenBE;
        memcpy(&keyLenBE, encryptedData.data(), 4);
        uint32_t keyLen = ntohl(keyLenBE);

        size_t offset = 4;
        std::vector<unsigned char> encryptedKey(
            encryptedData.begin() + offset,
            encryptedData.begin() + offset + keyLen);
        offset += keyLen;

        std::vector<unsigned char> iv(encryptedData.begin() + offset,
                                      encryptedData.begin() + offset + 12);
        offset += 12;

        std::vector<unsigned char> tag(encryptedData.begin() + offset,
                                       encryptedData.begin() + offset + 16);
        offset += 16;

        std::vector<unsigned char> ciphertext(encryptedData.begin() + offset,
                                              encryptedData.end());

        // Decrypt AES key using card
        ByteDynArray rawResult;
        ias->Sign(ByteArray(encryptedKey.data(), encryptedKey.size()),
                  rawResult);

        // Remove OAEP padding to get AES key
        std::vector<unsigned char> aesKey(rsaSize);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        int keyDecLen = RSA_padding_check_PKCS1_OAEP_mgf1(
            aesKey.data(), rsaSize, rawResult.data(), rawResult.size(), rsaSize,
            nullptr, 0, nullptr, nullptr);
#pragma GCC diagnostic pop

        if (keyDecLen != 32) {
          LOG_ERROR("cie_decrypt - AES key decryption failed");
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }

        // Decrypt ciphertext with AES-256-GCM
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
          LOG_ERROR("cie_decrypt - EVP_CIPHER_CTX_new failed");
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }

        std::vector<unsigned char> decrypted(ciphertext.size());
        int decLen = 0;
        int tmpLen = 0;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aesKey.data(),
                               iv.data()) != 1) {
          LOG_ERROR("cie_decrypt - EVP_DecryptInit_ex failed");
          EVP_CIPHER_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }

        // Set the authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) !=
            1) {
          LOG_ERROR("cie_decrypt - EVP_CIPHER_CTX_ctrl SET_TAG failed");
          EVP_CIPHER_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }

        if (EVP_DecryptUpdate(ctx, decrypted.data(), &tmpLen, ciphertext.data(),
                              ciphertext.size()) != 1) {
          LOG_ERROR("cie_decrypt - EVP_DecryptUpdate failed");
          EVP_CIPHER_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }
        decLen = tmpLen;

        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + decLen, &tmpLen) != 1) {
          LOG_ERROR(
              "cie_decrypt - EVP_DecryptFinal_ex failed (tag verification)");
          EVP_CIPHER_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          X509_free(cert);
          return CKR_FUNCTION_FAILED;
        }
        decLen += tmpLen;
        EVP_CIPHER_CTX_free(ctx);

        plaintext.insert(plaintext.end(), decrypted.begin(),
                         decrypted.begin() + decLen);
      }

      EVP_PKEY_free(pkey);
      X509_free(cert);

      progressCallBack(90, "Writing decrypted file...");

      // Write plaintext to output file
      FILE* outFp = fopen(outFilePath, "wb");
      if (outFp == nullptr) {
        LOG_ERROR("cie_decrypt - Failed to open output file: %s", outFilePath);
        return CKR_DEVICE_ERROR;
      }

      size_t bytesWritten =
          fwrite(plaintext.data(), 1, plaintext.size(), outFp);
      fclose(outFp);

      if (bytesWritten != plaintext.size()) {
        LOG_ERROR("cie_decrypt - Failed to write plaintext to file");
        return CKR_DEVICE_ERROR;
      }

      progressCallBack(100, "OK!");
      LOG_INFO("cie_decrypt - completed successfully");

      // A this point a CIE has been found, stop looking for it
      break;
    }

    if (!foundCIE) {
      return CKR_TOKEN_NOT_RECOGNIZED;
    }
  } catch (std::exception& ex) {
    LOG_ERROR("cie_decrypt - Exception: %s", ex.what());
    return CKR_GENERAL_ERROR;
  }

  if (panMismatch) return CARD_PAN_MISMATCH;

  return SCARD_S_SUCCESS;
}
