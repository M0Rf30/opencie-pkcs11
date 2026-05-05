// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// cie_timestamp_csp.cpp — Standalone RFC 3161 timestamp for an arbitrary file.
//
// Does NOT require a CIE card. Reads the file, computes SHA-256, sends a
// TimeStampRequest to the TSA, and writes the DER-encoded TimeStampToken to
// outTokenPath.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "crypto/sha256.h"
#include "logger/logger.h"
#include "opencie/cie_ext.h"
#include "pkcs11/pkcs11_functions.h"
#include "tsa_client.h"
#include "util/array.h"
#include "util/util_exception.h"

using namespace CieIDLogger;

extern "C" {
CK_RV CK_ENTRY cie_timestamp(const char* inFilePath, const char* tsaUrl,
                             const char* tsaUsername, const char* tsaPassword,
                             const char* outTokenPath,
                             PROGRESS_CALLBACK progressCallBack);
}

CK_RV CK_ENTRY cie_timestamp(const char* inFilePath, const char* tsaUrl,
                             const char* tsaUsername, const char* tsaPassword,
                             const char* outTokenPath,
                             PROGRESS_CALLBACK progressCallBack) {
  LOG_INFO("****** Starting cie_timestamp ******");

  if (inFilePath == nullptr || tsaUrl == nullptr || outTokenPath == nullptr) {
    LOG_ERROR("cie_timestamp - NULL argument");
    return CKR_ARGUMENTS_BAD;
  }

  try {
    // Step 1: Read file
    progressCallBack(10, "Reading file...");
    FILE* fp = fopen(inFilePath, "rb");
    if (fp == nullptr) {
      LOG_ERROR("cie_timestamp - Failed to open input file: %s", inFilePath);
      return CKR_DEVICE_ERROR;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize < 0) {
      LOG_ERROR("cie_timestamp - Failed to get file size");
      fclose(fp);
      return CKR_DEVICE_ERROR;
    }

    ByteDynArray fileData;
    if (fileSize > 0) {
      fileData.resize(static_cast<size_t>(fileSize));
      size_t bytesRead = fread(fileData.data(), 1, fileSize, fp);
      if (bytesRead != static_cast<size_t>(fileSize)) {
        LOG_ERROR("cie_timestamp - Failed to read file");
        fclose(fp);
        return CKR_DEVICE_ERROR;
      }
    }
    fclose(fp);

    // Step 2: Compute SHA-256
    progressCallBack(30, "Computing SHA-256...");
    ByteDynArray digest =
        CSHA256::Digest(ByteArray(fileData.data(), fileData.size()));

    // Step 3: Request timestamp
    progressCallBack(50, "Requesting timestamp...");
    CTSAClient tsa;
    tsa.SetTSAUrl(tsaUrl);
    if (tsaUsername != nullptr && tsaUsername[0] != '\0') {
      tsa.SetCredential(tsaUsername, tsaPassword);
    }

    CTimeStampToken* pToken = nullptr;
    long ret = tsa.GetTimeStampToken(digest, nullptr, &pToken);
    if (ret != 0 || pToken == nullptr) {
      LOG_ERROR("cie_timestamp - TSA request failed: %ld", ret);
      return CKR_FUNCTION_FAILED;
    }

    // Step 4: Write token
    progressCallBack(80, "Writing token...");
    ByteDynArray tokenBytes;
    pToken->toByteArray(tokenBytes);
    delete pToken;

    FILE* outFp = fopen(outTokenPath, "wb");
    if (outFp == nullptr) {
      LOG_ERROR("cie_timestamp - Failed to open output file: %s", outTokenPath);
      return CKR_DEVICE_ERROR;
    }

    size_t bytesWritten =
        fwrite(tokenBytes.data(), 1, tokenBytes.size(), outFp);
    fclose(outFp);

    if (bytesWritten != tokenBytes.size()) {
      LOG_ERROR("cie_timestamp - Failed to write token to file");
      return CKR_DEVICE_ERROR;
    }

    progressCallBack(100, "OK!");
    LOG_INFO("cie_timestamp - completed successfully");
    return SCARD_S_SUCCESS;

  } catch (const std::exception& ex) {
    LOG_ERROR("cie_timestamp - Exception: %s", ex.what());
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("cie_timestamp - Unknown exception");
    return CKR_GENERAL_ERROR;
  }
}
