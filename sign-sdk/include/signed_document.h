// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file signed_document.h
 * @brief CMS SignedData document wrapper for signature verification and
 * manipulation.
 */

#pragma once

#include <map>
#include <memory>

#include "asn1/content_info.h"
#include "asn1/signed_data.h"
#include "asn1/signer_info.h"
#include "sign/cie_sign_api.h"
#include "util/array.h"
#include "util/definitions.h"

/**
 * Parses and verifies CMS (PKCS#7) SignedData structures.
 *
 * Supports multi-signer documents, detached signatures, and timestamp
 * validation.
 */
class CSignedDocument {
 public:
  CSignedDocument(const BYTE* content, int len);
  CSignedDocument(const CSignedDocument& signedDocument);

  virtual ~CSignedDocument();

  /** Verify all signatures. Returns 0 on success. */
  int verify();

  /** Verify all signatures at the given date/time. Returns 0 on success. */
  int verify(const char* dateTime);

  /** Verify a specific signature by @p index. Returns 0 on success. */
  int verify(int index, REVOCATION_INFO* pRevocationInfo);

  /**
   * Verify a specific signature by @p index at the given date/time.
   * Returns 0 on success.
   */
  int verify(int index, const char* dateTime, REVOCATION_INFO* pRevocationInfo);

  /** Return the number of SignerInfo entries. */
  int getSignerCount();

  CASN1SetOf getSignerInfos();
  CASN1SetOf getCertificates();
  CASN1SetOf getDigestAlgos();

  CSignerInfo getSignerInfo(int index);
  CCertificate getSignerCertificate(int index);

  /** Extract the signed content (encapContentInfo). */
  void getContent(ByteDynArray& content);

  // static void init(map<string, CCertificate*> certMap);

  /** Convert to a detached signature by removing the embedded content. */
  void makeDetached();

  /** Serialize the CMS structure to DER-encoded bytes. */
  void toByteArray(ByteDynArray& signedData);

  CSignedData getSignedData();

  bool isDetached();
  void setContent(ByteDynArray& content);

  /**
   * Classify a date string relative to Italian legislative decree 45/2009
   * transition dates.
   *
   * Returns 0 if after 30 June 2011, 1 if after 30 August 2010,
   * 2 if before 30 August 2010.
   */
  static int get452009Range(char* szDateTime);

 private:
  std::unique_ptr<CContentInfo> m_pCMSSignedData;
  std::unique_ptr<CSignedData> m_pSignedData;
  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
};
