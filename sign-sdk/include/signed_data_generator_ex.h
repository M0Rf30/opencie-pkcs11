// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file signed_data_generator_ex.h
 * @brief Extended SignedData builder for adding signers, counter-signatures,
 * and timestamps.
 */

#pragma once

// #include "asn1/utiltypes.h"
#include <vector>

#include "asn1/asn1_set_of.h"
#include "asn1/signer_info.h"
#include "asn1/time_stamp_response.h"
#include "signed_document.h"
#include "util/array.h"

/**
 * Builds CMS SignedData structures by composing signer infos,
 * counter-signatures, and timestamp tokens from existing signed documents.
 */
class SignedDataGeneratorEx {
 public:
  explicit SignedDataGeneratorEx(CSignedDocument& sd);

  virtual ~SignedDataGeneratorEx();

  bool isDetached();

  void setContent(const BYTE* content, int len);

  /** Merge the signers from another SignedDocument into this one. */
  void addSigners(CSignedDocument& sd);

  /** Add a counter-signature to the specified signer. */
  void addCounterSignature(CSignerInfo& signerInfoRef,
                           CSignedDocument& countersignature);

  /** Add a counter-signature and optional TSR to the specified signer. */
  void addCounterSignature(CSignerInfo& signerInfoRef,
                           CSignedDocument& counterSignature,
                           CTimeStampResponse& tsr);

  /** Attach a timestamp token to the specified signer. */
  void setTimestamp(CTimeStampResponse& tsr, int signerInfoIndex);

  /** Serialize the complete CMS SignedData to DER-encoded bytes. */
  void toByteArray(ByteDynArray& pkcs7SignedData);

 private:
  ByteDynArray m_content;

  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
  CASN1SetOf m_digestAlgos;

  static bool addCounterSignature(CSignerInfo& signerInfo,
                                  CSignerInfo& signerInfoRef,
                                  CSignerInfo& counterSignature);
};
