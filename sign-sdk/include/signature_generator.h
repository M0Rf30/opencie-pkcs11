// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file signature_generator.h
 * @brief CMS/CAdES signature generation framework.
 */

#pragma once

#include "asn1/signer_info.h"
#include "base_signer.h"
#include "pkcs11/cryptoki.h"
#include "signed_document.h"
#include "signer_info_generator.h"
#include "tsa_client.h"
#include "util/array.h"
#include "util/definitions.h"

#define ALGO_SHA1 1    ///< SHA-1 hash algorithm identifier.
#define ALGO_SHA256 2  ///< SHA-256 hash algorithm identifier.

/**
 * Abstract base for CMS signature generators.
 *
 * Provides data input, alias selection, hash algorithm choice, and TSA
 * configuration.
 */
class CSignatureGeneratorBase {
 protected:
  CSignatureGeneratorBase(CBaseSigner* pCryptoki);
  CSignatureGeneratorBase(CSignatureGeneratorBase* pGenerator);
  virtual ~CSignatureGeneratorBase(void);

 public:
  /** Set the data to be signed. */
  virtual void SetData(const ByteArray& data);

  /** Set the key alias to use for signing. */
  virtual void SetAlias(char* alias);

  /** Set the hash algorithm (ALGO_SHA1 or ALGO_SHA256). */
  virtual void SetHashAlgo(int hashAlgo);

  /** Configure the TSA endpoint for timestamp token requests. */
  virtual void SetTSA(char* szUrl, char* szUsername, char* szPassword);

  /** Set the TSA authentication username. */
  virtual void SetTSAUsername(char* szUsername);

  /** Set the TSA authentication password. */
  virtual void SetTSAPassword(char* szPassword);

  /** Generate the signed data. Pure virtual in the base class. */
  virtual long Generate(ByteDynArray& pkcs7SignedData, BOOL bDetached = FALSE,
                        BOOL bVerifyRevocation = FALSE) = 0;

 protected:
  CBaseSigner* m_pSigner;
  ByteDynArray m_data;
  int m_nHashAlgo;
  char m_szAlias[MAX_PATH];
  CTSAClient* m_pTSAClient;
};

/**
 * Concrete CMS/CAdES signature generator.
 *
 * Produces PKCS#7 SignedData structures with optional CAdES-BES extensions
 * and timestamp tokens.
 */
class CSignatureGenerator : public CSignatureGeneratorBase {
 public:
  CSignatureGenerator(CBaseSigner* pSigner, bool bRemote = false);
  virtual ~CSignatureGenerator(void);

  /** Provide existing PKCS#7 data to add a new signature to. */
  void SetPKCS7Data(const ByteArray& pkcs7Data);

  /** Enable CAdES-BES mode. */
  void SetCAdES(bool cades);

  /** Query whether CAdES-BES mode is enabled. */
  bool GetCAdES();

  /** Retrieve the signer's certificate from the configured signer. */
  long GetCertificate(CCertificate** ppCertificate);

  /** Generate the signed data. */
  virtual long Generate(ByteDynArray& pkcs7SignedData, BOOL bDetached = FALSE,
                        BOOL bVerifyRevocation = FALSE);

 private:
  bool m_bCAdES;
  bool m_bRemote;

  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
  CASN1SetOf m_digestAlgos;

  CSignerInfoGenerator m_signerInfoGenerator;
};
